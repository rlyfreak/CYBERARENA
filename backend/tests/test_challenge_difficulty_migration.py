from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker
from test_ctf_api import authenticate
from test_ctf_service import factory_for

from app.auth import bootstrap, dependencies
from app.ctf import service
from app.database import Base
from app.main import app
from app.migrations import (
    challenge_difficulty,
    challenge_resources,
    ctf_core,
    user_auth,
)
from app.models import SchemaMigration


@pytest.fixture
def difficulty_engine(tmp_path):
    engine, _ = factory_for((tmp_path / "difficulty.db").as_posix())
    yield engine
    engine.dispose()


def early_schema(engine, marked=True):
    Base.metadata.create_all(engine, tables=[Base.metadata.tables["users"]])
    with engine.begin() as db:
        # Include schema features that an ORM-based replacement could silently lose.
        db.exec_driver_sql("""CREATE TABLE challenges /* preserve (comments) */ (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code VARCHAR(32) UNIQUE,
            title VARCHAR(150) NOT NULL CHECK(length(title) > 0),
            description TEXT NOT NULL,
            category VARCHAR(50) NOT NULL,
            points INTEGER NOT NULL CHECK(points > 0),
            flag_hash VARCHAR(64) NOT NULL,
            is_published BOOLEAN NOT NULL DEFAULT 0,
            revision INTEGER NOT NULL DEFAULT 1,
            difficulty VARCHAR(16) NOT NULL DEFAULT 'easy',
            resource_url TEXT,
            owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL
                DEFERRABLE INITIALLY DEFERRED,
            "extra(name)" TEXT COLLATE NOCASE UNIQUE DEFAULT 'a)''b(',
            derived TEXT GENERATED ALWAYS AS (title || points) VIRTUAL
        )""")
    ctf_core.migrate(engine)
    with engine.begin() as db:
        db.exec_driver_sql("INSERT INTO users(id,username,password_hash) VALUES (1,'player','unused')")
        db.exec_driver_sql("""INSERT INTO challenges
            (id,code,title,description,category,points,flag_hash,is_published,owner_id,resource_url)
            VALUES (1,'WEB-01','Existing task','Keep text','WEB',100,?,1,1,'/lab/status')""", ("a" * 64,))
        db.exec_driver_sql("""INSERT INTO submissions
            (id,user_id,challenge_id,is_correct,submitted_at,result)
            VALUES (1,1,1,1,'2026-01-01 00:00:00','correct')""")
        db.exec_driver_sql("""INSERT INTO solves
            (id,user_id,challenge_id,submission_id,points_awarded,solved_at)
            VALUES (1,1,1,1,100,'2026-01-01 00:00:00')""")
        db.exec_driver_sql("CREATE INDEX custom_difficulty_index ON challenges(difficulty, points) WHERE is_published=1")
        db.exec_driver_sql("CREATE TABLE challenge_notes(id INTEGER PRIMARY KEY, task INTEGER REFERENCES challenges(id) ON DELETE CASCADE)")
        db.exec_driver_sql("INSERT INTO challenge_notes VALUES (1,1)")
        db.exec_driver_sql("CREATE TABLE challenge_audit(task INTEGER, title TEXT)")
        db.exec_driver_sql("""CREATE TRIGGER challenge_title_audit AFTER UPDATE OF title ON challenges
            BEGIN INSERT INTO challenge_audit VALUES (NEW.id, NEW.title); END""")
        db.exec_driver_sql("CREATE VIEW task_titles AS SELECT id,title FROM challenges")
        db.exec_driver_sql("CREATE VIEW task_titles_nested AS SELECT title FROM task_titles")
        db.exec_driver_sql("""CREATE TRIGGER note_added AFTER INSERT ON challenge_notes
            BEGIN INSERT INTO challenge_audit SELECT id,title FROM challenges WHERE id=NEW.task; END""")
        if marked:
            db.exec_driver_sql("INSERT INTO schema_migrations(name) VALUES (?)", (challenge_resources.VERSION,))


def snapshot(engine):
    with engine.connect() as db:
        schema = db.exec_driver_sql(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
        ).all()
        tables = db.exec_driver_sql("SELECT name FROM sqlite_schema WHERE type='table'").scalars()
        data = {
            name: db.exec_driver_sql('SELECT * FROM "' + name.replace('"', '""') + '" ORDER BY 1').all()
            for name in tables
        }
        return schema, data


def assert_connection_settings(engine, foreign_keys=1, legacy_alter_table=0):
    with engine.connect() as db:
        assert db.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == foreign_keys
        assert db.exec_driver_sql("PRAGMA legacy_alter_table").scalar_one() == legacy_alter_table


@pytest.mark.parametrize("marked", [False, True])
def test_early_difficulty_schema_is_rebuilt_and_rejects_invalid_writes(difficulty_engine, marked):
    engine = difficulty_engine
    early_schema(engine, marked)
    # Reproduce v1 accepting a value rejected by ChallengeOutput.
    with engine.begin() as db:
        db.exec_driver_sql("UPDATE challenges SET difficulty='expert'")
        db.exec_driver_sql("UPDATE challenges SET difficulty='medium'")
    challenge_resources.migrate(engine)
    challenge_difficulty.migrate(engine)
    for value in ("expert", "EASY", "", None):
        with pytest.raises(IntegrityError), engine.begin() as db:
            db.exec_driver_sql("UPDATE challenges SET difficulty=? WHERE id=1", (value,))
        with pytest.raises(IntegrityError), engine.begin() as db:
            db.exec_driver_sql("""INSERT INTO challenges
                (title,description,category,points,flag_hash,difficulty)
                VALUES ('Other','Text','WEB',100,'unused',?)""", (value,))
    with engine.connect() as db:
        assert db.exec_driver_sql("SELECT difficulty FROM challenges").scalar_one() == "medium"
        assert db.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    assert_connection_settings(engine)


def test_rebuild_preserves_rows_constraints_indexes_triggers_and_views(difficulty_engine):
    engine = difficulty_engine
    early_schema(engine)
    _, before_data = snapshot(engine)
    with engine.connect() as db:
        objects = db.exec_driver_sql(
            "SELECT type,name,sql FROM sqlite_schema WHERE type IN ('index','trigger','view') ORDER BY type,name"
        ).all()
        child_fks = {
            name: db.exec_driver_sql(f'PRAGMA foreign_key_list("{name}")').all()
            for name in ("submissions", "solves", "challenge_notes", "challenges")
        }
        columns = db.exec_driver_sql("PRAGMA table_xinfo(challenges)").all()
    challenge_difficulty.migrate(engine)
    _, after_data = snapshot(engine)
    after_data["schema_migrations"] = before_data["schema_migrations"]
    assert before_data == after_data
    with engine.connect() as db:
        assert db.exec_driver_sql(
            "SELECT type,name,sql FROM sqlite_schema WHERE type IN ('index','trigger','view') ORDER BY type,name"
        ).all() == objects
        assert db.exec_driver_sql("PRAGMA table_xinfo(challenges)").all() == columns
        for name, expected in child_fks.items():
            assert db.exec_driver_sql(f'PRAGMA foreign_key_list("{name}")').all() == expected
        assert db.exec_driver_sql("SELECT title FROM task_titles_nested").scalar_one() == "Existing task"
        assert db.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert db.exec_driver_sql("PRAGMA integrity_check").scalar_one() == "ok"
    with engine.begin() as db:
        db.exec_driver_sql("UPDATE challenges SET title='Changed' WHERE id=1")
        db.exec_driver_sql("INSERT INTO challenge_notes VALUES (2,1)")
        assert db.exec_driver_sql("SELECT * FROM challenge_audit").all() == [(1, "Changed"), (1, "Changed")]
    for statement in (
        "UPDATE challenges SET points=0",
        "UPDATE challenges SET title=''",
        "UPDATE challenges SET owner_id=999",
        "DELETE FROM challenges",
    ):
        with pytest.raises(IntegrityError), engine.begin() as db:
            db.exec_driver_sql(statement)
    with pytest.raises(IntegrityError), engine.begin() as db:
        db.exec_driver_sql("""INSERT INTO challenges(code,title,description,category,points,flag_hash)
            VALUES ('WEB-01','Duplicate','Text','WEB',100,'unused')""")


@pytest.mark.parametrize("value", ["expert", "EASY"])
def test_invalid_existing_data_aborts_without_replacement_and_blocks_startup(difficulty_engine, monkeypatch, value):
    engine = difficulty_engine
    early_schema(engine)
    challenge_resources.migrate(engine)
    with engine.begin() as db:
        db.exec_driver_sql("UPDATE challenges SET difficulty=?", (value,))
    factory = sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(dependencies, "SessionLocal", factory)
    monkeypatch.setattr(service, "SessionLocal", factory)
    client = TestClient(app, raise_server_exceptions=False)
    try:
        authenticate(client, factory, 1)
        assert client.get("/api/challenges").status_code == 500
    finally:
        client.close()
    before = snapshot(engine)
    with pytest.raises(RuntimeError, match=r"invalid challenges\.difficulty.*1"):
        challenge_difficulty.migrate(engine)
    assert snapshot(engine) == before
    assert_connection_settings(engine)
    for module in (user_auth, ctf_core, challenge_resources, challenge_difficulty):
        monkeypatch.setattr(module, "engine", engine)
    monkeypatch.setattr(bootstrap, "SessionLocal", factory)
    monkeypatch.setenv("ADMIN_USERNAME", "migration_admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "IsolatedMigrationPassword2026")
    with pytest.raises(RuntimeError, match=r"invalid challenges\.difficulty"), TestClient(app):
        pytest.fail("Startup must not serve requests with invalid difficulty")
    assert snapshot(engine) == before
    # Explicit operator repair; the migration must never choose a replacement itself.
    with engine.begin() as db:
        db.exec_driver_sql("UPDATE challenges SET difficulty='hard' WHERE id=1")
    for _ in range(2):
        with TestClient(app) as client:
            authenticate(client, factory, 1)
            response = client.get("/api/challenges")
            assert response.status_code == 200, response.text
            assert response.json()[0]["difficulty"] == "hard"
    with Session(engine) as db:
        assert db.get(SchemaMigration, challenge_difficulty.VERSION) is not None
    with pytest.raises(IntegrityError), engine.begin() as db:
        db.exec_driver_sql("UPDATE challenges SET difficulty='expert'")
    assert_connection_settings(engine)


@pytest.mark.parametrize("phase", ["copy", "rename", "indexes", "foreign_keys", "marker", "commit"])
def test_failed_rebuild_rolls_back_everything_and_restores_pragmas(difficulty_engine, phase):
    engine = difficulty_engine
    early_schema(engine)
    before = snapshot(engine)
    ready_to_commit = False

    def fail(_connection, _cursor, statement, *_):
        nonlocal ready_to_commit
        if phase == "foreign_keys" and statement.startswith("CREATE INDEX custom_difficulty_index"):
            # Exercise the final FK check, after the table has already been replaced.
            _connection.exec_driver_sql("UPDATE submissions SET user_id=999")
        if "INSERT INTO schema_migrations" in statement:
            ready_to_commit = True
        matches = {
            "copy": statement.startswith('INSERT INTO "_challenges_difficulty_v2"'),
            "rename": statement.startswith('ALTER TABLE "_challenges_difficulty_v2"'),
            "indexes": statement.startswith("CREATE INDEX custom_difficulty_index"),
            "marker": "INSERT INTO schema_migrations" in statement,
        }
        if matches.get(phase, False):
            raise RuntimeError("Injected rebuild failure")

    def fail_commit(_connection):
        nonlocal ready_to_commit
        if phase == "commit" and ready_to_commit:
            ready_to_commit = False
            raise RuntimeError("Injected rebuild failure")

    event.listen(engine, "before_cursor_execute", fail)
    event.listen(engine, "commit", fail_commit)
    try:
        message = "Foreign key" if phase == "foreign_keys" else "Injected rebuild failure"
        with pytest.raises(RuntimeError, match=message):
            challenge_difficulty.migrate(engine)
    finally:
        event.remove(engine, "before_cursor_execute", fail)
        event.remove(engine, "commit", fail_commit)
    assert snapshot(engine) == before
    assert_connection_settings(engine)
    challenge_difficulty.migrate(engine)
    with pytest.raises(IntegrityError), engine.begin() as db:
        db.exec_driver_sql("UPDATE challenges SET difficulty='expert'")


def test_foreign_key_violation_aborts_rebuild(difficulty_engine):
    engine = difficulty_engine
    early_schema(engine)
    with engine.connect() as db:
        db.exec_driver_sql("PRAGMA foreign_keys=OFF")
        db.exec_driver_sql("UPDATE submissions SET user_id=999")
        db.commit()
        db.exec_driver_sql("PRAGMA foreign_keys=ON")
    before = snapshot(engine)
    with pytest.raises(RuntimeError, match="Foreign key"):
        challenge_difficulty.migrate(engine)
    assert snapshot(engine) == before
    assert_connection_settings(engine)


def test_rebuild_preserves_autoincrement_high_water_mark(difficulty_engine):
    engine = difficulty_engine
    early_schema(engine)
    with engine.begin() as db:
        db.exec_driver_sql("""INSERT INTO challenges
            (id,title,description,category,points,flag_hash,"extra(name)")
            VALUES (100,'Deleted','Text','WEB',100,'unused','different')""")
        db.exec_driver_sql("DELETE FROM challenges WHERE id=100")
    challenge_difficulty.migrate(engine)
    with engine.begin() as db:
        db.exec_driver_sql("""INSERT INTO challenges
            (title,description,category,points,flag_hash,"extra(name)")
            VALUES ('Next','Text','WEB',100,'unused','different')""")
        assert db.exec_driver_sql("SELECT id FROM challenges WHERE title='Next'").scalar_one() == 101


@pytest.mark.parametrize("foreign_keys,legacy", [(1, 0), (0, 0), (1, 1)])
def test_repeat_migration_is_noop_and_restores_original_connection_settings(difficulty_engine, foreign_keys, legacy):
    engine = difficulty_engine
    early_schema(engine)
    with engine.connect() as db:
        db.exec_driver_sql(f"PRAGMA foreign_keys={foreign_keys}")
        db.exec_driver_sql(f"PRAGMA legacy_alter_table={legacy}")
    challenge_difficulty.migrate(engine)
    before = snapshot(engine)
    with engine.connect() as db:
        version = db.exec_driver_sql("PRAGMA schema_version").scalar_one()
    challenge_difficulty.migrate(engine)
    assert snapshot(engine) == before
    with engine.connect() as db:
        assert db.exec_driver_sql("PRAGMA schema_version").scalar_one() == version
    assert_connection_settings(engine, foreign_keys, legacy)


def test_concurrent_repair_runs_once(difficulty_engine):
    engine = difficulty_engine
    early_schema(engine)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: challenge_difficulty.migrate(engine), range(4)))
    with engine.connect() as db:
        assert db.exec_driver_sql(
            "SELECT COUNT(*) FROM schema_migrations WHERE name=?", (challenge_difficulty.VERSION,)
        ).scalar_one() == 1
        assert db.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    with pytest.raises(IntegrityError), engine.begin() as db:
        db.exec_driver_sql("UPDATE challenges SET difficulty='expert'")


def test_fresh_schema_and_defaults(difficulty_engine):
    engine = difficulty_engine
    ctf_core.migrate(engine)
    challenge_resources.migrate(engine)
    challenge_difficulty.migrate(engine)
    challenge_difficulty.migrate(engine)
    with engine.begin() as db:
        db.exec_driver_sql("""INSERT INTO challenges(title,description,category,points,flag_hash)
            VALUES ('New','Text','WEB',100,'unused')""")
        assert db.exec_driver_sql("SELECT difficulty,resource_url FROM challenges").all() == [("easy", None)]
    with pytest.raises(IntegrityError), engine.begin() as db:
        db.exec_driver_sql("UPDATE challenges SET difficulty='expert'")
    assert_connection_settings(engine)


@pytest.mark.parametrize("options", ["STRICT", "WITHOUT ROWID"])
def test_rebuild_preserves_table_options(difficulty_engine, options):
    engine = difficulty_engine
    Base.metadata.create_all(engine, tables=[Base.metadata.tables["schema_migrations"]])
    with engine.begin() as db:
        db.exec_driver_sql(
            "CREATE TABLE challenges(id INTEGER PRIMARY KEY, "
            f"difficulty TEXT NOT NULL DEFAULT 'easy') {options}"
        )
        db.exec_driver_sql("INSERT INTO challenges(id) VALUES (1)")
    challenge_difficulty.migrate(engine)
    with engine.connect() as db:
        sql = db.exec_driver_sql("SELECT sql FROM sqlite_schema WHERE name='challenges'").scalar_one()
        assert sql.endswith(options)
        assert db.exec_driver_sql("SELECT * FROM challenges").all() == [(1, "easy")]
    with pytest.raises(IntegrityError), engine.begin() as db:
        db.exec_driver_sql("UPDATE challenges SET difficulty='expert'")


def test_existing_replacement_name_is_not_overwritten(difficulty_engine):
    engine = difficulty_engine
    early_schema(engine)
    with engine.begin() as db:
        db.exec_driver_sql('CREATE TABLE "_challenges_difficulty_v2"(value TEXT)')
        db.exec_driver_sql("""INSERT INTO "_challenges_difficulty_v2" VALUES ('keep')""")
    before = snapshot(engine)
    with pytest.raises(OperationalError, match="already exists"):
        challenge_difficulty.migrate(engine)
    assert snapshot(engine) == before
    assert_connection_settings(engine)

from concurrent.futures import ThreadPoolExecutor

import pytest
from app.database import Base
from app.migrations import ctf_core, user_auth
from app.models import Challenge, SchemaMigration, Solve, Submission, User
from sqlalchemy import create_engine, event, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


@pytest.fixture
def migration_engine(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}")

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    yield engine
    engine.dispose()


def legacy_schema(engine):
    with engine.begin() as db:
        db.exec_driver_sql("""CREATE TABLE users (
            id INTEGER PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        db.exec_driver_sql("""CREATE TABLE challenges (
            id INTEGER PRIMARY KEY, title VARCHAR(150) NOT NULL,
            description TEXT NOT NULL, category VARCHAR(50) NOT NULL,
            points INTEGER NOT NULL CHECK(points > 0), flag_hash VARCHAR(64) NOT NULL)""")
        db.exec_driver_sql("""CREATE TABLE submissions (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
            challenge_id INTEGER NOT NULL REFERENCES challenges(id),
            is_correct BOOLEAN NOT NULL, submitted_at DATETIME NOT NULL)""")
        db.exec_driver_sql("INSERT INTO users VALUES (1,'legacy','keep-hash',CURRENT_TIMESTAMP)")
        db.exec_driver_sql("INSERT INTO challenges VALUES (1,'old','text','WEB',100,?)", ('a'*64,))
        db.exec_driver_sql("""INSERT INTO submissions VALUES
            (1,1,1,0,'2026-01-01 00:00:00'),
            (2,1,1,1,'2026-01-01 00:00:02'),
            (3,1,1,1,'2026-01-01 00:00:01'),
            (4,1,1,1,'2026-01-01 00:00:01')""")


def test_legacy_migration_preserves_data_and_backfills_once(migration_engine, monkeypatch):
    engine = migration_engine
    legacy_schema(engine)
    monkeypatch.setattr(user_auth, "engine", engine)
    user_auth.migrate()
    ctf_core.migrate(engine)
    ctf_core.migrate(engine)
    with Session(engine) as db:
        assert db.get(User, 1).password_hash == "keep-hash"
        challenge = db.get(Challenge, 1)
        assert challenge.flag_hash == 'a' * 64 and not challenge.is_published
        solves = db.scalars(select(Solve)).all()
        assert len(solves) == 1 and solves[0].submission_id == 3
        assert solves[0].points_awarded == 100
        assert len(db.scalars(select(Submission)).all()) == 4
        assert db.get(Submission, 1).result == "incorrect"
        assert db.get(Submission, 2).result == "correct"
        # VARCHAR(64) in old SQLite does not truncate new Argon2 encodings.
        challenge.flag_hash = '$argon2id$' + 'z' * 100
        db.delete(solves[0])
        db.commit()
    ctf_core.migrate(engine)
    with Session(engine) as db:
        assert db.scalar(select(Solve)) is None  # reset is not undone by startup
        assert len(db.get(Challenge, 1).flag_hash) == 110
        assert db.get(SchemaMigration, ctf_core.VERSION) is not None


def test_empty_and_concurrent_migration(migration_engine):
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: ctf_core.migrate(migration_engine), range(4)))
    assert set(Base.metadata.tables) <= set(inspect(migration_engine).get_table_names())
    with migration_engine.connect() as db:
        assert db.exec_driver_sql("SELECT generation FROM ctf_state").all() == [(0,)]


def test_solve_constraints(migration_engine):
    legacy_schema(migration_engine)
    # These checks exercise the database itself, independently of service checks.
    with migration_engine.begin() as db:
        db.exec_driver_sql("ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0")
        db.exec_driver_sql(
            "ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0"
        )
    ctf_core.migrate(migration_engine)
    for values in [(1, 1, 2, 100), (1, 1, 2, 0), (999, 1, 2, 100)]:
        with pytest.raises(IntegrityError), migration_engine.begin() as db:
            db.exec_driver_sql(
                "INSERT INTO solves(user_id,challenge_id,submission_id,points_awarded,solved_at) "
                "VALUES (?,?,?,?,CURRENT_TIMESTAMP)", values,
            )


def test_failed_migration_rolls_back_ddl(migration_engine):
    legacy_schema(migration_engine)
    # Invalid legacy rows must stop migration, rather than be silently discarded.
    with migration_engine.connect() as db:
        db.exec_driver_sql("PRAGMA foreign_keys=OFF")
        db.exec_driver_sql("INSERT INTO submissions VALUES (5,999,1,0,CURRENT_TIMESTAMP)")
        db.commit()
        db.exec_driver_sql("PRAGMA foreign_keys=ON")
    with pytest.raises(RuntimeError, match="Foreign key"):
        ctf_core.migrate(migration_engine)
    assert "result" not in {c['name'] for c in inspect(migration_engine).get_columns('submissions')}


def test_actual_lifespan_migrates_legacy_database(migration_engine, monkeypatch):
    from app.auth import bootstrap
    from app.main import app
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker

    legacy_schema(migration_engine)
    monkeypatch.setattr(user_auth, 'engine', migration_engine)
    monkeypatch.setattr(ctf_core, 'engine', migration_engine)
    monkeypatch.setattr(bootstrap, 'SessionLocal', sessionmaker(migration_engine))
    monkeypatch.setenv('ADMIN_USERNAME', 'lifespan_admin')
    monkeypatch.setenv('ADMIN_PASSWORD', 'IsolatedLifespanPass2026')
    for _ in range(2):
        with TestClient(app) as client:
            assert client.get('/api/health').status_code == 200
    with Session(migration_engine) as db:
        assert db.get(User, 1).password_hash == 'keep-hash'
        assert len(db.scalars(select(Solve)).all()) == 1
        assert db.scalar(select(User).where(User.username == 'lifespan_admin')).must_change_password

"""Repair early resource schemas with a real, transactional SQLite CHECK."""

import re

from sqlalchemy.engine import Connection, Engine

from ..database import engine

VERSION = "challenge_difficulty_v2"
REPLACEMENT = "_challenges_difficulty_v2"

# Locate the table's column list without treating quoted text or comments as SQL.
SQL_TOKENS = re.compile(
    r"""'(?:[^']|'')*'|"(?:[^"]|"")*"|\x60(?:[^\x60]|\x60\x60)*\x60|\[[^\]]*\]"""
    r"""|--[^\r\n]*|/\*.*?\*/|[()]""",
    re.DOTALL,
)


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _replacement_sql(original: str) -> str:
    opening = None
    depth = 0
    for token in SQL_TOKENS.finditer(original):
        if token[0] == "(":
            if opening is None:
                opening = token.start()
            depth += 1
        elif token[0] == ")":
            depth -= 1
            if depth == 0 and opening is not None:
                # Keep the actual columns, constraints, defaults and table options.
                return (
                    f"CREATE TABLE {_quote(REPLACEMENT)} "
                    + original[opening:token.start()]
                    + ", CONSTRAINT ck_challenges_difficulty_v2 CHECK ("
                    "difficulty IS NOT NULL AND difficulty COLLATE BINARY "
                    "IN ('easy', 'medium', 'hard'))"
                    + original[token.start():]
                )
    raise RuntimeError("Cannot read challenges table definition; migration rolled back")


def _check_foreign_keys(connection: Connection) -> None:
    if connection.exec_driver_sql("PRAGMA main.foreign_key_check").first() is not None:
        raise RuntimeError("Foreign key violations; difficulty migration rolled back")


def _rollback(connection: Connection) -> None:
    connection.rollback()
    if not connection.invalidated:
        # A failed COMMIT can deactivate SQLAlchemy's transaction while SQLite's
        # transaction is still open. End it before trying to restore FK enforcement.
        connection.connection.rollback()


def _rebuild(connection: Connection) -> None:
    original = connection.exec_driver_sql(
        "SELECT sql FROM main.sqlite_schema WHERE type='table' AND name='challenges'"
    ).scalar_one_or_none()
    if original is None:
        raise RuntimeError("Challenges table does not exist; run earlier migrations first")
    invalid_ids = connection.exec_driver_sql(
        "SELECT id FROM main.challenges WHERE difficulty IS NULL "
        "OR difficulty COLLATE BINARY NOT IN ('easy','medium','hard') ORDER BY id LIMIT 10"
    ).scalars().all()
    if invalid_ids:
        ids = ", ".join(str(value) for value in invalid_ids)
        raise RuntimeError(
            f"{VERSION}: invalid challenges.difficulty; first affected challenge IDs: {ids}. "
            "Explicitly correct these records to easy, medium or hard and retry. "
            "No records have been changed."
        )
    _check_foreign_keys(connection)
    objects = connection.exec_driver_sql(
        "SELECT sql FROM main.sqlite_schema WHERE tbl_name='challenges' "
        "AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type,name"
    ).scalars().all()
    columns = [
        row[1]
        for row in connection.exec_driver_sql("PRAGMA main.table_xinfo(challenges)")
        if row[6] == 0  # Generated columns are recomputed, never INSERTed.
    ]
    sequence = None
    if connection.exec_driver_sql(
        "SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name='sqlite_sequence'"
    ).scalar_one_or_none():
        sequence = connection.exec_driver_sql(
            "SELECT seq FROM main.sqlite_sequence WHERE name='challenges'"
        ).scalar_one_or_none()
    connection.exec_driver_sql(_replacement_sql(original))
    names = ", ".join(_quote(name) for name in columns)
    connection.exec_driver_sql(
        f"INSERT INTO {_quote(REPLACEMENT)} ({names}) SELECT {names} FROM main.challenges"
    )
    # Do not rename the old table: that can rewrite incoming foreign keys and views.
    connection.exec_driver_sql("DROP TABLE main.challenges")
    connection.exec_driver_sql(
        f"ALTER TABLE {_quote(REPLACEMENT)} RENAME TO challenges"
    )
    if sequence is not None:
        current = connection.exec_driver_sql(
            "SELECT seq FROM main.sqlite_sequence WHERE name='challenges'"
        ).scalar_one_or_none()
        connection.exec_driver_sql("DELETE FROM main.sqlite_sequence WHERE name='challenges'")
        connection.exec_driver_sql(
            "INSERT INTO main.sqlite_sequence(name,seq) VALUES ('challenges',?)",
            (max(sequence, current or 0),),
        )
    for sql in objects:
        connection.exec_driver_sql(sql)
    _check_foreign_keys(connection)


def migrate(bind: Engine | None = None) -> None:
    with (bind or engine).connect() as connection:
        foreign_keys = connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
        legacy = connection.exec_driver_sql("PRAGMA legacy_alter_table").scalar_one()
        connection.commit()
        try:
            # foreign_keys cannot be changed inside a SQLite transaction.
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            # Keep views and triggers on other tables referring to the final name.
            connection.exec_driver_sql("PRAGMA legacy_alter_table=ON")
            if connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() != 0:
                raise RuntimeError("Cannot disable foreign keys before difficulty migration")
            connection.commit()
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            applied = connection.exec_driver_sql(
                "SELECT 1 FROM main.schema_migrations WHERE name=?", (VERSION,)
            ).scalar_one_or_none()
            if not applied:
                _rebuild(connection)
                connection.exec_driver_sql(
                    "INSERT INTO schema_migrations(name) VALUES (?)", (VERSION,)
                )
            connection.commit()
        except BaseException:
            _rollback(connection)
            raise
        finally:
            try:
                _rollback(connection)
                connection.exec_driver_sql(f"PRAGMA legacy_alter_table={int(legacy)}")
                connection.exec_driver_sql(f"PRAGMA foreign_keys={int(foreign_keys)}")
                restored = connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
                if restored != foreign_keys:
                    raise RuntimeError("Failed to restore foreign key enforcement")
                if connection.exec_driver_sql("PRAGMA legacy_alter_table").scalar_one() != legacy:
                    raise RuntimeError("Failed to restore ALTER TABLE behavior")
                connection.commit()
            except BaseException:
                # Never return a connection with disabled FK enforcement to the pool.
                connection.invalidate()
                raise

"""Additive SQLite migration. Never run against live data from a test."""

from .. import models  # noqa: F401 -- register metadata
from ..database import Base, engine

VERSION = "ctf_core_v1"
ADDITIONS = {
    "challenges": {
        "code": "VARCHAR(32)",
        "is_published": "BOOLEAN NOT NULL DEFAULT 0",
        "revision": "INTEGER NOT NULL DEFAULT 1",
    },
    "submissions": {"result": "VARCHAR(32) NOT NULL DEFAULT 'incorrect'"},
}


def migrate(bind=None):
    with (bind or engine).connect() as connection:
        # Explicit BEGIN also makes SQLite DDL transactional and serializes startups.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            for table, columns in ADDITIONS.items():
                existing = {
                    row[1] for row in connection.exec_driver_sql(f"PRAGMA table_info({table})")
                }
                if existing:
                    for name, definition in columns.items():
                        if name not in existing:
                            connection.exec_driver_sql(
                                f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
                            )
            Base.metadata.create_all(connection)
            connection.exec_driver_sql(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_challenges_code ON challenges(code)"
            )
            connection.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_submissions_user_time "
                "ON submissions(user_id, submitted_at, id)"
            )
            migrated = connection.exec_driver_sql(
                "SELECT 1 FROM schema_migrations WHERE name = ?", (VERSION,)
            ).scalar()
            if not migrated:
                connection.exec_driver_sql(
                    "UPDATE submissions SET result = CASE WHEN is_correct = 1 "
                    "THEN 'correct' ELSE 'incorrect' END"
                )
                # Old schemas did not record awarded points: use the current price.
                connection.exec_driver_sql("""
                    INSERT INTO solves
                        (user_id, challenge_id, submission_id, points_awarded, solved_at)
                    SELECT s.user_id, s.challenge_id, s.id, c.points, s.submitted_at
                    FROM submissions s JOIN challenges c ON c.id = s.challenge_id
                    WHERE s.is_correct = 1 AND NOT EXISTS (
                        SELECT 1 FROM submissions earlier
                        WHERE earlier.user_id = s.user_id
                          AND earlier.challenge_id = s.challenge_id
                          AND earlier.is_correct = 1
                          AND (earlier.submitted_at < s.submitted_at OR
                              (earlier.submitted_at = s.submitted_at AND earlier.id < s.id))
                    )
                    ON CONFLICT(user_id, challenge_id) DO NOTHING
                """)
                connection.exec_driver_sql(
                    "INSERT INTO schema_migrations(name) VALUES (?)", (VERSION,)
                )
            connection.exec_driver_sql(
                "INSERT INTO ctf_state(id, generation) VALUES (1, 0) "
                "ON CONFLICT(id) DO NOTHING"
            )
            violations = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise RuntimeError("Foreign key violations; CTF migration rolled back")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise

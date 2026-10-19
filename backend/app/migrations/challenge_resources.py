from ..database import engine

VERSION = "challenge_resources_v1"
WEB01_RESOURCE_VERSION = "web01_resource_link_v1"

ADDITIONS = {
    "difficulty": (
        "VARCHAR(16) NOT NULL DEFAULT 'easy' "
        "CONSTRAINT ck_challenges_difficulty CHECK(difficulty IN ('easy', 'medium', 'hard'))"
    ),
    "resource_url": "TEXT",
}


def migrate(bind=None):
    with (bind or engine).connect() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            existing = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(challenges)")
            }
            resource_url_added = "resource_url" not in existing
            if not existing:
                raise RuntimeError(
                    "Challenges table does not exist. Run CTF Core migration first."
                )
            for name, definition in ADDITIONS.items():
                if name not in existing:
                    connection.exec_driver_sql(
                        f"ALTER TABLE challenges ADD COLUMN {name} {definition}"
                    )
            linked = connection.exec_driver_sql(
                "SELECT 1 FROM schema_migrations WHERE name = ?",
                (WEB01_RESOURCE_VERSION,),
            ).scalar()
            if not linked:
                if resource_url_added:
                    connection.exec_driver_sql(
                        "UPDATE challenges SET resource_url = '/lab/' "
                        "WHERE code = 'WEB-01' AND resource_url IS NULL"
                    )
                connection.exec_driver_sql(
                    "INSERT INTO schema_migrations(name) VALUES (?)",
                    (WEB01_RESOURCE_VERSION,),
                )
            connection.exec_driver_sql(
                "INSERT INTO schema_migrations(name) VALUES (?)"
                "ON CONFLICT(name) DO NOTHING",
                (VERSION,),
            )
            violations = connection.exec_driver_sql(
                "PRAGMA foreign_key_check"
            ).fetchall()

            if violations:
                raise RuntimeError("Foreign key violations; migration rolled back")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise

from app.database import engine

COLUMNS = {
    "is_admin": "BOOLEAN NOT NULL DEFAULT 0",
    "must_change_password": "BOOLEAN NOT NULL DEFAULT 0",
}


def migrate():
    with engine.begin() as connection:
        table_exists = connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        ).scalar()

        if not table_exists:
            raise RuntimeError("Table 'users' does not exist")

        result = connection.exec_driver_sql("PRAGMA table_info(users)")

        existing_columns = {row[1] for row in result.fetchall()}

        for name, definition in COLUMNS.items():
            if name not in existing_columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE users ADD COLUMN {name} {definition}"
                )
                print(f"Added column {name} to table 'users'")
            else:
                print(f"Column {name} already exists in table 'users'")

    with engine.connect() as connection:
        integrity = connection.exec_driver_sql("PRAGMA integrity_check").scalar_one()

        if integrity != "ok":
            raise RuntimeError(f"Ошибка целостности SQLite: {integrity}")

    print("Миграция успешно завершена.")
    print("Целостность SQLite: OK")


if __name__ == "__main__":
    migrate()

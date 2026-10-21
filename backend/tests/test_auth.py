import os
import re
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import login_throttle
from app.migrations import user_auth

# Используется только внутри процесса pytest.
os.environ["SESSION_SECRET"] = "cyberarena-isolated-test-secret-2026"

from app.auth import bootstrap, dependencies, routes
from app.auth.public_throttle import PublicAuthBudget
from app.auth.security import verify_password
from app.database import Base
from app.main import app
from app.models import LoginAttempt, User

USER_PASSWORD = "TestPlayerPass123!"
ADMIN_PASSWORD = "TestAdminPass123!"
NEW_ADMIN_PASSWORD = "NewAdminPass456!"


@pytest.mark.parametrize("password", ["", "x" * 11, "x" * 129, "change-me",
                                     "REPLACE_WITH_YOUR_PASSWORD"])
def test_bootstrap_rejects_invalid_password_and_public_placeholder(sandbox, monkeypatch, password):
    _, factory = sandbox
    monkeypatch.setenv("ADMIN_PASSWORD", password)
    with pytest.raises(RuntimeError, match="12.*128"):
        bootstrap.bootstrap_admin()
    with factory() as db:
        assert db.scalar(select(User.id)) is None


@pytest.mark.parametrize("length", [12, 128])
def test_bootstrap_accepts_password_length_boundaries(sandbox, monkeypatch, length):
    _, factory = sandbox
    monkeypatch.setenv("ADMIN_PASSWORD", "x" * length)
    bootstrap.bootstrap_admin()
    with factory() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        assert verify_password("x" * length, admin.password_hash)
        assert admin.must_change_password


def test_bootstrap_does_not_change_existing_passwords_or_sessions(sandbox, monkeypatch):
    from app.models import AuthSession

    client, factory = sandbox
    bootstrap.bootstrap_admin()
    register(client)
    assert login(client, "testplayer", USER_PASSWORD).status_code == 303
    with factory() as db:
        hashes = {user.id: user.password_hash for user in db.scalars(select(User))}
        sessions = [(row.token_hash, row.user_id, row.expires_at)
                    for row in db.scalars(select(AuthSession))]
    monkeypatch.setenv("ADMIN_PASSWORD", "DifferentBootstrapPassword2026")
    bootstrap.bootstrap_admin()
    with factory() as db:
        assert {user.id: user.password_hash for user in db.scalars(select(User))} == hashes
        assert [(row.token_hash, row.user_id, row.expires_at)
                for row in db.scalars(select(AuthSession))] == sessions
    assert client.get("/profile").status_code == 200


@pytest.mark.parametrize("token", [None, "", "тест", "x" * 129, "wrong"])
@pytest.mark.parametrize("path", ["/register", "/login", "/logout", "/change-password"])
def test_malformed_csrf_rejected_without_mutation(sandbox, token, path):
    client, factory = sandbox
    register(client)
    assert login(client, "testplayer", USER_PASSWORD).status_code == 303
    data = {
        "username": "otherplayer",
        "password": USER_PASSWORD,
        "password_confirm": USER_PASSWORD,
        "current_password": USER_PASSWORD,
        "new_password": "ReplacementPass456!",
    }
    if token is not None:
        data["csrf_token"] = token
    assert client.post(path, data=data).status_code == 403
    assert client.get("/profile").status_code == 200
    with factory() as db:
        users = db.scalars(select(User)).all()
        assert len(users) == 1
        assert verify_password(USER_PASSWORD, users[0].password_hash)


@pytest.mark.parametrize("stored", [None, 123, [], "тест", "x" * 129])
def test_invalid_stored_csrf_is_rejected_and_replaced(stored):
    from fastapi import HTTPException
    from starlette.requests import Request

    from app.auth.csrf import get_csrf_token, validate_csrf

    request = Request({"type": "http", "session": {"csrf_token": stored}})
    with pytest.raises(HTTPException) as error:
        validate_csrf(request, "valid-ascii")
    assert error.value.status_code == 403
    token = get_csrf_token(request)
    assert token.isascii() and len(token) == 43
    validate_csrf(request, token)


def _sandbox_setup(monkeypatch):
    """Отдельная SQLite-база для каждого теста."""

    test_engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(test_engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(test_engine)

    TestingSession = sessionmaker(
        bind=test_engine,
        autoflush=False,
        expire_on_commit=False,
    )

    # Все проверяемые обработчики работают
    # исключительно с тестовой базой.
    monkeypatch.setattr(routes, "SessionLocal", TestingSession)
    monkeypatch.setattr(routes, "public_auth_budget", PublicAuthBudget())
    monkeypatch.setattr(bootstrap, "SessionLocal", TestingSession)
    monkeypatch.setattr(dependencies, "SessionLocal", TestingSession)
    from app.ctf import service
    from app.models import CtfState

    monkeypatch.setattr(service, "SessionLocal", TestingSession)
    with TestingSession.begin() as db:
        db.add(CtfState(id=1, generation=0))
    monkeypatch.setattr(
        login_throttle,
        "SessionLocal",
        TestingSession,
    )

    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PASSWORD)

    # Не используем with TestClient(...):
    # он запустил бы production lifespan и bootstrap.
    client = TestClient(app, follow_redirects=False)

    yield client, TestingSession

    client.close()
    test_engine.dispose()


@pytest.fixture
def sandbox(monkeypatch):
    yield from _sandbox_setup(monkeypatch)


def get_csrf(client, path):
    response = client.get(path)

    assert response.status_code == 200

    match = re.search(
        r'name="csrf_token"\s+value="([^"]+)"',
        response.text,
    )

    assert match is not None, "CSRF-токен отсутствует"

    return match.group(1)


def register(client, username="testplayer"):
    token = get_csrf(client, "/register")

    return client.post(
        "/register",
        data={
            "username": username,
            "password": USER_PASSWORD,
            "password_confirm": USER_PASSWORD,
            "csrf_token": token,
        },
    )


def login(client, username, password):
    token = get_csrf(client, "/login")

    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": token,
        },
    )


def logout(client):
    token = get_csrf(client, "/profile")

    return client.post(
        "/logout",
        data={"csrf_token": token},
    )


def test_health(sandbox):
    client, _ = sandbox

    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_registration_and_password_hash(sandbox):
    client, TestingSession = sandbox

    response = register(client)

    assert response.status_code == 200
    assert "Аккаунт успешно создан" in response.text

    with TestingSession() as db:
        user = db.scalar(select(User).where(User.username == "testplayer"))

        assert user is not None
        assert user.is_admin is False
        assert user.password_hash != USER_PASSWORD
        assert user.password_hash.startswith("$argon2id$")
        assert verify_password(USER_PASSWORD, user.password_hash)


def test_duplicate_username(sandbox):
    client, TestingSession = sandbox

    assert register(client).status_code == 200
    assert register(client).status_code == 409

    with TestingSession() as db:
        users = db.scalars(select(User)).all()
        assert len(users) == 1


def test_registration_csrf(sandbox):
    client, TestingSession = sandbox

    response = client.post(
        "/register",
        data={
            "username": "attacker",
            "password": USER_PASSWORD,
            "password_confirm": USER_PASSWORD,
            "csrf_token": "invalid-token",
        },
    )

    assert response.status_code == 403

    with TestingSession() as db:
        assert db.scalar(select(User.id)) is None


def test_login_profile_and_logout(sandbox):
    client, _ = sandbox

    register(client)

    response = login(client, "testplayer", USER_PASSWORD)

    assert response.status_code == 303
    assert response.headers["location"] == "/profile"

    profile = client.get("/profile")

    assert profile.status_code == 200
    assert "testplayer" in profile.text

    # Обычному участнику админка недоступна.
    assert client.get("/admin").status_code == 403

    response = logout(client)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    profile = client.get("/profile")

    assert profile.status_code == 303
    assert profile.headers["location"] == "/login"

    assert client.get("/admin").status_code == 401


def test_wrong_password(sandbox):
    client, _ = sandbox

    register(client)

    response = login(client, "testplayer", "IncorrectPass123!")

    assert response.status_code == 401
    assert client.get("/profile").status_code == 303


def test_admin_initial_password_change(sandbox):
    client, TestingSession = sandbox

    bootstrap.bootstrap_admin()
    bootstrap.bootstrap_admin()

    with TestingSession() as db:
        admins = db.scalars(select(User).where(User.is_admin.is_(True))).all()

        assert len(admins) == 1
        assert admins[0].must_change_password is True

    response = login(client, "admin", ADMIN_PASSWORD)

    assert response.status_code == 303
    assert response.headers["location"] == "/change-password"

    # До смены пароля доступ запрещён.
    assert client.get("/admin").status_code == 403

    token = get_csrf(client, "/change-password")

    response = client.post(
        "/change-password",
        data={
            "current_password": ADMIN_PASSWORD,
            "new_password": NEW_ADMIN_PASSWORD,
            "password_confirm": NEW_ADMIN_PASSWORD,
            "csrf_token": token,
        },
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/profile"

    assert client.get("/admin").status_code == 200

    with TestingSession() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))

        assert admin.must_change_password is False
        assert verify_password(NEW_ADMIN_PASSWORD, admin.password_hash)
        assert not verify_password(ADMIN_PASSWORD, admin.password_hash)

    assert logout(client).status_code == 303

    assert login(client, "admin", ADMIN_PASSWORD).status_code == 401

    assert login(client, "admin", NEW_ADMIN_PASSWORD).status_code == 303


def test_password_change_csrf(sandbox):
    client, TestingSession = sandbox

    bootstrap.bootstrap_admin()
    login(client, "admin", ADMIN_PASSWORD)

    response = client.post(
        "/change-password",
        data={
            "current_password": ADMIN_PASSWORD,
            "new_password": NEW_ADMIN_PASSWORD,
            "password_confirm": NEW_ADMIN_PASSWORD,
            "csrf_token": "wrong-token",
        },
    )

    assert response.status_code == 403

    with TestingSession() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))

        assert admin.must_change_password is True
        assert verify_password(ADMIN_PASSWORD, admin.password_hash)


def test_login_rate_limit(sandbox, monkeypatch):
    client, _ = sandbox

    register(client)

    now = [1_800_000_000]
    monkeypatch.setattr(
        login_throttle,
        "_now",
        lambda: now[0],
    )

    for _ in range(4):
        response = login(
            client,
            "testplayer",
            "WrongPassword123!",
        )
        assert response.status_code == 401

    response = login(
        client,
        "testplayer",
        "WrongPassword123!",
    )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "900"

    # Даже верный пароль пока заблокирован.
    response = login(
        client,
        "testplayer",
        USER_PASSWORD,
    )

    assert response.status_code == 429

    # Проходит 15 минут и 1 секунда.
    now[0] += 901

    response = login(
        client,
        "testplayer",
        USER_PASSWORD,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/profile"


def test_login_invalid_csrf(sandbox):
    client, _ = sandbox

    register(client)

    response = client.post(
        "/login",
        data={
            "username": "testplayer",
            "password": USER_PASSWORD,
            "csrf_token": "invalid-token",
        },
    )

    assert response.status_code == 403
    assert client.get("/profile").status_code == 303


def test_logout_invalid_csrf(sandbox):
    client, _ = sandbox

    register(client)
    assert login(client, "testplayer", USER_PASSWORD).status_code == 303

    response = client.post(
        "/logout",
        data={"csrf_token": "invalid-token"},
    )

    assert response.status_code == 403

    # Некорректный запрос не должен завершать сессию.
    assert client.get("/profile").status_code == 200


def test_rate_limit_shared_between_browsers(sandbox, monkeypatch):
    client, _ = sandbox

    register(client)

    monkeypatch.setattr(
        login_throttle,
        "_now",
        lambda: 1_800_000_000,
    )

    for attempt in range(5):
        response = login(client, "testplayer", "WrongPassword123!")
        assert response.status_code == (429 if attempt == 4 else 401)

    # Новый браузер — без cookies предыдущего пользователя.
    second_client = TestClient(app, follow_redirects=False)

    try:
        response = login(second_client, "testplayer", USER_PASSWORD)

        assert response.status_code == 429
    finally:
        second_client.close()


def test_rate_limit_window_resets(sandbox, monkeypatch):
    client, _ = sandbox
    register(client)

    now = [1_800_000_000]

    monkeypatch.setattr(login_throttle, "_now", lambda: now[0])

    for _ in range(4):
        assert login(client, "testplayer", "WrongPassword123!").status_code == 401

    # Окно подсчёта неудачных попыток закончилось.
    now[0] += 601

    for _ in range(4):
        assert login(client, "testplayer", "WrongPassword123!").status_code == 401

    assert login(client, "testplayer", "WrongPassword123!").status_code == 429


def test_successful_login_resets_failures(sandbox):
    client, _ = sandbox
    register(client)

    for _ in range(4):
        assert login(client, "testplayer", "WrongPassword123!").status_code == 401

    # Правильный пароль сбрасывает счётчик.
    assert login(client, "testplayer", USER_PASSWORD).status_code == 303

    for _ in range(4):
        assert login(client, "testplayer", "WrongPassword123!").status_code == 401

    assert login(client, "testplayer", "WrongPassword123!").status_code == 429


def test_concurrent_login_failures_are_atomic(
    tmp_path,
    monkeypatch,
):
    """
    Восемь потоков одновременно обновляют
    счётчик неправильных попыток входа.

    Ни одно обновление не должно потеряться.
    """

    db_file = tmp_path / "concurrent_auth.db"

    test_engine = create_engine(
        f"sqlite+pysqlite:///{db_file.as_posix()}",
        connect_args={
            "check_same_thread": False,
            "timeout": 20,
        },
    )

    TestingSession = sessionmaker(
        bind=test_engine,
        autoflush=False,
        expire_on_commit=False,
    )

    Base.metadata.create_all(test_engine)

    monkeypatch.setattr(
        login_throttle,
        "SessionLocal",
        TestingSession,
    )

    monkeypatch.setattr(
        login_throttle,
        "_now",
        lambda: 1_800_000_000,
    )

    monkeypatch.setenv(
        "SESSION_SECRET",
        "cyberarena-isolated-concurrency-test-secret",
    )

    try:
        # Одновременно выполняем 8 операций.
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(
                executor.map(
                    login_throttle.record_failure,
                    ["testplayer"] * 8,
                )
            )

        with TestingSession() as db:
            key = login_throttle._key("testplayer")
            attempt = db.get(LoginAttempt, key)

            assert attempt is not None

            # Главное: все 8 попыток учтены.
            assert attempt.failures == 8

            # Блокировка установлена.
            assert attempt.blocked_until == 1_800_000_900

        # Вход запрещён на следующие 15 минут.
        assert login_throttle.blocked_for("testplayer") == 900

        # Хотя бы одна операция обнаружила блокировку.
        assert 900 in results

    finally:
        test_engine.dispose()


def test_logout_revokes_captured_cookie(sandbox):
    client, _ = sandbox

    register(client)

    assert login(client, "testplayer", USER_PASSWORD).status_code == 303

    token = get_csrf(client, "/profile")

    captured_cookie = client.cookies.get("cyberarena_session")
    assert captured_cookie is not None

    response = client.post(
        "/logout",
        data={"csrf_token": token},
    )
    assert response.status_code == 303

    # Имитируем восстановление ранее украденной cookie.
    client.cookies.set(
        "cyberarena_session",
        captured_cookie,
    )

    response = client.get("/profile")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert client.get("/admin").status_code == 401


def test_password_change_revokes_old_sessions(sandbox):
    client, _ = sandbox

    bootstrap.bootstrap_admin()

    assert login(client, "admin", ADMIN_PASSWORD).status_code == 303

    old_cookie = client.cookies.get("cyberarena_session")
    assert old_cookie is not None

    token = get_csrf(client, "/change-password")

    response = client.post(
        "/change-password",
        data={
            "current_password": ADMIN_PASSWORD,
            "new_password": NEW_ADMIN_PASSWORD,
            "password_confirm": NEW_ADMIN_PASSWORD,
            "csrf_token": token,
        },
    )

    assert response.status_code == 303
    assert client.get("/admin").status_code == 200

    # Старый идентификатор больше не действителен.
    second_client = TestClient(
        app,
        follow_redirects=False,
    )

    try:
        second_client.cookies.set(
            "cyberarena_session",
            old_cookie,
        )

        assert second_client.get("/admin").status_code == 401
    finally:
        second_client.close()


@pytest.mark.parametrize("legacy_database", [False, True])
def test_database_migration(
    tmp_path,
    monkeypatch,
    legacy_database,
):
    db_path = tmp_path / "migration_test.db"
    test_engine = create_engine(f"sqlite+pysqlite:///{db_path.as_posix()}")

    try:
        if legacy_database:
            with test_engine.begin() as connection:
                connection.exec_driver_sql("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        username VARCHAR(50) NOT NULL UNIQUE,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at DATETIME NOT NULL
                            DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                connection.exec_driver_sql(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    ("legacy", "existing-hash"),
                )

        monkeypatch.setattr(
            user_auth,
            "engine",
            test_engine,
        )

        # Два запуска не должны повреждать базу.
        user_auth.migrate()
        user_auth.migrate()

        Base.metadata.create_all(bind=test_engine)

        TestingSession = sessionmaker(bind=test_engine)

        with TestingSession() as db:
            if legacy_database:
                user = db.scalar(select(User).where(User.username == "legacy"))

                assert user is not None
                assert user.password_hash == "existing-hash"
                assert user.is_admin is False
                assert user.must_change_password is False
            else:
                assert db.scalar(select(User.id)) is None

    finally:
        test_engine.dispose()

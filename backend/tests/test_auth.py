import os
import re

import pytest
from app.auth import login_throttle
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Используется только внутри процесса pytest.
os.environ["SESSION_SECRET"] = "cyberarena-isolated-test-secret-2026"

from app.auth import bootstrap, dependencies, routes
from app.auth.security import verify_password
from app.database import Base
from app.main import app
from app.models import User

USER_PASSWORD = "TestPlayerPass123!"
ADMIN_PASSWORD = "TestAdminPass123!"
NEW_ADMIN_PASSWORD = "NewAdminPass456!"


@pytest.fixture
def sandbox(monkeypatch):
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
    monkeypatch.setattr(bootstrap, "SessionLocal", TestingSession)
    monkeypatch.setattr(dependencies, "SessionLocal", TestingSession)
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

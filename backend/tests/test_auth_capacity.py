"""Deterministic capacity and HTTP overload regressions for authentication."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from argon2 import PasswordHasher, Type, extract_parameters
from sqlalchemy import select, update
from test_auth import (
    ADMIN_PASSWORD,
    USER_PASSWORD,
    _sandbox_setup,
    get_csrf,
    login,
    register,
)

from app.auth import login_throttle, routes, security
from app.auth.public_throttle import PublicAuthBudget
from app.models import LoginAttempt, User


@pytest.fixture
def sandbox(monkeypatch):
    yield from _sandbox_setup(monkeypatch)


def test_password_limiter_bounds_running_and_waiting():
    limiter = security.PasswordOperationLimiter(1, 1, 1)
    waiting = threading.Event()
    entered = threading.Event()
    release = threading.Event()
    original_acquire = limiter._running.acquire

    def observed_acquire(*args, **kwargs):
        waiting.set()
        return original_acquire(*args, **kwargs)

    def queued():
        with limiter.slot():
            entered.set()
            assert release.wait(2)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with limiter.slot():
            limiter._running.acquire = observed_acquire
            future = pool.submit(queued)
            assert waiting.wait(2)
            with pytest.raises(security.PasswordCapacityError), limiter.slot():
                pass
        assert entered.wait(2)
        release.set()
        future.result(timeout=2)


def test_password_limiter_releases_on_error_and_timeout():
    limiter = security.PasswordOperationLimiter(1, 1, 0.01)
    with pytest.raises(ValueError, match="probe"), limiter.slot():
        raise ValueError("probe")
    with limiter.slot(), pytest.raises(security.PasswordCapacityError), limiter.slot():
        pass
    with limiter.slot():
        pass


def test_hash_and_verify_share_one_limiter(monkeypatch):
    limiter = security.PasswordOperationLimiter(1, 0, 0)
    monkeypatch.setattr(security, "password_operations", limiter)
    with limiter.slot():
        with pytest.raises(security.PasswordCapacityError):
            security.hash_password("probe")
        with pytest.raises(security.PasswordCapacityError):
            security.verify_password("probe", "unused")
    assert security.verify_password("probe", security.hash_password("probe"))


def test_argon2_parameters_and_existing_hash_format():
    digest = security.hash_password("IsolatedTestPassword2026!")
    params = extract_parameters(digest)
    assert params.type == Type.ID
    assert params.memory_cost == 65536
    assert params.time_cost == 3
    assert params.parallelism == 4
    prior_digest = PasswordHasher(
        memory_cost=65536, time_cost=3, parallelism=4,
    ).hash("IsolatedTestPassword2026!")
    assert security.verify_password("IsolatedTestPassword2026!", prior_digest)


def test_public_budget_refills_and_is_global():
    now = [100.0]
    budget = PublicAuthBudget(burst=2, refill=1, clock=lambda: now[0])
    assert budget.retry_after() == 0
    assert budget.retry_after() == 0
    assert budget.retry_after() == 1
    now[0] += 1
    assert budget.retry_after() == 0


def test_public_budget_is_atomic_across_threads():
    budget = PublicAuthBudget(burst=3, refill=1, clock=lambda: 100.0)
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: budget.retry_after(), range(16)))
    assert results.count(0) == 3
    assert results.count(1) == 13


def test_random_unknown_usernames_hit_shared_budget(sandbox, monkeypatch):
    client, factory = sandbox
    now = [100.0]
    monkeypatch.setattr(
        routes, "public_auth_budget",
        PublicAuthBudget(burst=3, refill=1, clock=lambda: now[0]),
    )
    responses = [login(client, f"unknown{i}", USER_PASSWORD) for i in range(4)]
    assert [response.status_code for response in responses] == [401, 401, 401, 429]
    assert responses[-1].headers["Retry-After"] == "1"
    with factory() as db:
        assert len(db.scalars(select(LoginAttempt)).all()) == 3
    now[0] += 1
    assert login(client, "unknown4", USER_PASSWORD).status_code == 401


def test_expired_random_login_keys_are_pruned(sandbox, monkeypatch):
    _, factory = sandbox
    now = [10_000]
    tick = [5.0]
    monkeypatch.setattr(login_throttle, "_now", lambda: now[0])
    monkeypatch.setattr(login_throttle, "_monotonic", lambda: tick[0])
    monkeypatch.setattr(login_throttle, "_last_cleanup", float("-inf"))
    login_throttle.record_failure("old-random")
    old_key = login_throttle._key("old-random")
    now[0] += login_throttle.WINDOW_SECONDS + 1
    tick[0] += 61
    login_throttle.record_failure("new-random")
    with factory() as db:
        assert db.get(LoginAttempt, old_key) is None
        assert len(db.scalars(select(LoginAttempt)).all()) == 1


def test_registration_overload_creates_no_user(sandbox, monkeypatch):
    client, factory = sandbox

    def busy(_):
        raise security.PasswordCapacityError

    with monkeypatch.context() as patch:
        patch.setattr(routes, "hash_password", busy)
        response = register(client)
        assert response.status_code == 503
        assert response.headers["Retry-After"] == "1"
        assert "Traceback" not in response.text
        with factory() as db:
            assert db.scalar(select(User.id)) is None
    assert register(client).status_code == 200


def test_login_overload_preserves_failure_counter(sandbox, monkeypatch):
    client, factory = sandbox
    assert register(client).status_code == 200

    def busy(*_):
        raise security.PasswordCapacityError

    with monkeypatch.context() as patch:
        patch.setattr(routes, "verify_password", busy)
        response = login(client, "testplayer", USER_PASSWORD)
        assert response.status_code == 503
        assert response.headers["Retry-After"] == "1"
        with factory() as db:
            assert db.scalar(select(LoginAttempt.key)) is None
    assert login(client, "testplayer", USER_PASSWORD).status_code == 303


@pytest.mark.parametrize("failure", ["verify", "hash"])
def test_change_password_overload_preserves_hash(sandbox, monkeypatch, failure):
    client, factory = sandbox
    from app.auth import bootstrap

    bootstrap.bootstrap_admin()
    assert login(client, "admin", ADMIN_PASSWORD).status_code == 303
    with factory() as db:
        original = db.scalar(select(User.password_hash).where(User.username == "admin"))

    def busy(*_):
        raise security.PasswordCapacityError

    monkeypatch.setattr(routes, "verify_password" if failure == "verify" else "hash_password", busy)
    token = get_csrf(client, "/change-password")
    response = client.post("/change-password", data={
        "current_password": ADMIN_PASSWORD,
        "new_password": "ReplacementPass456!",
        "password_confirm": "ReplacementPass456!",
        "csrf_token": token,
    })
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    with factory() as db:
        assert db.scalar(select(User.password_hash).where(User.username == "admin")) == original


def test_concurrent_password_change_does_not_overwrite_first(sandbox, monkeypatch):
    client, factory = sandbox
    from app.auth import bootstrap

    bootstrap.bootstrap_admin()
    assert login(client, "admin", ADMIN_PASSWORD).status_code == 303
    winning_digest = security.hash_password("WinningPassword2026!")
    losing_digest = security.hash_password("LosingPassword2026!")

    def competing_change(_):
        with factory.begin() as db:
            db.execute(update(User).where(User.username == "admin").values(
                password_hash=winning_digest,
            ))
        return losing_digest

    monkeypatch.setattr(routes, "hash_password", competing_change)
    token = get_csrf(client, "/change-password")
    response = client.post("/change-password", data={
        "current_password": ADMIN_PASSWORD,
        "new_password": "LosingPassword2026!",
        "password_confirm": "LosingPassword2026!",
        "csrf_token": token,
    })
    assert response.status_code == 409
    with factory() as db:
        assert db.scalar(select(User.password_hash).where(User.username == "admin")) == winning_digest

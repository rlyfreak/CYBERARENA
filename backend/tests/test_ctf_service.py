import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

from app.ctf import security, service
from app.database import Base
from app.models import (
    Challenge,
    CtfRateLimit,
    CtfState,
    CtfVerificationLease,
    Solve,
    Submission,
    User,
)

FLAG = "CTF{isolated_test_flag}"


def factory_for(path):
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    return engine, sessionmaker(engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
def ctf_db(tmp_path, monkeypatch):
    path = (tmp_path / "ctf.db").as_posix()
    engine, factory = factory_for(path)
    Base.metadata.create_all(engine)
    with factory.begin() as db:
        db.add_all([
            User(id=1, username="player", password_hash="unused"),
            User(id=2, username="second", password_hash="unused"),
            User(id=3, username="admin", password_hash="unused", is_admin=True),
            CtfState(id=1, generation=0),
            Challenge(id=1, code="WEB-01", title="WEB-01", description="Task", category="WEB",
                      points=100, flag_hash=security.hash_flag(FLAG), is_published=True,
                      resource_url="/lab/"),
        ])
    monkeypatch.setattr(service, "SessionLocal", factory)
    yield factory, path
    engine.dispose()


def retry_submit(_, flag=FLAG):
    for _ in range(100):
        try:
            return service.submit_flag(1, 1, flag).result
        except service.CtfError as exc:
            if exc.status != 503:
                raise
            time.sleep(0.02)
    raise AssertionError("Verification did not complete")


def process_submit(path):
    engine, service.SessionLocal = factory_for(path)
    try:
        return retry_submit(None)
    finally:
        engine.dispose()


@pytest.mark.parametrize("flag", ["CTF{}", "CTF{x} ", "ctf{x}", "CTF{x\n}", "CTF{тест}",
                                 "CTF{{x}}", "CTF{" + "x" * 252 + "}", None, 1])
def test_flag_format(flag):
    assert not security.valid_flag(flag)


def test_flag_hash_is_salted_and_bounded():
    first, second = security.hash_flag(FLAG), security.hash_flag(FLAG)
    assert first != second and FLAG not in first
    assert security.supported_hash(first)
    assert security.verify_flag(FLAG, first)
    assert not security.verify_flag("CTF{wrong}", first)
    assert not security.supported_hash("a" * 64)
    assert not security.supported_hash(first.replace("m=32768", "m=1048576"))


def test_attempts_and_single_award(ctf_db):
    factory, _ = ctf_db
    assert service.submit_flag(1, 1, "bad").result == "invalid_format"
    assert service.submit_flag(1, 1, "CTF{wrong}").result == "incorrect"
    assert service.submit_flag(1, 1, FLAG).points_awarded == 100
    with factory.begin() as db:
        db.get(Challenge, 1).points = 999
    assert service.submit_flag(1, 1, FLAG).result == "already_solved"
    with factory() as db:
        solves = db.scalars(select(Solve)).all()
        assert len(solves) == 1 and solves[0].points_awarded == 100
        attempts = db.scalars(select(Submission).order_by(Submission.id)).all()
        assert [s.result for s in attempts] == ["invalid_format", "incorrect", "correct", "already_solved"]
        assert [s.is_correct for s in attempts] == [False, False, True, False]
        assert db.scalar(select(func.count()).select_from(CtfVerificationLease)) == 0


@pytest.mark.parametrize("mode", ["threads", "processes"])
def test_concurrent_correct_flags_awarded_once(ctf_db, mode):
    factory, path = ctf_db
    if mode == "threads":
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(retry_submit, range(8)))
    else:
        with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context("spawn")) as executor:
            results = list(executor.map(process_submit, [path] * 4))
    assert results.count("correct") == 1
    assert set(results) == {"correct", "already_solved"}
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Solve)) == 1
        assert db.scalar(select(func.count()).select_from(Submission)) == len(results)
        assert db.scalar(select(func.sum(Solve.points_awarded))) == 100


def test_rate_limit_before_hash_and_window_reset(ctf_db, monkeypatch):
    factory, _ = ctf_db
    for _ in range(service.MAX_ATTEMPTS):
        service.submit_flag(1, 1, "invalid")
    monkeypatch.setattr(security, "verify_flag", lambda *_: pytest.fail("Hash must not run"))
    with pytest.raises(service.CtfError) as error:
        service.submit_flag(1, 1, FLAG)
    assert error.value.status == 429
    assert error.value.retry_after is not None and error.value.retry_after > 0
    with factory.begin() as db:
        db.get(CtfRateLimit, 1).window_started -= 61
    assert service.submit_flag(1, 1, "bad").result == "invalid_format"


def test_concurrent_wrong_attempts_are_not_lost(ctf_db):
    factory, _ = ctf_db
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda i: retry_submit(i, "CTF{wrong}"), range(6)))
    assert results == ["incorrect"] * 6
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Submission)) == 6
        assert db.scalar(select(func.count()).select_from(Solve)) == 0


def test_locked_database_returns_retryable_error(ctf_db, monkeypatch):
    factory, path = ctf_db
    quick_engine = create_engine(f"sqlite:///{path}", connect_args={"timeout": 0.001})
    monkeypatch.setattr(service, "SessionLocal", sessionmaker(quick_engine))
    try:
        with factory.kw['bind'].connect() as lock:
            lock.exec_driver_sql("BEGIN IMMEDIATE")
            with pytest.raises(service.CtfError) as error:
                service.submit_flag(1, 1, FLAG)
            assert error.value.status == 503 and error.value.retry_after == 1
            lock.rollback()
    finally:
        quick_engine.dispose()


def test_hidden_missing_and_unconfigured_challenges(ctf_db):
    factory, _ = ctf_db
    with factory.begin() as db:
        db.get(Challenge, 1).is_published = False
    for challenge_id in [1, 999]:
        with pytest.raises(service.CtfError) as error:
            service.submit_flag(1, challenge_id, FLAG)
        assert error.value.status == 404
    with factory.begin() as db:
        challenge = db.get(Challenge, 1)
        challenge.is_published, challenge.flag_hash = True, 'a' * 64
    with pytest.raises(service.CtfError) as error:
        service.submit_flag(1, 1, FLAG)
    assert error.value.status == 503


def test_verification_capacity_before_hash_and_expired_lease(ctf_db, monkeypatch):
    factory, _ = ctf_db
    with factory.begin() as db:
        for i in range(service.MAX_VERIFICATIONS):
            db.add(CtfVerificationLease(token=str(i), expires_at=int(time.time()) + 60))
    with monkeypatch.context() as patch:
        patch.setattr(security, "verify_flag", lambda *_: pytest.fail("Hash must not run"))
        with pytest.raises(service.CtfError) as error:
            service.submit_flag(1, 1, FLAG)
        assert error.value.status == 503
    with factory.begin() as db:
        for lease in db.scalars(select(CtfVerificationLease)):
            lease.expires_at = 0
    assert service.submit_flag(1, 1, FLAG).result == "correct"


def test_hash_failure_releases_capacity(ctf_db, monkeypatch):
    factory, _ = ctf_db
    def fail(*_):
        raise RuntimeError("hash failed")
    monkeypatch.setattr(security, "verify_flag", fail)
    with pytest.raises(RuntimeError, match="hash failed"):
        service.submit_flag(1, 1, FLAG)
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(CtfVerificationLease)) == 0
        assert db.scalar(select(func.count()).select_from(Submission)) == 0


def test_transaction_rolls_back_attempt_and_solve(ctf_db):
    factory, _ = ctf_db
    engine = factory.kw['bind']
    def fail_on_award(_connection, _cursor, statement, *_args):
        if statement.startswith("INSERT INTO solves"):
            raise RuntimeError("injected storage failure")
    event.listen(engine, "before_cursor_execute", fail_on_award)
    try:
        with pytest.raises(RuntimeError, match="storage failure"):
            service.submit_flag(1, 1, FLAG)
    finally:
        event.remove(engine, "before_cursor_execute", fail_on_award)
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Solve)) == 0
        assert db.scalar(select(func.count()).select_from(Submission)) == 0
    assert service.submit_flag(1, 1, FLAG).result == "correct"


@pytest.mark.parametrize("change", ["reset", "edit", "hide"])
def test_concurrent_admin_changes_invalidate_verification(ctf_db, monkeypatch, change):
    factory, _ = ctf_db
    original = security.verify_flag
    def verify(flag, encoded):
        with factory.begin() as db:
            if change == "reset":
                db.get(CtfState, 1).generation += 1
            elif change == "hide":
                db.get(Challenge, 1).is_published = False
            else:
                db.get(Challenge, 1).revision += 1
        return original(flag, encoded)
    monkeypatch.setattr(security, "verify_flag", verify)
    with pytest.raises(service.CtfError) as error:
        service.submit_flag(1, 1, FLAG)
    assert error.value.status == (404 if change == "hide" else 409)
    with factory() as db:
        assert db.scalar(select(Solve)) is None


def test_leaderboard_snapshot_ties_and_zero_scores(ctf_db):
    factory, _ = ctf_db
    service.submit_flag(2, 1, FLAG)
    service.submit_flag(1, 1, FLAG)
    with factory.begin() as db:
        db.add(User(id=4, username="zero", password_hash="unused"))
        for solve in db.scalars(select(Solve)):
            solve.solved_at = datetime(2026, 1, 1) + timedelta(seconds=solve.user_id == 1)
        db.get(Challenge, 1).is_published = False
    rows = service.leaderboard()
    assert [r['user_id'] for r in rows] == [2, 1, 4]
    assert [r['points'] for r in rows] == [100, 100, 0]
    assert service.leaderboard(offset=1, limit=1)[0]['rank'] == 2
    with factory.begin() as db:
        for solve in db.scalars(select(Solve)):
            solve.solved_at = datetime(2026, 1, 1)
    assert [r['user_id'] for r in service.leaderboard()] == [1, 2, 4]

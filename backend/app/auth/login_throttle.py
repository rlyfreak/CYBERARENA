import hashlib
import hmac
import os
import time
from threading import Lock

from sqlalchemy import case, delete
from sqlalchemy.dialects.sqlite import insert

from ..database import SessionLocal
from ..models import LoginAttempt

MAX_FAILURES = 5
WINDOW_SECONDS = 600
BLOCK_SECONDS = 900
_cleanup_lock = Lock()
_last_cleanup = 0.0


def _cleanup_expired(db, now: int) -> None:
    """Keep random, long-expired login keys from growing SQLite forever."""
    global _last_cleanup
    with _cleanup_lock:
        tick = time.monotonic()
        if tick - _last_cleanup < 60:
            return
        db.execute(delete(LoginAttempt).where(
            LoginAttempt.window_started < now - WINDOW_SECONDS,
            LoginAttempt.blocked_until <= now,
        ))
        _last_cleanup = tick


def _now() -> int:
    return int(time.time())


def _key(username: str) -> str:
    secret = os.environ["SESSION_SECRET"].encode("utf-8")

    return hmac.new(
        secret,
        username.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def blocked_for(username: str) -> int:
    now = _now()

    with SessionLocal() as db:
        attempt = db.get(LoginAttempt, _key(username))

        if attempt is None:
            return 0

        return max(0, attempt.blocked_until - now)


def record_failure(username: str) -> int:
    now = _now()
    key = _key(username)

    new_window = LoginAttempt.window_started <= now - WINDOW_SECONDS

    next_count = case(
        (new_window, 1),
        else_=LoginAttempt.failures + 1,
    )

    statement = insert(LoginAttempt).values(
        key=key,
        failures=1,
        window_started=now,
        blocked_until=0,
    )

    statement = statement.on_conflict_do_update(
        index_elements=[LoginAttempt.key],
        set_={
            "failures": next_count,
            "window_started": case(
                (new_window, now),
                else_=LoginAttempt.window_started,
            ),
            "blocked_until": case(
                (next_count >= MAX_FAILURES, now + BLOCK_SECONDS),
                else_=0,
            ),
        },
    )

    with SessionLocal.begin() as db:
        db.execute(statement)
        _cleanup_expired(db, now)
        attempt = db.get(LoginAttempt, key)

        if attempt is None:
            raise RuntimeError("Failed to record failure")
        return max(0, attempt.blocked_until - now)


def reset_failures(username: str) -> None:
    with SessionLocal.begin() as db:
        db.execute(delete(LoginAttempt).where(LoginAttempt.key == _key(username)))

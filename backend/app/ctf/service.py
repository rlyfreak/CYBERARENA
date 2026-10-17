import secrets
import sqlite3
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, func, select, text
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import OperationalError

from ..database import SessionLocal
from ..models import (
    Challenge,
    CtfRateLimit,
    CtfState,
    CtfVerificationLease,
    Solve,
    Submission,
    User,
)
from . import security

MAX_ATTEMPTS = 20
WINDOW_SECONDS = 60
MAX_VERIFICATIONS = 2
LEASE_SECONDS = 60


class CtfError(Exception):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        self.status = status
        self.message = message
        self.retry_after = retry_after


@dataclass(frozen=True)
class SubmissionResult:
    result: str
    submission_id: int
    points_awarded: int = 0


def utcnow():
    # SQLite stores UTC without a timezone; serialize with an explicit UTC suffix in API.
    return datetime.now(UTC).replace(tzinfo=None)


def write(operation):
    """Retry an entire short transaction, never a partially committed operation."""
    for retry in range(3):
        try:
            with SessionLocal() as db:
                db.execute(text("BEGIN IMMEDIATE"))
                result = operation(db)
                db.commit()
                return result
        except OperationalError as exc:
            code = getattr(exc.orig, "sqlite_errorcode", 0) & 0xFF
            if code not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise
            if retry == 2:
                raise CtfError(503, "Database busy; retry later", 1) from exc
            time.sleep(0.02 * (retry + 1))


def published(db, challenge_id):
    challenge = db.get(Challenge, challenge_id)
    if challenge is None or not challenge.is_published:
        raise CtfError(404, "Challenge not found")
    return challenge


def _solved(db, user_id, challenge_id):
    return db.scalar(select(Solve.id).where(
        Solve.user_id == user_id, Solve.challenge_id == challenge_id,
    )) is not None


def _record(db, user_id, challenge_id, result, now=None):
    attempt = Submission(
        user_id=user_id, challenge_id=challenge_id, result=result,
        is_correct=result == "correct", submitted_at=now or utcnow(),
    )
    db.add(attempt)
    db.flush()
    return attempt


def _rate_limit(db, user_id):
    now = int(time.time())
    rate = db.get(CtfRateLimit, user_id)
    if rate is None:
        db.add(CtfRateLimit(user_id=user_id, window_started=now, attempts=1))
    elif rate.window_started <= now - WINDOW_SECONDS:
        rate.window_started, rate.attempts = now, 1
    elif rate.attempts >= MAX_ATTEMPTS:
        raise CtfError(429, "Too many submissions", max(1, rate.window_started + WINDOW_SECONDS - now))
    else:
        rate.attempts += 1


def submit_flag(user_id: int, challenge_id: int, flag: object) -> SubmissionResult:
    token = secrets.token_hex(16)

    def reserve(db):
        user = db.get(User, user_id)
        if user is None or user.must_change_password:
            raise CtfError(403, "Participant access required")
        challenge = published(db, challenge_id)
        _rate_limit(db, user_id)  # before format/hash validation and expensive verification
        if _solved(db, user_id, challenge_id):
            attempt = _record(db, user_id, challenge_id, "already_solved")
            return SubmissionResult("already_solved", attempt.id)
        if not security.valid_flag(flag):
            attempt = _record(db, user_id, challenge_id, "invalid_format")
            return SubmissionResult("invalid_format", attempt.id)
        if not security.supported_hash(challenge.flag_hash):
            raise CtfError(503, "Challenge flag is not configured")
        now = int(time.time())
        db.execute(delete(CtfVerificationLease).where(CtfVerificationLease.expires_at <= now))
        if db.scalar(select(func.count()).select_from(CtfVerificationLease)) >= MAX_VERIFICATIONS:
            raise CtfError(503, "Flag verification busy; retry later", 1)
        db.add(CtfVerificationLease(token=token, expires_at=now + LEASE_SECONDS))
        return challenge.flag_hash, challenge.revision, db.get(CtfState, 1).generation

    reserved = write(reserve)
    if isinstance(reserved, SubmissionResult):
        return reserved
    encoded, revision, generation = reserved
    released = False
    try:
        correct = security.verify_flag(flag, encoded)

        def finish(db):
            # Reset or challenge edits during verification must not resurrect old results.
            if db.get(CtfState, 1).generation != generation:
                raise CtfError(409, "Results reset during submission; retry")
            challenge = published(db, challenge_id)
            if challenge.revision != revision or challenge.flag_hash != encoded:
                raise CtfError(409, "Challenge changed during submission; retry")
            user = db.get(User, user_id)
            if user is None or user.must_change_password:
                raise CtfError(403, "Participant access required")
            now = utcnow()
            if _solved(db, user_id, challenge_id):
                attempt = _record(db, user_id, challenge_id, "already_solved", now)
                return SubmissionResult("already_solved", attempt.id)
            attempt = _record(db, user_id, challenge_id, "incorrect", now)
            points = 0
            result = "incorrect"
            if correct:
                inserted = db.execute(insert(Solve).values(
                    user_id=user_id, challenge_id=challenge_id, submission_id=attempt.id,
                    points_awarded=challenge.points, solved_at=now,
                ).on_conflict_do_nothing(index_elements=[Solve.user_id, Solve.challenge_id]))
                result = "correct" if inserted.rowcount == 1 else "already_solved"
                points = challenge.points if result == "correct" else 0
            attempt.result, attempt.is_correct = result, result == "correct"
            db.execute(delete(CtfVerificationLease).where(CtfVerificationLease.token == token))
            return SubmissionResult(result, attempt.id, points)

        result = write(finish)
        released = True
        return result
    finally:
        # Separate cleanup also covers hash exceptions and rolled-back finish transactions.
        if not released:
            try:
                write(lambda db: db.execute(
                    delete(CtfVerificationLease).where(CtfVerificationLease.token == token)
                ))
            except CtfError:
                # A busy DB must not mask the original failure. Lease expires after a crash.
                pass


def leaderboard(offset=0, limit=50):
    with SessionLocal() as db:
        score = func.coalesce(func.sum(Solve.points_awarded), 0).label("points")
        last = func.max(Solve.solved_at).label("last_solve_at")
        ranked = select(
            User.id.label("user_id"), User.username, score, last,
        ).outerjoin(Solve, Solve.user_id == User.id).where(
            User.is_admin.is_(False),
        ).group_by(User.id, User.username).subquery()
        ordering = (ranked.c.points.desc(), ranked.c.last_solve_at.asc(), ranked.c.user_id.asc())
        rows = db.execute(select(
            func.row_number().over(order_by=ordering).label("rank"), ranked,
        ).order_by(*ordering).offset(offset).limit(limit)).mappings().all()
        return [dict(row) for row in rows]

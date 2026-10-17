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
CASE_POINTS = {"WEB-01": 100, "WEB-02": 150, "CRYPTO-01": 150}


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


def _lease(db, token):
    now = int(time.time())
    db.execute(delete(CtfVerificationLease).where(CtfVerificationLease.expires_at <= now))
    if db.scalar(select(func.count()).select_from(CtfVerificationLease)) >= MAX_VERIFICATIONS:
        raise CtfError(503, "Flag verification busy; retry later", 1)
    db.add(CtfVerificationLease(token=token, expires_at=now + LEASE_SECONDS))


def managed_hash(user_id, flag):
    if not security.valid_flag(flag):
        raise CtfError(422, "Flag must have format CTF{...}, 6–256 printable ASCII characters")
    token = secrets.token_hex(16)
    def reserve(db):
        _rate_limit(db, user_id)
        _lease(db, token)
    write(reserve)
    try:
        return security.hash_flag(flag)
    finally:
        write(lambda db: db.execute(
            delete(CtfVerificationLease).where(CtfVerificationLease.token == token)
        ))


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
        _lease(db, token)
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


def challenge_data(challenge, solved=False):
    return {name: getattr(challenge, name) for name in (
        "id", "code", "title", "description", "category", "points", "is_published", "revision",
    )} | {"solved": solved}


def catalog(user_id, offset=0, limit=50, category=None, include_hidden=False):
    with SessionLocal() as db:
        solved = select(Solve.id).where(
            Solve.user_id == user_id, Solve.challenge_id == Challenge.id,
        ).exists()
        query = select(Challenge, solved).order_by(Challenge.id).offset(offset).limit(limit)
        if not include_hidden:
            query = query.where(Challenge.is_published.is_(True))
        if category is not None:
            query = query.where(Challenge.category == category)
        return [challenge_data(task, done) for task, done in db.execute(query)]


def challenge_detail(user_id, challenge_id, include_hidden=False):
    with SessionLocal() as db:
        challenge = db.get(Challenge, challenge_id) if include_hidden else published(db, challenge_id)
        if challenge is None:
            raise CtfError(404, "Challenge not found")
        return challenge_data(challenge, _solved(db, user_id, challenge_id))


def history(user_id, offset=0, limit=50):
    with SessionLocal() as db:
        query = select(
            Submission.id, Submission.user_id, User.username, Submission.challenge_id,
            Challenge.code, Challenge.title, Submission.result, Submission.is_correct,
            Submission.submitted_at,
        ).join(User, User.id == Submission.user_id).join(
            Challenge, Challenge.id == Submission.challenge_id,
        ).order_by(Submission.submitted_at.desc(), Submission.id.desc()).offset(offset).limit(limit)
        if user_id is not None:
            query = query.where(Submission.user_id == user_id)
        return [dict(row) for row in db.execute(query).mappings()]


def _validate_challenge(values):
    for name in ("title", "description", "category"):
        if not values[name].strip():
            raise CtfError(422, f"{name} cannot be blank")
    expected = CASE_POINTS.get(values['code'])
    if expected is not None and values['points'] != expected:
        raise CtfError(422, f"{values['code']} must award {expected} points")
    if values['is_published'] and not security.supported_hash(values['flag_hash']):
        raise CtfError(422, "Set a supported flag before publishing")


def save_challenge(admin_id, values, challenge_id=None):
    values = dict(values)
    encoded = None
    if "flag" in values:
        secret = values.pop("flag")
        if secret is None:
            raise CtfError(422, "Flag cannot be null")
        encoded = managed_hash(admin_id, secret.get_secret_value())
    if any(value is None for value in values.values()):
        raise CtfError(422, "Fields cannot be null")

    def save(db):
        if challenge_id is None:
            if db.scalar(select(Challenge.id).where(Challenge.code == values['code'])) is not None:
                raise CtfError(409, "Challenge code already exists")
            fields = values | {"flag_hash": encoded}
            _validate_challenge(fields)
            challenge = Challenge(**fields)
            db.add(challenge)
        else:
            challenge = db.get(Challenge, challenge_id)
            if challenge is None:
                raise CtfError(404, "Challenge not found")
            if challenge.revision != values['expected_revision']:
                raise CtfError(409, "Challenge changed; refresh before editing")
            changes = {k: v for k, v in values.items() if k != 'expected_revision'}
            fields = challenge_data(challenge) | {"flag_hash": challenge.flag_hash} | changes
            if encoded is not None:
                fields['flag_hash'] = encoded
            _validate_challenge(fields)
            for name, value in changes.items():
                setattr(challenge, name, value)
            challenge.flag_hash = fields['flag_hash']
            challenge.revision += 1
        db.flush()
        return challenge_data(challenge)
    return write(save)


def results_state():
    with SessionLocal() as db:
        return {"generation": db.get(CtfState, 1).generation}


def reset_results(expected_generation):
    def reset(db):
        state = db.get(CtfState, 1)
        if state.generation != expected_generation:
            raise CtfError(409, "Results changed; refresh before resetting")
        solves = db.execute(delete(Solve)).rowcount
        attempts = db.execute(delete(Submission)).rowcount
        db.execute(delete(CtfRateLimit))
        state.generation += 1
        return {"solves_deleted": solves, "attempts_deleted": attempts, "generation": state.generation}
    return write(reset)

import hashlib
import secrets
import time

from fastapi import Request
from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..models import AuthSession, User

SESSION_LIFETIME = 8 * 60 * 60


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_session_user(
    request: Request,
    db: Session,
) -> User | None:
    token = request.session.get("sid")
    user_id = request.session.get("user_id")

    if not isinstance(token, str) or len(token) > 128 or type(user_id) is not int:
        return None

    session = db.get(AuthSession, _digest(token))

    if (
        session is None
        or session.user_id != user_id
        or session.expires_at <= int(time.time())
    ):
        return None

    return db.get(User, user_id)


def issue_session(
    request: Request,
    db: Session,
    user_id: int,
    revoke_all: bool = False,
) -> None:
    now = int(time.time())

    # Периодически очищаем устаревшие сессии.
    db.execute(delete(AuthSession).where(AuthSession.expires_at <= now))

    if revoke_all:
        db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))
    else:
        old_token = request.session.get("sid")

        if isinstance(old_token, str) and len(old_token) <= 128:
            db.execute(
                delete(AuthSession).where(AuthSession.token_hash == _digest(old_token))
            )

    token = secrets.token_urlsafe(32)

    db.add(
        AuthSession(
            token_hash=_digest(token),
            user_id=user_id,
            expires_at=now + SESSION_LIFETIME,
        )
    )

    db.commit()

    request.session.clear()
    request.session["user_id"] = user_id
    request.session["sid"] = token


def revoke_session(
    request: Request,
    db: Session,
) -> None:
    token = request.session.get("sid")

    if isinstance(token, str) and len(token) <= 128:
        db.execute(delete(AuthSession).where(AuthSession.token_hash == _digest(token)))
        db.commit()

    request.session.clear()

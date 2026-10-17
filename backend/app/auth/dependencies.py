from typing import Annotated

from fastapi import Depends, HTTPException, Request

from ..database import SessionLocal
from ..models import User
from .session_store import get_session_user


def get_current_user(request: Request) -> User:
    with SessionLocal() as db:
        user = get_session_user(request, db)

        if user is None:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
            )

        if user.must_change_password:
            raise HTTPException(
                status_code=403,
                detail="Password change required",
            )

        return user


def require_admin(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    if not user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Administrator access required",
        )

    return user

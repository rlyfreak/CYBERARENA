from typing import Annotated

from fastapi import Depends, HTTPException, Request

from ..database import SessionLocal
from ..models import User


def get_current_user(request: Request) -> User:
    user_id = request.session.get("user_id")

    if type(user_id) is not int:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    with SessionLocal() as db:
        user = db.get(User, user_id)

        if user is None:
            raise HTTPException(
                status_code=401,
                detail="User not found",
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

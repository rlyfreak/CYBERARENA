import os
import re
import secrets

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..database import SessionLocal
from ..models import User
from ..templates import templates
from .security import hash_password

router = APIRouter(tags=["Authentication"])


def render_register(
    request: Request,
    error: str | None = None,
    success: str | None = None,
    username: str = "",
    status_code: int = 200,
):
    token = request.session.get("csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token

    response = templates.TemplateResponse(
        request,
        "register.html",
        {
            "csrf_token": token,
            "error": error,
            "success": success,
            "username": username,
        },
        status_code=status_code,
    )

    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return render_register(request)


@router.post("/register", response_class=HTMLResponse)
def register_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    csrf_token: str = Form(...),
):
    expected = request.session.get("csrf_token")

    if not expected or not secrets.compare_digest(csrf_token, expected):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    username = username.strip().lower()

    if not re.fullmatch(r"[a-z0-9_]{3,32}", username):
        return render_register(
            request,
            error="Логин: 3–32 символа, латиница, цифры и _",
            username=username,
            status_code=400,
        )

    if not 12 <= len(password) <= 128:
        return render_register(
            request,
            error="Пароль должен содержать от 12 до 128 символов",
            username=username,
            status_code=400,
        )

    if password != password_confirm:
        return render_register(
            request,
            error="Пароли не совпадают",
            username=username,
            status_code=400,
        )

    admin_username = os.getenv("ADMIN_USERNAME", "admin").strip().lower()

    if username == admin_username:
        return render_register(
            request,
            error="Этот логин зарезервирован",
            status_code=400,
        )

    with SessionLocal() as db:
        existing = db.scalar(select(User.id).where(User.username == username))

        if existing is not None:
            return render_register(
                request,
                error="Такой логин уже занят",
                username=username,
                status_code=409,
            )

        user = User(
            username=username,
            password_hash=hash_password(password),
            is_admin=False,
            must_change_password=False,
        )

        db.add(user)

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return render_register(
                request,
                error="Не удалось создать аккаунт: логин занят",
                username=username,
                status_code=409,
            )

    request.session["csrf_token"] = secrets.token_urlsafe(32)

    return render_register(
        request,
        success="Аккаунт успешно создан! Теперь можно войти.",
    )

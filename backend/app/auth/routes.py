import os
import re
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..database import SessionLocal
from ..models import User
from ..templates import templates
from .dependencies import require_admin
from .login_throttle import (
    blocked_for,
    record_failure,
    reset_failures,
)
from .security import hash_password, verify_password
from .session_store import (
    get_session_user,
    issue_session,
    revoke_session,
)

router = APIRouter(tags=["Authentication"])

# Используется для проверки времени ответа
# даже при вводе несуществующего логина
_DUMMY_HASH = hash_password("dummy-password-for-unknown-user")


def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")

    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token

    return token


def render_login(
    request: Request,
    error: str | None = None,
    username: str = "",
    status_code: int = 200,
):
    response = templates.TemplateResponse(
        request,
        "login.html",
        {
            "csrf_token": get_csrf_token(request),
            "error": error,
            "username": username,
        },
        status_code=status_code,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def render_locked_login(
    request: Request,
    username: str,
    retry_after: int,
):
    response = render_login(
        request,
        error="Слишком много попыток входа. Попробуйте позже.",
        username=username,
        status_code=429,
    )

    response.headers["Retry-After"] = str(retry_after)
    return response


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


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render_login(request)


@router.post("/login", response_class=HTMLResponse)
def login_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    expected = request.session.get("csrf_token")

    if not isinstance(expected, str) or not secrets.compare_digest(
        csrf_token, expected
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    username = username.strip().lower()

    if len(username) > 32 or len(password) > 128:
        return render_login(
            request,
            error="Неверный логин или пароль",
            status_code=401,
        )

    retry_after = blocked_for(username)

    if retry_after > 0:
        return render_locked_login(request, username, retry_after)

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))

        stored_hash = user.password_hash if user is not None else _DUMMY_HASH

        password_valid = verify_password(password, stored_hash)

        if user is None or not password_valid:
            retry_after = record_failure(username)

            if retry_after > 0:
                return render_locked_login(request, username, retry_after)

            return render_login(
                request,
                error="Неверный логин или пароль",
                username=username,
                status_code=401,
            )

        user_id = user.id
        must_change_password = user.must_change_password

    retry_after = blocked_for(username)

    if retry_after > 0:
        return render_locked_login(request, username, retry_after)

    reset_failures(username)

    # Удаляем предыдущие данные сессии
    with SessionLocal() as db:
        issue_session(request, db, user_id)

    return RedirectResponse(
        url="/change-password" if must_change_password else "/profile",
        status_code=303,
    )


@router.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request):
    user_id = request.session.get("user_id")

    if type(user_id) is not int:
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    with SessionLocal() as db:
        user = get_session_user(request, db)

        if user is None:
            request.session.clear()
            return RedirectResponse(
                url="/login",
                status_code=303,
            )

        if user.must_change_password:
            return RedirectResponse(
                url="/change-password",
                status_code=303,
            )

        response = templates.TemplateResponse(
            request,
            "profile.html",
            {
                "user": user,
                "csrf_token": get_csrf_token(request),
            },
        )

        response.headers["Cache-Control"] = "no-store"
        return response


@router.post("/logout")
def logout_user(
    request: Request,
    csrf_token: str = Form(...),
):
    expected = request.session.get("csrf_token")

    if not isinstance(expected, str) or not secrets.compare_digest(
        csrf_token, expected
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    with SessionLocal() as db:
        revoke_session(request, db)

    return RedirectResponse(
        url="/login",
        status_code=303,
    )


def render_password_change(
    request: Request,
    error: str | None = None,
    status_code: int = 200,
):
    response = templates.TemplateResponse(
        request,
        "change_password.html",
        {
            "csrf_token": get_csrf_token(request),
            "error": error,
        },
        status_code=status_code,
    )

    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/change-password", response_class=HTMLResponse)
def change_password_page(request: Request):
    with SessionLocal() as db:
        user = get_session_user(request, db)
        if user is None:
            request.session.clear()
            return RedirectResponse("/login", status_code=303)

    return render_password_change(request)


@router.post("/change-password", response_class=HTMLResponse)
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    password_confirm: str = Form(...),
    csrf_token: str = Form(...),
):
    expected = request.session.get("csrf_token")

    if not isinstance(expected, str) or not secrets.compare_digest(
        csrf_token, expected
    ):
        raise HTTPException(403, "Invalid CSRF token")

    user_id = request.session.get("user_id")

    if type(user_id) is not int:
        return RedirectResponse("/login", status_code=303)

    if not 12 <= len(new_password) <= 128:
        return render_password_change(
            request,
            "Новый пароль должен содержать 12–128 символов",
            400,
        )

    if new_password != password_confirm:
        return render_password_change(request, "Пароли не совпадают", 400)

    with SessionLocal() as db:
        user = get_session_user(request, db)

        if user is None:
            request.session.clear()
            return RedirectResponse("/login", status_code=303)

        if not verify_password(current_password, user.password_hash):
            return render_password_change(request, "Неверный текущий пароль", 400)

        if new_password == current_password:
            return render_password_change(
                request, "Новый пароль должен отличаться", 400
            )

        user.password_hash = hash_password(new_password)
        user.must_change_password = False

        issue_session(
            request,
            db,
            user.id,
            revoke_all=True,
        )

    return RedirectResponse("/profile", status_code=303)


@router.get("/admin", response_class=HTMLResponse)
def admin_page(
    user: Annotated[User, Depends(require_admin)],
):
    return HTMLResponse(
        "<h1>CYBERARENA / ADMIN</h1><p>Административный доступ подтверждён.</p>"
    )

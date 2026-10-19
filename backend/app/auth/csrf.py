"""CSRF helpers shared by HTML forms and cookie-authenticated JSON APIs."""

import secrets
from typing import TypeGuard

from fastapi import HTTPException, Request


def _valid_token(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and 0 < len(value) <= 128 and value.isascii()


def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not _valid_token(token):
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def validate_csrf(request: Request, token: object) -> None:
    expected = request.session.get("csrf_token")
    if (
        not _valid_token(expected)
        or not _valid_token(token)
        or not secrets.compare_digest(token, expected)
    ):
        raise HTTPException(403, "Invalid CSRF token")

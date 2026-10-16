import os
import re

from sqlalchemy import select

from ..database import SessionLocal
from ..models import User
from .security import hash_password


def bootstrap_admin():
    username = os.environ["ADMIN_USERNAME"].strip().lower()
    password = os.environ["ADMIN_PASSWORD"]

    if not re.fullmatch(r"[a-z0-9_]{3,32}", username):
        raise RuntimeError("Недопустимый ADMIN_USERNAME")

    if not 12 <= len(password) <= 128 or password == "change-me":
        raise RuntimeError(
            "Задайте безопасный ADMIN_PASSWORD длиной от 12 до 128 символов"
        )

    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.username == username))

        if existing:
            if not existing.is_admin:
                raise RuntimeError("ADMIN_USERNAME уже занят обычным пользователем")
            return

        admin = User(
            username=username,
            password_hash=hash_password(password),
            is_admin=True,
            must_change_password=True,
        )

        db.add(admin)
        db.commit()

        print("Начальная учётная запись администратора создана")

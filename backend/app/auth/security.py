from contextlib import contextmanager
from threading import BoundedSemaphore

from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()
MAX_CONCURRENT_PASSWORD_OPERATIONS = 2
MAX_WAITING_PASSWORD_OPERATIONS = 8
PASSWORD_SLOT_WAIT_SECONDS = 2.0


class PasswordCapacityError(Exception):
    """All password workers or their bounded waiting slots are occupied."""


class PasswordOperationLimiter:
    def __init__(self, running: int, waiting: int, timeout: float):
        if running < 1 or waiting < 0 or timeout < 0:
            raise ValueError("Invalid password operation limits")
        self._running = BoundedSemaphore(running)
        self._admitted = BoundedSemaphore(running + waiting)
        self._timeout = timeout

    @contextmanager
    def slot(self):
        if not self._admitted.acquire(blocking=False):
            raise PasswordCapacityError
        try:
            if not self._running.acquire(timeout=self._timeout):
                raise PasswordCapacityError
            try:
                yield
            finally:
                self._running.release()
        finally:
            self._admitted.release()


password_operations = PasswordOperationLimiter(
    MAX_CONCURRENT_PASSWORD_OPERATIONS,
    MAX_WAITING_PASSWORD_OPERATIONS,
    PASSWORD_SLOT_WAIT_SECONDS,
)


def hash_password(password: str) -> str:
    """Создаёт защищённый хэш пароля."""
    with password_operations.slot():
        return password_hash.hash(password)


def verify_password(
    password: str,
    hashed_password: str,
) -> bool:
    """Проверяет, совпадает ли пароль с хэшом."""
    with password_operations.slot():
        return password_hash.verify(password, hashed_password)

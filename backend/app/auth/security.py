from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Создаёт защищённый хэш пароля."""
    return password_hash.hash(password)


def verify_password(
    password: str,
    hashed_password: str,
) -> bool:
    """Проверяет, совпадает ли пароль с хэшом."""
    return password_hash.verify(password, hashed_password)

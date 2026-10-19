"""Flags use a fixed, bounded Argon2id policy; no plaintext is persisted."""

from typing import TypeGuard

from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError

hasher = PasswordHasher(time_cost=3, memory_cost=32768, parallelism=1)


def valid_flag(flag: object) -> TypeGuard[str]:
    return (
        isinstance(flag, str)
        and 6 <= len(flag) <= 256
        and flag.startswith("CTF{")
        and flag.endswith("}")
        and all(33 <= ord(char) <= 126 and char not in "{}" for char in flag[4:-1])
    )


def supported_hash(encoded: str) -> bool:
    try:
        params = extract_parameters(encoded)
        return (
            params.type == Type.ID
            and params.version == 19
            and params.memory_cost == 32768
            and params.time_cost == 3
            and params.parallelism == 1
            and params.hash_len == 32
            and params.salt_len == 16
        )
    except (InvalidHashError, ValueError, TypeError):
        return False


def hash_flag(flag: str) -> str:
    if not valid_flag(flag):
        raise ValueError("Flag must have the format CTF{...}, 6–256 printable ASCII characters")
    return hasher.hash(flag)


def verify_flag(flag: str, encoded: str) -> bool:
    if not valid_flag(flag) or not supported_hash(encoded):
        return False
    try:
        return hasher.verify(encoded, flag)
    except (VerificationError, InvalidHashError):
        return False

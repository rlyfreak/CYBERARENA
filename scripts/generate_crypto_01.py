"""Build the public CRYPTO-01 ciphertext without storing a plaintext flag."""

import argparse
import getpass
import re
import textwrap
from pathlib import Path

KNOWN_PREFIX = b"CYBERARENA INCIDENT REPORT\n"
KEY_LENGTH = 7
RESOURCE_MARKER = "CYBERARENA CRYPTO-01 XOR DATA v1"


def build_challenge(flag: str, key: str) -> str:
    """Return a deterministic, UTF-8 text asset for a valid flag and key."""
    if not re.fullmatch(r"CTF\{[!-z|~]+\}", flag, flags=re.ASCII):
        raise ValueError("Flag must be CTF{...} with printable ASCII and no nested braces")
    if len(flag) > 256:
        raise ValueError("Flag exceeds the CTF Core limit of 256 characters")
    if len(key) != KEY_LENGTH or not all(33 <= ord(char) <= 126 for char in key):
        raise ValueError("Key must contain exactly seven printable ASCII characters")

    plaintext = (
        KNOWN_PREFIX
        + b"Ticket: CRYPTO-01\n"
        + b"Access token: "
        + flag.encode("ascii")
        + b"\nEnd of report.\n"
    )
    key_bytes = key.encode("ascii")
    ciphertext = bytes(byte ^ key_bytes[index % KEY_LENGTH]
                       for index, byte in enumerate(plaintext))
    wrapped_hex = "\n".join(textwrap.wrap(ciphertext.hex(), 64))
    return (
        f"{RESOURCE_MARKER}\n"
        "Encoding: UTF-8\n"
        "Cipher: repeating-key XOR\n"
        f"Key length: {KEY_LENGTH} bytes\n"
        "Known plaintext prefix: CYBERARENA INCIDENT REPORT\\n\n"
        "Ciphertext (hex):\n"
        f"{wrapped_hex}\n"
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="Public challenge.txt path")
    parser.add_argument("--replace", action="store_true", help="Explicitly replace an existing file")
    args = parser.parse_args(argv)

    flag = getpass.getpass("CRYPTO-01 flag (CTF{...}): ")
    key = getpass.getpass("Seven-character XOR key: ")
    try:
        material = build_challenge(flag, key)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        with args.output.open("w" if args.replace else "x", encoding="utf-8", newline="\n") as file:
            file.write(material)
    except FileExistsError:
        parser.error("Output exists; pass --replace only for an intentional regeneration")
    print(f"Wrote {args.output} ({len(material.encode('utf-8'))} bytes)")


if __name__ == "__main__":
    main()

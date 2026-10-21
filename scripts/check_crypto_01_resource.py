"""Check the real CRYPTO-01 file through nginx after /files/ is deployed."""

import argparse
import urllib.error
import urllib.request
from pathlib import Path

PATH = "/files/crypto-01/challenge.txt"
MARKER = b"CYBERARENA CRYPTO-01 XOR DATA v1"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(base: str, path: str, limit: int) -> tuple[int, str, bytes]:
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(base.rstrip("/") + path, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers.get("Content-Type", ""), response.read(limit)


def verify(base: str, material: Path) -> None:
    expected = material.read_bytes()
    if not expected or MARKER not in expected or b"CTF{" in expected:
        raise RuntimeError("Real CRYPTO-01 material is missing or invalid")
    status, content_type, body = fetch(base, PATH, len(expected) + 1)
    if status != 200 or not content_type.lower().startswith("text/plain") or body != expected:
        raise RuntimeError(
            f"CRYPTO-01: expected exact text/plain file with HTTP 200; "
            f"got HTTP {status}, Content-Type {content_type!r}"
        )
    for path in (
        "/files/crypto-01/__missing_crypto01_probe__.txt",
        "/files/crypto-01/CRYPTO-01-writeup.md",
        "/files/CRYPTO-01-writeup.md",
    ):
        absent, _, _ = fetch(base, path, 4096)
        if absent != 404:
            raise RuntimeError(f"{path}: expected HTTP 404, got {absent}")
    print("PASS: real CRYPTO-01 text file 200 with exact bytes; absent/write-up paths 404")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="Base URL of deployed nginx")
    parser.add_argument(
        "--material", type=Path,
        default=Path(__file__).resolve().parents[1] / "files/crypto-01/challenge.txt",
    )
    args = parser.parse_args()
    verify(args.base, args.material)


if __name__ == "__main__":
    main()

"""Verify nginx delivery against local fixture bytes; never claim CTF readiness."""
import argparse
import hashlib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(base, path, max_bytes):
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(base.rstrip("/") + path, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read(max_bytes + 1)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify(base, root, request=fetch):
    root = Path(root)
    require(root.is_dir(), "Expected material directory does not exist")
    assets = sorted(p for p in root.rglob("*") if p.is_file() and not p.name.startswith("."))
    require(bool(assets), "No public materials to verify; this check cannot be skipped")
    for asset in assets:
        require(not asset.is_symlink(), "Symlinked materials are not supported")
        relative = asset.relative_to(root).as_posix()
        expected = asset.read_bytes()
        require(bool(expected), f"{relative}: empty material")
        url = "/files/" + urllib.parse.quote(relative, safe="/")
        status, headers, body = request(base, url, len(expected))
        require(status == 200, f"{url}: expected 200, got {status}")
        require(body == expected, f"{url}: response differs from the expected file")
        require(headers.get("X-Content-Type-Options") == "nosniff", f"{url}: missing nosniff")
        require("sandbox" in headers.get("Content-Security-Policy", ""), f"{url}: missing HTML sandbox")
        if asset.suffix.lower() in (".html", ".htm"):
            require("text/html" in headers.get("Content-Type", "").lower(), f"{url}: not HTML")
        if relative.endswith("/index.html"):
            directory_url = "/files/" + urllib.parse.quote(relative[:-10], safe="/")
            directory_status, _, directory_body = request(base, directory_url, len(expected))
            require(directory_status == 200 and directory_body == expected,
                    f"{directory_url}: directory index does not match index.html")
        print(f"OK {url} sha256={hashlib.sha256(expected).hexdigest()}")
    for url, expected_status in (
        ("/files/__cyberarena_missing_static_probe__", 404),
        ("/files/.env", 404),
        ("/files/.private-probe", 404),
        ("/files/", 403),
    ):
        status, _, _ = request(base, url, 4096)
        require(status == expected_status, f"{url}: expected {expected_status}, got {status}")
    print("PASS: static file bytes, directory index, security headers, missing/hidden files and no listing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:18080")
    parser.add_argument("--root", type=Path, default=Path("scripts/fixtures/files"))
    args = parser.parse_args()
    verify(args.base, args.root)


if __name__ == "__main__":
    main()

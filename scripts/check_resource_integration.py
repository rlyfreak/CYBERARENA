"""Strict HTTP integration smoke check for real /files/ resources.

Run after nginx serves WEB-02 and CRYPTO-01; no missing dependency can be skipped.
All required URLs and markers must come from the infrastructure owner.
"""
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("CYBERARENA_SMOKE_BASE", "http://127.0.0.1:8080").rstrip("/")
ERROR_SIGNATURES = (
    b"<title>502 bad gateway",
    b"<title>503 service temporarily unavailable",
    b"<title>404 not found",
    "Учебная лаборатория сейчас недоступна".encode(),
)


def required(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise AssertionError(f"{name} must be configured; /files/ checks cannot be skipped")
    return value


def resource_path(name):
    path = required(name)
    parts = urllib.parse.urlsplit(path)
    if not path.startswith("/files/") or parts.scheme or parts.netloc or parts.fragment:
        raise AssertionError(f"{name} must be a local /files/ URL without a fragment")
    if not parts.path.startswith("/files/") or ".." in parts.path.split("/"):
        raise AssertionError(f"{name} contains an unsafe path")
    return path


def fetch(path):
    url = BASE + path
    req = urllib.request.Request(url, headers={"Accept": "*/*"})
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read()


def assert_no_error_page(body, label):
    lower = body.lower()
    for signature in ERROR_SIGNATURES:
        assert signature.lower() not in lower, f"{label}: nginx/error fallback served"


def verify():
    web_path = resource_path("WEB02_RESOURCE_PATH")
    crypto_path = resource_path("CRYPTO01_RESOURCE_PATH")
    missing_path = os.environ.get(
        "MISSING_RESOURCE_PATH", "/files/__cyberarena_missing_resource_smoke__"
    )
    assert missing_path.startswith("/files/") and "?" not in missing_path
    assert missing_path not in (web_path, crypto_path)

    web_marker = required("WEB02_EXPECTED_MARKER").encode("utf-8")
    crypto_marker = required("CRYPTO01_EXPECTED_MARKER").encode("utf-8")

    web_status, web_headers, web_body = fetch(web_path)
    assert web_status == 200, f"WEB-02: expected 200, got {web_status}"
    assert "text/html" in web_headers.get("Content-Type", "").lower(), "WEB-02: not HTML"
    assert re.search(rb"<!doctype\s+html|<html(?:\s|>)", web_body, re.IGNORECASE), "WEB-02: no HTML document"
    assert web_marker in web_body, "WEB-02: expected content is missing"
    assert_no_error_page(web_body, "WEB-02")

    crypto_status, crypto_headers, crypto_body = fetch(crypto_path)
    assert crypto_status == 200, f"CRYPTO-01: expected 200, got {crypto_status}"
    assert crypto_body, "CRYPTO-01: downloaded file is empty"
    assert crypto_marker in crypto_body, "CRYPTO-01: expected file content is missing"
    assert "text/html" not in crypto_headers.get("Content-Type", "").lower(), (
        "CRYPTO-01: HTML returned instead of a downloadable file"
    )
    assert_no_error_page(crypto_body, "CRYPTO-01")

    missing_status, _, _ = fetch(missing_path)
    assert missing_status == 404, f"Missing material: expected 404, got {missing_status}"
    print("PASS: WEB-02 HTML 200 + marker; CRYPTO-01 file 200 + marker; absent resource 404")


if __name__ == "__main__":
    try:
        verify()
    except (AssertionError, OSError, urllib.error.URLError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)

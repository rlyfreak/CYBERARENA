"""Offline regression tests for the strict /files/ integration checker."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "resource_integration_smoke", ROOT / "scripts" / "check_resource_integration.py"
)
assert spec and spec.loader
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("WEB02_RESOURCE_PATH", "/files/web-02/index.html")
    monkeypatch.setenv("CRYPTO01_RESOURCE_PATH", "/files/crypto-01/challenge.txt")
    monkeypatch.setenv("WEB02_EXPECTED_MARKER", "WEB02-CONTENT")
    monkeypatch.setenv("CRYPTO01_EXPECTED_MARKER", "CRYPTO01-CONTENT")
    monkeypatch.delenv("MISSING_RESOURCE_PATH", raising=False)


def responses(web_status=200, web_body=b"<html>WEB02-CONTENT</html>",
              crypto_status=200, crypto_body=b"CRYPTO01-CONTENT",
              missing_status=404, crypto_type="text/plain"):
    data = {
        "/files/web-02/index.html": (
            web_status, {"Content-Type": "text/html; charset=utf-8"}, web_body
        ),
        "/files/crypto-01/challenge.txt": (
            crypto_status, {"Content-Type": crypto_type}, crypto_body
        ),
        "/files/__cyberarena_missing_resource_smoke__": (
            missing_status, {"Content-Type": "text/html"}, b"Not Found"
        ),
    }
    return lambda path: data[path]


def test_all_real_resources_pass(configured, monkeypatch, capsys):
    monkeypatch.setattr(smoke, "fetch", responses())
    smoke.verify()
    assert "PASS:" in capsys.readouterr().out


@pytest.mark.parametrize("changes,diagnostic", [
    ({"web_status": 404}, "WEB-02: expected 200"),
    ({"web_body": b"<html><title>502 Bad Gateway</title>WEB02-CONTENT</html>"},
     "nginx/error fallback"),
    ({"web_body": b"<html>Wrong page</html>"}, "WEB-02: expected content"),
    ({"crypto_status": 404}, "CRYPTO-01: expected 200"),
    ({"crypto_body": b"<html>CRYPTO01-CONTENT</html>", "crypto_type": "text/html"},
     "HTML returned"),
    ({"crypto_body": b"Wrong file"}, "CRYPTO-01: expected file content"),
    ({"missing_status": 200}, "Missing material: expected 404"),
])
def test_integration_failures_are_not_skipped(configured, monkeypatch, changes, diagnostic):
    monkeypatch.setattr(smoke, "fetch", responses(**changes))
    with pytest.raises(AssertionError, match=diagnostic):
        smoke.verify()


def test_missing_configuration_is_a_failure(monkeypatch):
    monkeypatch.delenv("WEB02_RESOURCE_PATH", raising=False)
    with pytest.raises(AssertionError, match="cannot be skipped"):
        smoke.verify()


def test_untrusted_resource_paths_are_rejected(configured, monkeypatch):
    monkeypatch.setenv("WEB02_RESOURCE_PATH", "https://example.com/files/index.html")
    with pytest.raises(AssertionError, match="local /files/ URL"):
        smoke.verify()

"""The HTTP checker must reject missing or substituted static materials."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "check_static_files", Path(__file__).resolve().parents[2] / "scripts/check_static_files.py"
)
assert spec is not None and spec.loader is not None
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


@pytest.fixture
def materials(tmp_path):
    root = tmp_path / "files"
    (root / "web-02").mkdir(parents=True)
    (root / "web-02/index.html").write_bytes(b"<!doctype html><p>expected</p>")
    return root


def responder(status=200, body=b"<!doctype html><p>expected</p>", nosniff=True):
    def request(base, path, max_bytes):
        headers = {"Content-Type": "text/html", "Content-Security-Policy": "sandbox allow-scripts"}
        if nosniff:
            headers["X-Content-Type-Options"] = "nosniff"
        if path == "/files/":
            return 403, headers, b"forbidden"
        if "/." in path or "missing_static_probe" in path:
            return 404, headers, b"not found"
        return status, headers, body
    return request


def test_expected_static_materials_pass(materials):
    smoke.verify("http://example.invalid", materials, responder())


@pytest.mark.parametrize("changes,message", [
    ({"status": 404}, "expected 200"),
    ({"status": 302}, "expected 200"),
    ({"body": b"<!doctype html><p>wrong page</p>"}, "differs"),
    ({"nosniff": False}, "missing nosniff"),
])
def test_wrong_responses_fail(materials, changes, message):
    with pytest.raises(RuntimeError, match=message):
        smoke.verify("http://example.invalid", materials, responder(**changes))


def test_empty_material_directory_fails(tmp_path):
    with pytest.raises(RuntimeError, match="cannot be skipped"):
        smoke.verify("http://example.invalid", tmp_path, responder())

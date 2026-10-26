import importlib.util
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

LAB_PATH = Path(__file__).resolve().parents[2] / "labs" / "web-01" / "server.py"

spec = importlib.util.spec_from_file_location("web01_lab", LAB_PATH)
assert spec is not None and spec.loader is not None

lab_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab_module)

TEST_FLAG = "CTF{web01_pytest_flag}"


def test_lab_requires_a_submit_compatible_flag():
    assert lab_module.valid_flag(TEST_FLAG)
    assert not lab_module.valid_flag("CYBERARENA{old_demo_flag}")
    assert not lab_module.valid_flag("")



@pytest.fixture
def lab_server(monkeypatch):
    monkeypatch.setenv("WEB01_FLAG", TEST_FLAG)

    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        lab_module.Handler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def get_page(base_url, path):
    with urllib.request.urlopen(
        f"{base_url}{path}",
        timeout=3,
    ) as response:
        return response.status, response.read().decode("utf-8")


def test_archive_homepage(lab_server):
    status, html = get_page(lab_server, "/")

    assert status == 200
    assert "Реестр документов" in html
    assert "DOCUMENT #101" in html
    assert "DOCUMENT #102" in html

    # Закрытый документ отсутствует в каталоге.
    assert "DOCUMENT #103" not in html
    assert TEST_FLAG not in html


def test_public_documents(lab_server):
    status, html = get_page(lab_server, "/document?id=101")

    assert status == 200
    assert "Правила работы с архивом" in html
    assert TEST_FLAG not in html

    status, html = get_page(lab_server, "/document?id=102")

    assert status == 200
    assert "Журнал изменений" in html
    assert "103" in html
    assert TEST_FLAG not in html


def test_idor_exposes_private_document(lab_server):
    status, html = get_page(lab_server, "/document?id=103")

    # Намеренная уязвимость лаборатории.
    assert status == 200
    assert "Служебный документ" in html
    assert TEST_FLAG in html


def test_unknown_document_returns_404(lab_server):
    with pytest.raises(urllib.error.HTTPError) as error:
        get_page(lab_server, "/document?id=999")

    assert error.value.code == 404


def test_healthcheck(lab_server):
    status, body = get_page(lab_server, "/healthz")

    assert status == 200
    assert '"status":"ok"' in body


def test_status_page(lab_server):
    status, html = get_page(lab_server, "/status")

    assert status == 200
    assert "Архив работает" in html
    assert TEST_FLAG not in html

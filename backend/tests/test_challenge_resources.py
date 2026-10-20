import json
from html.parser import HTMLParser

import pytest
from pydantic import ValidationError
from sqlalchemy import delete, func, select

from app.ctf import schemas, security, service
from app.models import Challenge, CtfState, CtfVerificationLease, Solve
from test_ctf_api import FLAG, admin_login, authenticate, payload
from test_ctf_pages import token


class FormFields(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.inputs = {}
        self.options = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag in ("input", "select") and "name" in fields:
            self.inputs[fields["name"]] = fields
        if tag == "option":
            self.options.append(fields)


UNSAFE_URLS = [
    "https://example.org/lab/",
    "javascript:alert(1)",
    "data:text/html,test",
    "//example.org/",
    "///example.org/",
    "/\\example.org/",
    "/lab/\x00",
    "\t/lab/",
    "/lab/\n",
    "/lab/\x7f",
    "/%2fexample.org/",
    "/%5cexample.org/",
    "/%252fexample.org/",
    "/%255cexample.org/",
    "/lab/%0a",
    "/lab/%250d",
    "/lab/%00",
    "/lab/%7f",
    "/lab/../admin",
    "/lab/%2e%2e/admin",
    "/lab/%252e%252e/admin",
    "/lab/%GG",
    "/lab/%",
    "/%ff",
    "/%2525252fexample.org/",
    "/lab/%3F/%252e%252e/private",
]


@pytest.mark.parametrize("url", UNSAFE_URLS)
def test_resource_schema_rejects_unsafe_urls(url):
    with pytest.raises(ValidationError):
        schemas.ChallengeCreate.model_validate(payload() | {"resource_url": url})
    with pytest.raises(ValidationError):
        schemas.ChallengeUpdate.model_validate(
            {"expected_revision": 1, "resource_url": url}
        )


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "   ",
        "/lab/",
        "/lab/document?id=101",
        "/files/task%20one.zip",
        "/lab/?next=https://example.org",
        "/files/100%25.zip",
        "/files/%D1%82%D0%B5%D1%81%D1%82.zip",
    ],
)
def test_resource_schema_accepts_local_urls(url):
    task = schemas.ChallengeCreate.model_validate(payload() | {"resource_url": url})
    assert task.resource_url == (url.strip() or None if url is not None else None)


def test_resource_api_create_patch_clear_and_no_secret_leaks(api):
    client, factory = api
    admin_login(client, factory)
    data = payload() | {"difficulty": "hard", "resource_url": "/lab/?a=1&b=2"}
    created = client.post("/api/admin/challenges", json=data)
    assert created.status_code == 201, created.text
    task = created.json()
    task_id = task["id"]
    path = f"/api/admin/challenges/{task_id}"
    assert task["difficulty"] == "hard" and task["resource_url"] == data["resource_url"]
    assert "flag" not in created.text and FLAG not in created.text
    changed = client.patch(
        path, json={"expected_revision": task["revision"], "title": "Edited"}
    )
    assert changed.status_code == 200
    task = changed.json()
    assert task["difficulty"] == "hard" and task["resource_url"] == data["resource_url"]
    for value in ["/files/task.zip", None, "/lab/", ""]:
        response = client.patch(
            path, json={"expected_revision": task["revision"], "resource_url": value}
        )
        assert response.status_code == 200, response.text
        task = response.json()
        assert task["resource_url"] == (value or None)
        assert task["title"] == "Edited" and task["difficulty"] == "hard"
        assert task["points"] == 150 and task["is_published"] is True
    response = client.post("/api/admin/challenges", json=payload("WEB-03", 100))
    assert response.status_code == 201
    assert (
        response.json()["difficulty"] == "easy"
        and response.json()["resource_url"] is None
    )
    authenticate(client, factory, 1)
    for route in [
        "/api/challenges",
        f"/api/challenges/{task_id}",
        "/challenges",
        f"/challenges/{task_id}",
    ]:
        response = client.get(route)
        assert response.status_code == 200
        assert (
            FLAG not in response.text
            and "flag_hash" not in response.text
            and "$argon2" not in response.text
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("difficulty", "expert"),
        ("difficulty", None),
        ("title", None),
        ("points", None),
        ("is_published", None),
    ],
)
def test_invalid_resource_updates_do_not_change_task(api, field, value):
    client, factory = api
    admin_login(client, factory)
    before = client.get("/api/admin/challenges").json()[0]
    response = client.patch(
        "/api/admin/challenges/1", json={"expected_revision": 1, field: value}
    )
    assert response.status_code == 422
    assert client.get("/api/admin/challenges").json()[0] == before
    if field == "difficulty":
        response = client.post("/api/admin/challenges", json=payload() | {field: value})
        assert response.status_code == 422


def test_resource_api_rejects_url_bypasses(api):
    client, factory = api
    admin_login(client, factory)
    for url in UNSAFE_URLS:
        response = client.patch(
            "/api/admin/challenges/1",
            json={"expected_revision": 1, "resource_url": url},
        )
        assert response.status_code == 422, repr(url)
    assert client.get("/api/admin/challenges").json()[0]["revision"] == 1


def test_resource_admin_forms_and_player_rendering(api):
    client, factory = api
    admin_login(client, factory)
    page = client.get("/admin/challenges/new")
    form = FormFields(page.text)
    assert form.inputs["difficulty"]["required"] is None
    assert {option["value"] for option in form.options} == {"easy", "medium", "hard"}
    assert form.inputs["resource_url"]["maxlength"] == "2048"
    data = payload() | {
        "difficulty": "medium",
        "resource_url": '/lab/?q="<&x=1',
        "is_published": "on",
        "csrf_token": token(page),
    }
    response = client.post("/admin/challenges/new", data=data)
    assert response.status_code == 303, response.text
    edit_path = response.headers["location"]
    page = client.get(edit_path)
    form = FormFields(page.text)
    assert form.inputs["resource_url"]["value"] == data["resource_url"]
    assert any(o.get("value") == "medium" and "selected" in o for o in form.options)
    assert FLAG not in page.text and "$argon2" not in page.text
    task_id = int(edit_path.rsplit("/", 1)[1])
    player_page = client.get(f"/challenges/{task_id}")
    assert 'href="/lab/?q=&#34;&lt;&amp;x=1"' in player_page.text
    assert "Открыть материалы задания" in player_page.text
    assert "Средняя" in player_page.text and "Средняя" in client.get("/challenges").text
    data.pop("code")
    data["flag"] = ""
    data.update(
        expected_revision="1",
        resource_url="",
        difficulty="hard",
        csrf_token=token(page),
    )
    assert client.post(edit_path, data=data).status_code == 303
    page = client.get(f"/challenges/{task_id}")
    assert 'target="_blank"' not in page.text
    assert "Сложная" in page.text
    data.update(
        expected_revision="2",
        resource_url="/%2fexample.org/",
        csrf_token=token(client.get(edit_path)),
    )
    assert client.post(edit_path, data=data).status_code == 422


def test_web01_resource_is_data_driven(api):
    client, factory = api
    assert 'href="/lab/"' in client.get("/challenges/1").text
    with factory.begin() as db:
        task = db.get(Challenge, 1)
        assert task is not None
        task.resource_url = "/lab/status"
    page = client.get("/challenges/1")
    assert 'href="/lab/status"' in page.text and 'href="/lab/"' not in page.text
    with factory.begin() as db:
        task = db.get(Challenge, 1)
        assert task is not None
        task.resource_url = None
    assert 'target="_blank"' not in client.get("/challenges/1").text


def test_challenge_resource_distinguishes_page_and_file(api):
    client, factory = api
    with factory.begin() as db:
        task = db.get(Challenge, 1)
        assert task is not None
        task.resource_url = "/files/web-02/index.html"
    page = client.get("/challenges/1")
    assert "Открыть материалы задания" in page.text
    assert " download" not in page.text
    with factory.begin() as db:
        task = db.get(Challenge, 1)
        assert task is not None
        task.resource_url = "/files/crypto-01/ciphertext.txt"
    page = client.get("/challenges/1")
    assert "Скачать файл: ciphertext.txt" in page.text
    assert " download" in page.text


def test_parallel_repeat_releases_verification_capacity(ctf_db, monkeypatch):
    factory, _ = ctf_db
    original = security.verify_flag
    nested = False

    def verify(flag, encoded):
        nonlocal nested
        if not nested:
            nested = True
            assert service.submit_flag(1, 1, flag).result == "correct"
        return original(flag, encoded)

    monkeypatch.setattr(security, "verify_flag", verify)
    assert service.submit_flag(1, 1, FLAG).result == "already_solved"
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Solve)) == 1
        assert db.scalar(select(func.count()).select_from(CtfVerificationLease)) == 0
    assert service.submit_flag(2, 1, FLAG).result == "correct"


@pytest.mark.parametrize("operation", ["submit", "results", "reset"])
def test_missing_ctf_state_returns_controlled_error(ctf_db, operation):
    factory, _ = ctf_db
    with factory.begin() as db:
        db.execute(delete(CtfState))
    with pytest.raises(service.CtfError) as error:
        if operation == "submit":
            service.submit_flag(1, 1, FLAG)
        elif operation == "results":
            service.results_state()
        else:
            service.reset_results(0)
    assert error.value.status == 503
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(CtfVerificationLease)) == 0


def test_seeded_resources_are_unpublished_and_repeat_preserves_edits(ctf_db):
    factory, _ = ctf_db
    with factory.begin() as db:
        db.execute(delete(Challenge))
    service.seed_case()
    with factory.begin() as db:
        task = db.scalar(select(Challenge).where(Challenge.code == "WEB-01"))
        assert task is not None
        assert task.resource_url == "/lab/" and task.difficulty == "easy"
        assert not task.is_published and task.flag_hash == ""
        task.resource_url = None
        task.difficulty = "hard"
    service.seed_case()
    with factory() as db:
        task = db.scalar(select(Challenge).where(Challenge.code == "WEB-01"))
        assert task is not None
        assert task.resource_url is None and task.difficulty == "hard"
        assert FLAG not in json.dumps(service.catalog(1, include_hidden=True))


@pytest.mark.parametrize(
    "path,field",
    [
        ("/admin/challenges/new", "points"),
        ("/admin/challenges/1", "expected_revision"),
    ],
)
def test_admin_form_rejects_uploaded_fields_without_server_error(api, path, field):
    client, factory = api
    admin_login(client, factory)
    page = client.get(path)
    data = payload() | {"csrf_token": token(page), "expected_revision": "1"}
    data.pop(field, None)
    response = client.post(
        path, data=data, files={field: ("input.txt", b"100", "text/plain")}
    )
    assert response.status_code == 422
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Challenge)) == 1


def test_state_removed_during_verification_releases_capacity(ctf_db, monkeypatch):
    factory, _ = ctf_db

    def verify(*_):
        with factory.begin() as db:
            db.execute(delete(CtfState))
        return True

    monkeypatch.setattr(security, "verify_flag", verify)
    with pytest.raises(service.CtfError) as error:
        service.submit_flag(1, 1, FLAG)
    assert error.value.status == 503
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(CtfVerificationLease)) == 0
        assert db.scalar(select(func.count()).select_from(Solve)) == 0

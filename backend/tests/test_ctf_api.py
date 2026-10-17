import base64
import hashlib
import json
import os
import secrets
import time

os.environ.setdefault("SESSION_SECRET", "cyberarena-isolated-test-secret-2026")

import pytest
from app.auth import dependencies
from app.main import SESSION_SECRET, app
from app.models import AuthSession, Challenge, User
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
from test_ctf_service import FLAG


def authenticate(client, factory, user_id):
    client.cookies.clear()
    sid = secrets.token_urlsafe(32)
    with factory.begin() as db:
        db.add(AuthSession(token_hash=hashlib.sha256(sid.encode()).hexdigest(),
                           user_id=user_id, expires_at=int(time.time()) + 3600))
    data = base64.b64encode(json.dumps({"user_id": user_id, "sid": sid}).encode())
    client.cookies.set("cyberarena_session", TimestampSigner(SESSION_SECRET).sign(data).decode())


@pytest.fixture
def api(ctf_db, monkeypatch):
    factory, _ = ctf_db
    monkeypatch.setattr(dependencies, "SessionLocal", factory)
    client = TestClient(app, follow_redirects=False)
    authenticate(client, factory, 1)
    token = client.get('/api/csrf').json()['csrf_token']
    client.headers['X-CSRF-Token'] = token
    yield client, factory
    client.close()


def admin_login(client, factory):
    authenticate(client, factory, 3)
    client.headers['X-CSRF-Token'] = client.get('/api/csrf').json()['csrf_token']


def payload(code="WEB-02", points=150):
    return {"code": code, "title": code, "description": "Task <script>alert(1)</script>",
            "category": "WEB", "points": points, "flag": FLAG, "is_published": True}


def test_catalog_requires_server_session(api):
    client, _ = api
    assert client.get('/api/challenges').status_code == 200
    client.cookies.clear()
    assert client.get('/api/challenges').status_code == 401
    assert client.get('/api/leaderboard').status_code == 200


def test_catalog_visibility_and_sanitized_output(api):
    client, factory = api
    data = client.get('/api/challenges').json()
    assert len(data) == 1 and data[0]['points'] == 100 and not data[0]['solved']
    assert 'flag' not in json.dumps(data)
    assert client.get('/api/challenges?category=CRYPTO').json() == []
    assert client.get('/api/challenges?limit=0').status_code == 422
    assert client.get('/api/challenges').headers['Cache-Control'] == 'no-store'
    with factory.begin() as db:
        db.get(Challenge, 1).is_published = False
    assert client.get('/api/challenges').json() == []
    assert client.get('/api/challenges/1').status_code == 404
    assert client.post('/api/challenges/1/submissions', json={'flag': FLAG}).status_code == 404


def test_submission_csrf_format_history_and_repeat(api):
    client, factory = api
    for token in ['', 'wrong', 'x' * 129]:
        response = client.post('/api/challenges/1/submissions', json={'flag': FLAG},
                               headers={'X-CSRF-Token': token})
        assert response.status_code == 403
    assert client.get('/api/submissions').json() == []
    assert client.post('/api/challenges/1/submissions', json={'flag': 'bad'}).status_code == 422
    correct = client.post('/api/challenges/1/submissions', json={'flag': FLAG})
    assert correct.json()['points_awarded'] == 100
    assert client.get('/api/challenges/1').json()['solved'] is True
    repeat = client.post('/api/challenges/1/submissions', json={'flag': FLAG})
    assert repeat.status_code == 409 and repeat.json()['points_awarded'] == 0
    assert len(client.get('/api/submissions').json()) == 3
    authenticate(client, factory, 2)
    assert client.get('/api/submissions?user_id=1').json() == []


@pytest.mark.parametrize('body', [{'flag': ['CTF{secret_marker}']}, {'flag': 'CTF{' + 'q' * 257 + '}'},
                                  {'flag': None}, {'flag': {'private': 'CTF{secret_marker}'}}, {}])
def test_validation_does_not_echo_secrets(api, body):
    client, _ = api
    response = client.post('/api/challenges/1/submissions', json=body)
    assert response.status_code == 422
    assert 'CTF{' not in response.text and 'secret_marker' not in response.text


def test_admin_permissions_and_forced_password_change(api):
    client, factory = api
    assert client.get('/api/admin/challenges').status_code == 403
    assert client.post('/api/admin/challenges', json=payload()).status_code == 403
    with factory.begin() as db:
        db.get(User, 1).must_change_password = True
    assert client.get('/api/challenges').status_code == 403
    assert client.post('/api/challenges/1/submissions', json={'flag': FLAG}).status_code == 403


def test_admin_create_edit_publish_hide_and_case_points(api):
    client, factory = api
    admin_login(client, factory)
    response = client.post('/api/admin/challenges', json=payload())
    assert response.status_code == 201, response.text
    task = response.json()
    assert 'flag' not in response.text
    assert client.post('/api/admin/challenges', json=payload()).status_code == 409
    assert client.post('/api/admin/challenges', json=payload('CRYPTO-01', 100)).status_code == 422
    assert client.post('/api/admin/challenges', json=payload('CRYPTO-01', 150)).status_code == 201
    edit = {'expected_revision': task['revision'], 'is_published': False, 'title': 'Edited'}
    response = client.patch(f"/api/admin/challenges/{task['id']}", json=edit)
    assert response.status_code == 200 and not response.json()['is_published']
    assert client.patch(f"/api/admin/challenges/{task['id']}", json=edit).status_code == 409
    assert len(client.get('/api/admin/challenges').json()) == 3
    edit['expected_revision'] += 1
    edit['is_published'] = True
    assert client.patch(f"/api/admin/challenges/{task['id']}", json=edit).status_code == 200
    assert client.patch(f"/api/admin/challenges/{task['id']}",
                        json={'expected_revision': 3, 'points': 5}).status_code == 422


def test_admin_attempts_reset_and_restart_does_not_restore_scores(api):
    from app.migrations.ctf_core import migrate

    client, factory = api
    client.post('/api/challenges/1/submissions', json={'flag': FLAG})
    admin_login(client, factory)
    assert len(client.get('/api/admin/submissions').json()) == 1
    assert client.get('/api/admin/submissions?user_id=2').json() == []
    state = client.get('/api/admin/results').json()
    assert client.post('/api/admin/results/reset', json={'confirmation': 'wrong',
                       'expected_generation': state['generation']}).status_code == 422
    body = {'confirmation': 'RESET DEMO RESULTS', 'expected_generation': state['generation']}
    result = client.post('/api/admin/results/reset', json=body)
    assert result.status_code == 200 and result.json()['solves_deleted'] == 1
    assert client.post('/api/admin/results/reset', json=body).status_code == 409
    # Migration was never applied in this create_all-only fixture; register the marker
    # before restart, as every real startup already does before receiving requests.
    migrate(factory.kw['bind'])
    migrate(factory.kw['bind'])
    assert all(r['points'] == 0 for r in client.get('/api/leaderboard').json())
    assert client.get('/api/admin/submissions').json() == []
    assert len(client.get('/api/admin/challenges').json()) == 1


def test_admin_unconfigured_hash_cannot_publish(api):
    client, factory = api
    with factory.begin() as db:
        task = db.get(Challenge, 1)
        task.is_published, task.flag_hash = False, 'a' * 64
    admin_login(client, factory)
    response = client.patch('/api/admin/challenges/1', json={
        'expected_revision': 1, 'is_published': True,
    })
    assert response.status_code == 422


def test_streamed_oversized_flag_rejected_without_echo(api):
    client, _ = api
    response = client.post('/api/challenges/1/submissions',
                           content=iter([b'{"flag":"CTF{', b'x' * 5000, b'}"}']),
                           headers={'Content-Type': 'application/json'})
    assert response.status_code == 413 and 'CTF{' not in response.text

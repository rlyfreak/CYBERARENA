import re

import pytest
from test_ctf_api import FLAG, admin_login

from app.ctf import cli
from app.models import Challenge


def token(response):
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


def test_participant_pages_and_form_flow(api):
    client, _ = api
    for path in ['/', '/challenges', '/challenges/1', '/submissions', '/leaderboard']:
        response = client.get(path)
        assert response.status_code == 200, response.text
    page = client.get('/challenges/1')
    assert client.post('/challenges/1', data={'flag': FLAG, 'csrf_token': 'тест'}).status_code == 403
    response = client.post('/challenges/1', data={'flag': FLAG, 'csrf_token': token(page)})
    assert response.status_code == 303 and FLAG not in response.headers['location']
    page = client.get(response.headers['location'])
    assert 'Баллы начислены' in page.text and FLAG not in page.text
    assert 'Отправленные флаги не сохраняются' in client.get('/submissions').text
    client.cookies.clear()
    assert client.get('/challenges').headers['location'] == '/login'
    assert client.get('/leaderboard').status_code == 200


def test_admin_browser_create_edit_hide_and_escape(api):
    client, factory = api
    assert client.get('/admin').status_code == 403
    admin_login(client, factory)
    page = client.get('/admin/challenges/new')
    data = {'code': 'WEB-02', 'title': '<script>alert(1)</script>', 'description': '<img src=x>',
            'category': 'WEB', 'points': '150', 'flag': FLAG, 'is_published': 'on',
            'csrf_token': token(page)}
    response = client.post('/admin/challenges/new', data=data)
    assert response.status_code == 303, response.text
    page = client.get(response.headers['location'])
    assert '&lt;script&gt;' in page.text and FLAG not in page.text
    task_id = int(response.headers['location'].split('/')[-1])
    published = client.get(f'/challenges/{task_id}')
    assert '&lt;img src=x&gt;' in published.text
    data.pop('code')
    data.pop('flag')
    data.pop('is_published')
    data['expected_revision'] = '1'
    data['csrf_token'] = token(page)
    assert client.post(f'/admin/challenges/{task_id}', data=data).status_code == 303
    assert client.get(f'/challenges/{task_id}').status_code == 404
    assert client.post(f'/admin/challenges/{task_id}', data=data).status_code == 409


def test_case_drafts_and_browser_reset(api):
    client, factory = api
    client.post('/api/challenges/1/submissions', json={'flag': FLAG})
    admin_login(client, factory)
    page = client.get('/admin')
    data = {'csrf_token': token(page)}
    for _ in range(2):
        assert client.post('/admin/seed-case', data=data).status_code == 303
    with factory() as db:
        tasks = db.query(Challenge).order_by(Challenge.id).all()
        assert {t.code: t.points for t in tasks} == {'WEB-01': 100, 'WEB-02': 150, 'CRYPTO-01': 150}
        assert all(not t.is_published and t.flag_hash == '' for t in tasks if t.id != 1)
    assert client.get('/admin/submissions').status_code == 200
    data.update(confirmation='wrong', expected_generation='0')
    assert client.post('/admin/results/reset', data=data).status_code == 422
    data['confirmation'] = 'RESET DEMO RESULTS'
    assert client.post('/admin/results/reset', data=data).status_code == 303
    assert all(row['points'] == 0 for row in client.get('/api/leaderboard').json())


def test_cli_uses_hidden_flag_input_and_admin_role(api, monkeypatch, capsys):
    _, factory = api
    monkeypatch.setattr(cli, 'SessionLocal', factory)
    monkeypatch.setattr(cli.getpass, 'getpass', lambda _: FLAG)
    with pytest.raises(SystemExit):
        cli.main(['--admin', 'player', 'seed-case'])
    cli.main(['--admin', 'admin', 'create', '--code', 'WEB-02', '--title', 'Task',
              '--description', 'Text', '--category', 'WEB', '--points', '150', '--publish',
              '--difficulty', 'hard', '--resource-url', '/lab/status'])
    with factory() as db:
        task = db.query(Challenge).filter_by(code='WEB-02').one()
        assert task.is_published and FLAG not in task.flag_hash
        assert task.difficulty == 'hard' and task.resource_url == '/lab/status'
        task_id, encoded = task.id, task.flag_hash
    cli.main(['--admin', 'admin', 'edit', str(task_id), '--difficulty', 'medium', '--resource-url', ''])
    with factory() as db:
        task = db.get(Challenge, task_id)
        assert task is not None
        assert task.difficulty == 'medium' and task.resource_url is None
        assert task.flag_hash == encoded and task.is_published
    assert FLAG not in capsys.readouterr().out

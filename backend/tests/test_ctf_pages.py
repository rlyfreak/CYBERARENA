import re
import time

import pytest
from sqlalchemy import delete, select

from app.auth import dependencies
from app.auth import routes as auth_routes
from app.ctf import cli, pages, service
from app.ctf.service import CtfError
from app.models import AuthSession, Challenge, User
from test_ctf_api import FLAG, admin_login


def token(response):
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


def navigation(response):
    match = re.search(r'<nav aria-label="Навигация">(.*?)</nav>', response.text, re.DOTALL)
    assert match is not None
    return set(re.findall(r'<(?:a|button)\b[^>]*>([^<]+)</(?:a|button)>', match.group(1)))


GUEST_NAVIGATION = {'CYBERARENA', 'Рейтинг', 'Задания', 'Вход', 'Регистрация'}
PLAYER_NAVIGATION = {'CYBERARENA', 'Рейтинг', 'Задания', 'Мои попытки', 'Профиль', 'Выйти'}
ADMIN_NAVIGATION = PLAYER_NAVIGATION | {'Управление'}
PASSWORD_CHANGE_NAVIGATION = {'CYBERARENA', 'Рейтинг', 'Сменить пароль', 'Выйти'}


def test_html_error_preserves_service_unavailable_when_session_database_fails(api, monkeypatch):
    client, factory = api
    calls = 0

    def database_session():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise RuntimeError('session database unavailable')
        return factory()

    def prepared_error(*args, **kwargs):
        raise CtfError(503, 'Сервис временно недоступен', retry_after=7)

    monkeypatch.setattr(dependencies, 'SessionLocal', database_session)
    monkeypatch.setattr(service, 'challenge_detail', prepared_error)
    response = client.get('/challenges/1')

    assert response.status_code == 503
    assert response.headers['Retry-After'] == '7'
    assert response.headers['Cache-Control'] == 'no-store'
    assert 'Сервис временно недоступен' in response.text
    assert calls == 1


def test_session_pages_disable_caching_for_guest_player_and_admin(api):
    client, factory = api

    for path in ['/', '/leaderboard', '/challenges/1']:
        assert client.get(path).headers['Cache-Control'] == 'no-store'

    admin_login(client, factory)
    for path in ['/', '/leaderboard', '/challenges/1']:
        assert client.get(path).headers['Cache-Control'] == 'no-store'

    client.cookies.clear()
    for path in ['/', '/leaderboard']:
        assert client.get(path).headers['Cache-Control'] == 'no-store'


def test_navigation_is_server_rendered_for_guest_player_and_admin(api):
    client, factory = api

    for path in ['/', '/leaderboard', '/challenges/1']:
        page = client.get(path)
        assert page.status_code == 200
        assert navigation(page) == PLAYER_NAVIGATION
        assert '/api/csrf' not in page.text and '/api/admin/results' not in page.text
        assert token(page)

    admin_login(client, factory)
    for path in ['/', '/leaderboard', '/challenges/1']:
        page = client.get(path)
        assert page.status_code == 200
        assert navigation(page) == ADMIN_NAVIGATION
        assert token(page)

    client.cookies.clear()
    for path in ['/', '/leaderboard']:
        page = client.get(path)
        assert page.status_code == 200
        assert navigation(page) == GUEST_NAVIGATION
        assert 'action="/logout"' not in page.text
    challenge = client.get('/challenges/1')
    assert challenge.status_code == 303 and challenge.headers['location'] == '/login'


@pytest.mark.parametrize('state', ['expired', 'revoked'])
def test_invalid_server_session_renders_guest_navigation(api, state):
    client, factory = api
    with factory.begin() as db:
        if state == 'expired':
            sessions = db.scalars(select(AuthSession).where(AuthSession.user_id == 1)).all()
            assert sessions
            for session in sessions:
                session.expires_at = int(time.time()) - 1
        else:
            db.execute(delete(AuthSession).where(AuthSession.user_id == 1))

    for path in ['/', '/leaderboard']:
        assert navigation(client.get(path)) == GUEST_NAVIGATION
    challenge = client.get('/challenges/1')
    assert challenge.status_code == 303 and challenge.headers['location'] == '/login'


def test_password_change_navigation_and_admin_redirect(api):
    client, factory = api
    with factory.begin() as db:
        user = db.get(User, 1)
        assert user is not None
        user.must_change_password = True

    for path in ['/', '/leaderboard']:
        assert navigation(client.get(path)) == PASSWORD_CHANGE_NAVIGATION
    for path in ['/challenges/1', '/admin']:
        response = client.get(path)
        assert response.status_code == 303
        assert response.headers['location'] == '/change-password'
    assert client.get('/api/admin/challenges').status_code == 403


def test_logout_navigation_csrf_and_protected_pages(api, monkeypatch):
    client, factory = api
    monkeypatch.setattr(auth_routes, 'SessionLocal', factory)
    home = client.get('/')
    csrf_token = token(home)

    invalid = client.post('/logout', data={'csrf_token': 'wrong-token'})
    assert invalid.status_code == 403
    assert navigation(client.get('/')) == PLAYER_NAVIGATION
    assert client.get('/challenges/1').status_code == 200

    logout = client.post('/logout', data={'csrf_token': csrf_token})
    assert logout.status_code == 303 and logout.headers['location'] == '/login'
    assert navigation(client.get('/')) == GUEST_NAVIGATION
    challenge = client.get('/challenges/1')
    assert challenge.status_code == 303 and challenge.headers['location'] == '/login'
    assert client.get('/api/challenges').status_code == 401


def test_admin_html_and_api_access_policy(api):
    client, _ = api
    denied = client.get('/admin')
    assert denied.status_code == 403
    assert 'Доступ к управлению есть только у администратора' in denied.text
    assert navigation(denied) == PLAYER_NAVIGATION
    assert client.get('/api/admin/challenges').status_code == 403

    client.cookies.clear()
    redirected = client.get('/admin')
    assert redirected.status_code == 303 and redirected.headers['location'] == '/login'
    assert client.get('/api/admin/challenges').status_code == 401


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


@pytest.mark.parametrize('result,message', [
    ('incorrect', 'Неверный флаг.'),
    ('invalid_format', 'Формат флага: CTF{...}'),
])
def test_flag_errors_use_error_visual_state(api, result, message):
    client, _ = api
    page = client.get(f'/challenges/1?result={result}')

    assert page.status_code == 200
    assert 'class="message error"' in page.text
    assert message in page.text


def test_catalog_progress_is_global_when_category_is_filtered(api):
    client, factory = api
    with factory.begin() as db:
        db.add(Challenge(
            id=2, code='CRYPTO-01', title='CRYPTO-01', description='Task',
            category='CRYPTO', difficulty='medium', points=150,
            flag_hash='unused', is_published=True,
        ))

    filtered = client.get('/challenges?category=CRYPTO')
    assert filtered.status_code == 200
    assert '0 из 2 решено' in filtered.text
    assert 'CRYPTO-01' in filtered.text and 'WEB-01' not in filtered.text

    service.submit_flag(1, 1, FLAG)
    filtered = client.get('/challenges?category=CRYPTO')
    assert '1 из 2 решено' in filtered.text


def test_catalog_filters_include_arbitrary_published_categories(api):
    client, factory = api
    with factory.begin() as db:
        db.add_all([
            Challenge(
                id=2, code='FORENSICS-01', title='FORENSICS-01', description='Task',
                category='FORENSICS', difficulty='medium', points=200,
                flag_hash='unused', is_published=True,
            ),
            Challenge(
                id=3, code='HIDDEN-01', title='HIDDEN-01', description='Task',
                category='HIDDEN', difficulty='medium', points=200,
                flag_hash='unused', is_published=False,
            ),
        ])

    page = client.get('/challenges')
    assert 'href="/challenges?category=FORENSICS"' in page.text
    assert '>FORENSICS</a>' in page.text
    assert 'category=HIDDEN' not in page.text

    filtered = client.get('/challenges?category=FORENSICS')
    assert filtered.status_code == 200
    assert 'FORENSICS-01' in filtered.text and 'WEB-01' not in filtered.text
    assert 'filter-pill active" href="/challenges?category=FORENSICS"' in filtered.text


def test_admin_summary_is_global_across_pages_and_limits(api):
    client, factory = api
    with factory.begin() as db:
        db.add_all([
            Challenge(
                id=2, code='WEB-02', title='Published', description='Task', category='WEB',
                difficulty='medium', points=150, flag_hash='unused', is_published=True,
            ),
            Challenge(
                id=3, code='CRYPTO-01', title='Hidden', description='Task', category='CRYPTO',
                difficulty='medium', points=150, flag_hash='unused', is_published=False,
            ),
        ])
    admin_login(client, factory)

    for path in ['/admin?limit=1', '/admin?offset=1&limit=1', '/admin?offset=2&limit=2']:
        page = client.get(path)
        assert page.status_code == 200
        assert '<strong>3</strong><span>всего заданий</span>' in page.text
        assert '<strong>2</strong><span>опубликовано</span>' in page.text
        assert '<strong>1</strong><span>скрыто</span>' in page.text


def test_participant_form_retries_transient_flag_capacity(api, monkeypatch):
    client, _ = api
    original = service.submit_flag
    calls = 0

    def temporarily_busy(*args):
        nonlocal calls
        calls += 1
        if calls <= 2:
            raise CtfError(503, 'Flag verification busy; retry later', retry_after=1)
        return original(*args)

    monkeypatch.setattr(service, 'submit_flag', temporarily_busy)
    monkeypatch.setattr(pages, 'sleep', lambda _: None)
    csrf = token(client.get('/challenges/1'))
    response = client.post('/challenges/1', data={'flag': FLAG, 'csrf_token': csrf})
    assert response.status_code == 303
    assert calls == 3
    assert 'Баллы начислены' in client.get(response.headers['location']).text


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

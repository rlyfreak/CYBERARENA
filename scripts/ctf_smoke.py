"""End-to-end smoke checks. Deliberately restricted to the isolated test port."""

import argparse
import hashlib
import http.cookiejar
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from time import monotonic, sleep

BASE = 'http://127.0.0.1:18080'
FALLBACK_MESSAGE = 'Учебная лаборатория сейчас недоступна'
UPSTREAM_ERRORS = (502, 503, 504)
OUTAGE_WAIT_SECONDS = 20


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def request(self, path, method='GET', data=None, form=None, csrf=None,
                timeout=15, headers=None, parse_json=True):
        headers = dict(headers or {})
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers['Content-Type'] = 'application/json'
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if csrf:
            headers['X-CSRF-Token'] = csrf
        request = urllib.request.Request(BASE + path, data=body, method=method, headers=headers)
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            text = response.read().decode('utf-8', errors='replace')
            content = json.loads(text) if parse_json and 'application/json' in response.headers.get('Content-Type', '') else text
            return response.status, content, response.headers

    def csrf(self, path='/api/csrf'):
        status, data, _ = self.request(path)
        assert status == 200
        if isinstance(data, dict):
            return data['csrf_token']
        return re.search(r'name="csrf_token"\s+value="([^"]+)"', data).group(1)

    def login(self, username, password):
        return self.request('/login', 'POST', form={
            'username': username, 'password': password, 'csrf_token': self.csrf('/login'),
        })


def outage_diagnostics(observations):
    """Print HTTP evidence and test-only proxy logs; never inspect the working stack."""
    print('CTF outage verification failed. HTTP observations:', file=sys.stderr, flush=True)
    print(json.dumps(observations, ensure_ascii=False, indent=2), file=sys.stderr, flush=True)
    # Direct logs do not require Compose interpolation or any test secrets.
    commands = [['docker', 'ps', '--all', '--filter',
                 'label=com.docker.compose.project=cyberarena-ctf-check']]
    commands += [['docker', 'logs', '--timestamps', '--tail', '100',
                  f'cyberarena-ctf-check-{service}-1'] for service in ['nginx', 'lab-gateway']]
    for command in commands:
        print('Diagnostic: ' + ' '.join(command), file=sys.stderr, flush=True)
        try:
            result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
                                    errors='replace', timeout=5, check=False)
            print(result.stdout, file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            if result.returncode:
                print(f'Diagnostic command exited {result.returncode}', file=sys.stderr)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f'Diagnostic unavailable: {error}', file=sys.stderr)


def probe(browser, path, timeout, headers=None):
    try:
        status, body, response_headers = browser.request(
            path, timeout=timeout, headers=headers, parse_json=False,
        )
        return {'path': path, 'status': status, 'body': body,
                'content_type': response_headers.get('Content-Type')}
    except (OSError, urllib.error.URLError) as error:
        return {'path': path, 'status': None, 'body': None, 'error': str(error)}


def verify_lab_outage(browser, wait_seconds=OUTAGE_WAIT_SECONDS):
    deadline = monotonic() + wait_seconds
    observations = []
    while True:
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        attempt = {}
        for path in ['/lab/', '/api/health', '/api/leaderboard']:
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            attempt[path] = probe(browser, path, min(5, remaining))
        observations.append(attempt)
        lab = attempt.get('/lab/', {})
        app_available = all(attempt.get(path, {}).get('status') == 200
                            for path in ['/api/health', '/api/leaderboard'])
        if not app_available:
            # Do not heal over an outage of the main application or leaderboard.
            break
        if lab.get('status') in UPSTREAM_ERRORS and FALLBACK_MESSAGE in (lab.get('body') or ''):
            print(json.dumps({'phase': 'lab-down', 'status': lab['status'], 'fallback': True,
                              'app_available': True, 'attempts': len(observations)}))
            return
        remaining = deadline - monotonic()
        if remaining > 0:
            sleep(min(0.5, remaining))
    outage_diagnostics(observations)
    raise AssertionError(
        f'Lab fallback not verified within {wait_seconds}s: expected HTTP 502/503/504 '
        'with the fallback page and HTTP 200 from app and leaderboard; see diagnostics above'
    )


def verify_upstream_errors(browser):
    observations = []
    for expected in UPSTREAM_ERRORS:
        result = probe(browser, f'/lab/{expected}', 5, {'Host': 'ctf-fallback-probe'})
        observations.append(result)
        if result['status'] != expected or FALLBACK_MESSAGE not in (result['body'] or ''):
            outage_diagnostics(observations)
            raise AssertionError(f'Upstream {expected} did not preserve its status and fallback page')
    print(json.dumps({'phase': 'upstream-errors', 'statuses': list(UPSTREAM_ERRORS), 'fallback': True}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['prepare', 'verify', 'lab-down', 'upstream-errors'])
    args = parser.parse_args()
    if args.phase == 'lab-down':
        verify_lab_outage(Browser())
        return
    if args.phase == 'upstream-errors':
        verify_upstream_errors(Browser())
        return
    password = os.environ['CTF_CHECK_ADMIN_PASSWORD']
    flag = 'CTF{' + hashlib.sha256((password + 'WEB-01').encode()).hexdigest() + '}'
    admin = Browser()
    if args.phase == 'prepare':
        status, _, headers = admin.login('ctfcheckadmin', password)
        if status != 303:
            status, _, headers = admin.login('ctfcheckadmin', password + 'Changed')
        assert status == 303
        if headers['Location'] == '/change-password':
            status, _, _ = admin.request('/change-password', 'POST', form={
                'current_password': password, 'new_password': password + 'Changed',
                'password_confirm': password + 'Changed', 'csrf_token': admin.csrf('/change-password'),
            })
            assert status == 303
        token = admin.csrf()
        existing = {task['code']: task for task in admin.request('/api/admin/challenges')[1]}
        for code, points in [('WEB-01', 100), ('WEB-02', 150), ('CRYPTO-01', 150)]:
            fields = {'title': code, 'description': 'Isolated smoke task', 'category': code.split('-')[0],
                      'points': points, 'flag': flag, 'is_published': True}
            if code in existing:
                fields['expected_revision'] = existing[code]['revision']
                status = admin.request(f"/api/admin/challenges/{existing[code]['id']}", 'PATCH',
                                       data=fields, csrf=token)[0]
                assert status == 200
            else:
                fields['code'] = code
                assert admin.request('/api/admin/challenges', 'POST', data=fields, csrf=token)[0] == 201
        generation = admin.request('/api/admin/results')[1]['generation']
        assert admin.request('/api/admin/results/reset', 'POST', csrf=token, data={
            'confirmation': 'RESET DEMO RESULTS', 'expected_generation': generation,
        })[0] == 200

    player = Browser()
    if args.phase == 'prepare':
        status, _, _ = player.request('/register', 'POST', form={
            'username': 'ctfcheckplayer', 'password': password, 'password_confirm': password,
            'csrf_token': player.csrf('/register'),
        })
        assert status in (200, 409)
    assert player.login('ctfcheckplayer', password)[0] == 303
    csrf = player.csrf()
    tasks = player.request('/api/challenges')[1]
    assert {task['code']: task['points'] for task in tasks} == {'WEB-01': 100, 'WEB-02': 150, 'CRYPTO-01': 150}
    task_id = next(task['id'] for task in tasks if task['code'] == 'WEB-01')
    path = f'/api/challenges/{task_id}/submissions'
    if args.phase == 'prepare':
        assert player.request(path, 'POST', data={'flag': 'wrong'}, csrf=csrf)[0] == 422
        assert player.request(path, 'POST', data={'flag': 'CTF{wrong}'}, csrf=csrf)[1]['result'] == 'incorrect'

        def send(_):
            # Each thread owns its cookie jar; reuse only this test participant's cookies.
            browser = Browser()
            for cookie in player.jar:
                browser.jar.set_cookie(cookie)
            for _ in range(15):
                status, data, _ = browser.request(path, 'POST', data={'flag': flag}, csrf=csrf)
                if status == 503:
                    sleep(1)
                    continue
                assert status in (200, 409)
                return data['result']
            raise AssertionError('Concurrent retry budget exhausted')

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(send, range(8)))
        assert results.count('correct') == 1 and results.count('already_solved') == 7
    else:
        assert player.request(path, 'POST', data={'flag': flag}, csrf=csrf)[0] == 409
    leaderboard = player.request('/api/leaderboard')[1]
    assert next(row for row in leaderboard if row['username'] == 'ctfcheckplayer')['points'] == 100
    assert len(player.request('/api/submissions')[1]) >= 10
    for page in ['/', '/challenges', f'/challenges/{task_id}', '/submissions', '/leaderboard', '/lab/', '/lab/status']:
        assert player.request(page)[0] == 200, page
    print(json.dumps({'phase': args.phase, 'status': 'passed', 'points': 100,
                      'case_points': [100, 150, 150], 'concurrent_correct': 1 if args.phase == 'prepare' else None}))


if __name__ == '__main__':
    main()

import importlib.util
import re
import subprocess
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ctf_smoke', ROOT / 'scripts' / 'ctf_smoke.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


@pytest.fixture
def clock(monkeypatch):
    state = SimpleNamespace(now=0)
    monkeypatch.setattr(smoke, 'monotonic', lambda: state.now)

    def sleep(seconds):
        state.now += seconds
    monkeypatch.setattr(smoke, 'sleep', sleep)
    return state


class Browser:
    def __init__(self, lab, health=200, leaders=200):
        self.lab = iter(lab)
        self.last = None
        self.health = health
        self.leaders = leaders
        self.paths = []

    def request(self, path, **kwargs):
        self.paths.append(path)
        assert kwargs['parse_json'] is False
        assert 0 < kwargs['timeout'] <= 5
        if path == '/api/health':
            result = self.health, 'health response'
        elif path == '/api/leaderboard':
            result = self.leaders, 'leaderboard response'
        else:
            self.last = next(self.lab, self.last)
            if isinstance(self.last, Exception):
                raise self.last
            result = self.last
        return *result, {'Content-Type': 'text/html'}


@pytest.mark.parametrize('status', [502, 503, 504])
def test_outage_accepts_each_preserved_status_with_fallback(clock, capsys, status):
    browser = Browser([(status, smoke.FALLBACK_MESSAGE)])
    smoke.verify_lab_outage(browser, wait_seconds=1)
    assert browser.paths == ['/lab/', '/api/health', '/api/leaderboard']
    assert f'"status": {status}' in capsys.readouterr().out


@pytest.mark.parametrize('initial', [(200, 'still serving'), urllib.error.URLError('reconnecting')])
def test_outage_waits_for_transition_within_deadline(clock, capsys, initial):
    browser = Browser([initial, (504, smoke.FALLBACK_MESSAGE)])
    smoke.verify_lab_outage(browser, wait_seconds=1)
    assert clock.now == 0.5
    assert '"attempts": 2' in capsys.readouterr().out


@pytest.mark.parametrize('status,body', [(502, 'generic bad gateway'), (503, 'missing page'),
                                      (504, 'wrong page'), (200, 'wrong 200'), (404, 'missing')])
def test_permanent_failure_has_http_body_and_proxy_logs(clock, monkeypatch, capsys, status, body):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        assert kwargs['timeout'] == 5
        return SimpleNamespace(returncode=0, stdout='lab-gateway: upstream timed out', stderr='nginx log')
    monkeypatch.setattr(smoke.subprocess, 'run', run)
    browser = Browser([(status, body)])
    with pytest.raises(AssertionError, match='within 1s'):
        smoke.verify_lab_outage(browser, wait_seconds=1)
    assert clock.now == 1
    stderr = capsys.readouterr().err
    assert f'"status": {status}' in stderr and body in stderr
    assert 'upstream timed out' in stderr and 'nginx log' in stderr
    assert len(commands) == 3
    assert all(any('cyberarena-ctf-check' in part for part in command) for command in commands)
    assert commands[-2][-1] == 'cyberarena-ctf-check-nginx-1'
    assert commands[-1][-1] == 'cyberarena-ctf-check-lab-gateway-1'


@pytest.mark.parametrize('health,leaders', [(500, 200), (200, 503)])
def test_main_application_failure_is_not_retried(clock, monkeypatch, health, leaders):
    monkeypatch.setattr(smoke, 'outage_diagnostics', lambda _: None)
    browser = Browser([(502, smoke.FALLBACK_MESSAGE)], health=health, leaders=leaders)
    with pytest.raises(AssertionError):
        smoke.verify_lab_outage(browser, wait_seconds=10)
    assert clock.now == 0 and len(browser.paths) == 3


def test_diagnostic_failure_does_not_mask_assertion(clock, monkeypatch, capsys):
    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs['timeout'])
    monkeypatch.setattr(smoke.subprocess, 'run', timeout)
    with pytest.raises(AssertionError, match='Lab fallback not verified'):
        smoke.verify_lab_outage(Browser([(500, 'actual body')]), wait_seconds=0.5)
    assert 'Diagnostic unavailable' in capsys.readouterr().err


def test_transport_timeouts_stay_inside_deadline(clock, monkeypatch):
    monkeypatch.setattr(smoke, 'outage_diagnostics', lambda _: None)

    class SlowBrowser:
        def request(self, path, **kwargs):
            clock.now += kwargs['timeout']
            raise TimeoutError('request timed out')
    with pytest.raises(AssertionError):
        smoke.verify_lab_outage(SlowBrowser(), wait_seconds=7)
    assert clock.now == 7


def test_ci_session_secret_satisfies_application_minimum():
    workflow = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
    secrets = re.findall(r'^\s+SESSION_SECRET:\s*(\S+)\s*$', workflow, re.MULTILINE)
    assert secrets and all(len(value) >= 32 for value in secrets)

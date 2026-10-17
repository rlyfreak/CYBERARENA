"""Run only in an isolated container: 32 clients, 16 concurrent requests, 512 MiB/1 CPU."""

import json
import os
import platform
import secrets
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ.setdefault('SESSION_SECRET', 'cyberarena-isolated-test-secret-2026')

from app.auth import dependencies
from app.ctf import security, service
from app.main import app
from app.migrations.ctf_core import migrate
from app.models import Challenge, User
from fastapi.testclient import TestClient
from test_ctf_api import authenticate
from test_ctf_service import factory_for


def main():
    with tempfile.TemporaryDirectory() as directory:
        engine, factory = factory_for((Path(directory) / 'load.db').as_posix())
        migrate(engine)
        service.SessionLocal = dependencies.SessionLocal = factory
        flag = 'CTF{' + secrets.token_urlsafe(24) + '}'
        with factory.begin() as db:
            db.add_all([User(id=i, username=f'load_{i}', password_hash='unused') for i in range(1, 33)])
            db.add(Challenge(id=1, code='WEB-01', title='Load only', description='Isolated', category='WEB',
                             points=100, flag_hash=security.hash_flag(flag), is_published=True))
        active, maximum = 0, 0
        guard = threading.Lock()
        original = security.verify_flag

        def measured(*args):
            nonlocal active, maximum
            with guard:
                active += 1
                maximum = max(maximum, active)
            try:
                return original(*args)
            finally:
                with guard:
                    active -= 1
        security.verify_flag = measured

        def client_request(user_id):
            retries = 0
            started = time.monotonic()
            # Avoid context manager: all requests must use the temporary database.
            client = TestClient(app)
            try:
                authenticate(client, factory, user_id)
                token = client.get('/api/csrf').json()['csrf_token']
                for _ in range(150):
                    response = client.post('/api/challenges/1/submissions', json={'flag': 'CTF{wrong}'},
                                           headers={'X-CSRF-Token': token})
                    if response.status_code == 503:
                        assert response.headers['Retry-After'] == '1'
                        retries += 1
                        time.sleep(0.08 + (user_id % 5) * 0.02)
                        continue
                    assert response.status_code == 200, response.text
                    assert response.json()['result'] == 'incorrect'
                    return retries, time.monotonic() - started
                raise AssertionError('Retry budget exhausted')
            finally:
                client.close()

        started = time.monotonic()
        try:
            with ThreadPoolExecutor(max_workers=16) as executor:
                results = list(executor.map(client_request, range(1, 33)))
        finally:
            security.verify_flag = original
            engine.dispose()
        elapsed = time.monotonic() - started
        peak = int(Path('/sys/fs/cgroup/memory.peak').read_text())
        events = Path('/sys/fs/cgroup/memory.events').read_text()
        assert maximum <= 2
        assert 'oom_kill 0' in events
        print(json.dumps({
            'python': platform.python_version(), 'clients': len(results), 'concurrency': 16,
            'completed': len(results), 'busy_retries': sum(r[0] for r in results),
            'max_concurrent_argon2': maximum, 'seconds': round(elapsed, 3),
            'max_client_seconds': round(max(r[1] for r in results), 3),
            'memory_peak_mib': round(peak / 1024**2, 2), 'oom_kills': 0,
        }))


if __name__ == '__main__':
    main()

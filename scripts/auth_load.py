#!/usr/bin/env python3
"""Bounded HTTP auth load against an isolated Compose project only.

Example (PowerShell):
  python scripts/auth_load.py --project cyberarena-auth-oom --scenario unknown --clients 32
"""

import argparse
import http.cookiejar
import json
import re
import secrets
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=10).strip()


def get_url(opener, url):
    try:
        response = opener.open(url, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read().decode("utf-8", errors="replace")


def post_form(opener, url, fields):
    started = time.monotonic()
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode("utf-8"),
        method="POST",
    )
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        response.read()
        return response.status, time.monotonic() - started


def browser():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        NoRedirect(),
    )


def csrf(opener, url):
    status, body = get_url(opener, url)
    if status != 200:
        raise RuntimeError(f"Form unavailable: HTTP {status}")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', body)
    if match is None:
        raise RuntimeError("CSRF token missing")
    return match.group(1)


def cgroup(container, path):
    return docker("exec", container, "cat", f"/sys/fs/cgroup/{path}")


def cpu_usec(container):
    return int(re.search(r"^usage_usec (\d+)$", cgroup(container, "cpu.stat"), re.MULTILINE).group(1))


def inspect_state(container):
    return json.loads(docker("inspect", "--format", "{{json .State}}", container))


def prepare_client(base, scenario, number, username, password, run_id):
    opener = browser()
    path = "/register" if scenario == "register" else "/login"
    token = csrf(opener, base + path)
    if scenario == "register":
        form = {
            "username": f"load{run_id}{number:03d}",
            "password": password,
            "password_confirm": password,
            "csrf_token": token,
        }
    else:
        name = f"missing{run_id}{number:03d}" if scenario == "unknown" else username
        form = {
            "username": name,
            "password": password if scenario == "correct" else "IncorrectLoadPassword2026!",
            "csrf_token": token,
        }
    return opener, base + path, form


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--scenario", choices=("unknown", "wrong", "correct", "register"), required=True)
    parser.add_argument("--clients", type=int, choices=(1, 5, 10, 16, 32), required=True)
    args = parser.parse_args()
    parsed = urllib.parse.urlparse(args.base_url)
    if (args.project != "cyberarena-auth-oom"
            or parsed.scheme != "http" or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment or parsed.username or parsed.password
            or parsed.hostname not in {"localhost", "127.0.0.1"}
            or parsed.port != 18080):
        parser.error("Load test requires the dedicated local cyberarena-auth-oom project")

    container = f"{args.project}-app-1"
    label = docker("inspect", "--format", "{{index .Config.Labels \"com.docker.compose.project\"}}", container)
    if label != args.project:
        raise RuntimeError("Target container is not the dedicated test project")
    state_before = inspect_state(container)
    restarts_before = int(docker("inspect", "--format", "{{.RestartCount}}", container))
    if not state_before["Running"]:
        raise RuntimeError("Test app is not running")

    base = args.base_url.rstrip("/")
    run_id = secrets.token_hex(3)
    username = f"loaduser{run_id}"
    recovery_username = f"recovery{run_id}"
    password = secrets.token_urlsafe(20)

    def create_account(name):
        opener = browser()
        status, _ = post_form(opener, base + "/register", {
            "username": name,
            "password": password,
            "password_confirm": password,
            "csrf_token": csrf(opener, base + "/register"),
        })
        if status != 200:
            raise RuntimeError(f"Test account creation failed: HTTP {status}")

    create_account(recovery_username)
    if args.scenario in ("wrong", "correct"):
        create_account(username)

    clients = [prepare_client(base, args.scenario, i, username, password, run_id)
               for i in range(args.clients)]
    start_event = threading.Event()
    stop_samples = threading.Event()
    samples = []

    def sample_memory():
        while not stop_samples.is_set():
            try:
                samples.append(int(cgroup(container, "memory.current")))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
                pass
            stop_samples.wait(0.2)

    def work(client):
        start_event.wait()
        try:
            return post_form(*client)
        except (OSError, TimeoutError):
            return "timeout", 15.0

    cpu_started = time.monotonic()
    before_cpu = cpu_usec(container)
    idle_memory = int(cgroup(container, "memory.current"))
    started = time.monotonic()
    sampler = threading.Thread(target=sample_memory, daemon=True)
    sampler.start()
    with ThreadPoolExecutor(max_workers=args.clients) as pool:
        futures = [pool.submit(work, client) for client in clients]
        start_event.set()
        results = [future.result(timeout=25) for future in futures]
    elapsed = time.monotonic() - started
    stop_samples.set()
    sampler.join(timeout=3)
    cpu_after_burst = cpu_usec(container)
    cpu_elapsed = time.monotonic() - cpu_started

    # A fresh browser demonstrates that admission recovers after a burst.
    recovery = None
    for _ in range(10):
        opener = browser()
        token = csrf(opener, base + "/login")
        recovery, _ = post_form(opener, base + "/login", {
            "username": recovery_username,
            "password": password,
            "csrf_token": token,
        })
        if recovery == 303:
            break
        time.sleep(0.5)

    health, _ = get_url(browser(), base + "/api/health")
    ctf_status, _ = get_url(browser(), base + "/api/challenges")
    state_after = inspect_state(container)
    restarts_after = int(docker("inspect", "--format", "{{.RestartCount}}", container))
    events = cgroup(container, "memory.events")
    oom_kill = int(re.search(r"^oom_kill (\d+)$", events, re.MULTILINE).group(1))
    durations = sorted(duration for _, duration in results)
    counts = {str(status): sum(s == status for s, _ in results) for status, _ in results}
    report = {
        "scenario": args.scenario, "clients": args.clients, "statuses": counts,
        "idle_mib": round(idle_memory / 1048576, 2),
        "mean_sample_mib": round(statistics.mean(samples) / 1048576, 2) if samples else None,
        "peak_mib": round(int(cgroup(container, "memory.peak")) / 1048576, 2),
        "cpu_percent_of_one_core": round((cpu_after_burst - before_cpu) / (cpu_elapsed * 10000), 1),
        "p50_ms": round(statistics.median(durations) * 1000),
        "p95_ms": round(durations[max(0, (len(durations) * 95 + 99) // 100 - 1)] * 1000),
        "elapsed_seconds": round(elapsed, 2), "recovery_status": recovery,
        "health_status": health, "ctf_status": ctf_status,
        "oom_kill_events": oom_kill, "oom_killed": state_after["OOMKilled"],
        "restart_count": restarts_after, "new_restarts": restarts_after - restarts_before,
        "container_running": state_after["Running"],
    }
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    expected = {"unknown": "401", "wrong": "401", "correct": "303", "register": "200"}
    if (not state_after["Running"] or state_after["OOMKilled"] or oom_kill
            or restarts_after != restarts_before or counts.get("timeout", 0)
            or any(str(status).startswith("5") and status != 503 for status, _ in results)
            or counts.get(expected[args.scenario], 0) == 0
            or health != 200 or ctf_status != 401 or recovery != 303):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

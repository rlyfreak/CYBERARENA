"""CRYPTO-01 material and the existing CTF Core publication flow."""

import re
import runpy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import func, select

from app.ctf import security, service
from app.models import Challenge, Solve
from test_ctf_api import admin_login, authenticate

ROOT = Path(__file__).resolve().parents[2]
MATERIAL = ROOT / "files" / "crypto-01" / "challenge.txt"
GENERATOR = runpy.run_path(str(ROOT / "scripts" / "generate_crypto_01.py"))
build_challenge = GENERATOR["build_challenge"]
MARKER = GENERATOR["RESOURCE_MARKER"]
KNOWN = b"CYBERARENA INCIDENT REPORT\n"
RESOURCE_URL = "/files/crypto-01/challenge.txt"


def assert_no_flag_leak(flag: str, response_text: str) -> None:
    if flag in response_text:
        raise AssertionError("CTF response disclosed the challenge flag")


def solve(material: str) -> tuple[str, str]:
    """Use only the information given to a player, independently of the builder."""
    assert material.startswith(MARKER + "\n")
    ciphertext = bytes.fromhex(material.split("Ciphertext (hex):\n", 1)[1])
    key = bytes(ciphertext[i] ^ KNOWN[i] for i in range(7))
    plaintext = bytes(value ^ key[i % 7] for i, value in enumerate(ciphertext))
    assert plaintext.startswith(KNOWN)
    message = plaintext.decode("utf-8")
    assert "Ticket: CRYPTO-01\n" in message
    assert message.endswith("\nEnd of report.\n")
    flag = message.split("Access token: ", 1)[1].split("\n", 1)[0]
    if not security.valid_flag(flag):
        raise AssertionError("Recovered CRYPTO-01 flag has invalid format")
    return flag, key.decode("ascii")


def test_generator_round_trip_is_deterministic_and_validates_input():
    sample_flag = "CTF{sample_repeating_mask}"
    material = build_challenge(sample_flag, "LANTERN")
    assert build_challenge(sample_flag, "LANTERN") == material
    assert solve(material) == (sample_flag, "LANTERN")
    assert sample_flag not in material
    for flag, key in [
        ("CTF{}", "LANTERN"),
        ("CTF{nested{brace}", "LANTERN"),
        ("CTF{тест}", "LANTERN"),
        (sample_flag, "SHORT"),
        (sample_flag, "КЛЮЧ123"),
    ]:
        with pytest.raises(ValueError):
            build_challenge(flag, key)


def test_generator_cli_hides_inputs_and_requires_explicit_replace(tmp_path, monkeypatch, capsys):
    flag = "CTF{private_sample_for_cli}"
    key = "LANTERN"
    answers = iter((flag, key, flag, key))
    monkeypatch.setattr("getpass.getpass", lambda _: next(answers))
    output = tmp_path / "challenge.txt"
    GENERATOR["main"](["--output", str(output)])
    original = output.read_text(encoding="utf-8")
    assert original == build_challenge(flag, key)
    with pytest.raises(SystemExit):
        GENERATOR["main"](["--output", str(output)])
    assert output.read_text(encoding="utf-8") == original
    captured = capsys.readouterr()
    assert flag not in captured.out + captured.err
    assert key not in captured.out + captured.err


def test_committed_material_is_solvable_without_published_secret():
    material = MATERIAL.read_text(encoding="utf-8")
    flag, key = solve(material)
    assert "CTF{" not in material
    if re.fullmatch(r"CTF\{relay_mask_[0-9a-f]{24}\}", flag) is None:
        raise AssertionError("CRYPTO-01 flag has the wrong challenge-specific format")
    if build_challenge(flag, key) != material:
        raise AssertionError("Committed material differs from deterministic regeneration")
    assert MATERIAL.read_bytes().decode("utf-8") == material


def publish_draft(client, factory, flag):
    admin_login(client, factory)
    service.seed_case()
    draft = next(task for task in client.get("/api/admin/challenges").json()
                 if task["code"] == "CRYPTO-01")
    assert not draft["is_published"] and "flag_hash" not in draft
    response = client.patch(
        f"/api/admin/challenges/{draft['id']}",
        json={
            "expected_revision": draft["revision"],
            "title": "Повторяющаяся маска",
            "description": "Скачайте challenge.txt, восстановите ключ XOR и найдите Access token.",
            "category": "Crypto",
            "difficulty": "easy",
            "resource_url": RESOURCE_URL,
            "points": 150,
            "flag": flag,
            "is_published": True,
        },
    )
    assert response.status_code == 200
    assert_no_flag_leak(flag, response.text)
    assert "flag_hash" not in response.text
    service.seed_case()
    with factory() as db:
        task = db.get(Challenge, draft["id"])
        if task is None or not security.verify_flag(flag, task.flag_hash):
            raise AssertionError("Published flag hash does not match the ciphertext")
    return draft["id"]


def test_crypto01_catalog_card_submission_and_isolated_scores(api):
    client, factory = api
    flag, _ = solve(MATERIAL.read_text(encoding="utf-8"))
    task_id = publish_draft(client, factory, flag)
    authenticate(client, factory, 1)
    client.headers["X-CSRF-Token"] = client.get("/api/csrf").json()["csrf_token"]
    catalog = client.get("/api/challenges").json()
    task = next(item for item in catalog if item["code"] == "CRYPTO-01")
    assert task["id"] == task_id
    assert task["category"] == "Crypto" and task["difficulty"] == "easy"
    assert task["points"] == 150 and task["resource_url"] == RESOURCE_URL
    assert_no_flag_leak(flag, str(catalog))
    assert "flag_hash" not in str(catalog)
    assert "CRYPTO-01" in client.get("/challenges").text
    card = client.get(f"/challenges/{task_id}")
    assert card.status_code == 200 and f'href="{RESOURCE_URL}"' in card.text
    assert "Повторяющаяся маска" in card.text
    assert_no_flag_leak(flag, card.text)

    path = f"/api/challenges/{task_id}/submissions"
    rejected_csrf = client.post(path, json={"flag": flag}, headers={"X-CSRF-Token": "wrong"})
    assert rejected_csrf.status_code == 403
    for wrong in ("CTF{wrong}", "CTF{isolated_test_flag}"):
        response = client.post(path, json={"flag": wrong})
        assert response.status_code == 200 and response.json()["result"] == "incorrect"
        assert response.json()["points_awarded"] == 0
    correct = client.post(path, json={"flag": flag})
    assert correct.status_code == 200 and correct.json()["points_awarded"] == 150
    assert_no_flag_leak(flag, correct.text)
    duplicate = client.post(path, json={"flag": flag})
    assert duplicate.status_code == 409 and duplicate.json()["points_awarded"] == 0
    assert client.get(f"/api/challenges/{task_id}").json()["solved"] is True

    client.cookies.clear()
    guest_attempt = client.post(path, json={"flag": flag})
    assert guest_attempt.status_code == 403
    authenticate(client, factory, 2)
    client.headers["X-CSRF-Token"] = client.get("/api/csrf").json()["csrf_token"]
    assert client.get(f"/api/challenges/{task_id}").json()["solved"] is False
    second = client.post(path, json={"flag": flag})
    assert second.status_code == 200 and second.json()["points_awarded"] == 150
    with factory() as db:
        solves = db.scalars(select(Solve).where(Solve.challenge_id == task_id)).all()
        assert len(solves) == 2
        assert {item.user_id for item in solves} == {1, 2}
        assert {item.points_awarded for item in solves} == {150}


def test_crypto01_concurrent_correct_submissions_award_once(api):
    client, factory = api
    flag, _ = solve(MATERIAL.read_text(encoding="utf-8"))
    task_id = publish_draft(client, factory, flag)
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: service.submit_flag(1, task_id, flag), range(2)))
    assert sorted(item.result for item in outcomes) == ["already_solved", "correct"]
    assert sum(item.points_awarded for item in outcomes) == 150
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Solve).where(
            Solve.challenge_id == task_id, Solve.user_id == 1,
        )) == 1

"""Publish and solve the real CRYPTO-01 in the isolated CTF test stack only.

Run after ctf_smoke.py prepare/verify, then prepare here, restart app, verify here.
The recovered answer stays in memory and is never printed.
"""

import argparse
import os
from pathlib import Path

from check_crypto_01_resource import verify
from ctf_smoke import BASE, Browser

MATERIAL = Path(__file__).resolve().parents[1] / "files/crypto-01/challenge.txt"
RESOURCE = "/files/crypto-01/challenge.txt"
PLAYER = "crypto01checkplayer"


def recover_flag() -> str:
    ciphertext = bytes.fromhex(MATERIAL.read_text(encoding="utf-8").split(
        "Ciphertext (hex):\n", 1,
    )[1])
    known = b"CYBERARENA INCIDENT REPORT\n"
    key = bytes(ciphertext[i] ^ known[i] for i in range(7))
    plaintext = bytes(value ^ key[i % 7] for i, value in enumerate(ciphertext))
    if not plaintext.startswith(known):
        raise RuntimeError("Real CRYPTO-01 cannot be recovered from its known prefix")
    return plaintext.decode().split("Access token: ", 1)[1].split("\n", 1)[0]


def no_leak(flag, body):
    if flag in str(body) or "flag_hash" in str(body):
        raise RuntimeError("CRYPTO-01 response discloses an answer or hash")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "verify"))
    phase = parser.parse_args().phase
    password = os.environ["CTF_CHECK_ADMIN_PASSWORD"]
    verify(BASE, MATERIAL)
    flag = recover_flag()
    if phase == "prepare":
        admin = Browser()
        assert admin.login("ctfcheckadmin", password + "Changed")[0] == 303
        csrf = admin.csrf()
        tasks = admin.request("/api/admin/challenges")[1]
        task = next(item for item in tasks if item["code"] == "CRYPTO-01")
        status, body, _ = admin.request(
            f"/api/admin/challenges/{task['id']}", "PATCH", csrf=csrf,
            data={
                "expected_revision": task["revision"],
                "title": "Повторяющаяся маска",
                "description": "XOR: ключ 7 байт; префикс CYBERARENA INCIDENT REPORT и перевод строки.",
                "category": "Crypto", "difficulty": "easy", "points": 150,
                "resource_url": RESOURCE, "flag": flag, "is_published": True,
            },
        )
        assert status == 200
        no_leak(flag, body)

    player = Browser()
    if phase == "prepare":
        status, _, _ = player.request("/register", "POST", form={
            "username": PLAYER, "password": password, "password_confirm": password,
            "csrf_token": player.csrf("/register"),
        })
        assert status == 200
    assert player.login(PLAYER, password)[0] == 303
    csrf = player.csrf()
    status, tasks, _ = player.request("/api/challenges")
    assert status == 200
    no_leak(flag, tasks)
    task = next(item for item in tasks if item["code"] == "CRYPTO-01")
    assert task["resource_url"] == RESOURCE and task["difficulty"] == "easy"
    assert task["points"] == 150
    status, card, _ = player.request(f"/challenges/{task['id']}")
    assert status == 200 and f'href="{RESOURCE}"' in card
    no_leak(flag, card)
    path = f"/api/challenges/{task['id']}/submissions"
    if phase == "prepare":
        status, wrong, _ = player.request(path, "POST", csrf=csrf, data={"flag": "CTF{wrong}"})
        assert status == 200 and wrong["result"] == "incorrect" and wrong["points_awarded"] == 0
        status, correct, _ = player.request(path, "POST", csrf=csrf, data={"flag": flag})
        assert status == 200 and correct["result"] == "correct" and correct["points_awarded"] == 150
        no_leak(flag, correct)
    status, duplicate, _ = player.request(path, "POST", csrf=csrf, data={"flag": flag})
    assert status == 409 and duplicate["points_awarded"] == 0
    no_leak(flag, duplicate)
    rows = player.request("/api/leaderboard")[1]
    assert next(row for row in rows if row["username"] == PLAYER)["points"] == 150
    assert player.request(f"/api/challenges/{task['id']}")[1]["solved"] is True
    print(f"PASS: real CRYPTO-01 {phase}; resource/card/answers/150 points; no duplicate award")


if __name__ == "__main__":
    main()

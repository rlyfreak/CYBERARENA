"""Solve the real WEB-02 in Chromium and verify scoring in the isolated stack.

Run prepare after ctf_smoke.py prepare, restart app, then run verify.
The answer is reconstructed from what the browser displays and never printed.
"""

import argparse
import os
import re

from ctf_smoke import BASE, Browser

RESOURCE = "/files/web-02/"
PLAYER = "web02checkplayer"


def solve_in_browser(challenge_id: int, password: str) -> str:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context()
            page = context.new_page()
            page.set_default_timeout(15000)
            page.goto(BASE + "/login")
            page.locator('input[name="username"]').fill(PLAYER)
            page.locator('input[name="password"]').fill(password)
            page.locator('button[type="submit"]').click()
            page.wait_for_url(BASE + "/profile")
            assert context.request.get(BASE + "/api/challenges").status == 200

            page.goto(BASE + f"/challenges/{challenge_id}")
            link = page.locator(f'a[href="{RESOURCE}"]')
            assert link.count() == 1 and link.get_attribute("download") is None
            page.evaluate("""() => {
                const frame = document.createElement('iframe');
                frame.id = 'web02-isolation-probe';
                frame.src = '/files/web-02/';
                document.body.append(frame);
            }""")
            page.frame_locator("#web02-isolation-probe").get_by_role(
                "heading", name="Архив допуска",
            ).wait_for()
            assert page.evaluate("""() => {
                try { return document.querySelector('iframe').contentWindow.document.title; }
                catch (error) { return error.name; }
            }""") == "SecurityError"
            child = next(frame for frame in page.frames if frame != page.main_frame)
            assert child.evaluate("""() => {
                try { return parent.document.title; }
                catch (error) { return error.name; }
            }""") == "SecurityError"
            with page.expect_popup() as popup:
                link.click()
            challenge = popup.value
            challenge.get_by_role("heading", name="Архив допуска").wait_for()
            assert challenge.url == BASE + RESOURCE
            assert challenge.locator("#archive").is_hidden()
            challenge.locator("#open").click()
            assert "Отказано" in challenge.locator("#status").inner_text()
            assert challenge.locator("#archive").is_hidden()

            # Reproduce the documented indexOf(-1) access bug with DevTools.
            challenge.evaluate("document.querySelector('#badge').value = 'visitor'")
            challenge.locator("#open").click()
            assert challenge.locator("#archive").is_visible()
            assert "SecurityError" == challenge.evaluate("""() => {
                try { return document.cookie; }
                catch (error) { return error.name; }
            }""")
            network = context.new_cdp_session(challenge)
            network.send("Network.enable")
            urls, statuses = {}, {}
            network.on("Network.requestWillBeSent", lambda event: urls.update(
                {event["requestId"]: event["request"]["url"]}))
            network.on("Network.responseReceivedExtraInfo", lambda event: statuses.update(
                {event["requestId"]: event["statusCode"]}))
            with challenge.expect_event("requestfailed", predicate=lambda request:
                                        request.url == BASE + "/api/challenges"):
                assert challenge.evaluate("""async () => {
                    try {
                        await (await fetch('/api/challenges', {credentials: 'include'})).text();
                        return false;
                    } catch { return true; }
                }"""), "WEB-02 can read the platform API"
            api_statuses = [statuses.get(key) for key, url in urls.items()
                            if url == BASE + "/api/challenges"]
            assert api_statuses == [401], f"WEB-02 API request statuses: {api_statuses}"
            network.detach()

            packets = {}
            for line in challenge.locator("#packets li").all_text_contents():
                match = re.fullmatch(r"seq=(\d+) · ((?:[0-9a-f]{2} ?)+)", line)
                assert match, "Malformed WEB-02 packet"
                packets[int(match.group(1))] = bytes.fromhex(match.group(2))
            assert sorted(packets) == [0, 1, 2]
            mask_text = challenge.locator("#archive code").nth(1).inner_text()
            mask = bytes.fromhex(mask_text.split("(hex)", 1)[0])
            encoded = b"".join(packets[i] for i in sorted(packets))
            answer = bytes(byte ^ mask[i % len(mask)] for i, byte in enumerate(encoded))
            flag = answer.decode("ascii")
            assert re.fullmatch(r"CTF\{[ -~]{1,250}\}", flag)
            for path in ("index.html", "script.js", "style.css"):
                response = context.request.get(BASE + RESOURCE + path)
                assert response.status == 200 and flag not in response.text()
            assert context.request.get(BASE + "/files/web-02/WEB-02-writeup.md").status == 404
            assert context.request.get(BASE + "/files/WEB-02-writeup.md").status == 404
            assert context.request.get(BASE + "/api/challenges").status == 200
            return flag
        finally:
            browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "verify"))
    phase = parser.parse_args().phase
    password = os.environ["CTF_CHECK_ADMIN_PASSWORD"]

    admin = Browser()
    assert admin.login("ctfcheckadmin", password + "Changed")[0] == 303
    csrf = admin.csrf()
    tasks = admin.request("/api/admin/challenges")[1]
    task = next(item for item in tasks if item["code"] == "WEB-02")
    if phase == "prepare":
        # First derive the answer from the public browser exercise, then
        # configure its server-side hash through the normal admin API.
        # A temporary account is needed to verify the card after publishing.
        preview = Browser()
        register = preview.request("/register", "POST", form={
            "username": PLAYER, "password": password, "password_confirm": password,
            "csrf_token": preview.csrf("/register"),
        })
        assert register[0] == 200
        flag = solve_material_without_card()
        status, body, _ = admin.request(
            f"/api/admin/challenges/{task['id']}", "PATCH", csrf=csrf,
            data={
                "expected_revision": task["revision"],
                "title": "Архив допуска",
                "description": "Изучите клиентскую проверку роли через DevTools, "
                               "откройте журнал и восстановите токен из XOR-пакетов.",
                "category": "Web", "difficulty": "easy", "points": 150,
                "resource_url": RESOURCE, "flag": flag, "is_published": True,
            },
        )
        assert status == 200 and flag not in str(body) and "flag_hash" not in str(body)

    player = Browser()
    assert player.login(PLAYER, password)[0] == 303
    status, tasks, _ = player.request("/api/challenges")
    assert status == 200
    card = next(item for item in tasks if item["code"] == "WEB-02")
    assert card["resource_url"] == RESOURCE and card["points"] == 150
    flag = solve_in_browser(card["id"], password)
    assert flag not in str(tasks)
    path = f"/api/challenges/{card['id']}/submissions"
    if phase == "prepare":
        status, wrong, _ = player.request(path, "POST", csrf=player.csrf(),
                                          data={"flag": "CTF{wrong}"})
        assert status == 200 and wrong["result"] == "incorrect"
        status, correct, _ = player.request(path, "POST", csrf=player.csrf(), data={"flag": flag})
        assert status == 200 and correct["result"] == "correct" and correct["points_awarded"] == 150
        assert flag not in str(correct)
    status, duplicate, _ = player.request(path, "POST", csrf=player.csrf(), data={"flag": flag})
    assert status == 409 and duplicate["points_awarded"] == 0
    assert next(row for row in player.request("/api/leaderboard")[1]
                if row["username"] == PLAYER)["points"] == 150
    assert player.request(f"/api/challenges/{card['id']}")[1]["solved"] is True
    print(f"PASS: real WEB-02 {phase}; Chromium solve/card/answers/150 points; no duplicate award")


def solve_material_without_card() -> str:
    """Derive setup flag from public packet data without embedding an answer."""
    from pathlib import Path

    material = Path(__file__).resolve().parents[1] / "files/web-02/script.js"
    source = material.read_text(encoding="utf-8")
    packets = {
        int(seq): bytes(int(part.strip()) for part in values.split(",") if part.strip())
        for seq, values in re.findall(r"seq: (\d+), bytes: \[([^]]+)\]", source)
    }
    assert sorted(packets) == [0, 1, 2]
    key = bytes.fromhex("21 32 43 54 65 76 17")
    encoded = b"".join(packets[i] for i in sorted(packets))
    answer = bytes(byte ^ key[i % len(key)] for i, byte in enumerate(encoded))
    flag = answer.decode("ascii")
    assert re.fullmatch(r"CTF\{[ -~]{1,250}\}", flag)
    return flag


if __name__ == "__main__":
    main()

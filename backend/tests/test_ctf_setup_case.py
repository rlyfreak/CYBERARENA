import io
import json

import pytest
from sqlalchemy import select

from app.auth.security import hash_password
from app.ctf import schemas, security, service, setup_case
from app.models import Challenge, User

FLAGS = {
    "WEB-01": "CTF{setup_web_one_flag}",
    "WEB-02": "CTF{setup_web_two_flag}",
    "CRYPTO-01": "CTF{setup_crypto_flag}",
}


@pytest.fixture
def setup_env(ctf_db, monkeypatch):
    factory, _ = ctf_db
    monkeypatch.setattr(setup_case, "SessionLocal", factory)
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    with factory.begin() as db:
        db.execute(Challenge.__table__.delete())
    return factory


def run(flags=FLAGS):
    return setup_case.main(io.StringIO(json.dumps(flags)))


def rows(factory):
    with factory() as db:
        return {row.code: row for row in db.scalars(select(Challenge))}


def snapshot(factory):
    return {code: (card.flag_hash, card.revision, card.is_published) for code, card in rows(factory).items()}


def assert_no_flags(text):
    assert "CTF{" not in text.replace("CTF{...}", "")


def test_configures_and_publishes_all_three_cards(setup_env):
    assert run() == 0
    cards = rows(setup_env)
    assert set(cards) == set(FLAGS)
    for code, card in cards.items():
        assert card.is_published
        assert card.description != setup_case.DRAFT_TEXT
        assert security.verify_flag(FLAGS[code], card.flag_hash)
        assert not security.verify_flag("CTF{wrong}", card.flag_hash)
    assert cards["WEB-01"].resource_url == "/lab/"
    assert cards["WEB-02"].resource_url == "/files/web-02/"
    assert cards["CRYPTO-01"].resource_url == "/files/crypto-01/challenge.txt"
    assert [cards[code].points for code in FLAGS] == [100, 150, 150]


def test_second_run_keeps_data_and_succeeds(setup_env, capsys):
    assert run() == 0
    before = snapshot(setup_env)
    capsys.readouterr()
    assert run() == 0
    assert snapshot(setup_env) == before
    captured = capsys.readouterr()
    assert captured.out.count("уже настроено") == 3
    assert captured.err == ""


def test_flag_mismatch_fails_without_changing_cards(setup_env, capsys):
    assert run() == 0
    before = snapshot(setup_env)
    capsys.readouterr()
    assert run({**FLAGS, "WEB-01": "CTF{flag_from_a_new_env_file}"}) == 1
    assert snapshot(setup_env) == before
    captured = capsys.readouterr()
    assert "WEB-01: флаг в карточке не совпадает" in captured.out
    assert "турнир не готов" in captured.err
    assert "WEB01_FLAG" in captured.err and "Новый флаг" in captured.err
    assert captured.out.count("уже настроено") == 2
    assert_no_flags(captured.out + captured.err)


def test_hidden_edited_card_fails_and_is_not_touched(setup_env, capsys):
    service.seed_case()
    task = next(t for t in service.catalog(1, include_hidden=True) if t["code"] == "WEB-02")
    service.save_challenge(3, {"description": "Свой текст", "expected_revision": task["revision"]}, task["id"])
    assert run() == 1
    cards = rows(setup_env)
    assert cards["WEB-02"].description == "Свой текст"
    assert not cards["WEB-02"].is_published
    assert cards["WEB-01"].is_published and cards["CRYPTO-01"].is_published
    captured = capsys.readouterr()
    assert "WEB-02: изменено вручную" in captured.out
    assert "Опубликовать задание" in captured.err
    assert_no_flags(captured.out + captured.err)


def edit_draft(code, **changes):
    service.seed_case()
    task = next(t for t in service.catalog(1, include_hidden=True) if t["code"] == code)
    payload = schemas.ChallengeUpdate.model_validate({**changes, "expected_revision": task["revision"]})
    service.save_challenge(3, payload.model_dump(exclude_unset=True), task["id"])


@pytest.mark.parametrize("changes", [
    {"title": "Своё название", "resource_url": "/files/web-02/other.html"},
    {"title": "Своё название"},
    {"difficulty": "hard"},
    {"flag": "CTF{flag_set_by_admin}"},
])
def test_draft_edited_without_changing_description_is_not_overwritten(setup_env, capsys, changes):
    edit_draft("WEB-02", **changes)
    before = snapshot(setup_env)["WEB-02"]
    edited = rows(setup_env)["WEB-02"]
    assert edited.description == setup_case.DRAFT_TEXT
    assert run() == 1
    card = rows(setup_env)["WEB-02"]
    assert snapshot(setup_env)["WEB-02"] == before
    assert not card.is_published
    for name, value in changes.items():
        if name != "flag":
            assert getattr(card, name) == value
    assert rows(setup_env)["WEB-01"].is_published and rows(setup_env)["CRYPTO-01"].is_published
    captured = capsys.readouterr()
    assert "WEB-02: изменено вручную" in captured.out
    assert_no_flags(captured.out + captured.err)


def test_untouched_seeded_drafts_are_configured(setup_env):
    service.seed_case()
    assert all(setup_case.is_untouched_draft(t) for t in service.catalog(1, include_hidden=True))
    assert run() == 0


def test_admin_username_is_normalized_like_bootstrap(setup_env, monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "  Admin ")
    assert run() == 0
    assert all(card.is_published for card in rows(setup_env).values())


@pytest.mark.parametrize("payload", ["not json", "[]", json.dumps({"WEB-01": "CTF{x_valid_flag}"}),
                                     json.dumps({**FLAGS, "WEB-02": "plain"})])
def test_bad_input_is_rejected_without_changes(setup_env, payload, capsys):
    assert setup_case.main(io.StringIO(payload)) == 1
    assert rows(setup_env) == {}
    assert_no_flags(capsys.readouterr().err)


def test_missing_admin_is_reported(setup_env, monkeypatch, capsys):
    monkeypatch.setenv("ADMIN_USERNAME", "nobody")
    assert run() == 1
    assert "не найден" in capsys.readouterr().err
    assert rows(setup_env) == {}


ADMIN_PASSWORD = "Initial-admin-pass-2026"


@pytest.fixture
def admin_with_password(setup_env, monkeypatch):
    with setup_env.begin() as db:
        db.get(User, 3).password_hash = hash_password(ADMIN_PASSWORD)
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PASSWORD)
    return setup_env


def test_check_admin_password_accepts_effective_initial_password(admin_with_password, capsys):
    assert setup_case.check_admin_password() == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("effective", ["Changed-in-env-or-dotenv-1", ""])
def test_check_admin_password_rejects_value_that_does_not_open_account(admin_with_password, monkeypatch,
                                                                       capsys, effective):
    monkeypatch.setenv("ADMIN_PASSWORD", effective)
    assert setup_case.check_admin_password() == 2
    captured = capsys.readouterr()
    assert ADMIN_PASSWORD not in captured.out + captured.err


def test_check_admin_password_reports_missing_admin(admin_with_password, monkeypatch, capsys):
    monkeypatch.setenv("ADMIN_USERNAME", "nobody")
    assert setup_case.check_admin_password() == 1
    assert "не найден" in capsys.readouterr().err

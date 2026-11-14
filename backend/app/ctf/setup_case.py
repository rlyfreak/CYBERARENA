"""One-shot bootstrap: fill in and publish the three case cards.

Flags are read from stdin as a JSON object such as {"WEB-01": "CTF{...}", ...}.
They are never accepted as arguments and never printed. Cards that are already
published or edited by an administrator are never overwritten. If such a card
does not match the supplied flags, or an edited card is still hidden, the
command reports what to fix and exits with code 1, so setup never claims success
for a tournament that is not ready. Run it inside the app container:

    docker compose exec -T app python -m app.ctf.setup_case

With --check-admin-password it only reports, by exit code, whether ADMIN_PASSWORD
from the container environment opens the administrator account: 0 yes, 2 no,
1 error. The password is never printed.
"""

import json
import os
import sys

from sqlalchemy import select

from ..auth.security import verify_password
from ..database import SessionLocal
from ..models import Challenge, User
from . import schemas, security, service

DRAFT_TEXT = 'Черновик кейса. Добавьте условие, материалы и флаг перед публикацией.'

CARDS = {
    'WEB-01': {
        'title': 'Закрытый архив',
        'difficulty': 'easy',
        'resource_url': '/lab/',
        'description': (
            'Вы получили доступ к внутреннему архиву организации. В списке отображаются два '
            'общедоступных документа, но один служебный документ скрыт от обычных пользователей. '
            'Исследуйте механизм просмотра документов, найдите ошибку разграничения доступа и '
            'получите флаг формата CTF{...}.'
        ),
    },
    'WEB-02': {
        'title': 'Архив допуска',
        'difficulty': 'easy',
        'resource_url': '/files/web-02/',
        'description': (
            'Изучите клиентскую проверку роли через DevTools, откройте журнал и восстановите '
            'токен из XOR-пакетов.'
        ),
    },
    'CRYPTO-01': {
        'title': 'Повторяющаяся маска',
        'difficulty': 'easy',
        'resource_url': '/files/crypto-01/challenge.txt',
        'description': (
            'Перехвачена служебная записка CYBERARENA. Скачайте challenge.txt: её байты '
            'зашифрованы XOR с повторяющимся семибайтным ключом и записаны шестнадцатерично. '
            'Исходное сообщение начинается ровно с CYBERARENA INCIDENT REPORT и символа перевода '
            'строки. Восстановите ключ, расшифруйте записку и отправьте значение после '
            'Access token: в формате CTF{...}. Перебор не требуется.'
        ),
    },
}

FLAG_SOURCE = {
    'WEB-01': 'WEB01_FLAG, который получает лаборатория (из .env)',
    'WEB-02': 'флагом, восстановленным из files/web-02/',
    'CRYPTO-01': 'флагом, восстановленным из files/crypto-01/challenge.txt',
}

FLAG_FIX = {
    'WEB-01': ('верните в .env прежнее значение WEB01_FLAG либо задайте в карточке новый флаг '
               'через «Управление» (поле «Новый флаг») и запустите установку снова'),
    'WEB-02': ('проверьте, не менялись ли материалы в files/web-02/, и задайте в карточке верный '
               'флаг через «Управление»'),
    'CRYPTO-01': ('проверьте, не менялся ли files/crypto-01/challenge.txt, и задайте в карточке '
                  'верный флаг через «Управление»'),
}


class SetupError(Exception):
    pass


def read_flags(stream):
    try:
        flags = json.load(stream)
    except ValueError as exc:
        raise SetupError('На вход ожидается JSON с флагами заданий') from exc
    if not isinstance(flags, dict):
        raise SetupError('На вход ожидается JSON-объект {"код задания": "флаг"}')
    for code in CARDS:
        if not security.valid_flag(flags.get(code)):
            raise SetupError(f'{code}: флаг отсутствует или не в формате CTF{{...}}')
    return {code: flags[code] for code in CARDS}


def find_admin():
    # Same normalization as bootstrap_admin(), which creates the account.
    username = os.environ.get('ADMIN_USERNAME', 'admin').strip().lower()
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == username))
        if admin is None or not admin.is_admin:
            raise SetupError(f'Администратор «{username}» не найден: сначала запустите приложение')
        return admin.id, admin.password_hash


def find_admin_id():
    return find_admin()[0]


def admin_password_works():
    """ADMIN_PASSWORD only seeds a new account; later it may no longer open it."""
    return verify_password(os.environ.get('ADMIN_PASSWORD', ''), find_admin()[1])


def stored_flag_hash(code):
    with SessionLocal() as db:
        return db.scalar(select(Challenge.flag_hash).where(Challenge.code == code)) or ''


def is_untouched_draft(task):
    """True only for a draft exactly as seed_case() created it and never saved since.

    Every save increments the revision, so any manual edit (title, resource, flag,
    difficulty, ...) makes the card count as edited, even with the original description.
    """
    code = task['code']
    seeded = {
        'title': code,
        'category': code.split('-')[0],
        'points': service.CASE_POINTS[code],
        'description': DRAFT_TEXT,
        'resource_url': '/lab/' if code == 'WEB-01' else None,
    }
    return (
        task['revision'] == 1
        and not task['is_published']
        and stored_flag_hash(code) == ''
        and all(task[name] == value for name, value in seeded.items())
    )


def stored_flag_matches(code, flag):
    encoded = stored_flag_hash(code)
    return security.supported_hash(encoded) and security.verify_flag(flag, encoded)


def configure(admin_id, flags, out=print):
    """Configure untouched drafts; return a list of problems that block the tournament."""
    service.seed_case()
    tasks = {task['code']: task for task in service.catalog(admin_id, limit=100, include_hidden=True)}
    problems = []
    for code, card in CARDS.items():
        task = tasks.get(code)
        if task is None:
            raise SetupError(f'{code}: черновик не создан')
        if task['is_published']:
            if stored_flag_matches(code, flags[code]):
                out(f'{code}: уже настроено, пропускаю')
            else:
                out(f'{code}: флаг в карточке не совпадает, карточка не изменена')
                problems.append(f'{code}: флаг в опубликованной карточке не совпадает с '
                                f'{FLAG_SOURCE[code]}. Исправление: {FLAG_FIX[code]}.')
            continue
        if not is_untouched_draft(task):
            out(f'{code}: изменено вручную и скрыто, карточка не изменена')
            problems.append(f'{code}: карточка изменена вручную, но не опубликована, поэтому скрипт '
                            'её не трогает. Исправление: проверьте карточку в «Управлении», задайте '
                            'флаг и поставьте галочку «Опубликовать задание».')
            continue
        payload = schemas.ChallengeUpdate.model_validate({
            **card,
            'flag': flags[code],
            'is_published': True,
            'expected_revision': task['revision'],
        })
        service.save_challenge(admin_id, payload.model_dump(exclude_unset=True), task['id'])
        out(f'{code}: настроено и опубликовано')
    return problems


def main(stream=None):
    try:
        flags = read_flags(stream or sys.stdin)
        problems = configure(find_admin_id(), flags)
    except service.CtfError as exc:
        print(f'Ошибка: {exc.message}', file=sys.stderr)
        return 1
    except SetupError as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 1
    if problems:
        print('Установка не завершена: турнир не готов.', file=sys.stderr)
        for problem in problems:
            print(f'- {problem}', file=sys.stderr)
        return 1
    return 0


def check_admin_password():
    try:
        return 0 if admin_password_works() else 2
    except SetupError as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(check_admin_password() if sys.argv[1:] == ['--check-admin-password'] else main())

"""One-shot bootstrap: fill in and publish the three case cards.

Flags are read from stdin as a JSON object such as {"WEB-01": "CTF{...}", ...}.
They are never accepted as arguments and never printed. Cards that are already
published or edited by an administrator are left untouched, so the command can
be repeated safely; a published card whose stored flag differs from the supplied
one is reported but not changed. Run it inside the app container:

    docker compose exec -T app python -m app.ctf.setup_case
"""

import json
import os
import sys

from sqlalchemy import select

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


def find_admin_id():
    username = os.environ.get('ADMIN_USERNAME', 'admin')
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == username))
        if admin is None or not admin.is_admin:
            raise SetupError(f'Администратор «{username}» не найден: сначала запустите приложение')
        return admin.id


def stored_flag_matches(code, flag):
    with SessionLocal() as db:
        encoded = db.scalar(select(Challenge.flag_hash).where(Challenge.code == code))
    return not security.supported_hash(encoded or '') or security.verify_flag(flag, encoded)


def configure(admin_id, flags, out=print):
    service.seed_case()
    tasks = {task['code']: task for task in service.catalog(admin_id, limit=100, include_hidden=True)}
    configured = 0
    for code, card in CARDS.items():
        task = tasks.get(code)
        if task is None:
            raise SetupError(f'{code}: черновик не создан')
        if task['is_published'] or task['description'] != DRAFT_TEXT:
            if task['is_published'] and not stored_flag_matches(code, flags[code]):
                source = 'WEB01_FLAG из .env' if code == 'WEB-01' else 'флагом из материалов'
                out(f'{code}: ВНИМАНИЕ: флаг в карточке не совпадает с {source}; карточка не изменена')
            else:
                out(f'{code}: уже настроено, пропускаю')
            continue
        payload = schemas.ChallengeUpdate.model_validate({
            **card,
            'flag': flags[code],
            'is_published': True,
            'expected_revision': task['revision'],
        })
        service.save_challenge(admin_id, payload.model_dump(exclude_unset=True), task['id'])
        out(f'{code}: настроено и опубликовано')
        configured += 1
    return configured


def main(stream=None):
    try:
        flags = read_flags(stream or sys.stdin)
        configure(find_admin_id(), flags)
    except service.CtfError as exc:
        print(f'Ошибка: {exc.message}', file=sys.stderr)
        return 1
    except SetupError as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

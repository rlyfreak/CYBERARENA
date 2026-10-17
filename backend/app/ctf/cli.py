"""Optional local CLI; browser UI and JSON API also support administration."""

import argparse
import getpass

from pydantic import ValidationError
from sqlalchemy import select

from ..database import SessionLocal
from ..models import User
from . import schemas, service


def main(argv=None):
    parser = argparse.ArgumentParser(description='CYBERARENA CTF administration')
    parser.add_argument('--admin', required=True, help='Existing administrator username')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('seed-case', help='Add unpublished case drafts')
    create = commands.add_parser('create')
    for name in ['code', 'title', 'description', 'category']:
        create.add_argument('--' + name, required=True)
    create.add_argument('--points', type=int, required=True)
    create.add_argument('--publish', action='store_true')
    edit = commands.add_parser('edit')
    edit.add_argument('id', type=int)
    for name in ['title', 'description', 'category']:
        edit.add_argument('--' + name)
    edit.add_argument('--points', type=int)
    edit.add_argument('--set-flag', action='store_true')
    visibility = edit.add_mutually_exclusive_group()
    visibility.add_argument('--publish', action='store_true')
    visibility.add_argument('--hide', action='store_true')
    args = parser.parse_args(argv)
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == args.admin))
        if admin is None or not admin.is_admin or admin.must_change_password:
            parser.error('An administrator with a changed initial password is required')
        admin_id = admin.id
    try:
        if args.command == 'seed-case':
            service.seed_case()
            print('Case drafts created; configure flags and descriptions in /admin.')
            return
        if args.command == 'create':
            values = {name: getattr(args, name) for name in ['code', 'title', 'description', 'category', 'points']}
            values.update(flag=getpass.getpass('Flag (CTF{...}): '), is_published=args.publish)
            payload = schemas.ChallengeCreate.model_validate(values)
            result = service.save_challenge(admin_id, payload.model_dump())
        else:
            task = service.challenge_detail(admin_id, args.id, include_hidden=True)
            values = {name: getattr(args, name) for name in ['title', 'description', 'category', 'points']
                      if getattr(args, name) is not None}
            values['expected_revision'] = task['revision']
            if args.publish or args.hide:
                values['is_published'] = args.publish
            if args.set_flag:
                values['flag'] = getpass.getpass('New flag (CTF{...}): ')
            payload = schemas.ChallengeUpdate.model_validate(values)
            result = service.save_challenge(admin_id, payload.model_dump(exclude_unset=True), args.id)
        print(f"Saved challenge {result['id']} ({result['code']}).")
    except service.CtfError as exc:
        parser.error(exc.message)
    except ValidationError:
        parser.error('Invalid challenge fields; flag input is not displayed')


if __name__ == '__main__':
    main()

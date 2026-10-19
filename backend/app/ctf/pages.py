from typing import Annotated, TypeVar

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ValidationError
from starlette.concurrency import run_in_threadpool

from ..auth.csrf import get_csrf_token, validate_csrf
from ..auth.dependencies import get_current_user, require_admin
from ..models import User
from ..templates import templates
from . import schemas, service
from .routes import Limit, Offset

router = APIRouter(include_in_schema=False)
Admin = Annotated[User, Depends(require_admin)]
Model = TypeVar("Model", bound=BaseModel)


def page_user(request: Request):
    try:
        return get_current_user(request)
    except HTTPException as exc:
        if exc.status_code in (401, 403):
            destination = '/login' if exc.status_code == 401 else '/change-password'
            raise HTTPException(303, headers={'Location': destination}) from exc
        raise


Player = Annotated[User, Depends(page_user)]


def render(request, name, user=None, status_code=200, **context):
    return templates.TemplateResponse(request, name, {
        'user': user, 'csrf_token': get_csrf_token(request), **context,
    }, status_code=status_code, headers={'Cache-Control': 'no-store'})


def validated(model: type[Model], data: object) -> Model:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise service.CtfError(422, 'Проверьте заполнение полей. Флаг: CTF{...}, до 256 символов.') from exc


async def challenge_form_data(request: Request) -> dict[str, str | int | bool]:
    data: dict[str, str | int | bool] = {}
    for name, value in (await request.form()).items():
        if not isinstance(value, str):
            raise service.CtfError(422, 'Поля задания должны содержать текст, а не файлы')
        data[name] = value
    return data


@router.get('/challenges')
def catalog_page(request: Request, user: Player, offset: Offset = 0,
                 limit: Limit = 50, category: str | None = None):
    return render(request, 'challenges.html', user, tasks=service.catalog(user.id, offset, limit, category or None),
                  offset=offset, limit=limit, category=category or '')


@router.get('/challenges/{challenge_id}')
def challenge_page(challenge_id: int, request: Request, user: Player, result: str = ''):
    messages = {'correct': 'Верно! Баллы начислены.', 'incorrect': 'Неверный флаг.',
                'already_solved': 'Задание уже решено. Повторных баллов нет.',
                'invalid_format': 'Формат флага: CTF{...}, до 256 печатных ASCII-символов.'}
    return render(request, 'challenge.html', user,
                  task=service.challenge_detail(user.id, challenge_id), message=messages.get(result, ''))


@router.post('/challenges/{challenge_id}')
def challenge_form(challenge_id: int, request: Request, user: Player,
                   flag: str = Form(''), csrf_token: str = Form('')):
    validate_csrf(request, csrf_token)
    result = service.submit_flag(user.id, challenge_id, flag)
    return RedirectResponse(f'/challenges/{challenge_id}?result={result.result}', 303)


@router.get('/submissions')
def history_page(request: Request, user: Player, offset: Offset = 0, limit: Limit = 50):
    return render(request, 'submissions.html', user, attempts=service.history(user.id, offset, limit),
                  offset=offset, limit=limit, admin=False)


@router.get('/leaderboard')
def leaderboard_page(request: Request, offset: Offset = 0, limit: Limit = 50):
    return render(request, 'leaderboard.html', rows=service.leaderboard(offset, limit),
                  offset=offset, limit=limit)


@router.get('/admin')
def admin_page(request: Request, user: Admin, offset: Offset = 0, limit: Limit = 50):
    return render(request, 'admin.html', user,
                  tasks=service.catalog(user.id, offset, limit, include_hidden=True),
                  state=service.results_state(), offset=offset, limit=limit)


@router.get('/admin/challenges/new')
def admin_new(request: Request, user: Admin):
    return render(request, 'admin_challenge.html', user, task=None)


@router.get('/admin/challenges/{challenge_id}')
def admin_edit(challenge_id: int, request: Request, user: Admin):
    return render(request, 'admin_challenge.html', user,
                  task=service.challenge_detail(user.id, challenge_id, include_hidden=True))


@router.post('/admin/challenges/new')
async def admin_create_form(request: Request, user: Admin):
    data = await challenge_form_data(request)
    validate_csrf(request, data.pop('csrf_token', None))
    try:
        data['points'] = int(data.get('points', ''))
    except ValueError as exc:
        raise service.CtfError(422, 'Баллы должны быть целым числом') from exc
    data['is_published'] = data.get('is_published') == 'on'
    payload = validated(schemas.ChallengeCreate, data)
    task = await run_in_threadpool(service.save_challenge, user.id, payload.model_dump())
    return RedirectResponse(f"/admin/challenges/{task['id']}", 303)


@router.post('/admin/challenges/{challenge_id}')
async def admin_edit_form(challenge_id: int, request: Request, user: Admin):
    data = await challenge_form_data(request)
    validate_csrf(request, data.pop('csrf_token', None))
    try:
        data['points'] = int(data.get('points', ''))
        data['expected_revision'] = int(data.get('expected_revision', ''))
    except ValueError as exc:
        raise service.CtfError(422, 'Баллы и версия должны быть целыми числами') from exc
    data['is_published'] = data.get('is_published') == 'on'
    if not data.get('flag'):
        data.pop('flag', None)
    payload = validated(schemas.ChallengeUpdate, data)
    await run_in_threadpool(
        service.save_challenge, user.id, payload.model_dump(exclude_unset=True), challenge_id,
    )
    return RedirectResponse('/admin', 303)


@router.get('/admin/submissions')
def admin_history(request: Request, user: Admin, offset: Offset = 0, limit: Limit = 50):
    return render(request, 'submissions.html', user, attempts=service.history(None, offset, limit),
                  offset=offset, limit=limit, admin=True)


@router.post('/admin/seed-case')
def case_drafts(request: Request, user: Admin, csrf_token: str = Form('')):
    validate_csrf(request, csrf_token)
    service.seed_case()
    return RedirectResponse('/admin', 303)


@router.post('/admin/results/reset')
def admin_reset(request: Request, user: Admin, confirmation: str = Form(''),
                expected_generation: int = Form(...), csrf_token: str = Form('')):
    validate_csrf(request, csrf_token)
    payload = validated(schemas.ResetInput, {
        'confirmation': confirmation, 'expected_generation': expected_generation,
    })
    service.reset_results(payload.expected_generation)
    return RedirectResponse('/admin', 303)

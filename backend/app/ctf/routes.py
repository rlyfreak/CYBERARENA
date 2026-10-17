from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from ..auth.csrf import get_csrf_token, validate_csrf
from ..auth.dependencies import get_current_user, require_admin
from ..models import User
from . import schemas, service

router = APIRouter(tags=["CTF"])
Player = Annotated[User, Depends(get_current_user)]
Admin = Annotated[User, Depends(require_admin)]
Offset = Annotated[int, Query(ge=0)]
Limit = Annotated[int, Query(ge=1, le=100)]


def csrf_header(request: Request):
    validate_csrf(request, request.headers.get("X-CSRF-Token"))


WriteGuard = Depends(csrf_header)


@router.get("/api/csrf")
def csrf(request: Request, user: Player):
    return JSONResponse({"csrf_token": get_csrf_token(request)}, headers={"Cache-Control": "no-store"})


@router.get("/api/challenges", response_model=list[schemas.ChallengeOutput])
def challenges(user: Player, offset: Offset = 0, limit: Limit = 50,
               category: Annotated[str | None, Query(max_length=50)] = None):
    return service.catalog(user.id, offset, limit, category)


@router.get("/api/challenges/{challenge_id}", response_model=schemas.ChallengeOutput)
def challenge(challenge_id: int, user: Player):
    return service.challenge_detail(user.id, challenge_id)


@router.post("/api/challenges/{challenge_id}/submissions", dependencies=[WriteGuard])
def submit(challenge_id: int, data: schemas.FlagInput, user: Player):
    outcome = service.submit_flag(user.id, challenge_id, data.flag.get_secret_value())
    status = {"already_solved": 409, "invalid_format": 422}.get(outcome.result, 200)
    return JSONResponse({"result": outcome.result, "submission_id": outcome.submission_id,
                         "points_awarded": outcome.points_awarded}, status_code=status)


@router.get("/api/submissions", response_model=list[schemas.AttemptOutput])
def submissions(user: Player, offset: Offset = 0, limit: Limit = 50):
    return service.history(user.id, offset, limit)


@router.get("/api/leaderboard", response_model=list[schemas.LeaderOutput])
def leaders(offset: Offset = 0, limit: Limit = 50):
    return service.leaderboard(offset, limit)


@router.get("/api/admin/challenges", response_model=list[schemas.ChallengeOutput], tags=["CTF Admin"])
def admin_challenges(user: Admin, offset: Offset = 0, limit: Limit = 50):
    return service.catalog(user.id, offset, limit, include_hidden=True)


@router.post("/api/admin/challenges", response_model=schemas.ChallengeOutput,
             status_code=201, dependencies=[WriteGuard], tags=["CTF Admin"])
def create_challenge(data: schemas.ChallengeCreate, user: Admin):
    return service.save_challenge(user.id, data.model_dump())


@router.patch("/api/admin/challenges/{challenge_id}", response_model=schemas.ChallengeOutput,
              dependencies=[WriteGuard], tags=["CTF Admin"])
def edit_challenge(challenge_id: int, data: schemas.ChallengeUpdate, user: Admin):
    return service.save_challenge(user.id, data.model_dump(exclude_unset=True), challenge_id)


@router.get("/api/admin/submissions", response_model=list[schemas.AttemptOutput], tags=["CTF Admin"])
def admin_submissions(user: Admin, offset: Offset = 0, limit: Limit = 50,
                      user_id: Annotated[int | None, Query(ge=1)] = None):
    return service.history(user_id, offset, limit)


@router.get("/api/admin/results", tags=["CTF Admin"])
def admin_results(user: Admin):
    return service.results_state()


@router.post("/api/admin/results/reset", dependencies=[WriteGuard], tags=["CTF Admin"])
def reset_demo(data: schemas.ResetInput, user: Admin):
    return service.reset_results(data.expected_generation)

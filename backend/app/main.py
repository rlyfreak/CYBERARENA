import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

# регистрациямоделлейвsqlalchemyпередсозданиемтаблиц
from . import models  # noqa: F401
from .auth.bootstrap import bootstrap_admin
from .auth.routes import router as auth_router
from .ctf.body_limit import CtfBodyLimit
from .ctf.pages import router as ctf_pages
from .ctf.routes import router as ctf_router
from .ctf.service import CtfError
from .migrations.ctf_core import migrate as migrate_ctf_core
from .migrations.user_auth import migrate as migrate_user_auth
from .templates import templates


@asynccontextmanager
async def lifespan(app: FastAPI):
    migrate_user_auth()
    migrate_ctf_core()
    bootstrap_admin()
    yield


app = FastAPI(
    title="CYBERARENA API",
    description="Backend for Cyber Arena API",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth_router)
app.include_router(ctf_router)
app.include_router(ctf_pages)


@app.exception_handler(CtfError)
async def ctf_error(request: Request, error: CtfError):
    headers = {"Cache-Control": "no-store"}
    if error.retry_after is not None:
        headers['Retry-After'] = str(error.retry_after)
    if not request.url.path.startswith('/api/'):
        return templates.TemplateResponse(
            request, 'ctf_error.html', {'message': error.message, 'user': None},
            status_code=error.status, headers=headers,
        )
    return JSONResponse({"detail": error.message}, status_code=error.status, headers=headers)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError):
    # Never echo flag/password input in default FastAPI validation responses.
    errors = [{"loc": e['loc'], "type": e['type'], "msg": "Invalid input"} for e in error.errors()]
    return JSONResponse({"detail": errors}, status_code=422, headers={"Cache-Control": "no-store"})


@app.middleware("http")
async def private_cache(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith(("/api/challenges", "/api/submissions", "/api/admin", "/admin")):
        response.headers['Cache-Control'] = 'no-store'
    return response

SESSION_SECRET = os.getenv("SESSION_SECRET")

if not SESSION_SECRET or len(SESSION_SECRET) < 32:
    raise RuntimeError("SESSION_SECRET должен содержать минимум 32 символа")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="cyberarena_session",
    max_age=60 * 60 * 8,
    same_site="lax",
    https_only=False,
)
app.add_middleware(CtfBodyLimit)


@app.get("/", include_in_schema=False)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/health", tags=["System"])
async def health_check():
    return {"status": "ok", "service": "cyberarena-backend", "version": "0.1.0"}

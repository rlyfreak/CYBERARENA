import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware

# регистрациямоделлейвsqlalchemyпередсозданиемтаблиц
from . import models  # noqa: F401
from .auth.bootstrap import bootstrap_admin
from .auth.routes import router as auth_router
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


@app.get("/", include_in_schema=False)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/health", tags=["System"])
async def health_check():
    return {"status": "ok", "service": "cyberarena-backend", "version": "0.1.0"}

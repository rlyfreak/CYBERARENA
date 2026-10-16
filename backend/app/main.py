import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

from . import models
from .database import Base, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="CYBERARENA API",
    description="Backend for Cyber Arena API",
    version="0.1.0",
    lifespan=lifespan,
)

TEMPLATES_DIR = os.getenv(
    "TEMPLATES_DIR",
    str(Path(__file__).resolve().parents[2] / "frontend" / "templates"),
)

templates = Jinja2Templates(directory=TEMPLATES_DIR)


@app.get("/", include_in_schema=False)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/health", tags=["System"])
async def health_check():
    return {"status": "ok", "service": "cyberarena-backend", "version": "0.1.0"}

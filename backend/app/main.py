from contextlib import asynccontextmanager
from fastapi import FastAPI
from .database import Base, engine
from . import models

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title ="CYBERARENA API",
    description="Backend for Cyber Arena API",
    version="0.1.0",
    lifespan=lifespan,
)

@app.get("/api/health", tags=["System"])
async def health_check():
    return {
        "status": "ok",
        "service": "cyberarena-backend",
        "version": "0.1.0"
    }
    
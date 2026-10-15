from fastapi import FastAPI

app = FastAPI(
    title ="CYBERARENA API",
    description="Backend for Cyber Arena API",
    version="0.1.0"
)

@app.get("/api/health", tags=["System"])
async def health_check():
    return {
        "status": "ok",
        "service": "cyberarena-backend",
        "version": "0.1.0"
    }
    
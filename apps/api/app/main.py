"""SentinelAI API application entrypoint."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Passive Network Threat Detection & Security Operations Platform API",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    """Basic service health check."""
    return {
        "status": "healthy",
        "service": "sentinel-api",
        "version": settings.app_version,
        "phase": "Phase 0 - Foundation",
    }


# Future Phase 5 REST and WebSocket endpoints:
# app.include_router(alerts.router, prefix="/api/v1/alerts")
# app.include_router(telemetry.router, prefix="/api/v1/telemetry")
# app.include_router(websocket.router, prefix="/ws")

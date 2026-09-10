"""API v1 router composition."""

from fastapi import APIRouter
from app.api.v1.endpoints import health, flows, detections, alerts, statistics, ws, ai_analyst

api_v1_router = APIRouter()

api_v1_router.include_router(health.router)
api_v1_router.include_router(flows.router)
api_v1_router.include_router(detections.router)
api_v1_router.include_router(alerts.router)
api_v1_router.include_router(ai_analyst.router)
api_v1_router.include_router(statistics.router)
api_v1_router.include_router(ws.router)

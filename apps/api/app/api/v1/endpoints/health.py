"""Health, readiness, and processing status endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db, check_db_health
from app.services.stats_service import StatsService
from app.schemas.common import HealthResponse, ReadinessResponse
from app.schemas.stats import ProcessingStatusRead

router = APIRouter(tags=["System Health & Status"])


@router.get("/health", response_model=HealthResponse, summary="Service health check")
def health_check():
    """Returns basic liveness and application service health."""
    return HealthResponse(
        status="healthy",
        service=settings.app_name,
        version=settings.app_version,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get(
    "/readiness",
    response_model=ReadinessResponse,
    summary="Service dependency readiness check",
)
def readiness_check():
    """Checks database connectivity and core service readiness."""
    db_ok = check_db_health()
    if not db_ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "unhealthy",
                "database": False,
                "environment": settings.environment,
                "version": settings.app_version,
            },
        )
    return ReadinessResponse(
        status="ready",
        database=True,
        environment=settings.environment,
        version=settings.app_version,
    )


@router.get(
    "/status",
    response_model=ProcessingStatusRead,
    summary="Passive ingestion and processing pipeline status",
)
def processing_status(db: Session = Depends(get_db)):
    """Provides high-level processing status and confirms passive monitoring invariant."""
    service = StatsService(db)
    return service.get_processing_status()

"""System and threat statistics endpoints."""

from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.stats_service import StatsService
from app.services.detection_service import DetectionService
from app.services.alert_service import AlertService
from app.schemas.stats import (
    ThreatDistributionItem,
    EntityStatisticsItem,
    TelemetrySummaryRead,
)

router = APIRouter(prefix="/statistics", tags=["Statistics & Telemetry"])


@router.get(
    "/threats",
    response_model=List[ThreatDistributionItem],
    summary="Get threat distribution breakdown",
)
def threat_statistics(db: Session = Depends(get_db)):
    """Retrieve frequency counts of all detected threat types."""
    service = DetectionService(db)
    return service.get_threat_distribution()


@router.get(
    "/entities",
    response_model=List[EntityStatisticsItem],
    summary="Get top entities involved in security alerts",
)
def entity_statistics(
    limit: int = Query(10, ge=1, le=100, description="Number of top entities to return"),
    db: Session = Depends(get_db),
):
    """Identify the top network entities (IPs, domains) linked to security alerts."""
    service = AlertService(db)
    return service.get_entity_statistics(limit=limit)


@router.get(
    "/summary",
    response_model=TelemetrySummaryRead,
    summary="Get system-wide telemetry summary",
)
def telemetry_summary(db: Session = Depends(get_db)):
    """Retrieve aggregated overview telemetry covering flows, detections, and alerts."""
    service = StatsService(db)
    return service.get_telemetry_summary()

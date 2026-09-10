"""Security Alert query and internal lifecycle endpoints."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.alert_service import AlertService
from app.schemas.alert import (
    SecurityAlertRead,
    AlertStatisticsRead,
    AlertAcknowledgeRequest,
    AlertResolveRequest,
)
from app.schemas.common import PaginatedResponse
from app.core.config import settings

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get(
    "/statistics",
    response_model=AlertStatisticsRead,
    summary="Get aggregated alert statistics",
)
def alert_statistics(db: Session = Depends(get_db)):
    """Retrieve summarized alert metrics grouped by status, severity tier, and threat class."""
    service = AlertService(db)
    return service.get_alert_statistics()


@router.get("", response_model=PaginatedResponse[SecurityAlertRead], summary="List security alerts")
def list_alerts(
    threat_class: Optional[str] = Query(None, description="Filter by threat category"),
    severity: Optional[str] = Query(None, description="Filter by severity tier"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by alert status"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence"),
    max_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Maximum confidence"),
    min_risk: Optional[float] = Query(None, ge=0.0, le=100.0, description="Minimum risk score"),
    max_risk: Optional[float] = Query(None, ge=0.0, le=100.0, description="Maximum risk score"),
    start_time: Optional[datetime] = Query(None, description="Filter alerts created after"),
    end_time: Optional[datetime] = Query(None, description="Filter alerts created before"),
    limit: int = Query(settings.default_page_limit, ge=1, le=settings.max_page_limit, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    sort_by: str = Query("created_at", description="Sort field (e.g. created_at, risk_score, confidence)"),
    sort_desc: bool = Query(True, description="Sort descending if true"),
    db: Session = Depends(get_db),
):
    """Retrieve paginated security alerts with granular SOC filtering options."""
    service = AlertService(db)
    items, total = service.list_alerts(
        threat_class=threat_class,
        severity=severity,
        status=status_filter,
        min_confidence=min_confidence,
        max_confidence=max_confidence,
        min_risk=min_risk,
        max_risk=max_risk,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_desc=sort_desc,
    )
    return PaginatedResponse[SecurityAlertRead](
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(items)) < total,
    )


@router.get("/{alert_id}", response_model=SecurityAlertRead, summary="Get alert details by ID")
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    """Fetch complete security alert details including all signals, evidence, and audit history."""
    service = AlertService(db)
    alert = service.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID '{alert_id}' not found",
        )
    return alert


@router.post(
    "/{alert_id}/acknowledge",
    response_model=SecurityAlertRead,
    summary="Acknowledge alert (Internal Lifecycle Only)",
)
def acknowledge_alert(
    alert_id: str,
    payload: AlertAcknowledgeRequest = AlertAcknowledgeRequest(),
    db: Session = Depends(get_db),
):
    """Transition alert to ACKNOWLEDGED state.
    
    INVARIANT: Modifies internal database state only. No network transmission or firewall action.
    """
    service = AlertService(db)
    alert = service.acknowledge_alert(
        alert_id=alert_id,
        changed_by=payload.changed_by,
        notes=payload.notes,
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID '{alert_id}' not found",
        )
    return alert


@router.post(
    "/{alert_id}/resolve",
    response_model=SecurityAlertRead,
    summary="Resolve alert (Internal Lifecycle Only)",
)
def resolve_alert(
    alert_id: str,
    payload: AlertResolveRequest = AlertResolveRequest(),
    db: Session = Depends(get_db),
):
    """Transition alert to RESOLVED state.
    
    INVARIANT: Modifies internal database state only. No network transmission or remediation action.
    """
    service = AlertService(db)
    alert = service.resolve_alert(
        alert_id=alert_id,
        changed_by=payload.changed_by,
        notes=payload.notes,
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID '{alert_id}' not found",
        )
    return alert

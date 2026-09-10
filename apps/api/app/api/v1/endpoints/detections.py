"""Threat detection query endpoints."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.detection_service import DetectionService
from app.schemas.detection import DetectionRead
from app.schemas.common import PaginatedResponse
from app.core.config import settings

router = APIRouter(prefix="/detections", tags=["Threat Detections"])


@router.get("", response_model=PaginatedResponse[DetectionRead], summary="List detections")
def list_detections(
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    detector_name: Optional[str] = Query(None, description="Filter by detector engine"),
    is_threat: Optional[bool] = Query(None, description="Filter threats only"),
    flow_id: Optional[str] = Query(None, description="Filter by related flow ID"),
    start_time: Optional[datetime] = Query(None, description="Filter timestamp from"),
    end_time: Optional[datetime] = Query(None, description="Filter timestamp to"),
    limit: int = Query(settings.default_page_limit, ge=1, le=settings.max_page_limit, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    sort_by: str = Query("timestamp", description="Sort field"),
    sort_desc: bool = Query(True, description="Sort descending"),
    db: Session = Depends(get_db),
):
    """Retrieve paginated threat detections with evidence items."""
    service = DetectionService(db)
    items, total = service.list_detections(
        threat_type=threat_type,
        severity=severity,
        detector_name=detector_name,
        is_threat=is_threat,
        flow_id=flow_id,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_desc=sort_desc,
    )
    return PaginatedResponse[DetectionRead](
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(items)) < total,
    )


@router.get("/{detection_id}", response_model=DetectionRead, summary="Get detection details")
def get_detection(detection_id: str, db: Session = Depends(get_db)):
    """Fetch complete detection results along with all supporting evidence items."""
    service = DetectionService(db)
    detection = service.get_detection_by_id(detection_id)
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection with ID '{detection_id}' not found",
        )
    return detection

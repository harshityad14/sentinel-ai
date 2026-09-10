"""Network flow query endpoints."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.flow_service import FlowService
from app.schemas.flow import FlowRead
from app.schemas.common import PaginatedResponse
from app.core.config import settings

router = APIRouter(prefix="/flows", tags=["Network Flows"])


@router.get("", response_model=PaginatedResponse[FlowRead], summary="List network flows")
def list_flows(
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (e.g. TCP, UDP)"),
    start_time: Optional[datetime] = Query(None, description="Filter flows ending after this timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter flows starting before this timestamp"),
    limit: int = Query(settings.default_page_limit, ge=1, le=settings.max_page_limit, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    sort_by: str = Query("start_time", description="Sort field (e.g. start_time, duration, byte_count)"),
    sort_desc: bool = Query(True, description="Sort descending if true"),
    db: Session = Depends(get_db),
):
    """Retrieve paginated network flows with optional IP, protocol, and time-range filtering."""
    service = FlowService(db)
    items, total = service.list_flows(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_desc=sort_desc,
    )
    return PaginatedResponse[FlowRead](
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(items)) < total,
    )


@router.get("/{flow_id}", response_model=FlowRead, summary="Get flow details by ID")
def get_flow(flow_id: str, db: Session = Depends(get_db)):
    """Fetch complete bidirectional flow record details by flow_id."""
    service = FlowService(db)
    flow = service.get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow with ID '{flow_id}' not found",
        )
    return flow

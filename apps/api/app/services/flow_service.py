"""Flow Service for managing network flow queries and persistence."""

from datetime import datetime
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session

from app.repositories.flow_repo import FlowRepository
from app.models.flow import FlowModel
from sentinel_models.events import FlowRecord


class FlowService:
    """Service layer managing network flows and feature vectors."""

    def __init__(self, session: Session):
        self.session = session
        self.repo = FlowRepository(session)

    def persist_flow(self, flow: FlowRecord) -> FlowModel:
        """Persist a FlowRecord into the database."""
        return self.repo.create_flow(flow)

    def get_flow_by_id(self, flow_id: str) -> Optional[FlowModel]:
        """Retrieve a flow by its unique ID."""
        return self.repo.get_by_flow_id(flow_id)

    def list_flows(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "start_time",
        sort_desc: bool = True,
    ) -> Tuple[List[FlowModel], int]:
        """List flows matching filters."""
        return self.repo.list_flows(
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

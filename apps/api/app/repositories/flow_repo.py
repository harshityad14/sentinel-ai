"""Flow repository for flow records and features."""

from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc, asc

from app.models.flow import FlowModel, FlowFeatureModel
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class FlowRepository:
    """Data access repository for flows and extracted features."""

    def __init__(self, session: Session):
        self.session = session

    def create_flow(self, flow: FlowRecord) -> FlowModel:
        """Persist a FlowRecord domain model into the database."""
        start_dt = (
            datetime.fromtimestamp(flow.start_time)
            if isinstance(flow.start_time, (int, float))
            else flow.start_time
        )
        end_time_val = flow.end_time or flow.last_seen_time or flow.start_time
        end_dt = (
            datetime.fromtimestamp(end_time_val)
            if isinstance(end_time_val, (int, float))
            else end_time_val
        )

        db_flow = FlowModel(
            flow_id=flow.flow_id,
            start_time=start_dt,
            end_time=end_dt,
            duration=flow.duration_sec,
            src_ip=flow.source_ip,
            dst_ip=flow.destination_ip,
            src_port=flow.source_port or 0,
            dst_port=flow.destination_port or 0,
            protocol=flow.protocol.value if hasattr(flow.protocol, "value") else str(flow.protocol),
            packet_count=flow.total_packets,
            byte_count=flow.total_bytes,
            packets_fwd=flow.forward_packets,
            packets_bwd=flow.backward_packets,
            bytes_fwd=flow.forward_bytes,
            bytes_bwd=flow.backward_bytes,
            is_bidirectional=(flow.backward_packets > 0),
            metadata_json=flow.model_dump(
                mode="json",
                exclude={"flow_id", "source_ip", "destination_ip", "source_port", "destination_port", "protocol"},
            ),
        )
        self.session.add(db_flow)
        return db_flow

    def create_feature_vector(self, feature_vector: FeatureVector) -> FlowFeatureModel:
        """Persist an extracted FeatureVector into the database."""
        timestamp_dt = (
            datetime.fromtimestamp(feature_vector.timestamp)
            if isinstance(feature_vector.timestamp, (int, float))
            else feature_vector.timestamp
        )
        db_feat = FlowFeatureModel(
            flow_id=feature_vector.flow_id,
            timestamp=timestamp_dt,
            features=feature_vector.model_dump(),
            status=feature_vector.status.value if hasattr(feature_vector.status, "value") else str(feature_vector.status),
        )
        self.session.add(db_feat)
        return db_feat

    def get_by_flow_id(self, flow_id: str) -> Optional[FlowModel]:
        """Fetch a single flow by its unique flow_id."""
        stmt = select(FlowModel).where(FlowModel.flow_id == flow_id)
        return self.session.execute(stmt).scalar_one_or_none()

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
        """Query flows with filters and pagination."""
        query = select(FlowModel)
        count_query = select(func.count(FlowModel.id))

        if src_ip:
            query = query.where(FlowModel.src_ip == src_ip)
            count_query = count_query.where(FlowModel.src_ip == src_ip)
        if dst_ip:
            query = query.where(FlowModel.dst_ip == dst_ip)
            count_query = count_query.where(FlowModel.dst_ip == dst_ip)
        if protocol:
            query = query.where(FlowModel.protocol == protocol)
            count_query = count_query.where(FlowModel.protocol == protocol)
        if start_time:
            query = query.where(FlowModel.start_time >= start_time)
            count_query = count_query.where(FlowModel.start_time >= start_time)
        if end_time:
            query = query.where(FlowModel.end_time <= end_time)
            count_query = count_query.where(FlowModel.end_time <= end_time)

        total = self.session.execute(count_query).scalar_one()

        order_col = getattr(FlowModel, sort_by, FlowModel.start_time)
        query = query.order_by(desc(order_col) if sort_desc else asc(order_col))
        query = query.limit(limit).offset(offset)

        results = list(self.session.execute(query).scalars().all())
        return results, total

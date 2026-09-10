"""Detection repository for threat detections and evidence."""

from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select, func, desc, asc

from app.models.detection import DetectionModel, DetectionEvidenceModel
from sentinel_models.detection import DetectionResult


class DetectionRepository:
    """Data access repository for detection results and evidence."""

    def __init__(self, session: Session):
        self.session = session

    def create_detection(self, detection: DetectionResult) -> DetectionModel:
        """Persist a DetectionResult domain model into the database."""
        timestamp_dt = (
            datetime.fromtimestamp(detection.detection_timestamp)
            if isinstance(detection.detection_timestamp, (int, float))
            else detection.detection_timestamp
        )

        detector_str = (
            detection.detector_type.value
            if hasattr(detection.detector_type, "value")
            else str(detection.detector_type)
        )

        db_detection = DetectionModel(
            detection_id=detection.detection_id,
            flow_id=detection.flow_id,
            threat_type=detection.threat_type.value if hasattr(detection.threat_type, "value") else str(detection.threat_type),
            severity=detection.severity.value if hasattr(detection.severity, "value") else str(detection.severity),
            confidence=detection.confidence,
            is_threat=detection.is_threat,
            detector_name=detector_str,
            explanation=detection.explanation,
            context_json=detection.context,
            timestamp=timestamp_dt,
        )

        for ev in detection.evidence:
            observed_val = (
                float(ev.observed_value)
                if isinstance(ev.observed_value, (int, float))
                else 0.0
            )
            threshold_val = (
                float(ev.threshold_value)
                if isinstance(ev.threshold_value, (int, float))
                else None
            )
            db_ev = DetectionEvidenceModel(
                detection_id=detection.detection_id,
                feature_name=ev.feature_name,
                observed_value=observed_val,
                threshold=threshold_val,
                score=0.0,
                contribution=0.0,
                description=ev.description,
            )
            db_detection.evidence_items.append(db_ev)

        self.session.add(db_detection)
        return db_detection

    def get_by_detection_id(self, detection_id: str) -> Optional[DetectionModel]:
        """Fetch detection with evidence items loaded."""
        stmt = (
            select(DetectionModel)
            .options(selectinload(DetectionModel.evidence_items))
            .where(DetectionModel.detection_id == detection_id)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_detections(
        self,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        detector_name: Optional[str] = None,
        is_threat: Optional[bool] = None,
        flow_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "timestamp",
        sort_desc: bool = True,
    ) -> Tuple[List[DetectionModel], int]:
        """Query detections with filtering, ordering, and pagination."""
        query = select(DetectionModel).options(selectinload(DetectionModel.evidence_items))
        count_query = select(func.count(DetectionModel.id))

        if threat_type:
            query = query.where(DetectionModel.threat_type == threat_type)
            count_query = count_query.where(DetectionModel.threat_type == threat_type)
        if severity:
            query = query.where(DetectionModel.severity == severity)
            count_query = count_query.where(DetectionModel.severity == severity)
        if detector_name:
            query = query.where(DetectionModel.detector_name == detector_name)
            count_query = count_query.where(DetectionModel.detector_name == detector_name)
        if is_threat is not None:
            query = query.where(DetectionModel.is_threat == is_threat)
            count_query = count_query.where(DetectionModel.is_threat == is_threat)
        if flow_id:
            query = query.where(DetectionModel.flow_id == flow_id)
            count_query = count_query.where(DetectionModel.flow_id == flow_id)
        if start_time:
            query = query.where(DetectionModel.timestamp >= start_time)
            count_query = count_query.where(DetectionModel.timestamp >= start_time)
        if end_time:
            query = query.where(DetectionModel.timestamp <= end_time)
            count_query = count_query.where(DetectionModel.timestamp <= end_time)

        total = self.session.execute(count_query).scalar_one()

        order_col = getattr(DetectionModel, sort_by, DetectionModel.timestamp)
        query = query.order_by(desc(order_col) if sort_desc else asc(order_col))
        query = query.limit(limit).offset(offset)

        results = list(self.session.execute(query).scalars().all())
        return results, total

    def get_threat_distribution(self) -> List[Dict[str, Any]]:
        """Count detections grouped by threat_type."""
        stmt = (
            select(DetectionModel.threat_type, func.count(DetectionModel.id).label("count"))
            .group_by(DetectionModel.threat_type)
            .order_by(desc("count"))
        )
        rows = self.session.execute(stmt).all()
        return [{"threat_type": row[0], "count": row[1]} for row in rows]

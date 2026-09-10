"""Detection Service for querying and persisting threat detection results."""

from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.orm import Session

from app.repositories.detection_repo import DetectionRepository
from app.models.detection import DetectionModel
from sentinel_models.detection import DetectionResult


class DetectionService:
    """Service layer managing threat detections and evidence."""

    def __init__(self, session: Session):
        self.session = session
        self.repo = DetectionRepository(session)

    def persist_detection(self, detection: DetectionResult) -> DetectionModel:
        """Persist a DetectionResult into the database."""
        return self.repo.create_detection(detection)

    def get_detection_by_id(self, detection_id: str) -> Optional[DetectionModel]:
        """Retrieve a detection by its unique detection_id."""
        return self.repo.get_by_detection_id(detection_id)

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
        """List detections matching filters with pagination."""
        return self.repo.list_detections(
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

    def get_threat_distribution(self) -> List[Dict[str, Any]]:
        """Get counts grouped by threat type."""
        return self.repo.get_threat_distribution()

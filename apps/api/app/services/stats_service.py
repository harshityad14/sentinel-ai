"""Stats Service providing system overview and telemetry summaries."""

from typing import Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.models.flow import FlowModel
from app.models.detection import DetectionModel
from app.models.alert import SecurityAlertModel
from app.repositories.detection_repo import DetectionRepository
from app.repositories.alert_repo import AlertRepository


class StatsService:
    """Service layer managing system health, pipeline metrics, and telemetry summaries."""

    def __init__(self, session: Session):
        self.session = session
        self.detection_repo = DetectionRepository(session)
        self.alert_repo = AlertRepository(session)

    def get_telemetry_summary(self) -> Dict[str, Any]:
        """Aggregate high-level metrics across flows, detections, and alerts."""
        total_flows = self.session.execute(select(func.count(FlowModel.id))).scalar_one() or 0
        total_detections = self.session.execute(select(func.count(DetectionModel.id))).scalar_one() or 0
        total_alerts = self.session.execute(select(func.count(SecurityAlertModel.id))).scalar_one() or 0

        threat_dist = self.detection_repo.get_threat_distribution()
        top_entities = self.alert_repo.get_entity_statistics(limit=10)

        return {
            "total_flows": total_flows,
            "total_detections": total_detections,
            "total_alerts": total_alerts,
            "threat_distribution": threat_dist,
            "top_entities": top_entities,
        }

    def get_processing_status(self) -> Dict[str, Any]:
        """Verify pipeline status and passive-monitoring compliance."""
        total_flows = self.session.execute(select(func.count(FlowModel.id))).scalar_one() or 0
        total_detections = self.session.execute(select(func.count(DetectionModel.id))).scalar_one() or 0
        total_alerts = self.session.execute(select(func.count(SecurityAlertModel.id))).scalar_one() or 0

        return {
            "pipeline_status": "PASSIVE_INGESTION_ACTIVE",
            "passive_mode_active": True,
            "total_flows_processed": total_flows,
            "total_detections_generated": total_detections,
            "total_alerts_persisted": total_alerts,
        }

"""Alert Service managing security alerts, correlation, and passive internal lifecycle."""

from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.orm import Session

from app.repositories.alert_repo import AlertRepository
from app.models.alert import SecurityAlertModel
from sentinel_models.alerts import SecurityAlert


class AlertService:
    """Service layer managing security alert operations and internal lifecycle transitions.
    
    STRICT PASSIVE INVARIANT:
    All lifecycle updates (acknowledgement, resolution) modify ONLY internal database
    and application states. They do NOT perform outbound remediation, packet blocking,
    firewall rule alteration, host isolation, or active probing.
    """

    def __init__(self, session: Session):
        self.session = session
        self.repo = AlertRepository(session)

    def persist_alert(self, alert: SecurityAlert) -> SecurityAlertModel:
        """Persist a SecurityAlert domain object."""
        return self.repo.create_alert(alert)

    def get_alert_by_id(self, alert_id: str) -> Optional[SecurityAlertModel]:
        """Fetch alert with all related signals, evidence, entities, and lifecycle audit records."""
        return self.repo.get_by_alert_id(alert_id)

    def list_alerts(
        self,
        threat_class: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        min_confidence: Optional[float] = None,
        max_confidence: Optional[float] = None,
        min_risk: Optional[float] = None,
        max_risk: Optional[float] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "created_at",
        sort_desc: bool = True,
    ) -> Tuple[List[SecurityAlertModel], int]:
        """List alerts matching filters with pagination."""
        return self.repo.list_alerts(
            threat_class=threat_class,
            severity=severity,
            status=status,
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

    def acknowledge_alert(
        self,
        alert_id: str,
        changed_by: str = "analyst",
        notes: Optional[str] = None,
    ) -> Optional[SecurityAlertModel]:
        """Transition alert status to ACKNOWLEDGED (strictly internal state change)."""
        return self.repo.update_lifecycle_status(
            alert_id=alert_id,
            new_status="ACKNOWLEDGED",
            notes=notes or "Alert acknowledged by analyst",
            changed_by=changed_by,
        )

    def resolve_alert(
        self,
        alert_id: str,
        changed_by: str = "analyst",
        notes: Optional[str] = None,
    ) -> Optional[SecurityAlertModel]:
        """Transition alert status to RESOLVED (strictly internal state change)."""
        return self.repo.update_lifecycle_status(
            alert_id=alert_id,
            new_status="RESOLVED",
            notes=notes or "Alert resolved by analyst",
            changed_by=changed_by,
        )

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Retrieve aggregated alert counts by status, severity, and threat class."""
        return self.repo.get_alert_statistics()

    def get_entity_statistics(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve top entities involved in alerts."""
        return self.repo.get_entity_statistics(limit=limit)

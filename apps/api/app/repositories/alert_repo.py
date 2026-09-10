"""Alert repository for persisting, querying, and updating security alerts."""

from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select, func, desc, asc

from app.models.alert import (
    SecurityAlertModel,
    AlertSignalModel,
    AlertEvidenceModel,
    AlertEntityModel,
    AlertLifecycleHistoryModel,
)
from sentinel_models.alerts import SecurityAlert


class AlertRepository:
    """Data access repository for security alerts, evidence, signals, and lifecycle history."""

    def __init__(self, session: Session):
        self.session = session

    def create_alert(self, alert: SecurityAlert) -> SecurityAlertModel:
        """Persist a complete Phase 4 SecurityAlert domain model without losing fidelity."""
        first_seen_dt = (
            datetime.fromtimestamp(alert.first_seen)
            if isinstance(alert.first_seen, (int, float))
            else alert.first_seen
        )
        last_seen_dt = (
            datetime.fromtimestamp(alert.last_seen)
            if isinstance(alert.last_seen, (int, float))
            else alert.last_seen
        )

        # Determine risk value and breakdown
        if hasattr(alert, "risk_score") and hasattr(alert.risk_score, "score"):
            risk_val = float(alert.risk_score.score)
            risk_breakdown = alert.risk_score.breakdown
        elif hasattr(alert, "risk_score") and isinstance(alert.risk_score, (int, float)):
            risk_val = float(alert.risk_score)
            risk_breakdown = None
        elif hasattr(alert, "risk") and hasattr(alert.risk, "score"):
            risk_val = float(alert.risk.score)
            risk_breakdown = getattr(alert.risk, "breakdown", None)
        else:
            risk_val = float(getattr(alert, "risk", 0.0))
            risk_breakdown = None

        threat_class_val = getattr(alert, "threat_class", None) or getattr(alert, "category", "UNKNOWN")
        if hasattr(threat_class_val, "value"):
            threat_class_val = threat_class_val.value
        else:
            threat_class_val = str(threat_class_val)

        corr_group_id = (
            getattr(alert, "correlation_group_id", None)
            or (alert.correlation_group.group_id if getattr(alert, "correlation_group", None) else None)
        )

        title_val = getattr(alert, "title", None) or f"Security Alert: {threat_class_val}"
        explanation_val = getattr(alert, "explanation", "")
        description_val = getattr(alert, "description", None) or explanation_val

        db_alert = SecurityAlertModel(
            alert_id=alert.alert_id,
            correlation_group_id=corr_group_id,
            threat_class=threat_class_val,
            severity=alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
            status=alert.status.value if hasattr(alert.status, "value") else str(alert.status),
            confidence=alert.confidence,
            risk_score=risk_val,
            risk_level=alert.severity.value if hasattr(alert.severity, "value") else "MEDIUM",
            risk_breakdown=risk_breakdown,
            mitre_attack=[alert.mitre_attack.model_dump(mode="json")] if getattr(alert, "mitre_attack", None) and hasattr(alert.mitre_attack, "model_dump") else None,
            title=title_val,
            description=description_val,
            explanation=explanation_val,
            flow_ids=getattr(alert, "flow_ids", []),
            first_seen=first_seen_dt,
            last_seen=last_seen_dt,
        )

        # Signals
        signals_list = getattr(alert, "contributing_signals", []) or getattr(alert, "signals", [])
        for sig in signals_list:
            sig_ts = (
                datetime.fromtimestamp(sig.timestamp)
                if isinstance(sig.timestamp, (int, float))
                else sig.timestamp
            )
            detector_name_val = getattr(sig, "detector_name", None) or getattr(sig, "detector_type", "RULE")
            sig_threat = getattr(sig, "threat_type", None) or getattr(sig, "threat_name", "THREAT")
            sig_sev = sig.severity.value if hasattr(sig.severity, "value") else str(sig.severity)
            db_sig = AlertSignalModel(
                alert_id=alert.alert_id,
                detection_id=sig.signal_id,
                flow_id=sig.flow_id,
                threat_type=str(sig_threat),
                severity=sig_sev,
                confidence=sig.confidence,
                detector_type=str(detector_name_val),
                timestamp=sig_ts,
            )
            db_alert.signals.append(db_sig)

        # Evidence
        for ev in alert.evidence:
            ev_desc = getattr(ev, "description", None) or f"Evidence from {getattr(ev, 'detector_name', 'detector')}"
            raw_vals = getattr(ev, "raw_indicators", {}) or getattr(ev, "triggered_features", {}) or getattr(ev, "raw_values", {})
            db_ev = AlertEvidenceModel(
                alert_id=alert.alert_id,
                signal_id=getattr(ev, "signal_id", None),
                evidence_type=getattr(ev, "detection_type", "rule"),
                description=ev_desc,
                raw_values=raw_vals,
                confidence=getattr(ev, "confidence_contribution", 1.0),
                weight=1.0,
            )
            db_alert.evidence_items.append(db_ev)

        # Entities
        for ent in getattr(alert, "entities", []):
            ent_type = ent.entity_type.value if hasattr(ent.entity_type, "value") else str(ent.entity_type)
            db_ent = AlertEntityModel(
                alert_id=alert.alert_id,
                entity_type=ent_type,
                identifier=ent.identifier,
                role=ent.role or "ENTITY",
                confidence=getattr(ent, "confidence", 1.0),
            )
            db_alert.entities.append(db_ent)

        if not db_alert.entities:
            if getattr(alert, "source_entity", None):
                se = alert.source_entity
                db_alert.entities.append(
                    AlertEntityModel(
                        alert_id=alert.alert_id,
                        entity_type=se.entity_type.value if hasattr(se.entity_type, "value") else str(se.entity_type),
                        identifier=se.identifier,
                        role=se.role or "SOURCE",
                        confidence=getattr(se, "confidence", 1.0),
                    )
                )
            elif getattr(alert, "source_ip", None):
                db_alert.entities.append(
                    AlertEntityModel(
                        alert_id=alert.alert_id,
                        entity_type="IP",
                        identifier=alert.source_ip,
                        role="SOURCE",
                        confidence=1.0,
                    )
                )
            if getattr(alert, "destination_entity", None):
                de = alert.destination_entity
                db_alert.entities.append(
                    AlertEntityModel(
                        alert_id=alert.alert_id,
                        entity_type=de.entity_type.value if hasattr(de.entity_type, "value") else str(de.entity_type),
                        identifier=de.identifier,
                        role=de.role or "DESTINATION",
                        confidence=getattr(de, "confidence", 1.0),
                    )
                )
            elif getattr(alert, "destination_ip", None):
                db_alert.entities.append(
                    AlertEntityModel(
                        alert_id=alert.alert_id,
                        entity_type="IP",
                        identifier=alert.destination_ip,
                        role="DESTINATION",
                        confidence=1.0,
                    )
                )

        now_dt = datetime.now(timezone.utc)
        # Initial lifecycle record
        initial_history = AlertLifecycleHistoryModel(
            alert_id=alert.alert_id,
            previous_status="NONE",
            new_status=db_alert.status,
            changed_at=now_dt,
            changed_by="system",
            notes="Alert generated by SentinelAI correlation engine",
        )
        db_alert.lifecycle_history.append(initial_history)

        self.session.add(db_alert)
        return db_alert

    def get_by_alert_id(self, alert_id: str) -> Optional[SecurityAlertModel]:
        """Fetch alert with full related signals, evidence, entities, and lifecycle history."""
        stmt = (
            select(SecurityAlertModel)
            .options(
                selectinload(SecurityAlertModel.signals),
                selectinload(SecurityAlertModel.evidence_items),
                selectinload(SecurityAlertModel.entities),
                selectinload(SecurityAlertModel.lifecycle_history),
            )
            .where(SecurityAlertModel.alert_id == alert_id)
        )
        return self.session.execute(stmt).scalar_one_or_none()

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
        """Query alerts with filtering, ordering, and pagination."""
        query = (
            select(SecurityAlertModel)
            .options(
                selectinload(SecurityAlertModel.signals),
                selectinload(SecurityAlertModel.evidence_items),
                selectinload(SecurityAlertModel.entities),
            )
        )
        count_query = select(func.count(SecurityAlertModel.id))

        if threat_class:
            query = query.where(SecurityAlertModel.threat_class == threat_class)
            count_query = count_query.where(SecurityAlertModel.threat_class == threat_class)
        if severity:
            query = query.where(SecurityAlertModel.severity == severity)
            count_query = count_query.where(SecurityAlertModel.severity == severity)
        if status:
            query = query.where(SecurityAlertModel.status == status)
            count_query = count_query.where(SecurityAlertModel.status == status)
        if min_confidence is not None:
            query = query.where(SecurityAlertModel.confidence >= min_confidence)
            count_query = count_query.where(SecurityAlertModel.confidence >= min_confidence)
        if max_confidence is not None:
            query = query.where(SecurityAlertModel.confidence <= max_confidence)
            count_query = count_query.where(SecurityAlertModel.confidence <= max_confidence)
        if min_risk is not None:
            query = query.where(SecurityAlertModel.risk_score >= min_risk)
            count_query = count_query.where(SecurityAlertModel.risk_score >= min_risk)
        if max_risk is not None:
            query = query.where(SecurityAlertModel.risk_score <= max_risk)
            count_query = count_query.where(SecurityAlertModel.risk_score <= max_risk)
        if start_time:
            query = query.where(SecurityAlertModel.created_at >= start_time)
            count_query = count_query.where(SecurityAlertModel.created_at >= start_time)
        if end_time:
            query = query.where(SecurityAlertModel.created_at <= end_time)
            count_query = count_query.where(SecurityAlertModel.created_at <= end_time)

        total = self.session.execute(count_query).scalar_one()

        order_col = getattr(SecurityAlertModel, sort_by, SecurityAlertModel.created_at)
        query = query.order_by(desc(order_col) if sort_desc else asc(order_col))
        query = query.limit(limit).offset(offset)

        results = list(self.session.execute(query).scalars().all())
        return results, total

    def update_lifecycle_status(
        self,
        alert_id: str,
        new_status: str,
        notes: Optional[str] = None,
        changed_by: str = "analyst",
    ) -> Optional[SecurityAlertModel]:
        """Update internal lifecycle status and record audit entry."""
        alert = self.get_by_alert_id(alert_id)
        if not alert:
            return None

        now_dt = datetime.now(timezone.utc)
        previous_status = alert.status
        alert.status = new_status
        alert.updated_at = now_dt

        history = AlertLifecycleHistoryModel(
            alert_id=alert_id,
            previous_status=previous_status,
            new_status=new_status,
            changed_at=now_dt,
            changed_by=changed_by,
            notes=notes,
        )
        alert.lifecycle_history.insert(0, history)
        self.session.flush()
        return alert

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Aggregate counts by status, severity, threat class, and mean risk score."""
        total_alerts = self.session.execute(select(func.count(SecurityAlertModel.id))).scalar_one() or 0
        avg_risk = self.session.execute(select(func.avg(SecurityAlertModel.risk_score))).scalar_one() or 0.0

        # By status
        status_stmt = select(SecurityAlertModel.status, func.count(SecurityAlertModel.id)).group_by(SecurityAlertModel.status)
        by_status = {row[0]: row[1] for row in self.session.execute(status_stmt).all()}

        # By severity
        sev_stmt = select(SecurityAlertModel.severity, func.count(SecurityAlertModel.id)).group_by(SecurityAlertModel.severity)
        by_severity = {row[0]: row[1] for row in self.session.execute(sev_stmt).all()}

        # By threat class
        threat_stmt = select(SecurityAlertModel.threat_class, func.count(SecurityAlertModel.id)).group_by(SecurityAlertModel.threat_class)
        by_threat_class = {row[0]: row[1] for row in self.session.execute(threat_stmt).all()}

        return {
            "total_alerts": total_alerts,
            "average_risk_score": round(float(avg_risk), 2),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_threat_class": by_threat_class,
        }

    def get_entity_statistics(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Identify top entities involved across alerts."""
        stmt = (
            select(
                AlertEntityModel.identifier,
                AlertEntityModel.entity_type,
                func.count(AlertEntityModel.id).label("alert_count"),
            )
            .group_by(AlertEntityModel.identifier, AlertEntityModel.entity_type)
            .order_by(desc("alert_count"))
            .limit(limit)
        )
        rows = self.session.execute(stmt).all()
        return [
            {
                "identifier": row[0],
                "entity_type": row[1],
                "alert_count": row[2],
            }
            for row in rows
        ]

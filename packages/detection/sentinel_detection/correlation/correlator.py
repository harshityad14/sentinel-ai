"""Stateful streaming alert correlation, deduplication, and lifecycle management engine."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from sentinel_detection.correlation.config import CorrelationConfig
from sentinel_detection.correlation.mitre_mapper import MitreAttackMapper
from sentinel_detection.scoring.risk_calculator import RiskCalculator
from sentinel_models.alerts import (
    AlertEntity,
    AlertEntityType,
    AlertEvidence,
    AlertSeverity,
    AlertSignal,
    AlertStatus,
    CorrelationGroup,
    SecurityAlert,
)
from sentinel_models.detection import DetectionEvidence, DetectionResult, DetectionSeverity


class AlertCorrelator:
    """Stateful streaming correlation engine that aggregates DetectionResults into SecurityAlerts."""

    def __init__(
        self,
        config: Optional[CorrelationConfig] = None,
        risk_calculator: Optional[RiskCalculator] = None,
    ) -> None:
        self.config = config or CorrelationConfig()
        self.risk_calculator = risk_calculator or RiskCalculator(self.config)

        # Active state caches (bounded)
        self._active_alerts: Dict[str, SecurityAlert] = {}
        self._dedup_index: Dict[str, str] = {}  # key -> alert_id
        self._correlation_groups: Dict[str, CorrelationGroup] = {}  # group_id -> CorrelationGroup
        self._entity_group_index: Dict[str, str] = {}  # src_ip -> group_id
        self._recurrence_tracker: Dict[str, int] = {}  # key -> count
        self._suppression_index: Dict[str, datetime] = {}  # key -> cooldown_expiry

    @property
    def active_alerts_count(self) -> int:
        """Count of currently retained active alerts."""
        return len(self._active_alerts)

    @property
    def active_groups_count(self) -> int:
        """Count of currently retained correlation groups."""
        return len(self._correlation_groups)

    def process_detection(
        self,
        detection: DetectionResult,
        timestamp: Optional[datetime] = None,
    ) -> Tuple[Optional[SecurityAlert], bool]:
        """Process a DetectionResult through temporal correlation and deduplication.

        Returns:
            Tuple of (SecurityAlert, is_new_alert).
            If detection is benign or suppressed, returns (None, False).
        """
        # Skip benign traffic flows
        if not detection.is_threat:
            return None, False

        now = timestamp or detection.detection_timestamp or datetime.now(timezone.utc)
        self.prune_expired(now)

        # Extract network entities from detection context
        src_ip = str(detection.context.get("source_ip", "0.0.0.0"))
        dst_ip = detection.context.get("destination_ip")
        src_port = detection.context.get("source_port")
        dst_port = detection.context.get("destination_port")
        proto = detection.context.get("protocol")

        src_entity = AlertEntity(
            entity_type=AlertEntityType.IP,
            identifier=src_ip,
            ip_address=src_ip,
            port=src_port,
            role="source",
        )
        dst_entity = (
            AlertEntity(
                entity_type=AlertEntityType.IP,
                identifier=str(dst_ip),
                ip_address=str(dst_ip),
                port=dst_port,
                role="destination",
            )
            if dst_ip
            else None
        )

        threat_name = detection.threat_type.value
        dedup_key = f"{src_ip}|{threat_name}"

        # 1. Check suppression / cooldown window
        cooldown_expiry = self._suppression_index.get(dedup_key)
        if cooldown_expiry and now < cooldown_expiry:
            return None, False

        # 2. Check deduplication for repeated identical detections within duplicate_window_sec
        existing_alert_id = self._dedup_index.get(dedup_key)
        if existing_alert_id and existing_alert_id in self._active_alerts:
            existing_alert = self._active_alerts[existing_alert_id]
            time_since_last = (now - existing_alert.last_seen).total_seconds()

            if 0 <= time_since_last <= self.config.duplicate_window_sec:
                # Merge into existing alert
                self._recurrence_tracker[dedup_key] = self._recurrence_tracker.get(dedup_key, 1) + 1
                recurrence = self._recurrence_tracker[dedup_key]

                existing_alert.last_seen = now
                if detection.flow_id not in existing_alert.flow_ids:
                    existing_alert.flow_ids.append(detection.flow_id)

                # Merge contributing signals up to max_signals_per_alert
                for sig in detection.signals:
                    if len(existing_alert.contributing_signals) < self.config.max_signals_per_alert:
                        alert_sig = AlertSignal(
                            signal_id=sig.signal_id,
                            flow_id=detection.flow_id,
                            threat_type=sig.threat_type.value,
                            detector_type=sig.detector_type.value,
                            detector_name=sig.detector_name,
                            confidence=sig.confidence,
                            severity=sig.severity.value,
                            timestamp=now,
                            description=sig.description,
                            evidence=[ev.model_dump() for ev in sig.evidence],
                            metadata=sig.metadata,
                        )
                        existing_alert.contributing_signals.append(alert_sig)

                    if sig.detector_type.value not in existing_alert.detector_types:
                        existing_alert.detector_types.append(sig.detector_type.value)

                # Merge evidence without duplicates
                seen_features = {ev.feature_name for ev in existing_alert.evidence if ev.feature_name}
                for ev in detection.evidence:
                    if ev.feature_name not in seen_features:
                        seen_features.add(ev.feature_name)
                        existing_alert.evidence.append(
                            self._convert_evidence(ev, detection.detector_type.value)
                        )

                # Transition to ACTIVE if still NEW
                if existing_alert.status == AlertStatus.NEW:
                    existing_alert.status = AlertStatus.ACTIVE

                # Recalculate dynamic risk score with updated volume & recurrence
                time_span = (existing_alert.last_seen - existing_alert.first_seen).total_seconds()
                existing_alert.risk_score = self.risk_calculator.calculate_risk(
                    confidence=existing_alert.confidence,
                    severity=existing_alert.severity,
                    detector_types=existing_alert.detector_types,
                    signal_count=len(existing_alert.contributing_signals),
                    recurrence_count=recurrence,
                    time_delta_sec=time_span,
                )

                return existing_alert, False

        # 3. New Alert Path: Link or create CorrelationGroup
        group_id = self._entity_group_index.get(src_ip)
        if group_id and group_id in self._correlation_groups:
            corr_group = self._correlation_groups[group_id]
            corr_group.last_seen = now
            corr_group.signal_count += len(detection.signals)
        else:
            group_id = f"grp_{uuid.uuid4().hex[:8]}"
            corr_group = CorrelationGroup(
                group_id=group_id,
                key=src_ip,
                correlation_type="TEMPORAL_ENTITY",
                first_seen=now,
                last_seen=now,
                signal_count=len(detection.signals),
                entities=[src_entity] + ([dst_entity] if dst_entity else []),
            )
            self._correlation_groups[group_id] = corr_group
            self._entity_group_index[src_ip] = group_id

        # Convert detection evidence into AlertEvidence
        alert_evidence: List[AlertEvidence] = [
            self._convert_evidence(ev, detection.detector_type.value)
            for ev in detection.evidence
        ]

        # Convert detection signals into AlertSignals
        alert_signals: List[AlertSignal] = [
            AlertSignal(
                signal_id=sig.signal_id,
                flow_id=detection.flow_id,
                threat_type=sig.threat_type.value,
                detector_type=sig.detector_type.value,
                detector_name=sig.detector_name,
                confidence=sig.confidence,
                severity=sig.severity.value,
                timestamp=now,
                description=sig.description,
                evidence=[ev.model_dump() for ev in sig.evidence],
                metadata=sig.metadata,
            )
            for sig in detection.signals
        ]

        detector_types = list({sig.detector_type.value for sig in detection.signals})
        if not detector_types:
            detector_types = [detection.detector_type.value]

        feature_refs = list({ev.feature_name for ev in detection.evidence if ev.feature_name})

        # Calculate initial risk score
        self._recurrence_tracker[dedup_key] = 1
        initial_risk = self.risk_calculator.calculate_risk(
            confidence=detection.confidence,
            severity=detection.severity,
            detector_types=detector_types,
            signal_count=max(1, len(detection.signals)),
            recurrence_count=1,
            time_delta_sec=0.0,
        )

        alert_id = f"alt_{uuid.uuid4().hex[:12]}"
        corr_group.alert_ids.append(alert_id)

        # Lookup static MITRE ATT&CK reference
        mitre_ref = MitreAttackMapper.get_mapping(detection.threat_type)

        # Map detection severity to AlertSeverity
        try:
            alert_sev = AlertSeverity(detection.severity.value)
        except (ValueError, AttributeError):
            alert_sev = AlertSeverity.MEDIUM

        alert = SecurityAlert(
            alert_id=alert_id,
            timestamp=now,
            first_seen=now,
            last_seen=now,
            flow_ids=[detection.flow_id],
            source_entity=src_entity,
            destination_entity=dst_entity,
            source_ip=src_ip,
            destination_ip=str(dst_ip) if dst_ip else None,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto,
            threat_class=threat_name,
            confidence=detection.confidence,
            severity=alert_sev,
            risk_score=initial_risk,
            evidence=alert_evidence,
            contributing_signals=alert_signals,
            correlation_group_id=group_id,
            status=AlertStatus.NEW,
            detector_types=detector_types,
            feature_references=feature_refs,
            mitre_attack=mitre_ref,
            explanation=detection.explanation,
            context=dict(detection.context),
        )

        # Register in active state
        self._active_alerts[alert_id] = alert
        self._dedup_index[dedup_key] = alert_id

        # Enforce bounded memory caps
        self._enforce_capacity_limits()

        return alert, True

    def _convert_evidence(self, ev: DetectionEvidence, det_type: str) -> AlertEvidence:
        """Translate DetectionEvidence into canonical AlertEvidence."""
        return AlertEvidence(
            detector_name=getattr(ev, "detector_name", "detection_engine"),
            detection_type=det_type.lower(),
            feature_name=ev.feature_name,
            observed_value=ev.observed_value,
            threshold_value=ev.threshold_value,
            confidence_contribution=0.0,
            correlation_reason="Threshold condition matched in telemetry feature vector",
            description=ev.description,
            triggered_features={ev.feature_name: ev.observed_value} if ev.feature_name else {},
        )

    def prune_expired(self, current_time: datetime) -> int:
        """Prune correlation groups and deduplication indices older than time_window_sec."""
        cutoff_sec = self.config.time_window_sec
        expired_groups: List[str] = []

        for gid, grp in self._correlation_groups.items():
            age = (current_time - grp.last_seen).total_seconds()
            if age > cutoff_sec:
                expired_groups.append(gid)

        for gid in expired_groups:
            grp = self._correlation_groups.pop(gid)
            if grp.key in self._entity_group_index:
                del self._entity_group_index[grp.key]

        # Prune dedup index for alerts whose last_seen exceeded duplicate window
        expired_dedup: List[str] = []
        for key, aid in self._dedup_index.items():
            if aid in self._active_alerts:
                alt = self._active_alerts[aid]
                if (current_time - alt.last_seen).total_seconds() > self.config.duplicate_window_sec:
                    expired_dedup.append(key)
            else:
                expired_dedup.append(key)

        for k in expired_dedup:
            del self._dedup_index[k]

        return len(expired_groups)

    def _enforce_capacity_limits(self) -> None:
        """Evict oldest entries when active alert or group capacities are breached."""
        # Cap active alerts
        if len(self._active_alerts) > self.config.max_active_alerts:
            # Sort by last_seen ascending (oldest first)
            sorted_alerts = sorted(self._active_alerts.values(), key=lambda a: a.last_seen)
            to_remove = sorted_alerts[: len(self._active_alerts) - self.config.max_active_alerts]
            for a in to_remove:
                del self._active_alerts[a.alert_id]

        # Cap correlation groups
        if len(self._correlation_groups) > self.config.max_active_groups:
            sorted_groups = sorted(self._correlation_groups.values(), key=lambda g: g.last_seen)
            to_remove_grp = sorted_groups[: len(self._correlation_groups) - self.config.max_active_groups]
            for g in to_remove_grp:
                del self._correlation_groups[g.group_id]
                if g.key in self._entity_group_index:
                    del self._entity_group_index[g.key]

    def acknowledge_alert(self, alert_id: str) -> Optional[SecurityAlert]:
        """Acknowledge an alert without active network side effects."""
        if alert_id in self._active_alerts:
            self._active_alerts[alert_id].update_status(AlertStatus.ACKNOWLEDGED)
            return self._active_alerts[alert_id]
        return None

    def resolve_alert(self, alert_id: str) -> Optional[SecurityAlert]:
        """Resolve an alert without active network side effects."""
        if alert_id in self._active_alerts:
            self._active_alerts[alert_id].update_status(AlertStatus.RESOLVED)
            return self._active_alerts[alert_id]
        return None

    def suppress_entity_threat(self, source_ip: str, threat_class: str, duration_sec: Optional[float] = None) -> None:
        """Manually or programmatically apply a cooldown suppression window."""
        cooldown = duration_sec or self.config.suppression_window_sec
        expiry = datetime.now(timezone.utc).timestamp() + cooldown
        key = f"{source_ip}|{threat_class}"
        self._suppression_index[key] = datetime.fromtimestamp(expiry, timezone.utc)

    def get_alert(self, alert_id: str) -> Optional[SecurityAlert]:
        """Lookup an alert by ID."""
        return self._active_alerts.get(alert_id)

    def get_active_alerts(self) -> List[SecurityAlert]:
        """Return all currently active security alerts."""
        return list(self._active_alerts.values())

    def get_correlation_group(self, group_id: str) -> Optional[CorrelationGroup]:
        """Lookup a correlation group by ID."""
        return self._correlation_groups.get(group_id)

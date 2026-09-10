"""Security Alert and related lifecycle/evidence SQLAlchemy models."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    DateTime,
    JSON,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship

from app.db.base import Base


class SecurityAlertModel(Base):
    """High-fidelity correlated security alert."""

    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, nullable=False, index=True)
    correlation_group_id = Column(String(64), nullable=True, index=True)
    threat_class = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="NEW", index=True)
    confidence = Column(Float, nullable=False, index=True)
    risk_score = Column(Float, nullable=False, index=True)
    risk_level = Column(String(32), nullable=False, index=True)

    risk_breakdown = Column(JSON, nullable=True)
    mitre_attack = Column(JSON, nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    explanation = Column(Text, nullable=True)
    flow_ids = Column(JSON, nullable=True)

    first_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    last_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    signals = relationship(
        "AlertSignalModel",
        back_populates="alert",
        cascade="all, delete-orphan",
    )
    evidence_items = relationship(
        "AlertEvidenceModel",
        back_populates="alert",
        cascade="all, delete-orphan",
    )
    entities = relationship(
        "AlertEntityModel",
        back_populates="alert",
        cascade="all, delete-orphan",
    )
    lifecycle_history = relationship(
        "AlertLifecycleHistoryModel",
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="AlertLifecycleHistoryModel.changed_at.desc()",
    )

    __table_args__ = (
        Index("ix_alerts_status_sev", "status", "severity"),
        Index("ix_alerts_threat_risk", "threat_class", "risk_score"),
        Index("ix_alerts_time_status", "created_at", "status"),
    )


class AlertSignalModel(Base):
    """Detection signals contributing to an alert."""

    __tablename__ = "alert_signals"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(
        String(64),
        ForeignKey("security_alerts.alert_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    detection_id = Column(String(64), nullable=False, index=True)
    flow_id = Column(String(64), nullable=True, index=True)
    threat_type = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False)
    confidence = Column(Float, nullable=False)
    detector_type = Column(String(64), nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)

    alert = relationship("SecurityAlertModel", back_populates="signals")


class AlertEvidenceModel(Base):
    """Corroborating evidence attached to an alert."""

    __tablename__ = "alert_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(
        String(64),
        ForeignKey("security_alerts.alert_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    signal_id = Column(String(64), nullable=True, index=True)
    evidence_type = Column(String(64), nullable=False)
    description = Column(Text, nullable=False)
    raw_values = Column(JSON, nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    weight = Column(Float, nullable=False, default=1.0)

    alert = relationship("SecurityAlertModel", back_populates="evidence_items")


class AlertEntityModel(Base):
    """Entities (IPs, domains, endpoints) involved in an alert."""

    __tablename__ = "alert_entities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(
        String(64),
        ForeignKey("security_alerts.alert_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    entity_type = Column(String(32), nullable=False, index=True)
    identifier = Column(String(255), nullable=False, index=True)
    role = Column(String(32), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=1.0)

    alert = relationship("SecurityAlertModel", back_populates="entities")

    __table_args__ = (
        Index("ix_entity_type_identifier", "entity_type", "identifier"),
    )


class AlertLifecycleHistoryModel(Base):
    """Audit trail of internal alert state transitions (acknowledged, resolved, etc.)."""

    __tablename__ = "alert_lifecycle_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(
        String(64),
        ForeignKey("security_alerts.alert_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    previous_status = Column(String(32), nullable=False)
    new_status = Column(String(32), nullable=False)
    changed_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    changed_by = Column(String(64), nullable=False, default="system")
    notes = Column(Text, nullable=True)

    alert = relationship("SecurityAlertModel", back_populates="lifecycle_history")

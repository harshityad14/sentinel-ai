"""Detection and Detection Evidence SQLAlchemy models."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    Text,
    DateTime,
    JSON,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship

from app.db.base import Base


class DetectionModel(Base):
    """Detection result generated from Phase 3 detector pipelines."""

    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detection_id = Column(String(64), unique=True, nullable=False, index=True)
    flow_id = Column(String(64), nullable=False, index=True)
    threat_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    confidence = Column(Float, nullable=False, index=True)
    is_threat = Column(Boolean, nullable=False, default=True, index=True)
    detector_name = Column(String(64), nullable=False, index=True)
    explanation = Column(Text, nullable=True)
    context_json = Column(JSON, nullable=True)

    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    evidence_items = relationship(
        "DetectionEvidenceModel",
        back_populates="detection",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_detections_threat_time", "threat_type", "timestamp"),
        Index("ix_detections_flow_threat", "flow_id", "threat_type"),
    )


class DetectionEvidenceModel(Base):
    """Detailed feature-level evidence supporting a detection."""

    __tablename__ = "detection_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detection_id = Column(
        String(64),
        ForeignKey("detections.detection_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    feature_name = Column(String(128), nullable=False)
    observed_value = Column(Float, nullable=False)
    threshold = Column(Float, nullable=True)
    score = Column(Float, nullable=False, default=0.0)
    contribution = Column(Float, nullable=False, default=0.0)
    description = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    detection = relationship("DetectionModel", back_populates="evidence_items")

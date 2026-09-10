"""Correlation Group SQLAlchemy model."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    JSON,
    Index,
)
from app.db.base import Base


class CorrelationGroupModel(Base):
    """Correlation group representing aggregated threat signals across time/entities."""

    __tablename__ = "correlation_groups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    group_id = Column(String(64), unique=True, nullable=False, index=True)
    primary_entity = Column(String(255), nullable=False, index=True)
    threat_type = Column(String(64), nullable=False, index=True)
    first_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    last_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    alert_count = Column(Integer, nullable=False, default=0)
    signal_count = Column(Integer, nullable=False, default=0)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_corr_entity_threat", "primary_entity", "threat_type"),
    )

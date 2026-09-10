"""Flow and Flow Feature SQLAlchemy models."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    BigInteger,
    String,
    Float,
    Boolean,
    DateTime,
    JSON,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship

from app.db.base import Base


class FlowModel(Base):
    """Persisted bidirectional network flow record."""

    __tablename__ = "flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    flow_id = Column(String(64), unique=True, nullable=False, index=True)
    start_time = Column(DateTime(timezone=True), nullable=False, index=True)
    end_time = Column(DateTime(timezone=True), nullable=False, index=True)
    duration = Column(Float, nullable=False, default=0.0)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=False, index=True)
    dst_port = Column(Integer, nullable=False, index=True)
    protocol = Column(String(16), nullable=False, index=True)

    packet_count = Column(BigInteger, nullable=False, default=0)
    byte_count = Column(BigInteger, nullable=False, default=0)
    packets_fwd = Column(BigInteger, nullable=False, default=0)
    packets_bwd = Column(BigInteger, nullable=False, default=0)
    bytes_fwd = Column(BigInteger, nullable=False, default=0)
    bytes_bwd = Column(BigInteger, nullable=False, default=0)
    is_bidirectional = Column(Boolean, nullable=False, default=False)

    metadata_json = Column(JSON, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    features = relationship(
        "FlowFeatureModel",
        back_populates="flow",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_flows_time_range", "start_time", "end_time"),
        Index("ix_flows_endpoints", "src_ip", "dst_ip", "dst_port"),
    )


class FlowFeatureModel(Base):
    """Extracted statistical and protocol feature vectors."""

    __tablename__ = "flow_features"

    id = Column(Integer, primary_key=True, autoincrement=True)
    flow_id = Column(
        String(64),
        ForeignKey("flows.flow_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    features = Column(JSON, nullable=False)
    status = Column(String(32), nullable=False, default="COMPUTED")
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    flow = relationship("FlowModel", back_populates="features")

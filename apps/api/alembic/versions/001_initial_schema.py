"""Initial schema migration for SentinelAI.

Revision ID: 001_initial_schema
Revises: None
Create Date: 2026-09-10 18:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Flows table
    op.create_table(
        "flows",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("flow_id", sa.String(length=64), nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_ip", sa.String(length=45), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("packet_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("byte_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("packets_fwd", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("packets_bwd", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("bytes_fwd", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("bytes_bwd", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("is_bidirectional", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("flow_id"),
    )
    op.create_index("ix_flows_flow_id", "flows", ["flow_id"])
    op.create_index("ix_flows_start_time", "flows", ["start_time"])
    op.create_index("ix_flows_end_time", "flows", ["end_time"])
    op.create_index("ix_flows_src_ip", "flows", ["src_ip"])
    op.create_index("ix_flows_dst_ip", "flows", ["dst_ip"])
    op.create_index("ix_flows_src_port", "flows", ["src_port"])
    op.create_index("ix_flows_dst_port", "flows", ["dst_port"])
    op.create_index("ix_flows_protocol", "flows", ["protocol"])
    op.create_index("ix_flows_created_at", "flows", ["created_at"])
    op.create_index("ix_flows_time_range", "flows", ["start_time", "end_time"])
    op.create_index("ix_flows_endpoints", "flows", ["src_ip", "dst_ip", "dst_port"])

    # 2. Flow features table
    op.create_table(
        "flow_features",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("flow_id", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="COMPUTED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["flow_id"], ["flows.flow_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_flow_features_flow_id", "flow_features", ["flow_id"])
    op.create_index("ix_flow_features_timestamp", "flow_features", ["timestamp"])

    # 3. Detections table
    op.create_table(
        "detections",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("detection_id", sa.String(length=64), nullable=False),
        sa.Column("flow_id", sa.String(length=64), nullable=False),
        sa.Column("threat_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("is_threat", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("detector_name", sa.String(length=64), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("context_json", sa.JSON(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("detection_id"),
    )
    op.create_index("ix_detections_detection_id", "detections", ["detection_id"])
    op.create_index("ix_detections_flow_id", "detections", ["flow_id"])
    op.create_index("ix_detections_threat_type", "detections", ["threat_type"])
    op.create_index("ix_detections_severity", "detections", ["severity"])
    op.create_index("ix_detections_confidence", "detections", ["confidence"])
    op.create_index("ix_detections_is_threat", "detections", ["is_threat"])
    op.create_index("ix_detections_detector_name", "detections", ["detector_name"])
    op.create_index("ix_detections_timestamp", "detections", ["timestamp"])
    op.create_index("ix_detections_threat_time", "detections", ["threat_type", "timestamp"])
    op.create_index("ix_detections_flow_threat", "detections", ["flow_id", "threat_type"])

    # 4. Detection evidence table
    op.create_table(
        "detection_evidence",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("detection_id", sa.String(length=64), nullable=False),
        sa.Column("feature_name", sa.String(length=128), nullable=False),
        sa.Column("observed_value", sa.Float(), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=True),
        sa.Column("score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("contribution", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["detection_id"], ["detections.detection_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_detection_evidence_detection_id", "detection_evidence", ["detection_id"])

    # 5. Correlation groups table
    op.create_table(
        "correlation_groups",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("group_id", sa.String(length=64), nullable=False),
        sa.Column("primary_entity", sa.String(length=255), nullable=False),
        sa.Column("threat_type", sa.String(length=64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("signal_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_id"),
    )
    op.create_index("ix_correlation_groups_group_id", "correlation_groups", ["group_id"])
    op.create_index("ix_correlation_groups_primary_entity", "correlation_groups", ["primary_entity"])
    op.create_index("ix_correlation_groups_threat_type", "correlation_groups", ["threat_type"])
    op.create_index("ix_correlation_groups_first_seen", "correlation_groups", ["first_seen"])
    op.create_index("ix_correlation_groups_last_seen", "correlation_groups", ["last_seen"])
    op.create_index("ix_corr_entity_threat", "correlation_groups", ["primary_entity", "threat_type"])

    # 6. Security alerts table
    op.create_table(
        "security_alerts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("correlation_group_id", sa.String(length=64), nullable=True),
        sa.Column("threat_class", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="NEW"),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("risk_breakdown", sa.JSON(), nullable=True),
        sa.Column("mitre_attack", sa.JSON(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("flow_ids", sa.JSON(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_id"),
    )
    op.create_index("ix_security_alerts_alert_id", "security_alerts", ["alert_id"])
    op.create_index("ix_security_alerts_correlation_group_id", "security_alerts", ["correlation_group_id"])
    op.create_index("ix_security_alerts_threat_class", "security_alerts", ["threat_class"])
    op.create_index("ix_security_alerts_severity", "security_alerts", ["severity"])
    op.create_index("ix_security_alerts_status", "security_alerts", ["status"])
    op.create_index("ix_security_alerts_confidence", "security_alerts", ["confidence"])
    op.create_index("ix_security_alerts_risk_score", "security_alerts", ["risk_score"])
    op.create_index("ix_security_alerts_risk_level", "security_alerts", ["risk_level"])
    op.create_index("ix_security_alerts_first_seen", "security_alerts", ["first_seen"])
    op.create_index("ix_security_alerts_last_seen", "security_alerts", ["last_seen"])
    op.create_index("ix_security_alerts_created_at", "security_alerts", ["created_at"])
    op.create_index("ix_alerts_status_sev", "security_alerts", ["status", "severity"])
    op.create_index("ix_alerts_threat_risk", "security_alerts", ["threat_class", "risk_score"])
    op.create_index("ix_alerts_time_status", "security_alerts", ["created_at", "status"])

    # 7. Alert signals table
    op.create_table(
        "alert_signals",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("detection_id", sa.String(length=64), nullable=False),
        sa.Column("flow_id", sa.String(length=64), nullable=True),
        sa.Column("threat_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("detector_type", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.alert_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_signals_alert_id", "alert_signals", ["alert_id"])
    op.create_index("ix_alert_signals_detection_id", "alert_signals", ["detection_id"])
    op.create_index("ix_alert_signals_flow_id", "alert_signals", ["flow_id"])

    # 8. Alert evidence table
    op.create_table(
        "alert_evidence",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("signal_id", sa.String(length=64), nullable=True),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("raw_values", sa.JSON(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.alert_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_evidence_alert_id", "alert_evidence", ["alert_id"])
    op.create_index("ix_alert_evidence_signal_id", "alert_evidence", ["signal_id"])

    # 9. Alert entities table
    op.create_table(
        "alert_entities",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("identifier", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.alert_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_entities_alert_id", "alert_entities", ["alert_id"])
    op.create_index("ix_alert_entities_entity_type", "alert_entities", ["entity_type"])
    op.create_index("ix_alert_entities_identifier", "alert_entities", ["identifier"])
    op.create_index("ix_alert_entities_role", "alert_entities", ["role"])
    op.create_index("ix_entity_type_identifier", "alert_entities", ["entity_type", "identifier"])

    # 10. Alert lifecycle history table
    op.create_table(
        "alert_lifecycle_history",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("previous_status", sa.String(length=32), nullable=False),
        sa.Column("new_status", sa.String(length=32), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("changed_by", sa.String(length=64), nullable=False, server_default="system"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.alert_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_lifecycle_history_alert_id", "alert_lifecycle_history", ["alert_id"])
    op.create_index("ix_alert_lifecycle_history_changed_at", "alert_lifecycle_history", ["changed_at"])


def downgrade() -> None:
    op.drop_table("alert_lifecycle_history")
    op.drop_table("alert_entities")
    op.drop_table("alert_evidence")
    op.drop_table("alert_signals")
    op.drop_table("security_alerts")
    op.drop_table("correlation_groups")
    op.drop_table("detection_evidence")
    op.drop_table("detections")
    op.drop_table("flow_features")
    op.drop_table("flows")

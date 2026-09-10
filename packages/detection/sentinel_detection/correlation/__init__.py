"""SentinelAI correlation, deduplication, and ensemble detection engine."""

from sentinel_detection.correlation.config import CorrelationConfig
from sentinel_detection.correlation.correlator import AlertCorrelator
from sentinel_detection.correlation.ensemble import EnsembleCorrelationEngine
from sentinel_detection.correlation.mitre_mapper import MitreAttackMapper

__all__ = [
    "CorrelationConfig",
    "AlertCorrelator",
    "EnsembleCorrelationEngine",
    "MitreAttackMapper",
]

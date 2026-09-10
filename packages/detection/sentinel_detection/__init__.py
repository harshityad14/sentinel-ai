"""SentinelAI Hybrid Threat Detection Engine."""

from sentinel_detection.base import BaseDetector
from sentinel_detection.correlation.ensemble import EnsembleCorrelationEngine
from sentinel_detection.ml.model_metadata import MLModelMetadata
from sentinel_detection.ml.random_forest_detector import RandomForestMLDetector
from sentinel_detection.pipeline import DetectionPipeline, create_default_detection_pipeline
from sentinel_detection.rules import (
    C2BeaconingRuleDetector,
    DataExfiltrationRuleDetector,
    DNSDGARuleDetector,
    DNSTunnelingRuleDetector,
    PortScanRuleDetector,
    SuspiciousTLSRuleDetector,
    SYNFloodRuleDetector,
    UDPFloodRuleDetector,
)
from sentinel_detection.scoring.severity_policy import BASELINE_SEVERITY, evaluate_severity
from sentinel_detection.statistical.anomaly_detector import StatisticalAnomalyDetector

__all__ = [
    "BaseDetector",
    "DetectionPipeline",
    "create_default_detection_pipeline",
    "EnsembleCorrelationEngine",
    "evaluate_severity",
    "BASELINE_SEVERITY",
    "SYNFloodRuleDetector",
    "UDPFloodRuleDetector",
    "PortScanRuleDetector",
    "DNSDGARuleDetector",
    "DNSTunnelingRuleDetector",
    "C2BeaconingRuleDetector",
    "DataExfiltrationRuleDetector",
    "SuspiciousTLSRuleDetector",
    "StatisticalAnomalyDetector",
    "RandomForestMLDetector",
    "MLModelMetadata",
]

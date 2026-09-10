"""Hybrid threat detection pipeline orchestrating rules, statistical, and ML detectors."""

from typing import Any, Dict, List, Optional
from sentinel_detection.base import BaseDetector
from sentinel_detection.correlation.ensemble import EnsembleCorrelationEngine
from sentinel_detection.ml.random_forest_detector import RandomForestMLDetector
from sentinel_detection.rules.c2_beaconing import C2BeaconingRuleDetector
from sentinel_detection.rules.data_exfiltration import DataExfiltrationRuleDetector
from sentinel_detection.rules.dns_dga import DNSDGARuleDetector
from sentinel_detection.rules.dns_tunneling import DNSTunnelingRuleDetector
from sentinel_detection.rules.port_scan import PortScanRuleDetector
from sentinel_detection.rules.suspicious_tls import SuspiciousTLSRuleDetector
from sentinel_detection.rules.syn_flood import SYNFloodRuleDetector
from sentinel_detection.rules.udp_flood import UDPFloodRuleDetector
from sentinel_detection.statistical.anomaly_detector import StatisticalAnomalyDetector
from sentinel_models.detection import DetectionResult, DetectionSignal
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class DetectionPipeline:
    """Orchestrates modular threat detectors and correlates outputs into unified results."""

    def __init__(
        self,
        detectors: Optional[List[BaseDetector]] = None,
        ensemble_engine: Optional[EnsembleCorrelationEngine] = None,
    ) -> None:
        self._detectors: Dict[str, BaseDetector] = {}
        self.ensemble_engine = ensemble_engine or EnsembleCorrelationEngine()

        if detectors:
            for d in detectors:
                self.register_detector(d)

    @property
    def registered_detectors(self) -> List[BaseDetector]:
        """Return list of all registered detector instances."""
        return list(self._detectors.values())

    def register_detector(self, detector: BaseDetector) -> None:
        """Register a new or custom detector instance."""
        self._detectors[detector.detector_name] = detector

    def get_detector(self, detector_name: str) -> Optional[BaseDetector]:
        """Lookup a registered detector by name."""
        return self._detectors.get(detector_name)

    def enable_detector(self, detector_name: str) -> bool:
        """Enable an individual detector."""
        if detector_name in self._detectors:
            self._detectors[detector_name].enabled = True
            return True
        return False

    def disable_detector(self, detector_name: str) -> bool:
        """Disable an individual detector for false positive suppression or performance."""
        if detector_name in self._detectors:
            self._detectors[detector_name].enabled = False
            return True
        return False

    def analyze(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> DetectionResult:
        """Analyze a flow and its feature vector against all active detectors.
        
        Collects individual signals and correlates them via the ensemble layer.
        """
        signals: List[DetectionSignal] = []

        for detector in self._detectors.values():
            if not detector.enabled:
                continue

            try:
                sig = detector.detect(flow, features, context)
                if sig is not None:
                    signals.append(sig)
            except Exception as e:
                # Detection failures in an individual detector must never crash the pipeline
                # In production logging this would be captured as a detector fault metric
                continue

        # Ensemble correlation across all accumulated signals
        return self.ensemble_engine.correlate(flow, features, signals, context)


def create_default_detection_pipeline() -> DetectionPipeline:
    """Factory creating a fully initialized default hybrid detection engine."""
    pipeline = DetectionPipeline()

    # 1. Deterministic baseline rules (8 detectors)
    pipeline.register_detector(SYNFloodRuleDetector())
    pipeline.register_detector(UDPFloodRuleDetector())
    pipeline.register_detector(PortScanRuleDetector())
    pipeline.register_detector(DNSDGARuleDetector())
    pipeline.register_detector(DNSTunnelingRuleDetector())
    pipeline.register_detector(C2BeaconingRuleDetector())
    pipeline.register_detector(DataExfiltrationRuleDetector())
    pipeline.register_detector(SuspiciousTLSRuleDetector())

    # 2. Statistical / Anomaly profiling (1 detector)
    pipeline.register_detector(StatisticalAnomalyDetector())

    # 3. Supervised ML Classifier (1 detector)
    pipeline.register_detector(RandomForestMLDetector())

    return pipeline

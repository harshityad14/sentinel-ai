"""DNS Domain Generation Algorithm (DGA) rule-based detector."""

from typing import Any, Dict, Optional
from sentinel_detection.base import BaseDetector
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class DNSDGARuleDetector(BaseDetector):
    """Detects algorithmically generated domain names (DGA) via entropy and lexical features."""

    def __init__(
        self,
        min_entropy: float = 3.65,
        min_digit_ratio: float = 0.15,
        min_query_length: int = 12,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            min_entropy=min_entropy,
            min_digit_ratio=min_digit_ratio,
            min_query_length=min_query_length,
        )
        self.min_entropy = min_entropy
        self.min_digit_ratio = min_digit_ratio
        self.min_query_length = min_query_length

    @property
    def detector_name(self) -> str:
        return "dns_dga_rule"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.RULE

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.DNS_DGA

    def detect(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        if not self.enabled or features.dns is None:
            return None

        dns = features.dns
        qlen = dns.query_length
        entropy = dns.shannon_entropy
        d_ratio = dns.digit_ratio
        is_nx = dns.is_nxdomain

        # DGA indicators: high Shannon entropy + presence of digits or NXDOMAIN + minimum length
        if (entropy >= self.min_entropy and qlen >= self.min_query_length) and (
            d_ratio >= self.min_digit_ratio or is_nx
        ):
            confidence = min(0.95, 0.70 + (entropy - self.min_entropy) * 0.20 + (0.10 if is_nx else 0.0))
            severity = DetectionSeverity.HIGH if is_nx else DetectionSeverity.MEDIUM

            evidence = [
                DetectionEvidence(
                    feature_name="dns_shannon_entropy",
                    observed_value=entropy,
                    threshold_value=self.min_entropy,
                    description=f"High Shannon entropy ({entropy:.3f} bits/symbol) indicates non-natural string",
                ),
                DetectionEvidence(
                    feature_name="dns_query_length",
                    observed_value=qlen,
                    threshold_value=self.min_query_length,
                    description=f"Query string length ({qlen} chars)",
                ),
                DetectionEvidence(
                    feature_name="dns_digit_ratio",
                    observed_value=d_ratio,
                    threshold_value=self.min_digit_ratio,
                    description=f"Elevated digit ratio ({d_ratio:.2%}) in domain labels",
                ),
            ]
            if is_nx:
                evidence.append(
                    DetectionEvidence(
                        feature_name="dns_is_nxdomain",
                        observed_value=True,
                        threshold_value=True,
                        description="Query resulted in NXDOMAIN (domain non-existent)",
                    )
                )

            qname = flow.dns_context.query_name if flow.dns_context else "unknown"

            return DetectionSignal(
                signal_id=self._generate_signal_id(),
                threat_type=self.threat_type,
                detector_type=self.detector_type,
                detector_name=self.detector_name,
                confidence=round(confidence, 4),
                severity=severity,
                evidence=evidence,
                description=f"Algorithmic DGA domain query detected: {qname}",
                metadata={"query_name": qname, "entropy": entropy},
            )

        return None

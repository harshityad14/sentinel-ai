"""DNS Data Exfiltration & Tunneling rule-based detector."""

from typing import Any, Dict, Optional
from sentinel_detection.base import BaseDetector
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class DNSTunnelingRuleDetector(BaseDetector):
    """Detects DNS covert data tunneling based on query length, subdomain depth, and label characteristics."""

    def __init__(
        self,
        min_query_length: int = 35,
        min_subdomain_depth: int = 3,
        min_unique_char_ratio: float = 0.65,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            min_query_length=min_query_length,
            min_subdomain_depth=min_subdomain_depth,
            min_unique_char_ratio=min_unique_char_ratio,
        )
        self.min_query_length = min_query_length
        self.min_subdomain_depth = min_subdomain_depth
        self.min_unique_char_ratio = min_unique_char_ratio

    @property
    def detector_name(self) -> str:
        return "dns_tunneling_rule"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.RULE

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.DNS_TUNNELING

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
        depth = dns.subdomain_depth
        u_ratio = dns.unique_char_ratio

        # Tunneling signatures: exceptionally long queries with deep subdomains encoding binary data
        if qlen >= self.min_query_length and depth >= self.min_subdomain_depth and u_ratio >= self.min_unique_char_ratio:
            confidence = min(0.96, 0.75 + (qlen / 100.0) * 0.20)
            severity = DetectionSeverity.HIGH

            evidence = [
                DetectionEvidence(
                    feature_name="dns_query_length",
                    observed_value=qlen,
                    threshold_value=self.min_query_length,
                    description=f"Anomalously long DNS query name ({qlen} characters)",
                ),
                DetectionEvidence(
                    feature_name="dns_subdomain_depth",
                    observed_value=depth,
                    threshold_value=self.min_subdomain_depth,
                    description=f"Deep subdomain hierarchy ({depth} labels) typical of encoded data chunks",
                ),
                DetectionEvidence(
                    feature_name="dns_unique_char_ratio",
                    observed_value=u_ratio,
                    threshold_value=self.min_unique_char_ratio,
                    description=f"High character diversity ({u_ratio:.2%}) indicative of base64/hex payload encoding",
                ),
            ]

            qname = flow.dns_context.query_name if flow.dns_context else "unknown"

            return DetectionSignal(
                signal_id=self._generate_signal_id(),
                threat_type=self.threat_type,
                detector_type=self.detector_type,
                detector_name=self.detector_name,
                confidence=round(confidence, 4),
                severity=severity,
                evidence=evidence,
                description=f"Covert DNS tunneling / data exfiltration query pattern: {qname}",
                metadata={"query_name": qname, "query_length": qlen, "depth": depth},
            )

        return None

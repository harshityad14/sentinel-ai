"""Suspicious TLS metadata passive rule-based detector."""

from typing import Any, Dict, List, Optional, Set
from sentinel_detection.base import BaseDetector
from sentinel_models.detection import DetectionEvidence, DetectionSeverity, DetectionSignal, DetectorType, ThreatType
from sentinel_models.events import FlowRecord
from sentinel_models.features import FeatureVector


class SuspiciousTLSRuleDetector(BaseDetector):
    """Detects suspicious or anomalous passive TLS metadata and fingerprints."""

    DEPRECATED_TLS_VERSIONS = {
        "SSL 2.0",
        "SSL 3.0",
        "TLS 1.0",
        "TLS 1.1",
        "0x0200",
        "0x0300",
        "0x0301",
        "0x0302",
    }

    def __init__(
        self,
        flag_deprecated_versions: bool = True,
        flag_missing_sni_on_443: bool = True,
        min_cipher_suites: int = 2,
        suspicious_ja3_hashes: Optional[Set[str]] = None,
        suspicious_ja4_hashes: Optional[Set[str]] = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(
            enabled=enabled,
            flag_deprecated_versions=flag_deprecated_versions,
            flag_missing_sni_on_443=flag_missing_sni_on_443,
            min_cipher_suites=min_cipher_suites,
        )
        self.flag_deprecated_versions = flag_deprecated_versions
        self.flag_missing_sni_on_443 = flag_missing_sni_on_443
        self.min_cipher_suites = min_cipher_suites
        self.suspicious_ja3_hashes = suspicious_ja3_hashes or set()
        self.suspicious_ja4_hashes = suspicious_ja4_hashes or set()

    @property
    def detector_name(self) -> str:
        return "suspicious_tls_rule"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.RULE

    @property
    def threat_type(self) -> ThreatType:
        return ThreatType.SUSPICIOUS_TLS

    def detect(
        self,
        flow: FlowRecord,
        features: FeatureVector,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DetectionSignal]:
        if not self.enabled or features.tls is None:
            return None

        tls = features.tls
        evidence: List[DetectionEvidence] = []
        findings: List[str] = []

        # 1. Deprecated TLS version check
        if self.flag_deprecated_versions and tls.tls_version:
            if tls.tls_version in self.DEPRECATED_TLS_VERSIONS or any(
                dep in tls.tls_version for dep in ["TLS 1.0", "TLS 1.1", "SSL"]
            ):
                findings.append("deprecated_tls_version")
                evidence.append(
                    DetectionEvidence(
                        feature_name="tls_version",
                        observed_value=tls.tls_version,
                        threshold_value="TLS 1.2+",
                        description=f"Deprecated or insecure TLS version: {tls.tls_version} (RFC 8996)",
                    )
                )

        # 2. Missing SNI on port 443 (HTTPS)
        dst_port = flow.destination_port
        if self.flag_missing_sni_on_443 and dst_port == 443 and not tls.sni_present:
            findings.append("missing_sni_on_https")
            evidence.append(
                DetectionEvidence(
                    feature_name="sni_present",
                    observed_value=False,
                    threshold_value=True,
                    description="ClientHello lacks Server Name Indication (SNI) on standard HTTPS port 443",
                )
            )

        # 3. Abnormally low cipher suites
        if self.min_cipher_suites > 0 and 0 < tls.cipher_suite_count < self.min_cipher_suites:
            findings.append("minimal_cipher_suites")
            evidence.append(
                DetectionEvidence(
                    feature_name="cipher_suite_count",
                    observed_value=tls.cipher_suite_count,
                    threshold_value=self.min_cipher_suites,
                    description=f"Unusually low cipher suite count: {tls.cipher_suite_count}",
                )
            )

        # 4. Known suspicious JA3 hash
        if tls.ja3_hash and tls.ja3_hash in self.suspicious_ja3_hashes:
            findings.append("suspicious_ja3")
            evidence.append(
                DetectionEvidence(
                    feature_name="ja3_hash",
                    observed_value=tls.ja3_hash,
                    threshold_value="blacklist_match",
                    description=f"Client JA3 fingerprint matches suspicious threat signature: {tls.ja3_hash}",
                )
            )

        # 5. Known suspicious JA4 hash
        if tls.ja4_hash and tls.ja4_hash in self.suspicious_ja4_hashes:
            findings.append("suspicious_ja4")
            evidence.append(
                DetectionEvidence(
                    feature_name="ja4_hash",
                    observed_value=tls.ja4_hash,
                    threshold_value="blacklist_match",
                    description=f"Client JA4 fingerprint matches suspicious threat signature: {tls.ja4_hash}",
                )
            )

        if not findings:
            return None

        # Determine confidence and severity based on number and nature of findings
        confidence = min(0.95, 0.70 + (len(findings) - 1) * 0.10)

        if "suspicious_ja3" in findings or "suspicious_ja4" in findings:
            severity = DetectionSeverity.HIGH
            confidence = max(confidence, 0.90)
        elif len(findings) >= 2:
            severity = DetectionSeverity.HIGH
        elif "deprecated_tls_version" in findings:
            severity = DetectionSeverity.MEDIUM
        else:
            severity = DetectionSeverity.LOW

        return DetectionSignal(
            signal_id=self._generate_signal_id(),
            threat_type=ThreatType.SUSPICIOUS_TLS,
            detector_type=DetectorType.RULE,
            detector_name=self.detector_name,
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            description=f"Passive TLS anomaly detected: {', '.join(findings)}",
            metadata={
                "tls_version": tls.tls_version,
                "sni_present": tls.sni_present,
                "cipher_suite_count": tls.cipher_suite_count,
                "ja3_present": tls.ja3_present,
                "ja4_present": tls.ja4_present,
                "findings": findings,
            },
        )

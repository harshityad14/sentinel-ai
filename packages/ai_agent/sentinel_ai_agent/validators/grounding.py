"""Authoritative multi-entity grounding validator and auditable validation logger."""

import re
from typing import Any, Dict, List, Optional, Set

from sentinel_models.ai_analyst import (
    AlertAnalysisReport,
    AnalystQuestionResponse,
    AuditableValidationLog,
    GroundingStatus,
    UncertaintyIndicator,
)
from sentinel_models.alerts import SecurityAlert
from sentinel_models.events import FlowRecord


class GroundingValidator:
    """Validates that generated security reports and Q&A responses are grounded in authoritative data."""

    IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    FORBIDDEN_OPERATIONAL_COMMANDS = [
        "iptables",
        "nftables",
        "ufw",
        "netsh",
        "firewall-cmd",
        "ip link set",
        "shutdown",
        "pkill",
        "kill",
        "isolate-host",
        "isolate host",
        "block-ip",
        "block ip",
        "drop traffic",
        "nmap",
        "masscan",
        "ping",
        "traceroute",
        "curl",
        "wget",
    ]

    @classmethod
    def extract_ips_from_text(cls, text: str) -> Set[str]:
        """Extract all IPv4 addresses from text."""
        return set(cls.IP_REGEX.findall(text))

    @classmethod
    def validate_alert_report(
        cls,
        report: AlertAnalysisReport,
        alert: SecurityAlert,
        flows: Optional[List[FlowRecord]] = None,
    ) -> AlertAnalysisReport:
        """Validate an AlertAnalysisReport against source database models without silent text modification."""
        # 1. Collect authoritative reference sets from source records
        authoritative_ips: Set[str] = {alert.source_ip}
        if alert.destination_ip:
            authoritative_ips.add(alert.destination_ip)

        if getattr(alert, "source_entity", None):
            authoritative_ips.add(alert.source_entity.identifier)
            if alert.source_entity.ip_address:
                authoritative_ips.add(alert.source_entity.ip_address)
        if getattr(alert, "destination_entity", None):
            authoritative_ips.add(alert.destination_entity.identifier)
            if alert.destination_entity.ip_address:
                authoritative_ips.add(alert.destination_entity.ip_address)

        if hasattr(alert, "entities") and alert.entities:
            for ent in alert.entities:
                authoritative_ips.add(getattr(ent, "identifier", ""))
                if getattr(ent, "ip_address", None):
                    authoritative_ips.add(ent.ip_address)

        authoritative_ports: Set[int] = set()
        if alert.source_port is not None:
            authoritative_ports.add(alert.source_port)
        if alert.destination_port is not None:
            authoritative_ports.add(alert.destination_port)

        if flows:
            for fl in flows:
                authoritative_ips.add(fl.source_ip)
                authoritative_ips.add(fl.destination_ip)
                if fl.source_port is not None:
                    authoritative_ports.add(fl.source_port)
                if fl.destination_port is not None:
                    authoritative_ports.add(fl.destination_port)

        authoritative_detectors: Set[str] = {ev.detector_name for ev in alert.evidence}
        for sig in alert.contributing_signals:
            authoritative_detectors.add(sig.detector_name)

        authoritative_features: Set[str] = set()
        for ev in alert.evidence:
            if ev.feature_name:
                authoritative_features.add(ev.feature_name)
            for k in ev.triggered_features.keys():
                authoritative_features.add(k)

        authoritative_mitre: Set[str] = set()
        if alert.mitre_attack:
            authoritative_mitre.add(alert.mitre_attack.tactic_id)
            authoritative_mitre.add(alert.mitre_attack.technique_id)
            if alert.mitre_attack.subtechnique_id:
                authoritative_mitre.add(alert.mitre_attack.subtechnique_id)

        # 2. Check entities in report
        total_checked = 0
        verified_count = 0
        unsupported_entities: List[str] = []

        # Check Alert ID
        total_checked += 1
        if report.alert_id == alert.alert_id:
            verified_count += 1
        else:
            unsupported_entities.append(f"alert_id:{report.alert_id}")

        # Check IPs in observed facts and summary
        combined_text = (
            report.executive_summary + " " + " ".join(report.observed_facts) + " " + report.threat_assessment
        )
        found_ips = cls.extract_ips_from_text(combined_text)
        # Exclude standard subnet/mask patterns if found
        cleaned_ips = {ip for ip in found_ips if not ip.startswith("0.") and not ip.startswith("255.")}

        for ip in cleaned_ips:
            total_checked += 1
            if ip in authoritative_ips:
                verified_count += 1
            else:
                unsupported_entities.append(f"ip:{ip}")

        # Check citations
        for citation in report.evidence_citations:
            total_checked += 1
            if citation.detector_name in authoritative_detectors:
                verified_count += 1
            else:
                unsupported_entities.append(f"detector:{citation.detector_name}")

            if citation.feature_name:
                total_checked += 1
                if citation.feature_name in authoritative_features or not authoritative_features:
                    verified_count += 1
                else:
                    unsupported_entities.append(f"feature:{citation.feature_name}")

        # Check recommendations for forbidden operational command syntax
        for step in report.recommended_investigation_steps:
            action_lower = step.action.lower()
            for cmd in cls.FORBIDDEN_OPERATIONAL_COMMANDS:
                if cmd in action_lower:
                    unsupported_entities.append(f"forbidden_command:{cmd}")

        # 3. Determine status and populate auditable validation log
        status = GroundingStatus.PASSED
        if unsupported_entities:
            # If there are unsupported entities, do NOT silently delete text.
            # Instead, record them in the validation log and append an uncertainty indicator.
            if len(unsupported_entities) > 3:
                status = GroundingStatus.FLAGGED_UNGROUNDED

            report.uncertainties.append(
                UncertaintyIndicator(
                    aspect="Unverified claim(s) detected during grounding validation",
                    reason=f"Entities not found in authoritative source telemetry: {', '.join(unsupported_entities)}",
                    recommended_telemetry="Inspect authoritative packet metadata or flow records directly",
                )
            )

        report.validation_log = AuditableValidationLog(
            total_entities_checked=total_checked,
            verified_entities_count=verified_count,
            unsupported_entities=unsupported_entities,
            validation_status=status,
        )

        return report

    @classmethod
    def validate_qa_response(
        cls,
        response: AnalystQuestionResponse,
        alert: SecurityAlert,
    ) -> AnalystQuestionResponse:
        """Validate an AnalystQuestionResponse against source alert records."""
        if response.alert_id != alert.alert_id:
            response.grounded_in_telemetry = False
            response.uncertainty_notes = (
                f"Response alert_id {response.alert_id} does not match queried alert {alert.alert_id}"
            )
            return response

        # Check for non-existent IPs mentioned in answer
        authoritative_ips = {alert.source_ip}
        if alert.destination_ip:
            authoritative_ips.add(alert.destination_ip)

        found_ips = cls.extract_ips_from_text(response.answer)
        cleaned_ips = {ip for ip in found_ips if not ip.startswith("0.") and not ip.startswith("255.")}
        unsupported = [ip for ip in cleaned_ips if ip not in authoritative_ips]

        if unsupported:
            response.grounded_in_telemetry = False
            response.uncertainty_notes = f"Answer mentions ungrounded IP(s): {', '.join(unsupported)}"

        return response

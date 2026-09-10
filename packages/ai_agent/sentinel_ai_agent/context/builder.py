"""Grounded RAG context builder and token budgeter."""

import json
from typing import Any, Dict, List, Optional

from sentinel_ai_agent.context.sanitizer import TelemetrySanitizer
from sentinel_models.alerts import SecurityAlert
from sentinel_models.events import FlowRecord


class AlertContextBuilder:
    """Assembles and budgets grounded security context from authoritative SentinelAI models."""

    def __init__(self, max_context_tokens: int = 2000):
        self.max_context_tokens = max_context_tokens

    def build_analysis_context(
        self,
        alert: SecurityAlert,
        flows: Optional[List[FlowRecord]] = None,
        mode: str = "comprehensive",
    ) -> Dict[str, Any]:
        """Construct structured, grounded telemetry dictionary within token budget."""
        # 1. Base alert metadata
        alert_dict: Dict[str, Any] = {
            "alert_id": alert.alert_id,
            "threat_class": alert.threat_class,
            "category": str(alert.category) if alert.category else None,
            "severity": alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
            "status": alert.status.value if hasattr(alert.status, "value") else str(alert.status),
            "confidence": float(alert.confidence),
            "risk_score": alert.numeric_risk_score,
            "first_seen": alert.first_seen.isoformat() if alert.first_seen else None,
            "last_seen": alert.last_seen.isoformat() if alert.last_seen else None,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "source_port": alert.source_port,
            "destination_port": alert.destination_port,
            "protocol": alert.protocol,
            "explanation": alert.explanation,
        }

        if alert.mitre_attack:
            alert_dict["mitre_attack"] = {
                "tactic": alert.mitre_attack.tactic,
                "tactic_id": alert.mitre_attack.tactic_id,
                "technique": alert.mitre_attack.technique,
                "technique_id": alert.mitre_attack.technique_id,
                "subtechnique_id": alert.mitre_attack.subtechnique_id,
            }

        if hasattr(alert.risk_score, "breakdown") and alert.risk_score.breakdown:
            alert_dict["risk_breakdown"] = alert.risk_score.breakdown

        # 2. Evidence items (top 10 prioritized by confidence_contribution)
        evidence_list: List[Dict[str, Any]] = []
        sorted_evidence = sorted(
            alert.evidence,
            key=lambda e: getattr(e, "confidence_contribution", 0.0),
            reverse=True,
        )
        for ev in sorted_evidence[:10]:
            evidence_list.append({
                "detector_name": ev.detector_name,
                "detection_type": ev.detection_type,
                "feature_name": ev.feature_name,
                "observed_value": ev.observed_value,
                "threshold_value": ev.threshold_value,
                "confidence_contribution": ev.confidence_contribution,
                "triggered_features": ev.triggered_features,
            })
        alert_dict["evidence_items"] = evidence_list
        if len(sorted_evidence) > 10:
            alert_dict["additional_evidence_count"] = len(sorted_evidence) - 10

        # 3. Contributing signals (top 10)
        signal_list: List[Dict[str, Any]] = []
        for sig in alert.contributing_signals[:10]:
            signal_list.append({
                "signal_id": sig.signal_id,
                "threat_type": sig.threat_type,
                "detector_name": sig.detector_name,
                "confidence": sig.confidence,
                "severity": sig.severity,
            })
        alert_dict["contributing_signals"] = signal_list

        # 4. Associated flow sessions (condensed if > 5)
        if flows:
            if len(flows) <= 5:
                flow_list: List[Dict[str, Any]] = []
                for fl in flows:
                    item: Dict[str, Any] = {
                        "flow_id": fl.flow_id,
                        "source_ip": fl.source_ip,
                        "destination_ip": fl.destination_ip,
                        "source_port": fl.source_port,
                        "destination_port": fl.destination_port,
                        "protocol": str(fl.protocol),
                        "duration_sec": fl.duration_sec,
                        "total_packets": fl.total_packets,
                        "total_bytes": fl.total_bytes,
                        "tcp_flags": fl.tcp_flags,
                    }
                    flow_list.append(item)
                alert_dict["flows"] = flow_list
            else:
                # Statistical condensation
                durations = [fl.duration_sec for fl in flows]
                packets = [fl.total_packets for fl in flows]
                bytes_list = [fl.total_bytes for fl in flows]
                dest_ports = list({fl.destination_port for fl in flows if fl.destination_port is not None})[:10]

                alert_dict["flows_summary"] = {
                    "total_flow_count": len(flows),
                    "duration_min_sec": min(durations) if durations else 0.0,
                    "duration_max_sec": max(durations) if durations else 0.0,
                    "duration_mean_sec": round(sum(durations) / len(durations), 3) if durations else 0.0,
                    "aggregate_packets": sum(packets),
                    "aggregate_bytes": sum(bytes_list),
                    "unique_destination_ports": dest_ports,
                }

        # Sanitize all fields recursively
        sanitized = TelemetrySanitizer.sanitize_telemetry_dict(alert_dict)
        return sanitized

    def format_prompt(self, context_dict: Dict[str, Any], task_instructions: Optional[str] = None) -> str:
        """Format sanitized dictionary into strict JSON payload."""
        context_json = json.dumps(context_dict, indent=2)
        prompt = (
            "Here is the verified SentinelAI structured telemetry for analysis:\n\n"
            f"<telemetry_data>\n{context_json}\n</telemetry_data>\n\n"
        )
        if task_instructions:
            prompt += f"Task: {task_instructions}\n"
        else:
            prompt += (
                "Please generate a comprehensive, grounded advisory incident analysis report strictly "
                "conforming to the required output schema."
            )
        return prompt

    def format_qa_prompt(
        self,
        context_dict: Dict[str, Any],
        question: str,
        history: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        """Format Q&A prompt with untrusted question block."""
        safe_question = TelemetrySanitizer.sanitize_analyst_question(question)
        context_json = json.dumps(context_dict, indent=2)

        prompt = (
            "Here is the verified SentinelAI structured telemetry for the alert:\n\n"
            f"<telemetry_data>\n{context_json}\n</telemetry_data>\n\n"
        )

        if history:
            prompt += "Conversation Context:\n"
            for turn in history[-4:]:
                role = TelemetrySanitizer.sanitize_string(turn.get("role", "user"), max_length=16)
                content = TelemetrySanitizer.sanitize_string(turn.get("content", ""), max_length=300)
                prompt += f"- {role}: {content}\n"
            prompt += "\n"

        prompt += (
            f"Analyst Question: {safe_question}\n\n"
            "Answer the analyst question strictly using the provided telemetry. "
            "If the answer cannot be determined from the telemetry, explicitly state "
            "'Insufficient telemetry evidence'."
        )
        return prompt

"""Tests validating passive security invariants for Phase 8 GenAI Security Analyst.

These tests enforce non-negotiable architectural guardrails:
1. Purely advisory: no execution of commands, sockets, or active network probes.
2. Static AST / source inspection: no subprocess, raw sockets, or firewall modifiers.
3. No raw packet payloads or payload decryption in LLM context.
4. Grounding validator detects forbidden operational commands in recommendations.
5. Telemetry recommendations strictly specify passive data sources.
"""

import ast
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sentinel_models.ai_analyst import (
    AlertAnalysisReport,
    AttackStageAnalysis,
    EvidenceCitation,
    InvestigationStep,
)
from sentinel_models.alerts import (
    AlertEvidence,
    AlertSeverity,
    AlertStatus,
    RiskScore,
    SecurityAlert,
)
from sentinel_models.events import FlowRecord, ProtocolType
from sentinel_ai_agent.context.builder import AlertContextBuilder
from sentinel_ai_agent.fallback.engine import DeterministicFallbackEngine
from sentinel_ai_agent.validators.grounding import GroundingValidator


class TestPassiveSecurityInvariants(unittest.TestCase):
    """Rigorous audit of passive security constraints and boundaries."""

    def test_static_ast_no_execution_primitives(self):
        """Audit packages/ai_agent AST to ensure zero active execution primitives."""
        ai_agent_dir = Path("packages/ai_agent/sentinel_ai_agent")
        self.assertTrue(ai_agent_dir.exists(), "packages/ai_agent directory must exist")

        forbidden_modules = {"subprocess", "shlex", "pty", "telnetlib"}
        forbidden_calls = {
            "system",  # os.system
            "popen",   # os.popen
            "spawn",   # os.spawn
            "send",    # socket.send, scapy.send
            "sendto",
            "sendall",
            "gethostbyname",
            "getaddrinfo",
        }

        python_files = list(ai_agent_dir.rglob("*.py"))
        self.assertGreater(len(python_files), 5, "Must inspect all ai_agent modules")

        for py_path in python_files:
            content = py_path.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(py_path))

            for node in ast.walk(tree):
                # Check forbidden imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        base = alias.name.split(".")[0]
                        self.assertNotIn(
                            base,
                            forbidden_modules,
                            f"Forbidden module import '{base}' in {py_path}",
                        )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        base = node.module.split(".")[0]
                        self.assertNotIn(
                            base,
                            forbidden_modules,
                            f"Forbidden from-import module '{base}' in {py_path}",
                        )

                # Check forbidden call attributes
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                        # Only flag if not an internal or test method
                        if func_name in forbidden_calls:
                            self.fail(
                                f"Potentially active execution primitive '{func_name}' "
                                f"called in {py_path}:line {node.lineno}"
                            )

    def test_context_builder_excludes_raw_payloads(self):
        """Ensure context builder never accepts or outputs raw packet payloads."""
        now = datetime.now(timezone.utc)
        alert = SecurityAlert(
            alert_id="al-audit-payload",
            timestamp=now,
            first_seen=now,
            last_seen=now,
            threat_class="COMMAND_AND_CONTROL",
            severity=AlertSeverity.HIGH,
            confidence=0.9,
            risk_score=RiskScore(score=85, explanation="Beaconing"),
            status=AlertStatus.NEW,
            source_ip="10.0.0.5",
            destination_ip="198.51.100.1",
            explanation="Beaconing to external C2",
            evidence=[
                AlertEvidence(
                    evidence_id="ev-1",
                    detector_name="beacon_detector",
                    feature_name="interval_jitter",
                    observed_value=0.05,
                    threshold_value=0.1,
                    confidence_contribution=0.8,
                )
            ],
            contributing_signals=[],
            related_flow_ids=["fl-1"],
        )

        flow_record = FlowRecord(
            flow_id="fl-1",
            start_time=now,
            source_ip="10.0.0.5",
            destination_ip="198.51.100.1",
            source_port=49152,
            destination_port=443,
            protocol=ProtocolType.TCP,
            duration_sec=5.0,
            total_packets=20,
            total_bytes=3000,
            tcp_flags={"syn": 1, "ack": 1},
        )

        builder = AlertContextBuilder()
        ctx = builder.build_analysis_context(alert, flows=[flow_record])
        prompt = builder.format_prompt(ctx)

        # Context and prompt must NOT contain raw packet content
        self.assertNotIn("raw_payload", prompt)
        self.assertNotIn("payload_hex", prompt)
        self.assertNotIn("decrypted_tls_data", prompt)
        self.assertNotIn("\\x90\\x90", prompt)

    def test_fallback_engine_passive_recommendations_only(self):
        """Verify DeterministicFallbackEngine generates strictly passive investigation actions."""
        now = datetime.now(timezone.utc)
        alert = SecurityAlert(
            alert_id="al-audit-fallback",
            timestamp=now,
            first_seen=now,
            last_seen=now,
            threat_class="LATERAL_MOVEMENT",
            severity=AlertSeverity.CRITICAL,
            confidence=0.95,
            risk_score=RiskScore(score=92, explanation="Lateral movement"),
            status=AlertStatus.NEW,
            source_ip="10.0.0.10",
            destination_ip="10.0.0.20",
            explanation="Unauthorized lateral SMB connection",
            evidence=[],
            contributing_signals=[],
            related_flow_ids=[],
        )

        engine = DeterministicFallbackEngine()
        report = engine.generate_fallback_report(alert, reason="Provider unreachable")

        self.assertTrue(report.is_fallback)
        self.assertEqual(report.fallback_reason, "Provider unreachable")

        # Prohibited active keywords
        forbidden_active_terms = [
            "isolate host",
            "block ip",
            "iptables",
            "kill process",
            "firewall drop",
            "shutdown",
            "quarantine",
            "wipe",
        ]

        for step in report.recommended_investigation_steps:
            action_lower = step.action.lower()
            for forbidden in forbidden_active_terms:
                self.assertNotIn(
                    forbidden,
                    action_lower,
                    f"Fallback recommended forbidden active term: '{forbidden}' in step {step.step_number}",
                )

    def test_grounding_validator_catches_active_command_injections(self):
        """GroundingValidator must flag unauthorized host/network execution actions."""
        now = datetime.now(timezone.utc)
        alert = SecurityAlert(
            alert_id="al-audit-gv",
            timestamp=now,
            first_seen=now,
            last_seen=now,
            threat_class="PORT_SCAN",
            severity=AlertSeverity.MEDIUM,
            confidence=0.75,
            risk_score=RiskScore(score=60, explanation="Port scan"),
            status=AlertStatus.NEW,
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            explanation="Reconnaissance scanning against gateway",
            evidence=[],
            contributing_signals=[],
            related_flow_ids=[],
        )

        malicious_report = AlertAnalysisReport(
            analysis_id="rep-audit-active",
            alert_id=alert.alert_id,
            generated_at=datetime.now(timezone.utc),
            model_identifier="test-model",
            executive_summary="Reconnaissance detected.",
            observed_facts=["192.168.1.100 scanned ports."],
            threat_assessment="Threat.",
            threat_reasoning="Reasoning.",
            risk_interpretation="Risk.",
            evidence_citations=[],
            attack_stage=AttackStageAnalysis(stage_name="Recon", kill_chain_phase="Recon", confidence=0.8),
            mitre_explanation="",
            false_positive_analysis="",
            recommended_investigation_steps=[
                InvestigationStep(
                    step_number=1,
                    priority="HIGH",
                    action="Execute 'netsh advfirewall firewall add rule' to block traffic",
                    target_entity="192.168.1.100",
                    rationale="Block host immediately",
                ),
                InvestigationStep(
                    step_number=2,
                    priority="MEDIUM",
                    action="Run nmap -sS -A against 192.168.1.100 to probe for open ports",
                    target_entity="192.168.1.100",
                    rationale="Active probe",
                ),
            ],
        )

        validated = GroundingValidator.validate_alert_report(malicious_report, alert)

        # Content must NOT be silently erased
        self.assertEqual(len(validated.recommended_investigation_steps), 2)

        # Violations must be formally recorded in validation_log
        log = validated.validation_log
        self.assertTrue(
            any("netsh" in item or "nmap" in item for item in log.unsupported_entities),
            f"Expected forbidden commands to be logged, found: {log.unsupported_entities}",
        )
        self.assertGreaterEqual(len(validated.uncertainties), 1)


if __name__ == "__main__":
    unittest.main()

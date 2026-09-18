import React from "react";
import {
  ShieldAlert,
  CheckCircle2,
  ExternalLink,
  Activity,
  Server,
  ArrowRight,
  TrendingUp,
  Cpu,
} from "lucide-react";
import type { SecurityAlertRead, SecurityAlertStats } from "../../types/alert";
import type { DashboardData } from "../../hooks/useDashboardData";
import { Badge } from "../common/Badge";
import { StatusPill } from "../common/StatusPill";
import { RiskGauge } from "../common/RiskGauge";

interface DashboardViewProps {
  alerts: SecurityAlertRead[];
  stats: SecurityAlertStats | null;
  dashboardData: DashboardData;
  onSelectAlert: (alert: SecurityAlertRead) => void;
  onNavigateTab: (tab: "threats" | "network" | "assets" | "analytics" | "settings") => void;
  onAcknowledgeAlert?: (alertId: string) => Promise<void>;
  searchFilter?: string;
}

function formatRelativeTime(isoString?: string): string {
  if (!isoString) return "Recently";
  try {
    const diffMs = Date.now() - new Date(isoString).getTime();
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${Math.floor(diffHours / 24)}d ago`;
  } catch {
    return isoString;
  }
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  alerts,
  stats,
  dashboardData,
  onSelectAlert,
  onNavigateTab,
  onAcknowledgeAlert,
  searchFilter = "",
}) => {
  // Filter alerts if search query is provided
  const filteredAlerts = searchFilter
    ? alerts.filter(
        (a) =>
          a.title?.toLowerCase().includes(searchFilter.toLowerCase()) ||
          a.threat_class?.toLowerCase().includes(searchFilter.toLowerCase()) ||
          a.source_ip?.includes(searchFilter) ||
          a.destination_ip?.includes(searchFilter)
      )
    : alerts;

  // 1. Identify primary active threat for Row 1 Card A
  // Priority: Critical & New/Active -> High & New/Active -> First alert
  const activeCriticalThreat =
    filteredAlerts.find(
      (a) =>
        (a.status === "NEW" || a.status === "ACTIVE") &&
        (a.severity === "CRITICAL" || a.severity === "HIGH")
    ) ||
    filteredAlerts.find((a) => a.status === "NEW" || a.status === "ACTIVE") ||
    filteredAlerts[0] ||
    null;

  const activeThreatRisk =
    activeCriticalThreat && typeof activeCriticalThreat.risk_score === "object"
      ? (activeCriticalThreat.risk_score as any)?.score || 0
      : typeof activeCriticalThreat?.risk_score === "number"
      ? activeCriticalThreat.risk_score
      : 0;

  // 2. System Health & Processing stats
  const { processingStatus, telemetrySummary, entities, health } = dashboardData;
  const totalFlows =
    processingStatus?.total_flows_processed ?? telemetrySummary?.total_flows ?? 0;
  const totalDetections =
    processingStatus?.total_detections_generated ?? telemetrySummary?.total_detections ?? 0;
  const isPassiveMode = processingStatus?.passive_mode_active ?? true;
  const isDbHealthy = health?.status === "healthy" || processingStatus !== null;

  // 3. Security Posture calculations
  const totalAlertsCount = stats?.total_alerts || alerts.length;
  const resolvedCount = stats?.by_status?.["RESOLVED"] || 0;
  const resolutionRate =
    totalAlertsCount > 0 ? Math.round((resolvedCount / totalAlertsCount) * 100) : 100;
  const meanRisk = stats?.avg_risk_score ?? stats?.mean_risk_score ?? 0;

  // 4. Threat distribution for analytics card
  const threatDist =
    telemetrySummary?.threat_distribution && telemetrySummary.threat_distribution.length > 0
      ? telemetrySummary.threat_distribution
      : stats?.by_threat_class
      ? Object.entries(stats.by_threat_class).map(([k, v]) => ({ threat_type: k, count: v }))
      : [];
  const maxThreatCount = Math.max(...threatDist.map((t) => t.count), 1);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {/* =========================================================================
          ROW 1: CRITICAL / ACTIVE THREAT CARD (2/3) + SYSTEM HEALTH CARD (1/3)
         ========================================================================= */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: "1.25rem",
        }}
      >
        {/* Card 1A: Critical / Active Threat Card */}
        <div
          className="glass-panel"
          style={{
            gridColumn: "span 2",
            padding: "1.5rem",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            minHeight: "220px",
            borderLeft: activeCriticalThreat ? "4px solid var(--severity-critical)" : "4px solid var(--success)",
            position: "relative",
          }}
        >
          {activeCriticalThreat ? (
            <>
              <div>
                {/* Header: Status Pill & Threat Tag */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: "0.5rem",
                    marginBottom: "0.75rem",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                    <span
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "0.4rem",
                        padding: "0.2rem 0.6rem",
                        borderRadius: "9999px",
                        background: "var(--severity-critical-bg)",
                        color: "var(--severity-critical)",
                        fontSize: "0.725rem",
                        fontWeight: 700,
                        letterSpacing: "0.04em",
                        border: "1px solid var(--severity-critical-border)",
                      }}
                    >
                      <span
                        style={{
                          width: 6,
                          height: 6,
                          borderRadius: "50%",
                          backgroundColor: "var(--severity-critical)",
                          animation: "pulseGlow 1.5s infinite ease-in-out",
                        }}
                      />
                      ACTIVE THREAT DETECTED
                    </span>
                    <Badge severity={activeCriticalThreat.severity}>
                      {activeCriticalThreat.severity}
                    </Badge>
                    <StatusPill status={activeCriticalThreat.status} />
                  </div>

                  <span style={{ fontSize: "0.775rem", color: "var(--text-muted)" }}>
                    First seen: {formatRelativeTime(activeCriticalThreat.first_seen || activeCriticalThreat.created_at)}
                  </span>
                </div>

                {/* Threat Title & Risk Score */}
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    gap: "1rem",
                    marginTop: "0.25rem",
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <h2
                      style={{
                        fontSize: "1.35rem",
                        fontWeight: 700,
                        color: "#0f172a",
                        margin: 0,
                        lineHeight: 1.25,
                      }}
                    >
                      {activeCriticalThreat.title || activeCriticalThreat.threat_class}
                    </h2>
                    <p
                      style={{
                        fontSize: "0.85rem",
                        color: "var(--text-secondary)",
                        margin: "0.5rem 0 0 0",
                        lineHeight: 1.45,
                        maxWidth: "650px",
                      }}
                    >
                      {activeCriticalThreat.explanation ||
                        activeCriticalThreat.description ||
                        "Correlated behavioral anomaly observed across passive network flow telemetry."}
                    </p>
                  </div>

                  {/* Risk Score Container */}
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "flex-end",
                      flexShrink: 0,
                      padding: "0.6rem 1rem",
                      background: "#f8fafc",
                      borderRadius: "6px",
                      border: "1px solid var(--border)",
                    }}
                  >
                    <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
                      Risk Score
                    </span>
                    <div style={{ display: "flex", alignItems: "baseline", gap: "0.25rem", marginTop: "0.15rem" }}>
                      <span
                        style={{
                          fontSize: "1.75rem",
                          fontWeight: 700,
                          fontFamily: "var(--font-mono)",
                          color: "var(--severity-critical)",
                          lineHeight: 1,
                        }}
                      >
                        {activeThreatRisk}
                      </span>
                      <span style={{ fontSize: "0.85rem", color: "var(--text-muted)", fontWeight: 500 }}>
                        /100
                      </span>
                    </div>
                    <span style={{ fontSize: "0.725rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
                      {(activeCriticalThreat.confidence * 100).toFixed(0)}% Confidence
                    </span>
                  </div>
                </div>

                {/* Device & Flow Telemetry Context */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "1.5rem",
                    flexWrap: "wrap",
                    marginTop: "0.85rem",
                    paddingTop: "0.75rem",
                    borderTop: "1px solid var(--border-subtle)",
                    fontSize: "0.775rem",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                    <span style={{ color: "var(--text-muted)" }}>Source Device:</span>
                    <code style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "#0f172a" }}>
                      {activeCriticalThreat.source_ip || "Internal Telemetry"}
                    </code>
                  </div>
                  {activeCriticalThreat.destination_ip && (
                    <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                      <span style={{ color: "var(--text-muted)" }}>Target Device:</span>
                      <code style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "#0f172a" }}>
                        {activeCriticalThreat.destination_ip}
                      </code>
                    </div>
                  )}
                  {activeCriticalThreat.flow_ids && activeCriticalThreat.flow_ids.length > 0 && (
                    <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                      <span style={{ color: "var(--text-muted)" }}>Correlated Flows:</span>
                      <span style={{ color: "#0f172a", fontWeight: 600 }}>
                        {activeCriticalThreat.flow_ids.length}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Actions Footer - Strictly real existing actions */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginTop: "1.25rem",
                  paddingTop: "0.85rem",
                  borderTop: "1px solid var(--border-subtle)",
                }}
              >
                <div style={{ display: "flex", gap: "0.6rem" }}>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => onSelectAlert(activeCriticalThreat)}
                  >
                    <span>Investigate Incident</span>
                    <ExternalLink size={13} />
                  </button>

                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => onNavigateTab("threats")}
                  >
                    <span>View All Threats</span>
                  </button>

                  {onAcknowledgeAlert &&
                    (activeCriticalThreat.status === "NEW" || activeCriticalThreat.status === "ACTIVE") && (
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={async () => {
                          await onAcknowledgeAlert(activeCriticalThreat.alert_id);
                        }}
                      >
                        Acknowledge
                      </button>
                    )}
                </div>

                <span style={{ fontSize: "0.725rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                  ID: {activeCriticalThreat.alert_id.slice(0, 16)}...
                </span>
              </div>
            </>
          ) : (
            /* Clear State when no threats */
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "flex-start",
                justifyContent: "center",
                height: "100%",
                gap: "0.75rem",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <CheckCircle2 size={20} color="#16a34a" />
                <span
                  style={{
                    fontSize: "0.8rem",
                    fontWeight: 700,
                    color: "#16a34a",
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                  }}
                >
                  All Systems Normal
                </span>
              </div>
              <h2 style={{ fontSize: "1.25rem", fontWeight: 700, color: "#0f172a", margin: 0 }}>
                Zero Active Critical Threats Detected
              </h2>
              <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", margin: 0 }}>
                Passive packet inspection is active. No anomalous traffic signatures or correlated security incidents are currently flagged.
              </p>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigateTab("threats")}
                style={{ marginTop: "0.5rem" }}
              >
                View Incident History
              </button>
            </div>
          )}
        </div>

        {/* Card 1B: System Health Card */}
        <div
          className="glass-panel"
          style={{
            padding: "1.25rem 1.5rem",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "1rem",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <Activity size={16} color="var(--accent-primary)" />
                <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "#0f172a" }}>
                  System Health
                </span>
              </div>
              <span
                style={{
                  fontSize: "0.675rem",
                  padding: "0.15rem 0.45rem",
                  borderRadius: 4,
                  background: isDbHealthy ? "#f0fdf4" : "#fef2f2",
                  color: isDbHealthy ? "#16a34a" : "#dc2626",
                  fontWeight: 600,
                  border: isDbHealthy ? "1px solid #bbf7d0" : "1px solid #fecaca",
                }}
              >
                {isDbHealthy ? "OPERATIONAL" : "DEGRADED"}
              </span>
            </div>

            {/* Health Progress Indicators */}
            <div style={{ display: "flex", flexDirection: "column", gap: "0.85rem" }}>
              {/* Telemetry Ingestion Pipeline */}
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.775rem", marginBottom: "0.3rem" }}>
                  <span style={{ color: "var(--text-secondary)", fontWeight: 500 }}>
                    Passive Ingestion Pipeline
                  </span>
                  <span style={{ color: "#0f172a", fontWeight: 600 }}>Active (100%)</span>
                </div>
                <div style={{ height: 6, background: "#f1f5f9", borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ width: "100%", height: "100%", background: "#16a34a", borderRadius: 3 }} />
                </div>
              </div>

              {/* Database Status */}
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.775rem", marginBottom: "0.3rem" }}>
                  <span style={{ color: "var(--text-secondary)", fontWeight: 500 }}>
                    Database Telemetry Store
                  </span>
                  <span style={{ color: "#0f172a", fontWeight: 600 }}>
                    {isDbHealthy ? "Connected" : "Disconnected"}
                  </span>
                </div>
                <div style={{ height: 6, background: "#f1f5f9", borderRadius: 3, overflow: "hidden" }}>
                  <div
                    style={{
                      width: isDbHealthy ? "100%" : "0%",
                      height: "100%",
                      background: isDbHealthy ? "#1a73e8" : "#dc2626",
                      borderRadius: 3,
                    }}
                  />
                </div>
              </div>

              {/* Passive Boundary Mode */}
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.775rem", marginBottom: "0.3rem" }}>
                  <span style={{ color: "var(--text-secondary)", fontWeight: 500 }}>
                    Passive Boundary Mode
                  </span>
                  <span style={{ color: "#16a34a", fontWeight: 600 }}>
                    {isPassiveMode ? "Read-Only (Active)" : "Interactive"}
                  </span>
                </div>
                <div style={{ height: 6, background: "#f1f5f9", borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ width: "100%", height: "100%", background: "#16a34a", borderRadius: 3 }} />
                </div>
              </div>
            </div>
          </div>

          {/* Real Processed Counts */}
          <div
            style={{
              marginTop: "1.25rem",
              paddingTop: "0.85rem",
              borderTop: "1px solid var(--border-subtle)",
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "0.75rem",
            }}
          >
            <div>
              <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
                Flows Processed
              </span>
              <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#0f172a", fontFamily: "var(--font-mono)" }}>
                {totalFlows.toLocaleString()}
              </div>
            </div>
            <div>
              <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
                Total Detections
              </span>
              <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#0f172a", fontFamily: "var(--font-mono)" }}>
                {totalDetections.toLocaleString()}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* =========================================================================
          ROW 2: THREAT & AI ANALYTICS (2/3) + SECURITY POSTURE (1/3)
         ========================================================================= */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: "1.25rem",
        }}
      >
        {/* Card 2A: AI / Threat Analytics Card */}
        <div
          className="glass-panel"
          style={{
            gridColumn: "span 2",
            padding: "1.25rem 1.5rem",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "1rem",
            }}
          >
            <div>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 600, color: "#0f172a", margin: 0 }}>
                Threat Classification Analytics
              </h3>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Real-time threat class distribution generated by rule and statistical detectors
              </span>
            </div>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => onNavigateTab("analytics")}
              style={{ fontSize: "0.75rem" }}
            >
              <span>Full Analytics</span>
              <ArrowRight size={12} />
            </button>
          </div>

          {/* Real Threat Distribution Visualization */}
          {threatDist.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", flex: 1, justifyContent: "center" }}>
              {threatDist.slice(0, 5).map((item) => {
                const pct = Math.round((item.count / maxThreatCount) * 100);
                const isHighRisk =
                  item.threat_type.includes("FLOOD") ||
                  item.threat_type.includes("TUNNEL") ||
                  item.threat_type.includes("EXFILTRATION");

                return (
                  <div key={item.threat_type} style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.775rem" }}>
                      <span style={{ fontWeight: 600, color: "#0f172a" }}>
                        {item.threat_type}
                      </span>
                      <span style={{ color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
                        {item.count} incident{item.count === 1 ? "" : "s"}
                      </span>
                    </div>
                    <div style={{ height: 8, background: "#f1f5f9", borderRadius: 4, overflow: "hidden" }}>
                      <div
                        style={{
                          width: `${pct}%`,
                          height: "100%",
                          background: isHighRisk ? "var(--severity-critical)" : "var(--accent-primary)",
                          borderRadius: 4,
                          transition: "width 0.4s ease",
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                padding: "2.5rem 1rem",
                color: "var(--text-muted)",
                textAlign: "center",
                gap: "0.5rem",
              }}
            >
              <TrendingUp size={24} color="var(--border)" />
              <span style={{ fontSize: "0.85rem", fontWeight: 500 }}>
                No threat telemetry recorded yet
              </span>
              <span style={{ fontSize: "0.75rem" }}>
                Detections will appear here once anomalous network signals are observed.
              </span>
            </div>
          )}
        </div>

        {/* Card 2B: System Health / Security Posture Card */}
        <div
          className="glass-panel"
          style={{
            padding: "1.25rem 1.5rem",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "1rem",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <ShieldAlert size={16} color="var(--accent-primary)" />
                <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "#0f172a" }}>
                  Security Posture
                </span>
              </div>
              <span style={{ fontSize: "0.725rem", color: "var(--text-muted)" }}>
                SOC Telemetry
              </span>
            </div>

            {/* Metrics Breakdown */}
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              {/* Mean Risk Metric */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "0.6rem 0.85rem",
                  background: "#f8fafc",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                }}
              >
                <div>
                  <span style={{ fontSize: "0.725rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
                    Mean Risk Score
                  </span>
                  <div style={{ fontSize: "1.25rem", fontWeight: 700, color: "#0f172a", fontFamily: "var(--font-mono)" }}>
                    {meanRisk.toFixed(1)} / 100
                  </div>
                </div>
                <RiskGauge score={meanRisk} showLabel={false} />
              </div>

              {/* Triage Resolution Rate */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "0.6rem 0.85rem",
                  background: "#f8fafc",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                }}
              >
                <div>
                  <span style={{ fontSize: "0.725rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
                    Triage Resolution
                  </span>
                  <div style={{ fontSize: "1.25rem", fontWeight: 700, color: "#16a34a", fontFamily: "var(--font-mono)" }}>
                    {resolutionRate}%
                  </div>
                </div>
                <div style={{ textAlign: "right", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                  <div>{resolvedCount} resolved</div>
                  <div>{totalAlertsCount} total alerts</div>
                </div>
              </div>

              {/* Active Detection Engines */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "0.6rem 0.85rem",
                  background: "#f8fafc",
                  borderRadius: "6px",
                  border: "1px solid var(--border)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <Cpu size={16} color="var(--accent-primary)" />
                  <div>
                    <div style={{ fontSize: "0.8rem", fontWeight: 600, color: "#0f172a" }}>
                      Detection Engines
                    </div>
                    <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                      Rule + Statistical + GenAI
                    </span>
                  </div>
                </div>
                <span
                  style={{
                    fontSize: "0.7rem",
                    fontWeight: 600,
                    padding: "0.15rem 0.45rem",
                    borderRadius: 4,
                    background: "#f0fdf4",
                    color: "#16a34a",
                    border: "1px solid #bbf7d0",
                  }}
                >
                  3/3 Active
                </span>
              </div>
            </div>
          </div>

          <div
            style={{
              marginTop: "1.25rem",
              paddingTop: "0.75rem",
              borderTop: "1px solid var(--border-subtle)",
              display: "flex",
              justifyContent: "space-between",
              fontSize: "0.725rem",
              color: "var(--text-muted)",
            }}
          >
            <span>Telemetry Window: Real-time</span>
            <span style={{ color: "#16a34a", fontWeight: 600 }}>Hardened SOC</span>
          </div>
        </div>
      </div>

      {/* =========================================================================
          ROW 3: LIVE INCIDENT STREAM (3/5) + ASSET POSTURE (2/5)
         ========================================================================= */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: "1.25rem",
        }}
      >
        {/* Card 3A: Live Incident Stream */}
        <div
          className="glass-panel"
          style={{
            gridColumn: "span 2",
            padding: "1.25rem 1.5rem",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "1rem",
            }}
          >
            <div>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 600, color: "#0f172a", margin: 0 }}>
                Live Incident Stream
              </h3>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Latest security events and detections from passive sensor feeds
              </span>
            </div>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => onNavigateTab("threats")}
              style={{ fontSize: "0.75rem" }}
            >
              <span>View All</span>
              <ArrowRight size={12} />
            </button>
          </div>

          {/* Incidents List */}
          {filteredAlerts.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              {filteredAlerts.slice(0, 5).map((alert) => (
                <div
                  key={alert.alert_id}
                  onClick={() => onSelectAlert(alert)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "0.65rem 0.85rem",
                    borderRadius: "6px",
                    border: "1px solid var(--border)",
                    background: "#ffffff",
                    cursor: "pointer",
                    transition: "all 0.15s ease",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = "#f8fafc";
                    e.currentTarget.style.borderColor = "#cbd5e1";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = "#ffffff";
                    e.currentTarget.style.borderColor = "var(--border)";
                  }}
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onSelectAlert(alert);
                    }
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", minWidth: 0 }}>
                    <Badge severity={alert.severity}>{alert.severity}</Badge>
                    <div style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
                      <span
                        style={{
                          fontSize: "0.825rem",
                          fontWeight: 600,
                          color: "#0f172a",
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                        }}
                      >
                        {alert.title || alert.threat_class}
                      </span>
                      <div
                        style={{
                          fontSize: "0.725rem",
                          color: "var(--text-muted)",
                          display: "flex",
                          alignItems: "center",
                          gap: "0.35rem",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        <span>{alert.source_ip || "Internal"}</span>
                        {alert.destination_ip && (
                          <>
                            <ArrowRight size={10} color="var(--text-muted)" />
                            <span>{alert.destination_ip}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "1rem", flexShrink: 0 }}>
                    <span style={{ fontSize: "0.725rem", color: "var(--text-muted)" }}>
                      {formatRelativeTime(alert.created_at || alert.last_seen)}
                    </span>
                    <StatusPill status={alert.status} />
                    <button
                      className="btn btn-secondary btn-sm"
                      style={{ padding: "0.2rem 0.5rem", fontSize: "0.725rem" }}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectAlert(alert);
                      }}
                      aria-label={`View details for ${alert.title || alert.threat_class}`}
                    >
                      Details
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div
              style={{
                padding: "2rem",
                textAlign: "center",
                color: "var(--text-muted)",
                fontSize: "0.85rem",
              }}
            >
              No security incidents recorded.
            </div>
          )}
        </div>

        {/* Card 3B: Asset Posture */}
        <div
          className="glass-panel"
          style={{
            padding: "1.25rem 1.5rem",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "1rem",
            }}
          >
            <div>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 600, color: "#0f172a", margin: 0 }}>
                Asset Posture
              </h3>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Monitored devices and observed network entities
              </span>
            </div>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => onNavigateTab("assets")}
              style={{ fontSize: "0.75rem" }}
            >
              <span>View All</span>
              <ArrowRight size={12} />
            </button>
          </div>

          {/* Real Entities / Assets List */}
          {entities.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              {entities.slice(0, 5).map((entity) => {
                const hasAlerts = entity.alert_count > 0;
                return (
                  <div
                    key={entity.identifier}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "0.6rem 0.75rem",
                      borderRadius: "6px",
                      border: "1px solid var(--border)",
                      background: hasAlerts ? "#fff7ed" : "#ffffff",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                      <Server
                        size={15}
                        color={hasAlerts ? "var(--severity-high)" : "var(--accent-primary)"}
                      />
                      <div style={{ display: "flex", flexDirection: "column" }}>
                        <span
                          style={{
                            fontSize: "0.8rem",
                            fontWeight: 600,
                            color: "#0f172a",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {entity.identifier}
                        </span>
                        <span style={{ fontSize: "0.675rem", color: "var(--text-muted)" }}>
                          {entity.entity_type}
                        </span>
                      </div>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      {hasAlerts ? (
                        <span
                          style={{
                            fontSize: "0.7rem",
                            fontWeight: 600,
                            padding: "0.15rem 0.45rem",
                            borderRadius: 4,
                            background: "var(--severity-high-bg)",
                            color: "var(--severity-high)",
                            border: "1px solid var(--severity-high-border)",
                          }}
                        >
                          {entity.alert_count} Alerts
                        </span>
                      ) : (
                        <span
                          style={{
                            fontSize: "0.7rem",
                            fontWeight: 500,
                            color: "#16a34a",
                          }}
                        >
                          Clean
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                padding: "2.5rem 1rem",
                color: "var(--text-muted)",
                textAlign: "center",
                gap: "0.5rem",
              }}
            >
              <Server size={22} color="var(--border)" />
              <span style={{ fontSize: "0.825rem", fontWeight: 500 }}>
                No anomalous assets detected
              </span>
              <span style={{ fontSize: "0.725rem" }}>
                Identified network endpoints will appear here as flows are parsed.
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

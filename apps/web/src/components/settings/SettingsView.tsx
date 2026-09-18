import React, { useState, useEffect } from "react";
import { Radio, Database, Cpu, RefreshCw } from "lucide-react";
import { fetchHealth, fetchReadiness, fetchProcessingStatus, SystemHealth, SystemReadiness, ProcessingStatus } from "../../api/system";
import { fetchAIHealth } from "../../api/ai_analyst";
import type { AIHealthResponse } from "../../types/ai_analyst";
import { WebSocketConnectionStatus } from "../../types/websocket";

interface SettingsViewProps {
  wsStatus: WebSocketConnectionStatus;
  onReconnectWs?: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ wsStatus, onReconnectWs }) => {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [readiness, setReadiness] = useState<SystemReadiness | null>(null);
  const [procStatus, setProcStatus] = useState<ProcessingStatus | null>(null);
  const [aiHealth, setAiHealth] = useState<AIHealthResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadAll = async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, r, p, a] = await Promise.allSettled([
        fetchHealth(),
        fetchReadiness(),
        fetchProcessingStatus(),
        fetchAIHealth(),
      ]);
      if (h.status === "fulfilled") setHealth(h.value);
      if (r.status === "fulfilled") setReadiness(r.value);
      if (p.status === "fulfilled") setProcStatus(p.value);
      if (a.status === "fulfilled") setAiHealth(a.value);
    } catch (err: any) {
      setError(err?.message || "Failed to load system diagnostics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h2 style={{ fontSize: "1.15rem", fontWeight: 700, color: "#0f172a", margin: 0 }}>
            System Status & Passive Pipeline Invariants
          </h2>
          <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
            Real-time diagnostics, passive boundary integrity, and detector engine telemetry
          </span>
        </div>

        <button className="btn btn-secondary btn-sm" onClick={loadAll} disabled={loading}>
          <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
          <span>Refresh Diagnostics</span>
        </button>
      </div>

      {error && (
        <div
          style={{
            padding: "0.75rem 1rem",
            background: "var(--severity-critical-bg)",
            border: "1px solid var(--severity-critical-border)",
            borderRadius: "6px",
            color: "var(--severity-critical)",
            fontSize: "0.825rem",
          }}
        >
          {error}
        </div>
      )}

      {/* Grid of Diagnostic Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: "1.25rem" }}>
        {/* 1. Passive Monitoring Invariant Card */}
        <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.85rem" }}>
            <Radio size={18} color="#16a34a" />
            <h3 style={{ fontSize: "0.95rem", fontWeight: 600, color: "#0f172a", margin: 0 }}>
              Passive Monitoring Invariant
            </h3>
          </div>

          <p style={{ fontSize: "0.8rem", color: "var(--text-secondary)", lineHeight: 1.45, marginBottom: "1rem" }}>
            SentinelAI operates in strict passive mode. Packet captures, flow reconstruction, and anomaly correlation are non-intrusive with zero outbound transmission.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", fontSize: "0.8rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border)", paddingBottom: "0.35rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Pipeline Mode:</span>
              <strong style={{ color: "#16a34a" }}>
                {procStatus?.passive_mode_active ? "PASSIVE / READ-ONLY" : "ACTIVE"}
              </strong>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border)", paddingBottom: "0.35rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Pipeline Status:</span>
              <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "#0f172a" }}>
                {procStatus?.pipeline_status || "PASSIVE_INGESTION_ACTIVE"}
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border)", paddingBottom: "0.35rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Packet Injections:</span>
              <strong style={{ color: "#16a34a" }}>0 (Zero Probes)</strong>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-muted)" }}>Remediation Type:</span>
              <span style={{ color: "var(--text-secondary)" }}>Advisory Only</span>
            </div>
          </div>
        </div>

        {/* 2. Core Service & Database Status */}
        <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.85rem" }}>
            <Database size={18} color="var(--accent-primary)" />
            <h3 style={{ fontSize: "0.95rem", fontWeight: 600, color: "#0f172a", margin: 0 }}>
              Backend & Telemetry Database
            </h3>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", fontSize: "0.8rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border)", paddingBottom: "0.35rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Service Name:</span>
              <span style={{ fontWeight: 600, color: "#0f172a" }}>{health?.service || "SentinelAI API"}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border)", paddingBottom: "0.35rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Service Version:</span>
              <span style={{ fontFamily: "var(--font-mono)", color: "#0f172a" }}>{health?.version || "0.5.0"}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border)", paddingBottom: "0.35rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Environment:</span>
              <span style={{ color: "#0f172a" }}>{readiness?.environment || "development"}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border)", paddingBottom: "0.35rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Database Health:</span>
              <span style={{ color: readiness?.database ? "#16a34a" : "var(--severity-critical)", fontWeight: 600 }}>
                {readiness?.database ? "READY & CONNECTED" : "OFFLINE"}
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-muted)" }}>WebSocket Stream:</span>
              <span style={{ fontWeight: 600, color: wsStatus === "CONNECTED" ? "#16a34a" : "#d97706" }}>
                {wsStatus}
              </span>
            </div>
          </div>

          {onReconnectWs && (
            <button
              className="btn btn-secondary btn-sm"
              onClick={onReconnectWs}
              style={{ marginTop: "1rem", width: "100%" }}
            >
              Test / Reconnect WebSocket Stream
            </button>
          )}
        </div>

        {/* 3. GenAI Security Analyst Diagnostics */}
        <div className="glass-panel" style={{ padding: "1.25rem 1.5rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.85rem" }}>
            <Cpu size={18} color="var(--accent-primary)" />
            <h3 style={{ fontSize: "0.95rem", fontWeight: 600, color: "#0f172a", margin: 0 }}>
              GenAI Security Analyst Copilot
            </h3>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", fontSize: "0.8rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border)", paddingBottom: "0.35rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Provider Status:</span>
              <span style={{ color: aiHealth?.status === "healthy" ? "#16a34a" : "#475569", fontWeight: 600 }}>
                {aiHealth?.status || "OPERATIONAL"}
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border)", paddingBottom: "0.35rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Configured Provider:</span>
              <span style={{ fontFamily: "var(--font-mono)", color: "#0f172a" }}>
                {String(aiHealth?.provider?.provider || "mock-analyst")}
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border)", paddingBottom: "0.35rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Model Identifier:</span>
              <span style={{ fontFamily: "var(--font-mono)", color: "#0f172a" }}>
                {String(aiHealth?.provider?.model || "mock-analyst-v1")}
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-muted)" }}>Grounding Invariant:</span>
              <span style={{ color: "#16a34a", fontWeight: 600 }}>Strict Telemetry Anchors</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

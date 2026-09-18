import React from "react";
import { SecurityAlertRead } from "../../types/alert";
import { Badge } from "../common/Badge";
import { RiskGauge } from "../common/RiskGauge";
import { StatusPill } from "../common/StatusPill";
import { ArrowRight, ChevronRight } from "lucide-react";

interface AlertRowProps {
  alert: SecurityAlertRead;
  onSelect: (alert: SecurityAlertRead) => void;
  isNew?: boolean;
}

export const AlertRow: React.FC<AlertRowProps> = ({ alert, onSelect, isNew = false }) => {
  const riskValue =
    typeof alert.risk_score === "object" && alert.risk_score !== null
      ? (alert.risk_score as any).score || 0
      : typeof alert.risk_score === "number"
      ? alert.risk_score
      : 0;

  const formatDate = (isoString: string) => {
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch {
      return isoString;
    }
  };

  return (
    <tr
      onClick={() => onSelect(alert)}
      className={isNew ? "animate-highlight" : ""}
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(alert);
        }
      }}
      aria-label={`Alert ${alert.alert_id}: ${alert.threat_class}, Severity ${alert.severity}, Risk ${riskValue}`}
    >
      <td>
        <Badge severity={alert.severity}>{alert.severity}</Badge>
      </td>
      <td>
        <div style={{ display: "flex", flexDirection: "column" }}>
          <span style={{ fontWeight: 600, color: "#0f172a" }}>
            {alert.title || alert.threat_class}
          </span>
          <span
            style={{
              fontSize: "0.7rem",
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              maxWidth: "180px",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {alert.alert_id}
          </span>
        </div>
      </td>
      <td>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.35rem",
            fontSize: "0.8rem",
            fontFamily: "var(--font-mono)",
          }}
        >
          <span style={{ color: "#0f172a" }}>{alert.source_ip || "Unknown"}</span>
          {alert.destination_ip && (
            <>
              <ArrowRight size={11} color="var(--text-muted)" />
              <span style={{ color: "#0f172a" }}>{alert.destination_ip}</span>
            </>
          )}
        </div>
      </td>
      <td>
        <RiskGauge score={riskValue} />
      </td>
      <td>
        <span
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "0.8rem",
            color: "var(--text-secondary)",
            fontWeight: 500,
          }}
        >
          {(alert.confidence * 100).toFixed(0)}%
        </span>
      </td>
      <td>
        <StatusPill status={alert.status} />
      </td>
      <td style={{ fontSize: "0.775rem", color: "var(--text-muted)", whiteSpace: "nowrap" }}>
        {formatDate(alert.last_seen || alert.created_at || "")}
      </td>
      <td style={{ textAlign: "right" }}>
        <button
          className="btn btn-secondary btn-sm"
          style={{ padding: "0.2rem 0.4rem", border: "none", background: "transparent" }}
          aria-label={`View details for alert ${alert.alert_id}`}
        >
          <ChevronRight size={14} color="var(--text-muted)" />
        </button>
      </td>
    </tr>
  );
};

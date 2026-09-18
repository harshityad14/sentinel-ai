import React from "react";
import { AlertStatisticsRead } from "../../types/alert";
import { ShieldAlert, AlertTriangle, CheckCircle, Flame } from "lucide-react";

interface AlertStatsCardsProps {
  stats: AlertStatisticsRead | null;
  loading?: boolean;
}

export const AlertStatsCards: React.FC<AlertStatsCardsProps> = ({ stats, loading }) => {
  const cards = [
    {
      title: "Total Incidents",
      value: stats ? stats.total_alerts.toLocaleString() : "-",
      icon: <ShieldAlert size={18} color="var(--accent-primary)" />,
      change: "All recorded security incidents",
    },
    {
      title: "Critical & High",
      value: stats
        ? ((stats.by_severity["CRITICAL"] || 0) + (stats.by_severity["HIGH"] || 0)).toLocaleString()
        : "-",
      icon: <Flame size={18} color="var(--severity-critical)" />,
      change: "Urgent triage needed",
    },
    {
      title: "Active Triage",
      value: stats
        ? ((stats.by_status["NEW"] || 0) + (stats.by_status["ACTIVE"] || 0)).toLocaleString()
        : "-",
      icon: <AlertTriangle size={18} color="var(--status-active)" />,
      change: "Unresolved incidents",
    },
    {
      title: "Resolved Incidents",
      value: stats ? (stats.by_status["RESOLVED"] || 0).toLocaleString() : "-",
      icon: <CheckCircle size={18} color="var(--status-resolved)" />,
      change: "Closed investigations",
    },
  ];

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
        gap: "1rem",
        marginBottom: "1.25rem",
      }}
    >
      {cards.map((card, idx) => (
        <div
          key={idx}
          className="glass-panel"
          style={{
            padding: "1rem 1.25rem",
            display: "flex",
            flexDirection: "column",
            gap: "0.4rem",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontSize: "0.775rem", color: "var(--text-secondary)", fontWeight: 500 }}>
              {card.title}
            </span>
            <div
              style={{
                width: 30,
                height: 30,
                borderRadius: 6,
                background: "#f8fafc",
                border: "1px solid var(--border)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {card.icon}
            </div>
          </div>
          <div
            style={{
              fontSize: "1.5rem",
              fontWeight: 700,
              fontFamily: "var(--font-mono)",
              color: "#0f172a",
              lineHeight: 1.2,
            }}
          >
            {loading ? "..." : card.value}
          </div>
          <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
            {card.change}
          </span>
        </div>
      ))}
    </div>
  );
};

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
      value: stats ? stats.total_alerts : "-",
      icon: <ShieldAlert size={20} color="var(--accent-primary)" />,
      change: "All recorded security incidents",
      color: "var(--accent-primary)",
    },
    {
      title: "Critical & High",
      value: stats
        ? (stats.by_severity["CRITICAL"] || 0) + (stats.by_severity["HIGH"] || 0)
        : "-",
      icon: <Flame size={20} color="var(--severity-critical)" />,
      change: "Urgent triage needed",
      color: "var(--severity-critical)",
    },
    {
      title: "Active Triage",
      value: stats
        ? (stats.by_status["NEW"] || 0) + (stats.by_status["ACTIVE"] || 0)
        : "-",
      icon: <AlertTriangle size={20} color="var(--status-active)" />,
      change: "Unresolved incidents",
      color: "var(--status-active)",
    },
    {
      title: "Resolved Incidents",
      value: stats ? stats.by_status["RESOLVED"] || 0 : "-",
      icon: <CheckCircle size={20} color="var(--status-resolved)" />,
      change: "Closed investigations",
      color: "var(--status-resolved)",
    },
  ];

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
        gap: "1rem",
        marginBottom: "1.5rem",
      }}
    >
      {cards.map((card, idx) => (
        <div
          key={idx}
          className="glass-panel"
          style={{
            padding: "1.15rem 1.25rem",
            display: "flex",
            flexDirection: "column",
            gap: "0.5rem",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)", fontWeight: 500 }}>
              {card.title}
            </span>
            <div
              style={{
                width: 32,
                height: 32,
                borderRadius: 6,
                background: "rgba(255, 255, 255, 0.04)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {card.icon}
            </div>
          </div>
          <div style={{ fontSize: "1.65rem", fontWeight: 700, fontFamily: "var(--font-mono)" }}>
            {loading ? "..." : card.value}
          </div>
          <span style={{ fontSize: "0.725rem", color: "var(--text-muted)" }}>
            {card.change}
          </span>
        </div>
      ))}
    </div>
  );
};

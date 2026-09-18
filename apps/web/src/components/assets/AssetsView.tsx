import React, { useState } from "react";
import { Server, Search, ShieldCheck, RefreshCw } from "lucide-react";
import type { EntityStatisticsItem } from "../../api/system";
import type { SecurityAlertRead } from "../../types/alert";

interface AssetsViewProps {
  entities: EntityStatisticsItem[];
  alerts: SecurityAlertRead[];
  loading?: boolean;
  onSelectEntity?: (identifier: string) => void;
  onRefresh?: () => void;
}

export const AssetsView: React.FC<AssetsViewProps> = ({
  entities,
  alerts,
  loading = false,
  onSelectEntity,
  onRefresh,
}) => {
  const [search, setSearch] = useState("");

  // Also collect any unique entities mentioned in alerts
  const alertEntitiesMap = new Map<string, { role: string; alertCount: number; maxRisk: number }>();
  for (const alert of alerts) {
    const risk =
      typeof alert.risk_score === "object" && alert.risk_score !== null
        ? (alert.risk_score as any).score || 0
        : typeof alert.risk_score === "number"
        ? alert.risk_score
        : 0;

    if (alert.source_ip) {
      const existing = alertEntitiesMap.get(alert.source_ip) || { role: "SOURCE", alertCount: 0, maxRisk: 0 };
      existing.alertCount += 1;
      existing.maxRisk = Math.max(existing.maxRisk, risk);
      alertEntitiesMap.set(alert.source_ip, existing);
    }
    if (alert.destination_ip) {
      const existing = alertEntitiesMap.get(alert.destination_ip) || { role: "DESTINATION", alertCount: 0, maxRisk: 0 };
      existing.alertCount += 1;
      existing.maxRisk = Math.max(existing.maxRisk, risk);
      alertEntitiesMap.set(alert.destination_ip, existing);
    }
  }

  // Combine entities from backend statistics with alert entities
  const combinedAssets = entities.map((e) => {
    const fromAlert = alertEntitiesMap.get(e.identifier);
    return {
      identifier: e.identifier,
      entity_type: e.entity_type,
      role: fromAlert?.role || "ENDPOINT",
      alertCount: Math.max(e.alert_count, fromAlert?.alertCount || 0),
      maxRisk: fromAlert?.maxRisk || (e.alert_count > 0 ? 60 : 0),
    };
  });

  // Include any alert entities not in the stats array
  for (const [ip, info] of alertEntitiesMap.entries()) {
    if (!combinedAssets.some((a) => a.identifier === ip)) {
      combinedAssets.push({
        identifier: ip,
        entity_type: "IP_ADDRESS",
        role: info.role,
        alertCount: info.alertCount,
        maxRisk: info.maxRisk,
      });
    }
  }

  const filteredAssets = combinedAssets.filter(
    (a) =>
      a.identifier.toLowerCase().includes(search.toLowerCase()) ||
      a.entity_type.toLowerCase().includes(search.toLowerCase()) ||
      a.role.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {/* Header Bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
        <div>
          <h2 style={{ fontSize: "1.15rem", fontWeight: 700, color: "#0f172a", margin: 0 }}>
            Network Asset & Entity Inventory
          </h2>
          <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
            Observed network endpoints, devices, and associated threat correlation
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          {onRefresh && (
            <button className="btn btn-secondary btn-sm" onClick={onRefresh} disabled={loading}>
              <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
              <span>Refresh</span>
            </button>
          )}
        </div>
      </div>

      {/* Search & Filter */}
      <div
        className="glass-panel"
        style={{
          padding: "0.75rem 1rem",
          display: "flex",
          alignItems: "center",
          gap: "1rem",
        }}
      >
        <div style={{ position: "relative", flex: 1, maxWidth: "360px" }}>
          <Search
            size={15}
            color="var(--text-muted)"
            style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }}
          />
          <input
            type="text"
            placeholder="Filter assets by IP, type, or role..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ width: "100%", paddingLeft: "2rem" }}
            aria-label="Filter assets"
          />
        </div>
        <span style={{ fontSize: "0.775rem", color: "var(--text-muted)" }}>
          Showing {filteredAssets.length} tracked assets
        </span>
      </div>

      {/* Assets Table */}
      <div className="glass-panel" style={{ overflow: "hidden" }}>
        <table className="soc-table">
          <thead>
            <tr>
              <th>Asset Identifier</th>
              <th>Entity Type</th>
              <th>Observed Role</th>
              <th>Active Threats</th>
              <th>Risk Assessment</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {loading && filteredAssets.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
                  Aggregating observed network entity posture...
                </td>
              </tr>
            ) : filteredAssets.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
                  No network entities found matching filters.
                </td>
              </tr>
            ) : (
              filteredAssets.map((asset) => {
                const hasThreats = asset.alertCount > 0;
                return (
                  <tr
                    key={asset.identifier}
                    onClick={() => onSelectEntity && onSelectEntity(asset.identifier)}
                  >
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                        <Server size={16} color={hasThreats ? "var(--severity-high)" : "var(--accent-primary)"} />
                        <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "#0f172a" }}>
                          {asset.identifier}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span style={{ fontSize: "0.775rem", color: "var(--text-secondary)" }}>
                        {asset.entity_type}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontSize: "0.725rem",
                          fontWeight: 600,
                          padding: "0.15rem 0.45rem",
                          borderRadius: 4,
                          background: "#f1f5f9",
                          color: "#475569",
                        }}
                      >
                        {asset.role}
                      </span>
                    </td>
                    <td>
                      {hasThreats ? (
                        <span style={{ color: "var(--severity-critical)", fontWeight: 700, fontFamily: "var(--font-mono)" }}>
                          {asset.alertCount} Incident{asset.alertCount === 1 ? "" : "s"}
                        </span>
                      ) : (
                        <span style={{ color: "var(--text-muted)" }}>0 Incidents</span>
                      )}
                    </td>
                    <td>
                      {hasThreats ? (
                        <span
                          style={{
                            fontSize: "0.725rem",
                            fontWeight: 600,
                            padding: "0.15rem 0.45rem",
                            borderRadius: 4,
                            background: "var(--severity-critical-bg)",
                            color: "var(--severity-critical)",
                            border: "1px solid var(--severity-critical-border)",
                          }}
                        >
                          Risk: {asset.maxRisk} / 100
                        </span>
                      ) : (
                        <span
                          style={{
                            fontSize: "0.725rem",
                            fontWeight: 500,
                            color: "#16a34a",
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "0.25rem",
                          }}
                        >
                          <ShieldCheck size={14} />
                          Normal
                        </span>
                      )}
                    </td>
                    <td>
                      <span
                        style={{
                          fontSize: "0.7rem",
                          padding: "0.125rem 0.5rem",
                          borderRadius: 9999,
                          fontWeight: 600,
                          background: hasThreats ? "var(--severity-high-bg)" : "#f0fdf4",
                          color: hasThreats ? "var(--severity-high)" : "#16a34a",
                          border: hasThreats ? "1px solid var(--severity-high-border)" : "1px solid #bbf7d0",
                        }}
                      >
                        {hasThreats ? "AT RISK" : "MONITORED"}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

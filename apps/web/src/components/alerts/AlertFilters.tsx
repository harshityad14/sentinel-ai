import React from "react";
import { AlertFilterParams } from "../../types/alert";
import { Search, RotateCcw } from "lucide-react";

interface AlertFiltersProps {
  filters: AlertFilterParams;
  onFilterChange: (filters: Partial<AlertFilterParams>) => void;
  onReset: () => void;
}

export const AlertFilters: React.FC<AlertFiltersProps> = ({
  filters,
  onFilterChange,
  onReset,
}) => {
  return (
    <div
      className="glass-panel"
      style={{
        padding: "1rem 1.25rem",
        marginBottom: "1.25rem",
        display: "flex",
        flexDirection: "column",
        gap: "0.85rem",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "1rem", flexWrap: "wrap" }}>
        {/* Search bar */}
        <div style={{ position: "relative", flex: "1 1 240px" }}>
          <Search
            size={16}
            color="var(--text-muted)"
            style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }}
          />
          <input
            type="text"
            placeholder="Search by IP, Threat, or Alert ID..."
            value={filters.search || ""}
            onChange={(e) => onFilterChange({ search: e.target.value })}
            style={{ width: "100%", paddingLeft: "2rem" }}
            aria-label="Search alerts"
          />
        </div>

        {/* Severity filter */}
        <select
          value={filters.severity || ""}
          onChange={(e) => onFilterChange({ severity: e.target.value || undefined })}
          aria-label="Filter by severity"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        {/* Status filter */}
        <select
          value={filters.status || ""}
          onChange={(e) => onFilterChange({ status: e.target.value || undefined })}
          aria-label="Filter by lifecycle status"
        >
          <option value="">All Statuses</option>
          <option value="NEW">New</option>
          <option value="ACTIVE">Active</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="RESOLVED">Resolved</option>
        </select>

        {/* Threat class filter */}
        <select
          value={filters.threat_class || ""}
          onChange={(e) => onFilterChange({ threat_class: e.target.value || undefined })}
          aria-label="Filter by threat category"
        >
          <option value="">All Threat Classes</option>
          <option value="PORT_SCAN">Port Scan</option>
          <option value="SYN_FLOOD">SYN Flood</option>
          <option value="DNS_TUNNELING">DNS Tunneling</option>
          <option value="DNS_DGA">DNS DGA</option>
          <option value="C2_BEACONING">C2 Beaconing</option>
          <option value="DATA_EXFILTRATION">Data Exfiltration</option>
          <option value="SUSPICIOUS_TLS">Suspicious TLS</option>
        </select>

        {/* Reset filters button */}
        <button
          className="btn btn-secondary btn-sm"
          onClick={onReset}
          title="Reset all filters"
          style={{ display: "inline-flex", alignItems: "center", gap: "0.35rem" }}
        >
          <RotateCcw size={14} />
          <span>Reset</span>
        </button>
      </div>

      {/* Quick Filter Chips & Risk Slider */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "0.75rem",
          paddingTop: "0.5rem",
          borderTop: "1px solid var(--border-subtle)",
          fontSize: "0.8rem",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <span style={{ color: "var(--text-muted)", fontWeight: 500 }}>Quick:</span>
          {[
            { label: "Unresolved", status: "ACTIVE" },
            { label: "High Risk (>75)", min_risk: 75 },
            { label: "Port Scans", threat_class: "PORT_SCAN" },
            { label: "C2 Beacons", threat_class: "C2_BEACONING" },
          ].map((chip, idx) => (
            <button
              key={idx}
              onClick={() => onFilterChange(chip)}
              className="btn btn-secondary btn-sm"
              style={{ fontSize: "0.75rem", padding: "0.2rem 0.5rem" }}
            >
              {chip.label}
            </button>
          ))}
        </div>

        {/* Min Risk Slider */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <span style={{ color: "var(--text-muted)" }}>Min Risk:</span>
          <input
            type="range"
            min="0"
            max="100"
            step="5"
            value={filters.min_risk || 0}
            onChange={(e) => onFilterChange({ min_risk: Number(e.target.value) || undefined })}
            style={{ width: "90px", accentColor: "var(--accent-primary)" }}
            aria-label="Minimum risk score threshold"
          />
          <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600, minWidth: "1.5rem" }}>
            {filters.min_risk || 0}
          </span>
        </div>
      </div>
    </div>
  );
};

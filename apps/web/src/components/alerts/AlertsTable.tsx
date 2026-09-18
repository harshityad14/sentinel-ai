import React from "react";
import { SecurityAlertRead } from "../../types/alert";
import { AlertRow } from "./AlertRow";
import { Pagination } from "../common/Pagination";
import { EmptyState } from "../common/EmptyState";
import { ArrowUpDown } from "lucide-react";

interface AlertsTableProps {
  alerts: SecurityAlertRead[];
  total: number;
  loading: boolean;
  error: string | null;
  limit: number;
  offset: number;
  sortBy?: string;
  sortDesc?: boolean;
  onSort: (field: string) => void;
  onPageChange: (newOffset: number) => void;
  onSelectAlert: (alert: SecurityAlertRead) => void;
  onRetry?: () => void;
}

export const AlertsTable: React.FC<AlertsTableProps> = ({
  alerts,
  total,
  loading,
  error,
  limit,
  offset,
  sortBy: _sortBy,
  sortDesc: _sortDesc,
  onSort,
  onPageChange,
  onSelectAlert,
  onRetry,
}) => {
  if (error) {
    return (
      <div className="glass-panel">
        <EmptyState
          isError
          title="Failed to Load Alerts"
          message={error}
          onRetry={onRetry}
        />
      </div>
    );
  }

  return (
    <div className="glass-panel" style={{ overflow: "hidden" }}>
      <div style={{ overflowX: "auto" }}>
        <table className="soc-table">
          <thead>
            <tr>
              <th style={{ width: "90px" }}>Severity</th>
              <th
                onClick={() => onSort("threat_class")}
                style={{ cursor: "pointer", userSelect: "none" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
                  <span>Threat Class</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th>Source / Destination</th>
              <th
                onClick={() => onSort("risk_score")}
                style={{ cursor: "pointer", userSelect: "none" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
                  <span>Risk Score</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th
                onClick={() => onSort("confidence")}
                style={{ cursor: "pointer", userSelect: "none" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
                  <span>Confidence</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th>Status</th>
              <th
                onClick={() => onSort("created_at")}
                style={{ cursor: "pointer", userSelect: "none" }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
                  <span>Last Seen</span>
                  <ArrowUpDown size={12} />
                </div>
              </th>
              <th style={{ width: "40px" }} aria-label="Actions"></th>
            </tr>
          </thead>
          <tbody>
            {loading && alerts.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: "center", padding: "3rem" }}>
                  <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
                    Loading real-time security alerts...
                  </span>
                </td>
              </tr>
            ) : alerts.length === 0 ? (
              <tr>
                <td colSpan={8}>
                  <EmptyState />
                </td>
              </tr>
            ) : (
              alerts.map((alert) => (
                <AlertRow
                  key={alert.alert_id}
                  alert={alert}
                  onSelect={onSelectAlert}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      <Pagination
        total={total}
        limit={limit}
        offset={offset}
        onPageChange={onPageChange}
      />
    </div>
  );
};

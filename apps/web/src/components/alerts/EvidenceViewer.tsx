import React from "react";
import { AlertEvidenceRead } from "../../types/alert";
import { FileSearch } from "lucide-react";

interface EvidenceViewerProps {
  evidenceList?: AlertEvidenceRead[];
  evidence?: AlertEvidenceRead[] | Record<string, any>;
}

export const EvidenceViewer: React.FC<EvidenceViewerProps> = ({ evidenceList, evidence }) => {
  // Normalize evidence input: accept either array of evidence items or key-value map
  let items: AlertEvidenceRead[] = [];
  if (Array.isArray(evidenceList) && evidenceList.length > 0) {
    items = evidenceList;
  } else if (Array.isArray(evidence) && evidence.length > 0) {
    items = evidence;
  } else if (evidence && typeof evidence === 'object') {
    items = [
      {
        detector_name: 'Telemetry Indicators',
        description: 'Captured signal evidence metrics',
        raw_indicators: evidence as Record<string, any>,
      },
    ];
  }

  if (!items || items.length === 0) {
    return (
      <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", fontStyle: "italic" }}>
        No explicit evidence items attached to this alert.
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
      {items.map((item, idx) => {
        const indicators =
          item.triggered_features || item.raw_indicators || item.raw_values || {};
        return (
          <div
            key={idx}
            className="glass-panel"
            style={{
              padding: "0.85rem 1rem",
              background: "rgba(10, 14, 23, 0.6)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "6px",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "0.4rem",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <FileSearch size={14} color="var(--accent-primary)" />
                <span style={{ fontWeight: 600, fontSize: "0.825rem", color: "var(--text-primary)" }}>
                  {item.detector_name}
                </span>
              </div>
              {item.confidence_contribution !== undefined && (
                <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                  Confidence: {(item.confidence_contribution * 100).toFixed(0)}%
                </span>
              )}
            </div>

            {item.description && (
              <p style={{ fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.5rem" }}>
                {item.description}
              </p>
            )}

            {Object.keys(indicators).length > 0 && (
              <div
                style={{
                  background: "var(--bg-primary)",
                  borderRadius: "4px",
                  padding: "0.5rem 0.65rem",
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.75rem",
                  color: "#38bdf8",
                  overflowX: "auto",
                  border: "1px solid rgba(255, 255, 255, 0.05)",
                }}
              >
                {Object.entries(indicators).map(([k, v]) => (
                  <div key={k} style={{ display: "flex", gap: "0.5rem" }}>
                    <span style={{ color: "var(--text-muted)" }}>{k}:</span>
                    <span>{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

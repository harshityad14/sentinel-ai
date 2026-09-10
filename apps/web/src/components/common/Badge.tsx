import React from "react";
import { AlertSeverity } from "../../types/alert";

interface BadgeProps {
  severity?: AlertSeverity | string;
  variant?: string;
  label?: string;
  size?: "sm" | "md";
  children?: React.ReactNode;
}

export const Badge: React.FC<BadgeProps> = ({ severity, variant, label, size = "md", children }) => {
  const effectiveSeverity = severity || variant || (typeof children === 'string' ? children : 'info');
  const normalized = (effectiveSeverity || 'info').toLowerCase();
  const displayLabel = label || children || effectiveSeverity;

  const getStyleClass = () => {
    switch (normalized) {
      case "critical":
        return "badge-critical";
      case "high":
        return "badge-high";
      case "medium":
        return "badge-medium";
      case "low":
        return "badge-low";
      default:
        return "badge-info";
    }
  };

  return (
    <span
      className={`badge ${getStyleClass()} ${size === "sm" ? "text-xs" : ""}`}
      role="status"
      aria-label={`Severity: ${displayLabel}`}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: "50%",
          backgroundColor: "currentColor",
          display: "inline-block",
        }}
      />
      {displayLabel}
    </span>
  );
};

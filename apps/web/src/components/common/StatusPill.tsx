import React from "react";
import { AlertStatus } from "../../types/alert";

interface StatusPillProps {
  status: AlertStatus | string;
}

export const StatusPill: React.FC<StatusPillProps> = ({ status }) => {
  const normalized = status.toLowerCase();

  const getStyleClass = () => {
    switch (normalized) {
      case "new":
        return "status-new";
      case "active":
        return "status-active";
      case "acknowledged":
        return "status-acknowledged";
      case "resolved":
        return "status-resolved";
      default:
        return "status-new";
    }
  };

  return (
    <span
      className={`status-pill ${getStyleClass()}`}
      role="status"
      aria-label={`Lifecycle status: ${status}`}
    >
      <span
        style={{
          width: 5,
          height: 5,
          borderRadius: "50%",
          backgroundColor: "currentColor",
          display: "inline-block",
        }}
      />
      {status}
    </span>
  );
};

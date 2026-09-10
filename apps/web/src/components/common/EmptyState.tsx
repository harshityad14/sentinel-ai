import React from "react";
import { AlertCircle, Inbox } from "lucide-react";

interface EmptyStateProps {
  title?: string;
  message?: string;
  isError?: boolean;
  onRetry?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = "No data available",
  message = "There are no records matching your current filter criteria.",
  isError = false,
  onRetry,
}) => {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "3.5rem 1.5rem",
        textAlign: "center",
      }}
    >
      <div
        style={{
          width: 48,
          height: 48,
          borderRadius: "50%",
          backgroundColor: isError ? "rgba(239, 68, 68, 0.15)" : "rgba(255, 255, 255, 0.05)",
          color: isError ? "var(--severity-critical)" : "var(--text-muted)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          marginBottom: "1rem",
        }}
      >
        {isError ? <AlertCircle size={24} /> : <Inbox size={24} />}
      </div>
      <h4 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "0.25rem" }}>
        {title}
      </h4>
      <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", maxWidth: "380px" }}>
        {message}
      </p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="btn btn-secondary btn-sm"
          style={{ marginTop: "1rem" }}
        >
          Try Again
        </button>
      )}
    </div>
  );
};

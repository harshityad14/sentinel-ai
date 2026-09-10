import React from "react";

interface RiskGaugeProps {
  score: number;
  showLabel?: boolean;
  size?: number;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, showLabel = true }) => {
  const normalizedScore = Math.max(0, Math.min(100, Math.round(score)));

  const getColor = (val: number) => {
    if (val >= 80) return "var(--severity-critical)";
    if (val >= 60) return "var(--severity-high)";
    if (val >= 40) return "var(--severity-medium)";
    if (val >= 20) return "var(--severity-low)";
    return "var(--severity-info)";
  };

  const color = getColor(normalizedScore);

  return (
    <div
      style={{ display: "inline-flex", alignItems: "center", gap: "0.5rem" }}
      aria-label={`Risk score: ${normalizedScore} out of 100`}
    >
      <div
        style={{
          width: 48,
          height: 8,
          background: "rgba(255, 255, 255, 0.1)",
          borderRadius: 4,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${normalizedScore}%`,
            height: "100%",
            backgroundColor: color,
            borderRadius: 4,
            transition: "width 0.3s ease",
          }}
        />
      </div>
      {showLabel && (
        <span
          style={{
            fontFamily: "var(--font-mono)",
            fontWeight: 600,
            fontSize: "0.85rem",
            color,
            minWidth: "2rem",
          }}
        >
          {normalizedScore}
        </span>
      )}
    </div>
  );
};

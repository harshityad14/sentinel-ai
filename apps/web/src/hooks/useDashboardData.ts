import { useState, useEffect, useCallback } from "react";
import {
  fetchProcessingStatus,
  fetchTelemetrySummary,
  fetchEntityStatistics,
  fetchHealth,
  ProcessingStatus,
  TelemetrySummary,
  EntityStatisticsItem,
  SystemHealth,
} from "../api/system";

export interface DashboardData {
  processingStatus: ProcessingStatus | null;
  telemetrySummary: TelemetrySummary | null;
  entities: EntityStatisticsItem[];
  health: SystemHealth | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useDashboardData(): DashboardData {
  const [processingStatus, setProcessingStatus] = useState<ProcessingStatus | null>(null);
  const [telemetrySummary, setTelemetrySummary] = useState<TelemetrySummary | null>(null);
  const [entities, setEntities] = useState<EntityStatisticsItem[]>([]);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      setError(null);
      const [statusRes, summaryRes, entitiesRes, healthRes] = await Promise.allSettled([
        fetchProcessingStatus(),
        fetchTelemetrySummary(),
        fetchEntityStatistics(10),
        fetchHealth(),
      ]);

      if (statusRes.status === "fulfilled") {
        setProcessingStatus(statusRes.value);
      }
      if (summaryRes.status === "fulfilled") {
        setTelemetrySummary(summaryRes.value);
      }
      if (entitiesRes.status === "fulfilled") {
        setEntities(entitiesRes.value);
      }
      if (healthRes.status === "fulfilled") {
        setHealth(healthRes.value);
      }

      // If all failed, set an informative error
      if (
        statusRes.status === "rejected" &&
        summaryRes.status === "rejected" &&
        entitiesRes.status === "rejected"
      ) {
        setError("Backend API is currently offline or unreachable.");
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load dashboard telemetry.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  return {
    processingStatus,
    telemetrySummary,
    entities,
    health,
    loading,
    error,
    refetch: fetchData,
  };
}

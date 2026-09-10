import { useState, useEffect, useCallback } from "react";
import { fetchAlertById, acknowledgeAlert, resolveAlert } from "../api/alerts";
import { SecurityAlertRead } from "../types/alert";

export function useAlertDetail(alertId: string | null) {
  const [alert, setAlert] = useState<SecurityAlertRead | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mutating, setMutating] = useState(false);

  const loadAlert = useCallback(async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAlertById(id);
      setAlert(data);
    } catch (err: any) {
      setError(err?.message || "Failed to load alert details");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (alertId) {
      loadAlert(alertId);
    } else {
      setAlert(null);
    }
  }, [alertId, loadAlert]);

  const handleAcknowledge = async (changedBy: string, notes: string) => {
    if (!alert) return;
    const previous = { ...alert };
    setMutating(true);
    // Optimistic update
    setAlert({ ...alert, status: "ACKNOWLEDGED" });
    try {
      const updated = await acknowledgeAlert(alert.alert_id, changedBy, notes);
      setAlert(updated);
      return updated;
    } catch (err: any) {
      // Rollback
      setAlert(previous);
      throw err;
    } finally {
      setMutating(false);
    }
  };

  const handleResolve = async (changedBy: string, notes: string) => {
    if (!alert) return;
    const previous = { ...alert };
    setMutating(true);
    // Optimistic update
    setAlert({ ...alert, status: "RESOLVED" });
    try {
      const updated = await resolveAlert(alert.alert_id, changedBy, notes);
      setAlert(updated);
      return updated;
    } catch (err: any) {
      // Rollback
      setAlert(previous);
      throw err;
    } finally {
      setMutating(false);
    }
  };

  return {
    alert,
    loading,
    error,
    mutating,
    acknowledge: handleAcknowledge,
    resolve: handleResolve,
    refresh: () => alertId && loadAlert(alertId),
  };
}

import { useState, useEffect, useCallback, useRef } from "react";
import { fetchAlerts } from "../api/alerts";
import { AlertFilterParams, SecurityAlertRead } from "../types/alert";
import { useWebSocket } from "./useWebSocket";

export function useAlerts(initialFilters: AlertFilterParams = { limit: 25, offset: 0 }) {
  const [filters, setFilters] = useState<AlertFilterParams>(initialFilters);
  const [alerts, setAlerts] = useState<SecurityAlertRead[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load alerts from REST API
  const loadAlerts = useCallback(async (currentFilters: AlertFilterParams) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetchAlerts(currentFilters);
      setAlerts(response.items);
      setTotal(response.total);
    } catch (err: any) {
      setError(err?.message || "Failed to load security alerts");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAlerts(filters);
  }, [filters, loadAlerts]);

  // Handle incoming real-time alerts from WebSocket
  const handleIncomingAlert = useCallback((newAlert: SecurityAlertRead) => {
    setAlerts((prev) => {
      const existsIndex = prev.findIndex((a) => a.alert_id === newAlert.alert_id);
      if (existsIndex >= 0) {
        // Update existing record in-place
        const updated = [...prev];
        updated[existsIndex] = { ...updated[existsIndex], ...newAlert };
        return updated;
      }
      // Prepend newly emitted alert
      return [newAlert, ...prev];
    });
    setTotal((prev) => prev + 1);
  }, []);

  const { status: wsStatus, reconnect } = useWebSocket({
    onAlert: handleIncomingAlert,
  });

  // Fallback polling if WebSocket is in POLLING_FALLBACK mode
  const pollingTimerRef = useRef<any>(null);
  useEffect(() => {
    if (wsStatus === "POLLING_FALLBACK") {
      pollingTimerRef.current = setInterval(() => {
        loadAlerts(filters);
      }, 10000);
    } else {
      clearInterval(pollingTimerRef.current);
    }
    return () => clearInterval(pollingTimerRef.current);
  }, [wsStatus, filters, loadAlerts]);

  const updateFilters = useCallback((newFilters: Partial<AlertFilterParams>) => {
    setFilters((prev) => ({
      ...prev,
      ...newFilters,
      offset: newFilters.offset !== undefined ? newFilters.offset : 0, // Reset page on filter change
    }));
  }, []);

  const refresh = useCallback(() => {
    loadAlerts(filters);
  }, [filters, loadAlerts]);

  const updateStatus = useCallback(
    async (alertId: string, newStatus: string, operator: string, notes: string) => {
      const { updateAlertLifecycle } = await import("../api/alerts");
      const updated = await updateAlertLifecycle(alertId, newStatus, operator, notes);
      setAlerts((prev) =>
        prev.map((a) => (a.alert_id === alertId ? { ...a, ...updated } : a))
      );
    },
    []
  );

  return {
    alerts,
    total,
    loading,
    error,
    filters,
    wsStatus,
    updateFilters,
    updateStatus,
    refresh,
    reconnectWs: reconnect,
  };
}

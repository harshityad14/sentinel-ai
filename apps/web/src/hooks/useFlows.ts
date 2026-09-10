import { useState, useEffect, useCallback } from 'react';
import type { FlowRecordRead, FlowFilterParams } from '../types/flow';
import { getFlows } from '../api/flows';

export function useFlows(initialParams: FlowFilterParams = { limit: 50, offset: 0 }) {
  const [flows, setFlows] = useState<FlowRecordRead[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [params, setParams] = useState<FlowFilterParams>(initialParams);

  const fetchFlows = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getFlows(params);
      setFlows(res.items);
      setTotal(res.total);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch network flows');
    } finally {
      setLoading(false);
    }
  }, [params]);

  useEffect(() => {
    fetchFlows();
  }, [fetchFlows]);

  return { flows, total, loading, error, params, setParams, refetch: fetchFlows };
}

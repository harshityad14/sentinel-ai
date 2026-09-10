import { useState, useEffect, useCallback } from 'react';
import type { DetectionResultRead, DetectionFilterParams } from '../types/detection';
import { getDetections } from '../api/detections';

export function useDetections(initialParams: DetectionFilterParams = { limit: 50, offset: 0 }) {
  const [detections, setDetections] = useState<DetectionResultRead[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [params, setParams] = useState<DetectionFilterParams>(initialParams);

  const fetchDetections = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getDetections(params);
      setDetections(res.items);
      setTotal(res.total);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch detections');
    } finally {
      setLoading(false);
    }
  }, [params]);

  useEffect(() => {
    fetchDetections();
  }, [fetchDetections]);

  return { detections, total, loading, error, params, setParams, refetch: fetchDetections };
}

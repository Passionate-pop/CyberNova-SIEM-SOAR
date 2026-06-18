import { useState, useEffect, useCallback, useRef } from 'react';
import { isWsActive } from './useWebSocket';

export function usePolling<T>(
  fetcher: () => Promise<T>,
  interval: number = 5000,
  enabled: boolean = true
) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const refetchDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const loadingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchData = useCallback(async () => {
    if (isWsActive()) return;
    // Only show loading if fetch takes > 150ms (prevents skeleton flash)
    if (loadingTimerRef.current) clearTimeout(loadingTimerRef.current);
    const timerId = setTimeout(() => setLoading(true), 150);
    loadingTimerRef.current = timerId;
    try {
      const result = await fetcher();
      setData(result);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
      if (loadingTimerRef.current) {
        clearTimeout(loadingTimerRef.current);
        loadingTimerRef.current = null;
      }
    }
  }, [fetcher]);

  useEffect(() => {
    if (!enabled) return;

    if (isWsActive()) {
      setLoading(false);
      return;
    }

    fetchData();
    intervalRef.current = setInterval(fetchData, interval);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
      if (loadingTimerRef.current) {
        clearTimeout(loadingTimerRef.current);
      }
    };
  }, [fetchData, interval, enabled]);

  const refetch = useCallback(() => {
    if (refetchDebounceRef.current) return;
    refetchDebounceRef.current = setTimeout(() => {
      refetchDebounceRef.current = null;
    }, 300);
    fetchData();
  }, [fetchData]);

  return { data, loading, error, refetch };
}

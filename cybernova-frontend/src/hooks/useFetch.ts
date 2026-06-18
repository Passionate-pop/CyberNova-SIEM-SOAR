import { useState, useEffect, useCallback, useRef, Dispatch, SetStateAction } from 'react';

interface FetchState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

export function useFetch<T>(fetcher: () => Promise<T>, deps: unknown[] = []): FetchState<T> & { refetch: () => void; setData: Dispatch<SetStateAction<T | null>> } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const abortRef = useRef<AbortController | null>(null);
  const loadingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchData = useCallback(() => {
    // Cancel any in-flight request
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    // Only show loading skeleton if fetch takes longer than 150ms.
    // This prevents the flash where skeleton appears then instantly
    // disappears when data is cached or network is fast.
    if (loadingTimerRef.current) clearTimeout(loadingTimerRef.current);
    loadingTimerRef.current = setTimeout(() => {
      if (!controller.signal.aborted) {
        setLoading(true);
      }
    }, 150);

    fetcher()
      .then(result => {
        if (!controller.signal.aborted) {
          setData(result);
          setError(null);
        }
      })
      .catch(err => {
        if (!controller.signal.aborted) {
          setError(err instanceof Error ? err.message : 'Unknown error');
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
        if (loadingTimerRef.current) {
          clearTimeout(loadingTimerRef.current);
          loadingTimerRef.current = null;
        }
      });
  }, deps); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    fetchData();
    return () => {
      abortRef.current?.abort();
      if (loadingTimerRef.current) {
        clearTimeout(loadingTimerRef.current);
      }
    };
  }, [fetchData, version]); // eslint-disable-line react-hooks/exhaustive-deps

  const refetch = useCallback(() => {
    setVersion(v => v + 1);
  }, []);

  return { data, loading, error, refetch, setData };
}

/*
 * Generic async resource hook.
 *
 * Every data surface in ThreatPulse goes through this hook so that loading,
 * success and error handling are consistent, cancellations are always
 * cleaned up, and no component ever renders unverified data.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { toApiError, type ApiError } from '../api/errors';

export type AsyncStatus = 'loading' | 'success' | 'error';

export interface AsyncResource<T> {
  status: AsyncStatus;
  data: T | null;
  error: ApiError | null;
  /** True while a reload is in flight with previous data still on screen. */
  isRefreshing: boolean;
  /** Re-runs the request (used by retry buttons). */
  reload: () => void;
}

export interface LoaderContext {
  signal: AbortSignal;
}

export interface UseApiResourceOptions {
  /** Keep the previous data visible while a reload is in flight. */
  keepPreviousData?: boolean;
  /** Skip the request entirely (for example when a required id is missing). */
  enabled?: boolean;
}

/**
 * @param loader  Request function. It receives an AbortSignal and must pass it
 *                to the API client so navigation cancels in-flight requests.
 * @param deps    Primitive dependency list, fixed length across renders.
 */
export function useApiResource<T>(
  loader: (context: LoaderContext) => Promise<T>,
  deps: readonly unknown[],
  options: UseApiResourceOptions = {}
): AsyncResource<T> {
  const { keepPreviousData = false, enabled = true } = options;

  const loaderRef = useRef(loader);
  const [reloadToken, setReloadToken] = useState(0);

  const [state, setState] = useState<{
    status: AsyncStatus;
    data: T | null;
    error: ApiError | null;
    isRefreshing: boolean;
  }>({
    status: enabled ? 'loading' : 'success',
    data: null,
    error: null,
    isRefreshing: false,
  });

  useEffect(() => {
    loaderRef.current = loader;
  });

  useEffect(() => {
    if (!enabled) {
      setState({
        status: 'success',
        data: null,
        error: null,
        isRefreshing: false,
      });

      return;
    }

    const controller = new AbortController();

    setState((previous) => {
      if (keepPreviousData && previous.data !== null) {
        return { ...previous, isRefreshing: true, error: null };
      }

      return {
        status: 'loading',
        data: null,
        error: null,
        isRefreshing: false,
      };
    });

    loaderRef
      .current({ signal: controller.signal })
      .then((data) => {
        if (controller.signal.aborted) {
          return;
        }

        setState({
          status: 'success',
          data,
          error: null,
          isRefreshing: false,
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }

        const apiError = toApiError(error);

        if (apiError.isAbort) {
          return;
        }

        setState({
          status: 'error',
          data: null,
          error: apiError,
          isRefreshing: false,
        });
      });

    return () => {
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, reloadToken, enabled, keepPreviousData]);

  const reload = useCallback(() => {
    setReloadToken((token) => token + 1);
  }, []);

  return { ...state, reload };
}

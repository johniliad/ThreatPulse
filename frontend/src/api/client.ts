/*
 * ThreatPulse API client.
 *
 * Design constraints:
 *   - native fetch() only, GET only (the public API is read-only);
 *   - a client-side timeout so a stalled API cannot hang the UI;
 *   - a short-lived response cache aligned with the API's own
 *     `Cache-Control: public, max-age=60`;
 *   - in-flight de-duplication so React StrictMode double-mounting does not
 *     double the request count;
 *   - caller cancellation via AbortSignal that never cancels the shared
 *     request (so a navigating component cannot starve the cache);
 *   - no credentials, no cookies, no secrets of any kind.
 */

import { ApiError, toApiError } from './errors';

const DEFAULT_TIMEOUT_MS = 15_000;
const CACHE_TTL_MS = 60_000;
const FALLBACK_API_BASE = '/api/cti/v1/';

interface CacheEntry {
  expiresAt: number;
  value: unknown;
}

const responseCache = new Map<string, CacheEntry>();
const inFlightRequests = new Map<string, Promise<unknown>>();

export interface ApiGetOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Bypass the response cache and fetch a fresh copy. */
  fresh?: boolean;
}

export function getApiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_BASE_URL;

  if (typeof configured === 'string' && configured.trim() !== '') {
    const trimmed = configured.trim();

    return trimmed.endsWith('/') ? trimmed : `${trimmed}/`;
  }

  return FALLBACK_API_BASE;
}

/** Clears the response cache. Used by tests and by explicit refresh actions. */
export function clearApiCache(): void {
  responseCache.clear();
}

function buildUrl(path: string): string {
  const base = getApiBaseUrl();
  const normalizedPath = path.replace(/^\/+/, '');

  return `${base}${normalizedPath}`;
}

function readCache(url: string): { hit: boolean; value: unknown } {
  const entry = responseCache.get(url);

  if (!entry) {
    return { hit: false, value: undefined };
  }

  if (entry.expiresAt <= Date.now()) {
    responseCache.delete(url);

    return { hit: false, value: undefined };
  }

  return { hit: true, value: entry.value };
}

function writeCache(url: string, value: unknown): void {
  responseCache.set(url, {
    expiresAt: Date.now() + CACHE_TTL_MS,
    value,
  });
}

function extractServerMessage(json: unknown): string | null {
  if (typeof json !== 'object' || json === null) {
    return null;
  }

  const message = (json as Record<string, unknown>).message;

  return typeof message === 'string' && message.trim() !== ''
    ? message
    : null;
}

async function fetchJson(url: string, timeoutMs: number): Promise<unknown> {
  const controller = new AbortController();
  let timedOut = false;

  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  let response: Response;

  try {
    response = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'follow',
    });
  } catch (error) {
    clearTimeout(timer);

    if (timedOut) {
      throw new ApiError(
        'timeout',
        `Request to ${url} timed out after ${timeoutMs} ms.`
      );
    }

    throw toApiError(error);
  }

  let text: string;

  try {
    text = await response.text();
  } catch (error) {
    if (timedOut) {
      throw new ApiError(
        'timeout',
        `Response from ${url} did not complete within ${timeoutMs} ms.`
      );
    }

    throw toApiError(error);
  } finally {
    clearTimeout(timer);
  }

  let json: unknown = null;

  if (text.trim() !== '') {
    try {
      json = JSON.parse(text);
    } catch (error) {
      throw new ApiError(
        'invalid-response',
        'The API response body was not valid JSON.',
        { status: response.status, cause: error }
      );
    }
  }

  if (!response.ok) {
    throw new ApiError(
      'http',
      `The API responded with HTTP ${response.status}.`,
      {
        status: response.status,
        detail: extractServerMessage(json),
      }
    );
  }

  return json;
}

function raceWithSignal<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) {
    return promise;
  }

  if (signal.aborted) {
    return Promise.reject(
      new ApiError('aborted', 'The request was cancelled.')
    );
  }

  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      reject(new ApiError('aborted', 'The request was cancelled.'));
    };

    signal.addEventListener('abort', onAbort, { once: true });

    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error instanceof Error ? error : toApiError(error));
      }
    );
  });
}

/**
 * Performs a cached, timeout-guarded GET against the public CTI API.
 *
 * The returned value is the raw parsed JSON; callers must pass it through the
 * validators in `validate.ts` before it reaches the UI.
 */
export async function apiGet(
  path: string,
  options: ApiGetOptions = {}
): Promise<unknown> {
  const url = buildUrl(path);

  if (!options.fresh) {
    const cached = readCache(url);

    if (cached.hit) {
      return cached.value;
    }
  }

  let pending = inFlightRequests.get(url);

  if (!pending) {
    pending = fetchJson(url, options.timeoutMs ?? DEFAULT_TIMEOUT_MS)
      .then((value) => {
        writeCache(url, value);

        return value;
      })
      .finally(() => {
        inFlightRequests.delete(url);
      });

    inFlightRequests.set(url, pending);
  }

  return raceWithSignal(pending, options.signal);
}

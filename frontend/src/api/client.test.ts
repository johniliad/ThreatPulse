/*
 * API client tests.
 *
 * Covers the failure taxonomy, the response cache, in-flight de-duplication,
 * caller cancellation and the timeout guard — the behaviours the UI relies on
 * for honest loading/error states.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { apiGet, clearApiCache } from './client';
import { ApiError, isAbortError } from './errors';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('apiGet', () => {
  beforeEach(() => {
    clearApiCache();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns the parsed JSON body for a successful GET', async () => {
    const fetchStub = vi
      .fn()
      .mockResolvedValue(jsonResponse({ status: 'ok' }));

    vi.stubGlobal('fetch', fetchStub);

    await expect(apiGet('status.php')).resolves.toEqual({ status: 'ok' });

    expect(fetchStub).toHaveBeenCalledTimes(1);

    const [url, init] = fetchStub.mock.calls[0] as [string, RequestInit];

    expect(url).toBe('/api/cti/v1/status.php');
    expect(init.method).toBe('GET');
    expect(init.credentials).toBe('omit');
  });

  it('maps a 400 response to an http error carrying the server message', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          { status: 'error', message: 'Invalid CVE identifier.' },
          400
        )
      )
    );

    const error = await apiGet('threats.php?cve=bad').catch((caught) => caught);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).kind).toBe('http');
    expect((error as ApiError).status).toBe(400);
    expect((error as ApiError).detail).toBe('Invalid CVE identifier.');
    expect((error as ApiError).isRetryable).toBe(false);
  });

  it('marks 5xx responses as retryable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse({ status: 'error' }, 500))
    );

    const error = (await apiGet('threats.php').catch(
      (caught) => caught
    )) as ApiError;

    expect(error.kind).toBe('http');
    expect(error.isRetryable).toBe(true);
  });

  it('reports malformed JSON instead of throwing a parse error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response('<html>not json</html>', {
          status: 200,
          headers: { 'Content-Type': 'text/html' },
        })
      )
    );

    const error = (await apiGet('threats.php').catch(
      (caught) => caught
    )) as ApiError;

    expect(error.kind).toBe('invalid-response');
  });

  it('reports an HTML error page as the HTTP status it carries', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response('<!doctype html><h1>Forbidden</h1>', {
          status: 403,
          headers: { 'Content-Type': 'text/html' },
        })
      )
    );

    const error = (await apiGet('').catch((caught) => caught)) as ApiError;

    expect(error.kind).toBe('http');
    expect(error.status).toBe(403);
    expect(error.detail).toBeNull();
    expect(error.userMessage).toContain('refused');
  });

  it('reports a network failure without leaking the underlying error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new TypeError('Failed to fetch'))
    );

    const error = (await apiGet('threats.php').catch(
      (caught) => caught
    )) as ApiError;

    expect(error.kind).toBe('network');
    expect(error.userMessage).toContain('could not be reached');
  });

  it('times out a stalled request', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: string, init: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init.signal?.addEventListener('abort', () => {
              reject(new DOMException('Aborted', 'AbortError'));
            });
          })
      )
    );

    const error = (await apiGet('threats.php', { timeoutMs: 5 }).catch(
      (caught) => caught
    )) as ApiError;

    expect(error.kind).toBe('timeout');
    expect(error.isRetryable).toBe(true);
  });

  it('reports caller cancellation as an abort', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: string, init: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init.signal?.addEventListener('abort', () => {
              reject(new DOMException('Aborted', 'AbortError'));
            });
          })
      )
    );

    const controller = new AbortController();
    const pending = apiGet('threats.php', { signal: controller.signal });

    controller.abort();

    const error = await pending.catch((caught) => caught);

    expect(isAbortError(error)).toBe(true);
  });

  it('serves a repeat request from the cache', async () => {
    const fetchStub = vi
      .fn()
      .mockResolvedValue(jsonResponse({ status: 'ok' }));

    vi.stubGlobal('fetch', fetchStub);

    await apiGet('status.php');
    await apiGet('status.php');

    expect(fetchStub).toHaveBeenCalledTimes(1);
  });

  it('bypasses the cache when a fresh copy is requested', async () => {
    const fetchStub = vi
      .fn()
      .mockImplementation(() => Promise.resolve(jsonResponse({ status: 'ok' })));

    vi.stubGlobal('fetch', fetchStub);

    await apiGet('status.php');
    await apiGet('status.php', { fresh: true });

    expect(fetchStub).toHaveBeenCalledTimes(2);
  });

  it('de-duplicates concurrent identical requests', async () => {
    const fetchStub = vi
      .fn()
      .mockResolvedValue(jsonResponse({ status: 'ok' }));

    vi.stubGlobal('fetch', fetchStub);

    await Promise.all([apiGet('status.php'), apiGet('status.php')]);

    expect(fetchStub).toHaveBeenCalledTimes(1);
  });
});

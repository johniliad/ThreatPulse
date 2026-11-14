/*
 * Endpoint binding tests.
 *
 * The request shapes matter as much as the payloads: the discovery document is
 * a script, not a directory, and asking for the directory depends on server
 * configuration that the deployed .htaccess does not provide.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearApiCache } from './client';
import { fetchApiIndex } from './endpoints';

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('fetchApiIndex', () => {
  beforeEach(() => {
    clearApiCache();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('requests the discovery script by name, never the directory', async () => {
    const fetchStub = vi.fn().mockResolvedValue(
      jsonResponse({
        status: 'ok',
        service: 'ThreatPulse CTI API',
        api_version: '1.0',
        description: 'Public read-only cyber threat intelligence API.',
        documentation: { threats: '/api/cti/v1/threats.php' },
        capabilities: { cve_to_threat: true, source_health: true },
        data_provenance: { primary_source: 'Multiple independent sources' },
        timestamp: '2026-11-14T11:24:43+00:00',
      })
    );

    vi.stubGlobal('fetch', fetchStub);

    const index = await fetchApiIndex();

    expect(fetchStub).toHaveBeenCalledTimes(1);

    const [url, init] = fetchStub.mock.calls[0] as [string, RequestInit];

    expect(url).toBe('/api/cti/v1/index.php');
    expect(String(url).endsWith('/')).toBe(false);
    expect(init.method).toBe('GET');
    expect(index.capabilities.cve_to_threat).toBe(true);
    expect(index.data_provenance?.primary_source).toBe(
      'Multiple independent sources'
    );
  });
});

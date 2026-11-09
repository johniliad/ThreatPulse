/*
 * Payload validation tests.
 *
 * These are the guard rails that keep unverified JSON out of the UI, so the
 * cases that matter most are: a missing envelope, an unexpected severity, and
 * the difference between "the relationship is empty" and "this deployment does
 * not expose the relationship".
 */

import { describe, expect, it } from 'vitest';
import { ApiError } from './errors';
import {
  detectContract,
  isValidCveId,
  parseApiIndex,
  parseMetadata,
  parseThreat,
  parseThreatDetail,
  parseThreatList,
  parseVulnerability,
  parseVulnerabilityList,
} from './validate';

export const THREAT_UUID = '11111111-1111-4111-8111-111111111111';

export function threatPayload(overrides: Record<string, unknown> = {}) {
  return {
    id: 9,
    threat_uuid: THREAT_UUID,
    external_id: 'CVE-2026-109619',
    title: 'Fixture threat',
    threat_type: 'vulnerability',
    severity: 'critical',
    priority_score: 92.5,
    confidence_score: 100,
    confidence_level: 'high',
    exploitation_status: 'confirmed',
    first_seen: '2026-10-26 00:00:00',
    last_seen: '2026-10-30 01:36:50',
    summary: 'Summary',
    recommended_action: 'Apply mitigations.',
    metadata: {
      cwes: ['CWE-416'],
      reasoning: ['Listed in the CISA KEV catalog.'],
      score_factors: { impact: 100, exploitation: 100 },
      score_weights: { impact: 0.1, exploitation: 0.3 },
      scoring_model: 'threatpulse_priority_v0.1',
      vendor: 'PHP Group',
      product: 'PHP',
    },
    ...overrides,
  };
}

describe('parseThreatList', () => {
  it('normalises a valid threats envelope', () => {
    const result = parseThreatList({
      status: 'ok',
      api_version: '1.0',
      data: { threats: [threatPayload()] },
      pagination: {
        limit: 25,
        offset: 0,
        returned: 1,
        total: 1764,
        has_more: true,
      },
      timestamp: '2026-10-30T01:36:50Z',
    });

    expect(result.items).toHaveLength(1);
    expect(result.pagination.total).toBe(1764);
    expect(result.pagination.has_more).toBe(true);
    expect(result.timestamp).toBe('2026-10-30T01:36:50Z');
    expect(result.items[0]?.priority_score).toBe(92.5);
    expect(result.items[0]?.metadata?.vendor).toBe('PHP Group');
  });

  it('rejects an envelope that is missing the threats array', () => {
    expect(() =>
      parseThreatList({ status: 'ok', data: {}, pagination: {} })
    ).toThrow(ApiError);
  });

  it('rejects a non-ok status on a 200 response', () => {
    expect(() =>
      parseThreatList({ status: 'error', data: { threats: [] } })
    ).toThrow(/status "error"/);
  });

  it('reports an unreported severity as unknown rather than mislabelling it', () => {
    const threat = parseThreat({
      ...threatPayload({ severity: 'catastrophic' }),
    });

    expect(threat.severity).toBe('unknown');
  });

  it('requires a threat_uuid', () => {
    expect(() => parseThreat({ title: 'no uuid' })).toThrow(/threat_uuid/);
  });

  it('decodes metadata that arrives as a JSON string', () => {
    const metadata = parseMetadata(
      JSON.stringify({ vendor: 'PHP Group', cwes: ['CWE-416'] })
    );

    expect(metadata?.vendor).toBe('PHP Group');
    expect(metadata?.cwes).toEqual(['CWE-416']);
  });

  it('returns null for metadata that is not an object', () => {
    expect(parseMetadata('not json')).toBeNull();
    expect(parseMetadata(null)).toBeNull();
  });
});

describe('parseThreatDetail', () => {
  it('parses the relationship arrays and ignores the internal id', () => {
    const detail = parseThreatDetail({
      status: 'ok',
      data: {
        threat: threatPayload({
          id: undefined,
          vulnerabilities: [
            {
              id: 9,
              cve_id: 'CVE-2026-109619',
              description: 'd',
              cvss_score: null,
              cvss_vector: null,
              severity: 'critical',
              kev_listed: true,
              exploited_in_wild: true,
              published_at: null,
              modified_at: null,
              vendor: 'PHP Group',
              product: 'PHP',
            },
          ],
          sources: [
            {
              id: 1,
              source_key: 'cisa_kev',
              name: 'CISA KEV',
              source_type: 'advisory',
              url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
              provider: 'CISA',
              reliability: 'high',
              relationship: 'reported',
            },
          ],
          publications: [
            {
              id: 2,
              publication_uuid: '8585c51f-706c-43a1-bab3-75ad4f4a2e62',
              schema_version: '1.0',
              generated_at: '2026-10-30 01:36:50',
              created_at: '2026-10-30 17:32:18',
            },
          ],
        }),
      },
    });

    expect(detail.id).toBeUndefined();
    expect(detail.vulnerabilities).toHaveLength(1);
    expect(detail.vulnerabilities[0]?.kev_listed).toBe(true);
    expect(detail.sources[0]?.relationship).toBe('reported');
    expect(detail.publications[0]?.schema_version).toBe('1.0');
  });
});

describe('vulnerability threat relationship', () => {
  const base = {
    id: 9,
    cve_id: 'CVE-2026-109619',
    description: 'd',
    cvss_score: null,
    cvss_vector: null,
    severity: 'critical',
    kev_listed: true,
    exploited_in_wild: true,
    published_at: null,
    modified_at: null,
    vendor: 'PHP Group',
    product: 'PHP',
  };

  it('leaves threats undefined when the deployment does not expose the relationship', () => {
    const vulnerability = parseVulnerability(base);

    expect(vulnerability.threats).toBeUndefined();
  });

  it('keeps an empty array when the relationship is exposed but empty', () => {
    const vulnerability = parseVulnerability({ ...base, threats: [] });

    expect(vulnerability.threats).toEqual([]);
  });

  it('parses threat references when they are present', () => {
    const vulnerability = parseVulnerability({
      ...base,
      threats: [
        {
          threat_uuid: THREAT_UUID,
          external_id: 'CVE-2026-109619',
          title: 'Fixture threat',
          severity: 'critical',
          priority_score: 92.5,
          confidence_level: 'high',
          exploitation_status: 'confirmed',
        },
      ],
    });

    expect(vulnerability.threats).toHaveLength(1);
    expect(vulnerability.threats?.[0]?.priority_score).toBe(92.5);
  });

  it('parses a vulnerability list envelope', () => {
    const result = parseVulnerabilityList({
      status: 'ok',
      data: { vulnerabilities: [{ ...base, threats: [] }] },
      pagination: {
        limit: 50,
        offset: 0,
        returned: 1,
        total: 1,
        has_more: false,
      },
    });

    expect(result.items[0]?.cve_id).toBe('CVE-2026-109619');
  });
});

describe('detectContract', () => {
  const indexWith = (capabilities: Record<string, boolean>) =>
    parseApiIndex({
      status: 'ok',
      service: 'ThreatPulse CTI API',
      api_version: '1.0',
      description: '',
      documentation: {},
      capabilities,
      data_provenance: { primary_source: 'CISA KEV' },
      timestamp: '2026-10-30T01:36:50Z',
    });

  it('reports no CVE support when the index omits the capability', () => {
    const contract = detectContract(indexWith({ cve_lookup: true }), []);

    expect(contract.cveToThreat).toBe(false);
    expect(contract.vulnerabilityThreatRelationship).toBe(false);
  });

  it('reads the capability flags when the enhancement is deployed', () => {
    const contract = detectContract(
      indexWith({
        cve_to_threat: true,
        vulnerability_threat_relationship: true,
      }),
      []
    );

    expect(contract.cveToThreat).toBe(true);
    expect(contract.vulnerabilityThreatRelationship).toBe(true);
  });

  it('treats an observed threats array as proof of the relationship', () => {
    const vulnerability = parseVulnerability({
      id: 1,
      cve_id: 'CVE-2026-109619',
      severity: 'critical',
      kev_listed: true,
      exploited_in_wild: true,
      threats: [],
    });

    const contract = detectContract(null, [vulnerability]);

    expect(contract.cveToThreat).toBe(true);
    expect(contract.vulnerabilityThreatRelationship).toBe(true);
  });

  it('does not treat a missing index as proof of anything', () => {
    const contract = detectContract(null, []);

    expect(contract.cveToThreat).toBe(false);
    expect(contract.vulnerabilityThreatRelationship).toBe(false);
  });
});

describe('isValidCveId', () => {
  it('accepts well-formed identifiers in any case', () => {
    expect(isValidCveId('CVE-2026-109619')).toBe(true);
    expect(isValidCveId('cve-1999-0001')).toBe(true);
  });

  it('rejects malformed identifiers and injection attempts', () => {
    expect(isValidCveId('CVE-26-1')).toBe(false);
    expect(isValidCveId('CVE-2026-')).toBe(false);
    expect(isValidCveId("CVE-2026-109619' OR '1'='1")).toBe(false);
  });
});

/*
 * ThreatPulse API endpoints.
 *
 * Every function here is a thin, typed wrapper around `apiGet`: it builds a
 * whitelisted query string, calls the API and validates the payload. Filters
 * are normalised client-side using exactly the same rules the PHP endpoints
 * apply, so the UI never sends a request the API would reject with HTTP 400.
 */

import { apiGet, type ApiGetOptions } from './client';
import { ApiError } from './errors';
import {
  isValidCveId,
  parseApiIndex,
  parseApiStatus,
  parseAttribution,
  parsePublicationList,
  parseSourceList,
  parseThreatDetail,
  parseThreatList,
  parseVulnerabilityList,
} from './validate';
import type {
  ApiIndex,
  ApiStatus,
  AttributionRegister,
  Paginated,
  Publication,
  Severity,
  Source,
  SourceQuery,
  Threat,
  ThreatDetail,
  ThreatQuery,
  Vulnerability,
  VulnerabilityQuery,
} from './types';

const THREAT_UUID_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** The API caps `limit` at 100; larger values are clamped server-side. */
export const MAX_LIMIT = 100;

/** The five values the API accepts for `severity`. */
const FILTERABLE_SEVERITIES: readonly Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
];

type QueryValue = string | number | boolean | null | undefined;

export function buildQueryString(params: Record<string, QueryValue>): string {
  const search = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined) {
      continue;
    }

    if (typeof value === 'string' && value.trim() === '') {
      continue;
    }

    search.set(key, String(value));
  }

  const query = search.toString();

  return query === '' ? '' : `?${query}`;
}

export function clampLimit(limit: number | undefined, fallback: number): number {
  if (limit === undefined || !Number.isFinite(limit)) {
    return fallback;
  }

  return Math.max(1, Math.min(Math.trunc(limit), MAX_LIMIT));
}

export function normaliseOffset(offset: number | undefined): number {
  if (offset === undefined || !Number.isFinite(offset) || offset < 0) {
    return 0;
  }

  return Math.trunc(offset);
}

function normaliseCve(cve: string | null | undefined): string | null {
  if (cve === null || cve === undefined) {
    return null;
  }

  const trimmed = cve.trim();

  if (trimmed === '') {
    return null;
  }

  if (!isValidCveId(trimmed)) {
    throw new ApiError(
      'invalid-request',
      `"${trimmed}" is not a valid CVE identifier. Expected the form CVE-YYYY-NNNN.`
    );
  }

  return trimmed.toUpperCase();
}

function normaliseSeverity(
  severity: Severity | null | undefined
): string | null {
  if (!severity || !FILTERABLE_SEVERITIES.includes(severity)) {
    return null;
  }

  return severity;
}

/** GET /status.php — lightweight service health. */
export async function fetchApiStatus(
  options?: ApiGetOptions
): Promise<ApiStatus> {
  const json = await apiGet('status.php', options);

  return parseApiStatus(json);
}

/**
 * GET /index.php — API discovery document (documentation + capabilities).
 *
 * The file name is explicit, never the directory. `/api/cti/v1/` only resolves
 * to `index.php` when the server's `DirectoryIndex` allows it — server
 * configuration a client cannot verify. The configuration that shipped with
 * 1.0.0 answered the directory with HTTP 403, so the script is requested by
 * name, which is the form that does not depend on that setting.
 */
export async function fetchApiIndex(
  options?: ApiGetOptions
): Promise<ApiIndex> {
  const json = await apiGet('index.php', options);

  return parseApiIndex(json);
}

/**
 * GET /threats.php — paginated threat list, ordered by the API as
 * priority_score DESC, last_seen DESC, id DESC.
 */
export async function fetchThreats(
  query: ThreatQuery = {},
  options?: ApiGetOptions
): Promise<Paginated<Threat>> {
  const queryString = buildQueryString({
    limit: clampLimit(query.limit, 25),
    offset: normaliseOffset(query.offset),
    severity: normaliseSeverity(query.severity),
    exploitation_status: query.exploitationStatus ?? null,
    cve: normaliseCve(query.cve),
  });

  const json = await apiGet(`threats.php${queryString}`, options);

  return parseThreatList(json);
}

/** GET /threat.php?uuid= — full threat record with its relationships. */
export async function fetchThreat(
  uuid: string,
  options?: ApiGetOptions
): Promise<ThreatDetail> {
  const trimmed = uuid.trim();

  if (!THREAT_UUID_PATTERN.test(trimmed)) {
    throw new ApiError(
      'invalid-request',
      `"${trimmed}" is not a valid ThreatPulse threat UUID.`
    );
  }

  const json = await apiGet(
    `threat.php${buildQueryString({ uuid: trimmed })}`,
    options
  );

  return parseThreatDetail(json);
}

/** GET /vulnerabilities.php — paginated vulnerability list with threat links. */
export async function fetchVulnerabilities(
  query: VulnerabilityQuery = {},
  options?: ApiGetOptions
): Promise<Paginated<Vulnerability>> {
  const queryString = buildQueryString({
    limit: clampLimit(query.limit, 25),
    offset: normaliseOffset(query.offset),
    cve: normaliseCve(query.cve),
    severity: normaliseSeverity(query.severity),
    kev_listed:
      query.kevListed === null || query.kevListed === undefined
        ? null
        : query.kevListed,
  });

  const json = await apiGet(`vulnerabilities.php${queryString}`, options);

  return parseVulnerabilityList(json);
}

/** GET /sources.php — intelligence sources with their threat counts. */
export async function fetchSources(
  query: SourceQuery = {},
  options?: ApiGetOptions
): Promise<Paginated<Source>> {
  const queryString = buildQueryString({
    limit: clampLimit(query.limit, 25),
    offset: normaliseOffset(query.offset),
    source_key: query.sourceKey ?? null,
    source_type: query.sourceType ?? null,
  });

  const json = await apiGet(`sources.php${queryString}`, options);

  return parseSourceList(json);
}

/**
 * GET /attribution.php — the source and attribution register.
 *
 * Distinct from `fetchSources`: that returns what contributed a threat, this
 * returns what the product decided, including sources it deliberately does not
 * ingest. It is not paginated in the UI because a register is small and a reader
 * wants all of it at once.
 */
export async function fetchAttribution(
  options?: ApiGetOptions
): Promise<AttributionRegister> {
  const json = await apiGet('attribution.php?limit=200', options);

  return parseAttribution(json);
}

/** GET /publications.php — publication history with computed record counts. */
export async function fetchPublications(
  query: { limit?: number; offset?: number } = {},
  options?: ApiGetOptions
): Promise<Paginated<Publication>> {
  const queryString = buildQueryString({
    limit: clampLimit(query.limit, 10),
    offset: normaliseOffset(query.offset),
  });

  const json = await apiGet(`publications.php${queryString}`, options);

  return parsePublicationList(json);
}

/**
 * Endpoint reference used by the /api page.
 *
 * Kept next to the implementations so the documented surface cannot drift
 * away from the code that actually calls it.
 */
export interface ApiEndpointDoc {
  key: string;
  path: string;
  summary: string;
  parameters: string[];
  notes: string;
}

export const API_ENDPOINTS: readonly ApiEndpointDoc[] = [
  {
    key: 'index',
    path: '/api/cti/v1/',
    summary:
      'Service discovery: documentation, capabilities and data provenance.',
    parameters: [],
    notes: 'Reports which capabilities this deployment supports.',
  },
  {
    key: 'status',
    path: '/api/cti/v1/status.php',
    summary: 'Lightweight service health and version.',
    parameters: [],
    notes: 'Cached by the API for 60 seconds.',
  },
  {
    key: 'threats',
    path: '/api/cti/v1/threats.php',
    summary:
      'Prioritised threat list, ordered by priority score, then last seen.',
    parameters: [
      'limit (1–100, default 50)',
      'offset (default 0)',
      'severity (critical | high | medium | low | informational)',
      'exploitation_status (confirmed | suspected | unknown | not_exploited)',
      'cve (CVE-YYYY-NNNN) — resolves a CVE to its associated threats',
    ],
    notes: 'Invalid filter values return HTTP 400 with the allowed values.',
  },
  {
    key: 'threat',
    path: '/api/cti/v1/threat.php',
    summary:
      'One threat record with its vulnerabilities, sources and publications.',
    parameters: ['uuid (required, RFC-4122 form)'],
    notes:
      'HTTP 400 for a malformed UUID, HTTP 404 when the record does not exist.',
  },
  {
    key: 'vulnerabilities',
    path: '/api/cti/v1/vulnerabilities.php',
    summary:
      'Vulnerability records, each with the ThreatPulse threats they relate to.',
    parameters: [
      'limit (1–100, default 50)',
      'offset (default 0)',
      'cve (CVE-YYYY-NNNN)',
      'severity (critical | high | medium | low | informational)',
      'kev_listed (true | false)',
    ],
    notes:
      'The threats array is present only on deployments with the CVE enhancement.',
  },
  {
    key: 'sources',
    path: '/api/cti/v1/sources.php',
    summary:
      'Intelligence sources with the number of threats attributed to each.',
    parameters: [
      'limit (1–100, default 50)',
      'offset (default 0)',
      'source_key',
      'source_type',
    ],
    notes: 'Source provenance, not endorsement of any vendor or advisory.',
  },
  {
    key: 'attribution',
    path: '/api/cti/v1/attribution.php',
    summary:
      'The source and attribution register: what is used, on what terms, and what is deliberately not used.',
    parameters: ['limit (1–200, default 100)', 'offset', 'ingested (true | false)', 'source_key', 'tier'],
    notes:
      'Distinct from sources.php, which reports what contributed a threat. This reports what the product decided, including sources that contribute nothing.',
  },
  {
    key: 'publications',
    path: '/api/cti/v1/publications.php',
    summary:
      'Publication history with computed threat and vulnerability counts.',
    parameters: ['limit (1–100, default 20)', 'offset (default 0)'],
    notes:
      'Counts are derived from the relationship tables, not from summary fields.',
  },
  {
    key: 'changes',
    path: '/api/cti/v1/changes.php',
    summary:
      'What moved since the previous publication: threats added, removed and changed, with the fields that changed.',
    parameters: [
      'kind (added | removed | changed, default added)',
      'limit (1–100, default 50)',
      'offset (default 0)',
    ],
    notes:
      'Compares the two most recent completed publications. The summary always counts all three kinds, whichever list is returned, and added + changed + unchanged equals the published total.',
  },
  {
    key: 'source_health',
    path: '/api/cti/v1/source_health.php',
    summary:
      'How each source behaved on the run that produced the current publication: ok, degraded or failed, with the counts and the failure reason.',
    parameters: [
      'status (ok | degraded | failed)',
      'source_key',
      'limit (1–100, default 50)',
      'offset (default 0)',
    ],
    notes:
      'Per run, not per record. "available": false means the publication predates the report — a missing report, not a failure.',
  },
];



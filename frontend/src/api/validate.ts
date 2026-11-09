/*
 * Runtime validation and normalisation of API payloads.
 *
 * The frontend never renders raw JSON. Everything passes through these
 * helpers first, which:
 *   - enforce the structural parts of the contract (arrays, required ids);
 *   - normalise nullable/absent values;
 *   - throw ApiError('invalid-response') when the payload is not the
 *     documented shape, so the UI can say "not displayed" rather than
 *     presenting unverified data as intelligence.
 */

import { ApiError } from './errors';
import type {
  ApiContract,
  ApiIndex,
  ApiStatus,
  AttributionRecord,
  AttributionRegister,
  ExploitationStatus,
  Paginated,
  Pagination,
  Publication,
  PublicationReference,
  ScoreFactors,
  Severity,
  Source,
  SourceAttribution,
  Threat,
  ThreatDetail,
  ThreatMetadata,
  ThreatReference,
  ThreatSource,
  Vulnerability,
} from './types';

const SEVERITY_VALUES: readonly string[] = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
];

const EXPLOITATION_VALUES: readonly string[] = [
  'confirmed',
  'suspected',
  'unknown',
  'not_exploited',
];

function fail(message: string): never {
  throw new ApiError('invalid-response', message);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }

  return value as Record<string, unknown>;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown, fallback = ''): string {
  if (typeof value === 'string') {
    return value;
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }

  return fallback;
}

function asNullableString(value: unknown): string | null {
  if (typeof value === 'string') {
    const trimmed = value.trim();

    return trimmed === '' ? null : value;
  }

  return null;
}

function asNumber(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string') {
    const parsed = Number(value);

    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }

  return fallback;
}

function asNullableNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === '') {
    return null;
  }

  const parsed = asNumber(value, Number.NaN);

  return Number.isFinite(parsed) ? parsed : null;
}

function asBoolean(value: unknown): boolean {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'number') {
    return value !== 0;
  }

  if (typeof value === 'string') {
    return value === '1' || value.toLowerCase() === 'true';
  }

  return false;
}

export function asSeverity(value: unknown): Severity {
  const raw = asString(value).toLowerCase();

  return SEVERITY_VALUES.includes(raw) ? (raw as Severity) : 'unknown';
}

export function asExploitationStatus(value: unknown): ExploitationStatus {
  const raw = asString(value).toLowerCase();

  return EXPLOITATION_VALUES.includes(raw)
    ? (raw as ExploitationStatus)
    : 'unknown';
}

function asStringArray(value: unknown): string[] {
  return asArray(value)
    .map((entry) => (typeof entry === 'string' ? entry : null))
    .filter((entry): entry is string => entry !== null);
}

function asScoreFactors(value: unknown): ScoreFactors | undefined {
  const record = asRecord(value);

  if (!record) {
    return undefined;
  }

  const factors: ScoreFactors = {};

  for (const [key, entry] of Object.entries(record)) {
    if (typeof entry === 'number' && Number.isFinite(entry)) {
      factors[key] = entry;
    }
  }

  return Object.keys(factors).length > 0 ? factors : undefined;
}

function asSourceAttribution(value: unknown): SourceAttribution | undefined {
  const record = asRecord(value);

  if (!record) {
    return undefined;
  }

  return {
    source_key: asNullableString(record.source_key) ?? undefined,
    source_name: asNullableString(record.source_name) ?? undefined,
    retrieved_at: asNullableString(record.retrieved_at) ?? undefined,
    source_record_id: asNullableString(record.source_record_id) ?? undefined,
  };
}

export function parseMetadata(value: unknown): ThreatMetadata | null {
  let record = asRecord(value);

  // Defensive: the API decodes metadata before returning it, but a raw JSON
  // string must never be rendered as a value.
  if (!record && typeof value === 'string' && value.trim() !== '') {
    try {
      record = asRecord(JSON.parse(value));
    } catch {
      return null;
    }
  }

  if (!record) {
    return null;
  }

  const metadata: ThreatMetadata = {
    ...record,
    cwes: asStringArray(record.cwes),
    vendor: asNullableString(record.vendor),
    product: asNullableString(record.product),
    due_date: asNullableString(record.due_date),
    reasoning: asStringArray(record.reasoning),
    cisa_notes: asNullableString(record.cisa_notes),
    score_factors: asScoreFactors(record.score_factors),
    score_weights: asScoreFactors(record.score_weights),
    source_attribution: asSourceAttribution(record.source_attribution),
  };

  if (typeof record.scoring_model === 'string') {
    metadata.scoring_model = record.scoring_model;
  }

  if (typeof record.forensic_triage === 'string') {
    metadata.forensic_triage = record.forensic_triage;
  }

  if (typeof record.known_ransomware_campaign_use === 'string') {
    metadata.known_ransomware_campaign_use =
      record.known_ransomware_campaign_use;
  }

  return metadata;
}

interface Envelope {
  root: Record<string, unknown>;
  data: Record<string, unknown>;
  timestamp: string | null;
}

function parseEnvelope(json: unknown): Envelope {
  const root = asRecord(json);

  if (!root) {
    fail('Response body is not a JSON object.');
  }

  const status = asString(root.status);

  if (status !== 'ok') {
    fail(
      `API reported status "${status === '' ? 'missing' : status}" on a successful HTTP response.`
    );
  }

  const data = asRecord(root.data);

  if (!data) {
    fail('Response is missing the data object.');
  }

  return {
    root,
    data,
    timestamp: asNullableString(root.timestamp),
  };
}

function parsePagination(raw: unknown, returned: number): Pagination {
  const record = asRecord(raw);

  if (!record) {
    fail('Response is missing the pagination object.');
  }

  return {
    limit: asNumber(record.limit, returned),
    offset: asNumber(record.offset, 0),
    returned: asNumber(record.returned, returned),
    total: asNumber(record.total, returned),
    has_more: asBoolean(record.has_more),
  };
}

export function parseThreat(raw: unknown): Threat {
  const record = asRecord(raw);

  if (!record) {
    fail('Threat record is not an object.');
  }

  const threatUuid = asString(record.threat_uuid);

  if (threatUuid === '') {
    fail('Threat record is missing threat_uuid.');
  }

  return {
    id: typeof record.id === 'number' ? record.id : undefined,
    threat_uuid: threatUuid,
    external_id: asNullableString(record.external_id),
    title: asString(record.title, 'Untitled threat record'),
    threat_type: asString(record.threat_type, 'unknown'),
    severity: asSeverity(record.severity),
    priority_score: asNumber(record.priority_score),
    confidence_score: asNumber(record.confidence_score),
    confidence_level: asString(record.confidence_level, 'unknown'),
    exploitation_status: asExploitationStatus(record.exploitation_status),
    first_seen: asNullableString(record.first_seen),
    last_seen: asNullableString(record.last_seen),
    summary: asNullableString(record.summary),
    recommended_action: asNullableString(record.recommended_action),
    metadata: parseMetadata(record.metadata),
  };
}

export function parseThreatReference(raw: unknown): ThreatReference {
  const record = asRecord(raw);

  if (!record) {
    fail('Threat reference is not an object.');
  }

  const threatUuid = asString(record.threat_uuid);

  if (threatUuid === '') {
    fail('Threat reference is missing threat_uuid.');
  }

  return {
    threat_uuid: threatUuid,
    external_id: asNullableString(record.external_id),
    title: asString(record.title, 'Untitled threat record'),
    severity: asSeverity(record.severity),
    priority_score: asNumber(record.priority_score),
    confidence_level: asString(record.confidence_level, 'unknown'),
    exploitation_status: asExploitationStatus(record.exploitation_status),
  };
}

export function parseVulnerability(raw: unknown): Vulnerability {
  const record = asRecord(raw);

  if (!record) {
    fail('Vulnerability record is not an object.');
  }

  const cveId = asString(record.cve_id);

  if (cveId === '') {
    fail('Vulnerability record is missing cve_id.');
  }

  const vulnerability: Vulnerability = {
    id: asNumber(record.id),
    cve_id: cveId,
    description: asNullableString(record.description),
    cvss_score: asNullableNumber(record.cvss_score),
    cvss_vector: asNullableString(record.cvss_vector),
    severity: asSeverity(record.severity),
    kev_listed: asBoolean(record.kev_listed),
    exploited_in_wild: asBoolean(record.exploited_in_wild),
    published_at: asNullableString(record.published_at),
    modified_at: asNullableString(record.modified_at),
    vendor: asNullableString(record.vendor),
    product: asNullableString(record.product),
  };

  /*
   * The relationship is exposed only by the enhanced API. Keeping it
   * `undefined` when absent (rather than defaulting to []) is what lets the
   * UI distinguish "no associated threat" from "this deployment does not
   * expose the relationship".
   */
  if (Array.isArray(record.threats)) {
    vulnerability.threats = record.threats.map(parseThreatReference);
  }

  return vulnerability;
}

export function parseThreatList(json: unknown): Paginated<Threat> {
  const { root, data, timestamp } = parseEnvelope(json);

  if (!Array.isArray(data.threats)) {
    fail('Response is missing the data.threats array.');
  }

  const items = data.threats.map(parseThreat);

  return {
    items,
    pagination: parsePagination(root.pagination, items.length),
    timestamp,
  };
}

export function parseThreatDetail(json: unknown): ThreatDetail {
  const { data } = parseEnvelope(json);
  const record = asRecord(data.threat);

  if (!record) {
    fail('Response is missing the data.threat object.');
  }

  return {
    ...parseThreat(record),
    vulnerabilities: asArray(record.vulnerabilities).map(parseVulnerability),
    sources: asArray(record.sources).map(parseThreatSource),
    publications: asArray(record.publications).map(parsePublicationReference),
  };
}

export function parseThreatSource(raw: unknown): ThreatSource {
  const record = asRecord(raw);

  if (!record) {
    fail('Source reference is not an object.');
  }

  return {
    id: asNumber(record.id),
    source_key: asString(record.source_key),
    name: asString(record.name, 'Unnamed source'),
    source_type: asString(record.source_type, 'unknown'),
    url: asNullableString(record.url),
    provider: asNullableString(record.provider),
    reliability: asNullableString(record.reliability),
    relationship: asString(record.relationship, 'reported'),
  };
}

export function parsePublicationReference(raw: unknown): PublicationReference {
  const record = asRecord(raw);

  if (!record) {
    fail('Publication reference is not an object.');
  }

  return {
    id: asNumber(record.id),
    publication_uuid: asString(record.publication_uuid),
    schema_version: asString(record.schema_version, 'unknown'),
    generated_at: asNullableString(record.generated_at),
    created_at: asNullableString(record.created_at),
  };
}

export function parseSource(raw: unknown): Source {
  const record = asRecord(raw);

  if (!record) {
    fail('Source record is not an object.');
  }

  const sourceKey = asString(record.source_key);

  if (sourceKey === '') {
    fail('Source record is missing source_key.');
  }

  return {
    id: asNumber(record.id),
    source_key: sourceKey,
    name: asString(record.name, 'Unnamed source'),
    source_type: asString(record.source_type, 'unknown'),
    url: asNullableString(record.url),
    provider: asNullableString(record.provider),
    reliability: asNullableString(record.reliability),
    threat_count: asNumber(record.threat_count),
  };
}

export function parsePublication(raw: unknown): Publication {
  const record = asRecord(raw);

  if (!record) {
    fail('Publication record is not an object.');
  }

  const publicationUuid = asString(record.publication_uuid);

  if (publicationUuid === '') {
    fail('Publication record is missing publication_uuid.');
  }

  return {
    id: asNumber(record.id),
    publication_uuid: publicationUuid,
    schema_version: asString(record.schema_version, 'unknown'),
    generated_at: asNullableString(record.generated_at),
    created_at: asNullableString(record.created_at),
    threat_count: asNumber(record.threat_count),
    vulnerability_count: asNumber(record.vulnerability_count),
  };
}

export function parseVulnerabilityList(json: unknown): Paginated<Vulnerability> {
  const { root, data, timestamp } = parseEnvelope(json);

  if (!Array.isArray(data.vulnerabilities)) {
    fail('Response is missing the data.vulnerabilities array.');
  }

  const items = data.vulnerabilities.map(parseVulnerability);

  return {
    items,
    pagination: parsePagination(root.pagination, items.length),
    timestamp,
  };
}

export function parseSourceList(json: unknown): Paginated<Source> {
  const { root, data, timestamp } = parseEnvelope(json);

  if (!Array.isArray(data.sources)) {
    fail('Response is missing the data.sources array.');
  }

  const items = data.sources.map(parseSource);

  return {
    items,
    pagination: parsePagination(root.pagination, items.length),
    timestamp,
  };
}

export function parseAttributionRecord(raw: unknown): AttributionRecord {
  const record = asRecord(raw);

  if (!record) {
    fail('Attribution record is not an object.');
  }

  const sourceKey = asString(record.source_key);

  if (sourceKey === '') {
    fail('Attribution record is missing source_key.');
  }

  return {
    source_key: sourceKey,
    name: asString(record.name, 'Unnamed source'),
    provider: asNullableString(record.provider),
    homepage: asNullableString(record.homepage),
    licence: asNullableString(record.licence),
    licence_url: asNullableString(record.licence_url),
    terms_url: asNullableString(record.terms_url),
    tlp_default: asNullableString(record.tlp_default),
    ingested: asBoolean(record.ingested),
    attribution_text: asNullableString(record.attribution_text),
    tier: asNullableNumber(record.tier),
    notes: asNullableString(record.notes),
    updated_at: asNullableString(record.updated_at),
  };
}

export function parseAttribution(json: unknown): AttributionRegister {
  const { data } = parseEnvelope(json);

  const register = asRecord(data.attribution);

  if (!register) {
    fail('Response is missing the data.attribution object.');
  }

  return {
    policy: asString(register.policy, ''),
    stored: asBoolean(register.stored),
    message: asNullableString(register.message),
    sources: asArray(register.sources).map(parseAttributionRecord),
  };
}

export function parsePublicationList(json: unknown): Paginated<Publication> {
  const { root, data, timestamp } = parseEnvelope(json);

  if (!Array.isArray(data.publications)) {
    fail('Response is missing the data.publications array.');
  }

  const items = data.publications.map(parsePublication);

  return {
    items,
    pagination: parsePagination(root.pagination, items.length),
    timestamp,
  };
}

export function parseApiStatus(json: unknown): ApiStatus {
  const record = asRecord(json);

  if (!record) {
    fail('Status response is not an object.');
  }

  return {
    status: asString(record.status, 'unknown'),
    service: asString(record.service, 'unknown'),
    version: asString(record.version, 'unknown'),
  };
}

export function parseApiIndex(json: unknown): ApiIndex {
  const record = asRecord(json);

  if (!record) {
    fail('API index response is not an object.');
  }

  const documentation: Record<string, string> = {};

  for (const [key, value] of Object.entries(
    asRecord(record.documentation) ?? {}
  )) {
    if (typeof value === 'string') {
      documentation[key] = value;
    }
  }

  const capabilities: Record<string, boolean> = {};

  for (const [key, value] of Object.entries(
    asRecord(record.capabilities) ?? {}
  )) {
    capabilities[key] = asBoolean(value);
  }

  const provenance = asRecord(record.data_provenance);

  return {
    status: asString(record.status, 'unknown'),
    service: asString(record.service, 'ThreatPulse CTI API'),
    api_version: asString(record.api_version, 'unknown'),
    description: asString(record.description),
    documentation,
    capabilities,
    data_provenance: provenance
      ? {
          primary_source:
            asNullableString(provenance.primary_source) ?? undefined,
        }
      : null,
    timestamp: asNullableString(record.timestamp),
  };
}

/** Validates a CVE identifier using the same rule as the API. */
export function isValidCveId(value: string): boolean {
  return /^CVE-\d{4}-\d{4,}$/i.test(value.trim());
}

/**
 * Detects which parts of the CVE enhancement are live.
 *
 * The pre-enhancement API ignores unknown query parameters, so a missing
 * capability must never be assumed to work: CVE navigation is offered only
 * when a capability flag or an observed `threats` array confirms it.
 */
export function detectContract(
  index: ApiIndex | null,
  sampleVulnerabilities: readonly Vulnerability[] = []
): ApiContract {
  const capabilities = index?.capabilities ?? {};

  const observedRelationship = sampleVulnerabilities.some(
    (vulnerability) => vulnerability.threats !== undefined
  );

  return {
    cveToThreat: capabilities.cve_to_threat === true || observedRelationship,
    vulnerabilityThreatRelationship:
      capabilities.vulnerability_threat_relationship === true ||
      observedRelationship,
    publicationDelta: capabilities.publication_delta === true,
    sourceHealth: capabilities.source_health === true,
  };
}




/*
 * ThreatPulse public CTI API — typed models.
 *
 * Every field here was verified against the live API at
 * https://threatpulse.iliadis.net/api/cti/v1/ and against the PHP
 * implementations in api/cti/v1/. Nothing is inferred or invented.
 *
 * Optionality is deliberate: fields that the API can return as null are
 * typed as nullable, and fields that only exist on some deployments (such as
 * the vulnerability → threat relationship) are optional so the frontend
 * degrades honestly instead of asserting data that is not there.
 */

/**
 * Severity values accepted by the API's `severity` filter.
 *
 * `unknown` is a frontend-only value: it is used when the API returns a
 * severity outside the documented set, so the UI reports the anomaly instead
 * of silently mislabelling it.
 */
export type Severity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'
  | 'unknown';

export type ExploitationStatus =
  | 'confirmed'
  | 'suspected'
  | 'unknown'
  | 'not_exploited';

export interface Pagination {
  limit: number;
  offset: number;
  returned: number;
  total: number;
  has_more: boolean;
}

export interface ScoreFactors {
  impact?: number;
  recency?: number;
  urgency?: number;
  forensic?: number;
  ransomware?: number;
  exploitation?: number;
  [key: string]: number | undefined;
}

export interface SourceAttribution {
  source_key?: string;
  source_name?: string;
  retrieved_at?: string;
  source_record_id?: string;
}

/** `threats.metadata` — produced by the CTI scoring pipeline. */
export interface ThreatMetadata {
  cwes?: string[];
  vendor?: string | null;
  product?: string | null;
  due_date?: string | null;
  reasoning?: string[];
  cisa_notes?: string | null;
  score_factors?: ScoreFactors;
  score_weights?: ScoreFactors;
  scoring_model?: string;
  forensic_triage?: string;
  source_attribution?: SourceAttribution;
  known_ransomware_campaign_use?: string;
  [key: string]: unknown;
}

/** A threat record as returned by threats.php (list) and threat.php (detail). */
export interface Threat {
  /** Internal database id. Present on list responses only. */
  id?: number;
  threat_uuid: string;
  external_id: string | null;
  title: string;
  threat_type: string;
  severity: Severity;
  priority_score: number;
  confidence_score: number;
  confidence_level: string;
  exploitation_status: ExploitationStatus;
  first_seen: string | null;
  last_seen: string | null;
  summary: string | null;
  recommended_action: string | null;
  metadata: ThreatMetadata | null;
}

/** Compact threat reference exposed on vulnerabilities.php by the CVE enhancement. */
export interface ThreatReference {
  threat_uuid: string;
  external_id: string | null;
  title: string;
  severity: Severity;
  priority_score: number;
  confidence_level: string;
  exploitation_status: ExploitationStatus;
}

export interface Vulnerability {
  id: number;
  cve_id: string;
  description: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity: Severity;
  kev_listed: boolean;
  exploited_in_wild: boolean;
  published_at: string | null;
  modified_at: string | null;
  vendor: string | null;
  product: string | null;
  /**
   * Associated ThreatPulse threats.
   *
   * `undefined` means the deployed API does not expose the relationship
   * (pre-enhancement). An empty array means the relationship is exposed and
   * this vulnerability currently has no associated threat.
   */
  threats?: ThreatReference[];
}

export interface ThreatSource {
  id: number;
  source_key: string;
  name: string;
  source_type: string;
  url: string | null;
  provider: string | null;
  reliability: string | null;
  relationship: string;
}

export interface PublicationReference {
  id: number;
  publication_uuid: string;
  schema_version: string;
  generated_at: string | null;
  created_at: string | null;
}

/** Full record returned by threat.php?uuid=. */
export interface ThreatDetail extends Threat {
  vulnerabilities: Vulnerability[];
  sources: ThreatSource[];
  publications: PublicationReference[];
}

export interface Source {
  id: number;
  source_key: string;
  name: string;
  source_type: string;
  url: string | null;
  provider: string | null;
  reliability: string | null;
  threat_count: number;
}

/**
 * One record from the source and attribution register.
 *
 * Unlike `Source`, which records what contributed a threat, this records what the
 * product *decided*: whether the source is ingested, under what licence, at what
 * tier, and — for a source that is deliberately not used — why.
 */
export interface AttributionRecord {
  source_key: string;
  name: string;
  provider: string | null;
  homepage: string | null;
  licence: string | null;
  licence_url: string | null;
  terms_url: string | null;
  tlp_default: string | null;
  ingested: boolean;
  attribution_text: string | null;
  tier: number | null;
  notes: string | null;
  updated_at: string | null;
}

export interface AttributionRegister {
  policy: string;
  /** False when the deployment has not stored the register yet. */
  stored: boolean;
  /** Present when `stored` is false, explaining what to do about it. */
  message: string | null;
  sources: AttributionRecord[];
}

export interface Publication {
  id: number;
  publication_uuid: string;
  schema_version: string;
  generated_at: string | null;
  created_at: string | null;
  threat_count: number;
  vulnerability_count: number;
}

export interface ApiStatus {
  status: string;
  service: string;
  version: string;
}

export interface ApiIndex {
  status: string;
  service: string;
  api_version: string;
  description: string;
  documentation: Record<string, string>;
  capabilities: Record<string, boolean>;
  data_provenance: { primary_source?: string } | null;
  timestamp: string | null;
}

/** Normalised paginated result used by every list surface. */
export interface Paginated<T> {
  items: T[];
  pagination: Pagination;
  /** Server-reported timestamp for the response, when present. */
  timestamp: string | null;
}

export interface ThreatQuery {
  limit?: number;
  offset?: number;
  severity?: Severity | null;
  exploitationStatus?: ExploitationStatus | null;
  /** CVE filter — requires the enhanced API contract. */
  cve?: string | null;
}

export interface VulnerabilityQuery {
  limit?: number;
  offset?: number;
  cve?: string | null;
  severity?: Severity | null;
  kevListed?: boolean | null;
}

export interface SourceQuery {
  limit?: number;
  offset?: number;
  sourceKey?: string | null;
  sourceType?: string | null;
}

/**
 * Capability detection result.
 *
 * The pre-enhancement API silently ignores unknown query parameters, so a
 * `cve` filter cannot be assumed to have been applied. The frontend only
 * offers CVE-based navigation once the contract is confirmed.
 */
export interface ApiContract {
  cveToThreat: boolean;
  vulnerabilityThreatRelationship: boolean;
  publicationDelta: boolean;
  sourceHealth: boolean;
}

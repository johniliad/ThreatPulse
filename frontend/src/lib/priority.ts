/*
 * Priority Score presentation.
 *
 * The ThreatPulse Priority Score is produced by the backend scoring model, and the
 * frontend never recalculates it. The table below must stay identical to
 * `priority_band()` in `backend/scoring/priority.py`: the published `severity` *is*
 * this band, so a threshold changed on one side only would label the same record two
 * different ways in the API and in the interface.
 *
 * Boundaries confirmed against a 3,558-threat publication on 2 Nov 2026: critical at
 * 90 falls at the 97th percentile (3.5% of records), high at 75 is about the 66th
 * (31% with critical), medium starts at the exploitation floor of 50, and
 * informational sits below 25. Do not fine-tune them into the 85–90 plateau, where
 * five per cent of the catalogue sits inside eight tenths of a point.
 */

import type { ScoreFactors } from '../api/types';

export type PriorityBandKey =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational';

export interface PriorityBand {
  key: PriorityBandKey;
  label: string;
  min: number;
  max: number;
  guidance: string;
}

const CRITICAL_BAND: PriorityBand = {
  key: 'critical',
  label: 'Critical',
  min: 90,
  max: 100,
  guidance: 'Top of the ThreatPulse model — immediate attention.',
};

const HIGH_BAND: PriorityBand = {
  key: 'high',
  label: 'High',
  min: 75,
  max: 89.99,
  guidance: 'Strong signals — schedule action now.',
};

const MEDIUM_BAND: PriorityBand = {
  key: 'medium',
  label: 'Medium',
  min: 50,
  max: 74.99,
  guidance: 'Relevant, but not yet urgent.',
};

const LOW_BAND: PriorityBand = {
  key: 'low',
  label: 'Low',
  min: 25,
  max: 49.99,
  guidance: 'Monitor.',
};

const INFORMATIONAL_BAND: PriorityBand = {
  key: 'informational',
  label: 'Informational',
  min: 0,
  max: 24.99,
  guidance: 'Context only.',
};

export const PRIORITY_BANDS: readonly PriorityBand[] = [
  CRITICAL_BAND,
  HIGH_BAND,
  MEDIUM_BAND,
  LOW_BAND,
  INFORMATIONAL_BAND,
];

/** Maps an API-provided score onto the documented band table. */
export function priorityBand(score: number): PriorityBand {
  const clamped = Number.isFinite(score)
    ? Math.min(100, Math.max(0, score))
    : 0;

  if (clamped >= 90) {
    return CRITICAL_BAND;
  }

  if (clamped >= 75) {
    return HIGH_BAND;
  }

  if (clamped >= 50) {
    return MEDIUM_BAND;
  }

  if (clamped >= 25) {
    return LOW_BAND;
  }

  return INFORMATIONAL_BAND;
}

/** Factor order follows the documented scoring model, not the JSON order. */
export const SCORE_FACTOR_ORDER = [
  'exploitation',
  'recency',
  'urgency',
  'ransomware',
  'impact',
  'forensic',
  'epss',
  'evidence',
  'first_seen',
] as const;

export const SCORE_FACTOR_LABELS: Record<string, string> = {
  exploitation: 'Exploitation evidence',
  recency: 'Recency',
  urgency: 'Remediation urgency',
  ransomware: 'Ransomware relevance',
  impact: 'Technical impact',
  forensic: 'Forensic significance',
  epss: 'EPSS exploitation probability',
  evidence: 'Independent corroboration',
  first_seen: 'First observed by ThreatPulse',
};

export const SCORE_FACTOR_EXPLANATIONS: Record<string, string> = {
  exploitation: 'Whether the threat is observed or assessed to be exploited.',
  recency: 'How recently the signal appeared or was refreshed.',
  urgency: 'Remediation deadline pressure, such as a CISA due date.',
  ransomware: 'Known or suspected ransomware campaign use.',
  impact: 'Severity of the technical consequence.',
  forensic: 'Whether forensic triage is indicated.',
  epss: 'Where the CVE sits in the EPSS distribution of exploitation probability.',
  evidence: 'How many independent sources describe the same vulnerability.',
  first_seen:
    'When ThreatPulse first collected this vulnerability — not when it was published.',
};

export function scoreFactorLabel(key: string): string {
  return SCORE_FACTOR_LABELS[key] ?? key;
}

export interface ScoreFactorRow {
  key: string;
  label: string;
  /** Factor value as reported by the API (0–100), or null when absent. */
  value: number | null;
  /** Weight as reported by the API (0–1), or null when absent. */
  weight: number | null;
}

/**
 * Builds the factor table from the API's own `score_factors` / `score_weights`.
 *
 * Weights are never substituted from the documented model: if a record does
 * not report them, the UI shows that they were not reported.
 */
export function buildScoreFactorRows(
  factors: ScoreFactors | undefined,
  weights: ScoreFactors | undefined
): ScoreFactorRow[] {
  /*
   * Only factors the API actually reports are listed, so a record without a
   * breakdown renders an explicit "no breakdown" message rather than a grid of
   * empty rows. Documented factors come first; anything unexpected is appended
   * so a future model extension is never silently hidden.
   */
  const reported = new Set<string>([
    ...Object.keys(factors ?? {}),
    ...Object.keys(weights ?? {}),
  ]);

  const documented = SCORE_FACTOR_ORDER.filter((key) => reported.has(key));

  const unexpected = [...reported].filter(
    (key) => !(SCORE_FACTOR_ORDER as readonly string[]).includes(key)
  );

  return [...documented, ...unexpected].map((key) => ({
    key,
    label: scoreFactorLabel(key),
    value:
      typeof factors?.[key] === 'number' ? (factors[key] as number) : null,
    weight:
      typeof weights?.[key] === 'number' ? (weights[key] as number) : null,
  }));
}

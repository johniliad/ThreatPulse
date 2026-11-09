/*
 * Priority Score visualisation.
 *
 * The score, its band and the factor breakdown all come from the API. The
 * frontend never recomputes the score; the band label is a lookup against the
 * documented ThreatPulse band table.
 */

import { formatScore } from '../../lib/format';
import { priorityBand } from '../../lib/priority';

interface PriorityScoreProps {
  score: number;
  /** Compact variant for dense list rows. */
  compact?: boolean;
}

const BAND_TONE: Record<string, string> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  informational: 'informational',
};

export function PriorityScore({ score, compact = false }: PriorityScoreProps) {
  const band = priorityBand(score);
  const tone = BAND_TONE[band.key] ?? 'informational';
  const width = Math.min(100, Math.max(0, score));

  return (
    <div className="tp-score">
      <span className="tp-score__value">
        {formatScore(score)}
        <span className="tp-score__unit"> / 100</span>
      </span>
      <span className={`tp-score__band tp-badge--${tone}`}>
        {band.label} band
      </span>
      <span
        className="tp-score__track"
        role="img"
        aria-label={`Priority score ${formatScore(score)} out of 100, ${band.label} band`}
      >
        <span
          className={`tp-score__fill tp-score__fill--${tone}`}
          style={{ width: `${width}%` }}
        />
      </span>
      {compact ? null : (
        <span className="tp-meta tp-meta--small">{band.guidance}</span>
      )}
    </div>
  );
}

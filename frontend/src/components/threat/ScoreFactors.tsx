/*
 * Score factor breakdown.
 *
 * Renders the API's own `score_factors` (0–100) and `score_weights` (0–1).
 * When a record does not report weights, that is stated rather than
 * substituted with the documented model weights.
 */

import type { ScoreFactors } from '../../api/types';
import { formatFactorValue, formatWeight } from '../../lib/format';
import { buildScoreFactorRows, SCORE_FACTOR_EXPLANATIONS } from '../../lib/priority';

interface ScoreFactorsProps {
  factors: ScoreFactors | undefined;
  weights: ScoreFactors | undefined;
  scoringModel?: string;
}

export function ScoreFactors({ factors, weights, scoringModel }: ScoreFactorsProps) {
  const rows = buildScoreFactorRows(factors, weights);

  if (rows.length === 0) {
    return (
      <p className="tp-meta">
        This record does not include a scoring breakdown. The Priority Score
        above is still the value produced by the ThreatPulse scoring model.
      </p>
    );
  }

  return (
    <div className="tp-stack tp-stack--tight">
      <ul className="tp-factors">
        {rows.map((row) => (
          <li className="tp-factor" key={row.key}>
            <span className="tp-factor__head">
              <span className="tp-factor__label">{row.label}</span>
              <span className="tp-factor__value">
                {formatFactorValue(row.value)} / 100 · weight{' '}
                {formatWeight(row.weight)}
              </span>
            </span>
            <span className="tp-factor__track" aria-hidden="true">
              <span
                className="tp-factor__fill"
                style={{
                  width: `${Math.min(100, Math.max(0, row.value ?? 0))}%`,
                }}
              />
            </span>
            {SCORE_FACTOR_EXPLANATIONS[row.key] ? (
              <span className="tp-meta tp-meta--small">
                {SCORE_FACTOR_EXPLANATIONS[row.key]}
              </span>
            ) : null}
          </li>
        ))}
      </ul>

      {scoringModel ? (
        <p className="tp-meta tp-meta--small">
          Scoring model reported by the API: <span className="mono">{scoringModel}</span>
        </p>
      ) : null}
    </div>
  );
}

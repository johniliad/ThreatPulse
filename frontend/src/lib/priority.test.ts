/*
 * Priority model presentation tests.
 *
 * The band table is the documented ThreatPulse model, so the boundary values
 * are asserted exactly: an off-by-one here would mislabel real intelligence.
 */

import { describe, expect, it } from 'vitest';
import {
  buildScoreFactorRows,
  PRIORITY_BANDS,
  priorityBand,
  scoreFactorLabel,
  SCORE_FACTOR_ORDER,
} from './priority';
import { formatCvss, formatScore, formatWeight, pluralise } from './format';

describe('priorityBand', () => {
  it('maps each documented boundary to the right band', () => {
    expect(priorityBand(100).key).toBe('critical');
    expect(priorityBand(90).key).toBe('critical');
    expect(priorityBand(89.99).key).toBe('high');
    expect(priorityBand(75).key).toBe('high');
    expect(priorityBand(74.99).key).toBe('medium');
    expect(priorityBand(50).key).toBe('medium');
    expect(priorityBand(49.99).key).toBe('low');
    expect(priorityBand(25).key).toBe('low');
    expect(priorityBand(24.99).key).toBe('informational');
    expect(priorityBand(0).key).toBe('informational');
  });

  it('clamps out-of-range and invalid scores instead of throwing', () => {
    expect(priorityBand(140).key).toBe('critical');
    expect(priorityBand(-5).key).toBe('informational');
    expect(priorityBand(Number.NaN).key).toBe('informational');
  });

  it('labels a real published score correctly', () => {
    expect(priorityBand(92.5).label).toBe('Critical');
    expect(priorityBand(80.5).label).toBe('High');
    expect(priorityBand(60).label).toBe('Medium');
  });
});

describe('PRIORITY_BANDS', () => {
  /*
   * The table is rendered on the methodology page as "Priority score bands", so a
   * gap in it is a false statement to a reader — a score of 72 once belonged to no
   * band at all, because `medium` kept its pre-recalibration upper bound of 69.99
   * when `high` moved from 70 to 75. The function was right and the table was
   * wrong, which no boundary test could catch.
   */
  it('covers 0–100 with no gap and no overlap', () => {
    const ordered = [...PRIORITY_BANDS].sort((a, b) => a.min - b.min);

    expect(ordered[0]?.min).toBe(0);
    expect(ordered[ordered.length - 1]?.max).toBe(100);

    for (let index = 1; index < ordered.length; index += 1) {
      const previous = ordered[index - 1];
      const current = ordered[index];

      expect(previous && current).toBeTruthy();

      if (!previous || !current) {
        continue;
      }

      expect(Number((previous.max + 0.01).toFixed(2))).toBe(current.min);
    }
  });

  it('agrees with the function that labels a score', () => {
    for (const band of PRIORITY_BANDS) {
      expect(priorityBand(band.min).key).toBe(band.key);
      expect(priorityBand(band.max).key).toBe(band.key);
    }
  });
});

describe('buildScoreFactorRows', () => {
  it('orders factors by the documented model, not by JSON order', () => {
    const rows = buildScoreFactorRows(
      { impact: 50, exploitation: 100, recency: 65 },
      { impact: 0.1, exploitation: 0.3, recency: 0.2 }
    );

    expect(rows.map((row) => row.key)).toEqual([
      'exploitation',
      'recency',
      'impact',
    ]);
  });

  it('keeps unreported values and weights as null', () => {
    const rows = buildScoreFactorRows({ exploitation: 100 }, undefined);

    expect(rows[0]?.value).toBe(100);
    expect(rows[0]?.weight).toBeNull();
  });

  it('includes unexpected factor keys after the documented ones', () => {
    const rows = buildScoreFactorRows({ newFactor: 10 }, undefined);

    expect(rows.map((row) => row.key)).toContain('newFactor');
  });

  it('returns an empty list when no factors are reported', () => {
    expect(buildScoreFactorRows(undefined, undefined)).toEqual([]);
  });

  it('has a label for every documented factor', () => {
    for (const key of SCORE_FACTOR_ORDER) {
      expect(scoreFactorLabel(key)).not.toBe(key);
    }
  });
});

describe('formatting', () => {
  it('does not invent precision for scores', () => {
    expect(formatScore(92.5)).toBe('92.5');
    expect(formatScore(80)).toBe('80');
    expect(formatScore(null)).toBe('—');
  });

  it('reports an absent CVSS score instead of zero', () => {
    expect(formatCvss(null)).toBe('Not provided');
    expect(formatCvss(9.8)).toBe('9.8');
  });

  it('reports unreported weights explicitly', () => {
    expect(formatWeight(null)).toBe('Not reported');
    expect(formatWeight(0.3)).toBe('30%');
    expect(formatWeight(0.05)).toBe('5%');
  });

  it('pluralises item labels', () => {
    expect(pluralise(1, 'threat')).toBe('threat');
    expect(pluralise(2, 'threat')).toBe('threats');
  });
});

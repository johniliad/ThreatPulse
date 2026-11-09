/*
 * Status badges.
 *
 * Severity, exploitation status and confidence are always rendered as a text
 * label, with an aria-hidden visual mark as a secondary cue. Colour is never
 * the only carrier of meaning.
 */

import type { ExploitationStatus, Severity } from '../../api/types';
import {
  CONFIDENCE_LABELS,
  EXPLOITATION_SHORT_LABELS,
  SEVERITY_LABELS,
} from '../../lib/constants';

interface SeverityBadgeProps {
  severity: Severity;
}

const SEVERITY_MARKS: Record<Severity, string> = {
  critical: '!!',
  high: '!',
  medium: '=',
  low: '-',
  informational: 'i',
  unknown: '?',
};

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <span className={`tp-badge tp-badge--${severity}`}>
      <span className="tp-badge__mark" aria-hidden="true">
        {SEVERITY_MARKS[severity]}
      </span>
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

interface ExploitationBadgeProps {
  status: ExploitationStatus;
  /** Use the long label instead of the compact one. */
  verbose?: boolean;
}

export function ExploitationBadge({
  status,
  verbose = false,
}: ExploitationBadgeProps) {
  const label = verbose
    ? status === 'confirmed'
      ? 'Exploitation confirmed'
      : status === 'suspected'
        ? 'Exploitation suspected'
        : status === 'not_exploited'
          ? 'Not known to be exploited'
          : 'Exploitation status unknown'
    : EXPLOITATION_SHORT_LABELS[status];

  return (
    <span className={`tp-badge tp-badge--${status}`}>
      <span className="tp-badge__mark" aria-hidden="true">
        {status === 'confirmed' ? '●' : status === 'suspected' ? '◐' : '○'}
      </span>
      {label}
    </span>
  );
}

interface ConfidenceBadgeProps {
  level: string;
  score?: number;
}

export function ConfidenceBadge({ level, score }: ConfidenceBadgeProps) {
  const label = CONFIDENCE_LABELS[level.toLowerCase()] ?? `${level} confidence`;

  return (
    <span className="tp-badge tp-badge--quiet">
      {label}
      {typeof score === 'number' && Number.isFinite(score)
        ? ` (${score})`
        : ''}
    </span>
  );
}

interface QuietBadgeProps {
  children: React.ReactNode;
  tone?: 'quiet' | 'accent';
}

export function QuietBadge({ children, tone = 'quiet' }: QuietBadgeProps) {
  return <span className={`tp-badge tp-badge--${tone}`}>{children}</span>;
}

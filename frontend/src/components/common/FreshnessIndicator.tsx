/*
 * Freshness indicator.
 *
 * Shows the API-provided timestamp in UTC together with a factual age, so
 * stale data is never presented as current.
 */

import { ageSince, describeAge } from '../../lib/dates';
import { formatDateTimeUtc } from '../../lib/format';

interface FreshnessIndicatorProps {
  value: string | null | undefined;
  label: string;
  /** Show the "(3 days ago)" suffix. */
  showAge?: boolean;
}

export function FreshnessIndicator({
  value,
  label,
  showAge = true,
}: FreshnessIndicatorProps) {
  const absolute = formatDateTimeUtc(value);
  const age = showAge ? ageSince(value) : null;

  if (!absolute) {
    return (
      <span className="tp-meta tp-meta--small">
        {label}: not reported by the API
      </span>
    );
  }

  return (
    <span className="tp-meta tp-meta--small">
      {label}: <time dateTime={value ?? undefined}>{absolute}</time>
      {age ? ` (${describeAge(age)})` : ''}
    </span>
  );
}

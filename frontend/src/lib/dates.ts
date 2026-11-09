/*
 * Date handling.
 *
 * The publishing pipeline stores naive UTC timestamps in MySQL
 * ("YYYY-MM-DD HH:MM:SS") and emits ISO-8601 UTC timestamps for response-level
 * fields ("2026-10-30T01:36:50Z"). Verified against live data: the
 * source_attribution `retrieved_at` value 2026-10-30T01:36:50Z corresponds to
 * `last_seen` "2026-10-30 01:36:50".
 *
 * Naive values are therefore interpreted as UTC, and every rendered timestamp
 * is labelled UTC rather than being silently converted to the viewer's local
 * time. Freshness is described factually ("6 hours ago") and never inflated.
 */

const NAIVE_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})$/;

export function parseApiDate(value: string | null | undefined): Date | null {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();

  if (trimmed === '') {
    return null;
  }

  const naive = NAIVE_TIMESTAMP.exec(trimmed);

  if (naive) {
    const year = Number(naive[1]);
    const month = Number(naive[2]);
    const day = Number(naive[3]);
    const hour = Number(naive[4]);
    const minute = Number(naive[5]);
    const second = Number(naive[6]);

    const date = new Date(
      Date.UTC(year, month - 1, day, hour, minute, second)
    );

    return Number.isNaN(date.getTime()) ? null : date;
  }

  const parsed = new Date(trimmed);

  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export interface Age {
  milliseconds: number;
  unit: 'minute' | 'hour' | 'day';
  value: number;
}

export function ageSince(
  value: string | null | undefined,
  now: Date = new Date()
): Age | null {
  const date = parseApiDate(value);

  if (!date) {
    return null;
  }

  const milliseconds = now.getTime() - date.getTime();

  if (milliseconds < 0) {
    return { milliseconds, unit: 'minute', value: 0 };
  }

  const minutes = Math.floor(milliseconds / 60_000);

  if (minutes < 60) {
    return { milliseconds, unit: 'minute', value: minutes };
  }

  const hours = Math.floor(minutes / 60);

  // 24 hours and beyond is reported in days, so "24 hours ago" is never shown
  // as an age that a reader would have to convert mentally.
  if (hours < 24) {
    return { milliseconds, unit: 'hour', value: hours };
  }

  return {
    milliseconds,
    unit: 'day',
    value: Math.floor(hours / 24),
  };
}

export function describeAge(age: Age): string {
  const { unit, value } = age;

  if (unit === 'minute') {
    if (value <= 0) {
      return 'just now';
    }

    return value === 1 ? '1 minute ago' : `${value} minutes ago`;
  }

  if (unit === 'hour') {
    return value === 1 ? '1 hour ago' : `${value} hours ago`;
  }

  return value === 1 ? '1 day ago' : `${value} days ago`;
}

/** Convenience wrapper: "3 days ago", or null when the value is unparseable. */
export function describeApiDate(
  value: string | null | undefined,
  now: Date = new Date()
): string | null {
  const age = ageSince(value, now);

  return age ? describeAge(age) : null;
}

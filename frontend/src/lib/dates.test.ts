/*
 * Date handling tests.
 *
 * The pipeline stores naive UTC timestamps, so the critical assertion is that
 * a value without a time zone is interpreted as UTC rather than as the
 * viewer's local time.
 */

import { describe, expect, it } from 'vitest';
import { ageSince, describeAge, describeApiDate, parseApiDate } from './dates';
import { formatDateTimeUtc, formatDateUtc } from './format';

describe('parseApiDate', () => {
  it('interprets a naive timestamp as UTC', () => {
    const date = parseApiDate('2026-10-30 01:36:50');

    expect(date?.getTime()).toBe(Date.UTC(2026, 9, 30, 1, 36, 50));
  });

  it('accepts an ISO timestamp with an explicit zone', () => {
    const date = parseApiDate('2026-10-30T01:36:50Z');

    expect(date?.getTime()).toBe(Date.UTC(2026, 9, 30, 1, 36, 50));
  });

  it('returns null for missing or unparseable values', () => {
    expect(parseApiDate(null)).toBeNull();
    expect(parseApiDate('')).toBeNull();
    expect(parseApiDate('not a date')).toBeNull();
  });
});

describe('ageSince / describeAge', () => {
  const now = new Date(Date.UTC(2026, 9, 30, 12, 0, 0));

  it('describes minutes, hours and days', () => {
    expect(describeApiDate('2026-10-30 11:30:00', now)).toBe('30 minutes ago');
    expect(describeApiDate('2026-10-30 01:00:00', now)).toBe('11 hours ago');
    expect(describeApiDate('2026-10-27 12:00:00', now)).toBe('3 days ago');
  });

  it('handles singular units', () => {
    expect(describeApiDate('2026-10-30 11:59:00', now)).toBe('1 minute ago');
    expect(describeApiDate('2026-10-30 11:00:00', now)).toBe('1 hour ago');
    expect(describeApiDate('2026-10-29 12:00:00', now)).toBe('1 day ago');
  });

  it('returns null when the value cannot be parsed', () => {
    expect(describeApiDate(null, now)).toBeNull();
    expect(ageSince('garbage', now)).toBeNull();
  });

  it('never reports a future timestamp as an age', () => {
    const age = ageSince('2026-10-31 00:00:00', now);

    expect(age).not.toBeNull();
    expect(describeAge(age!)).toBe('just now');
  });
});

describe('UTC formatting', () => {
  it('labels rendered timestamps as UTC', () => {
    expect(formatDateTimeUtc('2026-10-30 01:36:50')).toBe(
      '30 Oct 2026, 01:36 UTC'
    );
  });

  it('renders dates and returns null for absent values', () => {
    expect(formatDateUtc('2026-10-30 01:36:50')).toBe('30 Oct 2026');
    expect(formatDateUtc(null)).toBeNull();
  });
});

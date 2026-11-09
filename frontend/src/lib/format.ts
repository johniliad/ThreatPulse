/*
 * Display formatting.
 *
 * A fixed locale (en-GB) and a fixed time zone (UTC) are used so that the
 * same record renders identically for every viewer and in every test.
 */

import { parseApiDate } from './dates';

const NUMBER_FORMAT = new Intl.NumberFormat('en-GB');

const DATE_TIME_FORMAT = new Intl.DateTimeFormat('en-GB', {
  day: '2-digit',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  hour12: false,
  timeZone: 'UTC',
});

const DATE_FORMAT = new Intl.DateTimeFormat('en-GB', {
  day: '2-digit',
  month: 'short',
  year: 'numeric',
  timeZone: 'UTC',
});

export function formatCount(value: number): string {
  return Number.isFinite(value) ? NUMBER_FORMAT.format(value) : '—';
}

/** Priority score as reported by the API, without inventing precision. */
export function formatScore(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return '—';
  }

  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

export function formatFactorValue(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return 'Not reported';
  }

  return String(Math.round(value));
}

/** Weight as reported by the API (0–1) rendered as a percentage. */
export function formatWeight(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return 'Not reported';
  }

  const percent = value * 100;

  return `${Number.isInteger(percent) ? percent : percent.toFixed(1)}%`;
}

export function formatPercentage(value01: number | null | undefined): string {
  if (value01 === null || value01 === undefined || !Number.isFinite(value01)) {
    return '—';
  }

  return `${Math.round(value01 * 100)}%`;
}

/** CVSS is frequently absent in the source data; say so rather than imply 0. */
export function formatCvss(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return 'Not provided';
  }

  return value.toFixed(1);
}

export function formatDateTimeUtc(
  value: string | null | undefined
): string | null {
  const date = parseApiDate(value);

  return date ? `${DATE_TIME_FORMAT.format(date)} UTC` : null;
}

export function formatDateUtc(value: string | null | undefined): string | null {
  const date = parseApiDate(value);

  return date ? DATE_FORMAT.format(date) : null;
}

export function pluralise(
  count: number,
  singular: string,
  plural?: string
): string {
  return count === 1 ? singular : (plural ?? `${singular}s`);
}

/**
 * First sentence of a longer guidance text.
 *
 * Used to keep feed rows scannable. The full text is always available on the
 * record itself, and the truncation is shown explicitly rather than silently.
 */
export function firstSentence(text: string | null | undefined): string | null {
  if (typeof text !== 'string') {
    return null;
  }

  const trimmed = text.trim();

  if (trimmed === '') {
    return null;
  }

  const match = /^(.+?[.!?])(\s|$)/.exec(trimmed);

  return match?.[1] ?? trimmed;
}


/*
 * URL helpers and route builders.
 *
 * External links are only ever produced for http/https URLs, and CVE values
 * are validated before they are placed in a path. Nothing from the API is
 * interpolated into an href without passing through these functions.
 */

import { isValidCveId } from '../api/validate';
import type { ExploitationStatus, Severity } from '../api/types';
import { DEFAULT_PAGE_SIZE } from './constants';

export const CISA_KEV_URL =
  'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';

const NVD_DETAIL_BASE = 'https://nvd.nist.gov/vuln/detail/';

/** Returns the URL only when it is a valid absolute http(s) URL. */
export function safeExternalUrl(value: string | null | undefined): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();

  if (trimmed === '') {
    return null;
  }

  try {
    const url = new URL(trimmed);

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return null;
    }

    return url.toString();
  } catch {
    return null;
  }
}

/**
 * NVD reference for a CVE.
 *
 * The CVE identifier is validated first, so a malformed value can never be
 * placed into an outbound path.
 */
export function nvdUrlForCve(cveId: string | null | undefined): string | null {
  if (typeof cveId !== 'string' || !isValidCveId(cveId)) {
    return null;
  }

  return `${NVD_DETAIL_BASE}${encodeURIComponent(cveId.trim().toUpperCase())}`;
}

/** The CISA KEV catalogue is a searchable list; there is no per-record URL. */
export function cisaKevUrl(): string {
  return CISA_KEV_URL;
}

export function threatPath(uuid: string): string {
  return `/threats/${encodeURIComponent(uuid.trim())}`;
}

export function threatAbsoluteUrl(uuid: string, siteUrl: string): string {
  return `${siteUrl}${threatPath(uuid)}`;
}

export interface ThreatListParams {
  severity?: Severity | null;
  exploitation?: ExploitationStatus | null;
  cve?: string | null;
  offset?: number;
  limit?: number;
}

/** Builds a shareable /threats URL, omitting default values. */
export function threatsPath(params: ThreatListParams = {}): string {
  const search = new URLSearchParams();

  if (params.severity && params.severity !== 'unknown') {
    search.set('severity', params.severity);
  }

  if (params.exploitation) {
    search.set('exploitation', params.exploitation);
  }

  if (params.cve && params.cve.trim() !== '') {
    search.set('cve', params.cve.trim().toUpperCase());
  }

  if (params.limit !== undefined && params.limit !== DEFAULT_PAGE_SIZE) {
    search.set('limit', String(params.limit));
  }

  if (params.offset !== undefined && params.offset > 0) {
    search.set('offset', String(params.offset));
  }

  const query = search.toString();

  return query === '' ? '/threats' : `/threats?${query}`;
}

export interface VulnerabilityListParams {
  cve?: string | null;
  severity?: Severity | null;
  kevOnly?: boolean;
  offset?: number;
  limit?: number;
}

/** Builds a shareable /vulnerabilities URL, omitting default values. */
export function vulnerabilitiesPath(
  params: VulnerabilityListParams = {}
): string {
  const search = new URLSearchParams();

  if (params.cve && params.cve.trim() !== '') {
    search.set('cve', params.cve.trim().toUpperCase());
  }

  if (params.severity && params.severity !== 'unknown') {
    search.set('severity', params.severity);
  }

  if (params.kevOnly) {
    search.set('kev', 'true');
  }

  if (params.limit !== undefined && params.limit !== DEFAULT_PAGE_SIZE) {
    search.set('limit', String(params.limit));
  }

  if (params.offset !== undefined && params.offset > 0) {
    search.set('offset', String(params.offset));
  }

  const query = search.toString();

  return query === '' ? '/vulnerabilities' : `/vulnerabilities?${query}`;
}


export interface TextSegment {
  type: 'text' | 'link';
  text: string;
  href?: string;
}

const URL_PATTERN = /https?:\/\/[^\s;<>"']+/gi;

function stripTrailingPunctuation(value: string): string {
  return value.replace(/[.,;:)\]]+$/, '');
}

/**
 * Splits free text (for example CISA notes) into plain text and validated
 * external links. No HTML is ever produced: the caller renders React text
 * nodes and anchors, so markup in API data cannot be interpreted.
 */
export function splitExternalLinks(text: string): TextSegment[] {
  const segments: TextSegment[] = [];
  let lastIndex = 0;

  for (const match of text.matchAll(URL_PATTERN)) {
    const raw = match[0];
    const index = match.index ?? 0;

    if (index > lastIndex) {
      segments.push({ type: 'text', text: text.slice(lastIndex, index) });
    }

    const href = safeExternalUrl(stripTrailingPunctuation(raw));

    if (href) {
      segments.push({ type: 'link', text: raw, href });
    } else {
      segments.push({ type: 'text', text: raw });
    }

    lastIndex = index + raw.length;
  }

  if (lastIndex < text.length) {
    segments.push({ type: 'text', text: text.slice(lastIndex) });
  }

  return segments;
}

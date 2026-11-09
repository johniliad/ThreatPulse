/*
 * URL-synchronised filter state.
 *
 * Filters live in the query string so that refresh, browser back/forward,
 * bookmarking and link sharing all work, and so that a filtered view can be
 * pasted into a report or a ticket. Serialisation reuses the same builders as
 * the shareable links in lib/urls.ts, so the two can never drift apart.
 */

import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { ExploitationStatus, Severity } from '../api/types';
import { isValidCveId } from '../api/validate';
import {
  DEFAULT_PAGE_SIZE,
  EXPLOITATION_VALUES,
  PAGE_SIZE_OPTIONS,
  SEVERITY_VALUES,
} from '../lib/constants';
import {
  threatsPath,
  vulnerabilitiesPath,
  type ThreatListParams,
  type VulnerabilityListParams,
} from '../lib/urls';

function readSeverity(raw: string | null): Severity | 'all' {
  if (!raw) {
    return 'all';
  }

  const value = raw.toLowerCase();

  return (SEVERITY_VALUES as readonly string[]).includes(value)
    ? (value as Severity)
    : 'all';
}

function readExploitation(raw: string | null): ExploitationStatus | 'all' {
  if (!raw) {
    return 'all';
  }

  const value = raw.toLowerCase();

  return (EXPLOITATION_VALUES as readonly string[]).includes(value)
    ? (value as ExploitationStatus)
    : 'all';
}

function readCount(raw: string | null, fallback: number): number {
  if (!raw) {
    return fallback;
  }

  const parsed = Number.parseInt(raw, 10);

  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function readPageSize(raw: string | null): number {
  const parsed = readCount(raw, DEFAULT_PAGE_SIZE);

  return (PAGE_SIZE_OPTIONS as readonly number[]).includes(parsed)
    ? parsed
    : DEFAULT_PAGE_SIZE;
}

interface CveParam {
  value: string;
  invalid: boolean;
}

/** A CVE taken from the URL is only used when it is well formed. */
function readCve(raw: string | null): CveParam {
  const trimmed = (raw ?? '').trim();

  if (trimmed === '') {
    return { value: '', invalid: false };
  }

  return isValidCveId(trimmed)
    ? { value: trimmed.toUpperCase(), invalid: false }
    : { value: '', invalid: true };
}

function toSearchParams(path: string): URLSearchParams {
  const index = path.indexOf('?');

  return new URLSearchParams(index === -1 ? '' : path.slice(index + 1));
}

export interface ThreatFilters {
  severity: Severity | 'all';
  exploitation: ExploitationStatus | 'all';
  cve: string;
  /** True when the URL contained a CVE that is not well formed. */
  invalidCve: boolean;
  limit: number;
  offset: number;
}

export interface ThreatFilterControls {
  filters: ThreatFilters;
  /** Applies a partial change; page offset resets unless it is in the patch. */
  update: (patch: Partial<ThreatFilters>) => void;
  reset: () => void;
}

export function useThreatFilters(): ThreatFilterControls {
  const [searchParams, setSearchParams] = useSearchParams();

  const filters = useMemo<ThreatFilters>(() => {
    const cve = readCve(searchParams.get('cve'));

    return {
      severity: readSeverity(searchParams.get('severity')),
      exploitation: readExploitation(searchParams.get('exploitation')),
      cve: cve.value,
      invalidCve: cve.invalid,
      limit: readPageSize(searchParams.get('limit')),
      offset: readCount(searchParams.get('offset'), 0),
    };
  }, [searchParams]);

  const update = useCallback(
    (patch: Partial<ThreatFilters>) => {
      const next: ThreatFilters = { ...filters, ...patch, invalidCve: false };

      if (!('offset' in patch)) {
        next.offset = 0;
      }

      const params: ThreatListParams = {
        severity: next.severity === 'all' ? null : next.severity,
        exploitation:
          next.exploitation === 'all' ? null : next.exploitation,
        cve: next.cve === '' ? null : next.cve,
        limit: next.limit,
        offset: next.offset,
      };

      setSearchParams(toSearchParams(threatsPath(params)));
    },
    [filters, setSearchParams]
  );

  const reset = useCallback(() => {
    setSearchParams(new URLSearchParams());
  }, [setSearchParams]);

  return { filters, update, reset };
}

export interface VulnerabilityFilters {
  cve: string;
  invalidCve: boolean;
  severity: Severity | 'all';
  kevOnly: boolean;
  limit: number;
  offset: number;
}

export interface VulnerabilityFilterControls {
  filters: VulnerabilityFilters;
  update: (patch: Partial<VulnerabilityFilters>) => void;
  reset: () => void;
}

export function useVulnerabilityFilters(): VulnerabilityFilterControls {
  const [searchParams, setSearchParams] = useSearchParams();

  const filters = useMemo<VulnerabilityFilters>(() => {
    const cve = readCve(searchParams.get('cve'));

    return {
      cve: cve.value,
      invalidCve: cve.invalid,
      severity: readSeverity(searchParams.get('severity')),
      kevOnly: searchParams.get('kev') === 'true',
      limit: readPageSize(searchParams.get('limit')),
      offset: readCount(searchParams.get('offset'), 0),
    };
  }, [searchParams]);

  const update = useCallback(
    (patch: Partial<VulnerabilityFilters>) => {
      const next: VulnerabilityFilters = {
        ...filters,
        ...patch,
        invalidCve: false,
      };

      if (!('offset' in patch)) {
        next.offset = 0;
      }

      const params: VulnerabilityListParams = {
        cve: next.cve === '' ? null : next.cve,
        severity: next.severity === 'all' ? null : next.severity,
        kevOnly: next.kevOnly,
        limit: next.limit,
        offset: next.offset,
      };

      setSearchParams(toSearchParams(vulnerabilitiesPath(params)));
    },
    [filters, setSearchParams]
  );

  const reset = useCallback(() => {
    setSearchParams(new URLSearchParams());
  }, [setSearchParams]);

  return { filters, update, reset };
}

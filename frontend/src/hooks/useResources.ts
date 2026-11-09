/*
 * Endpoint-backed resource hooks.
 *
 * Each hook is a thin, typed binding between an endpoint function and
 * `useApiResource`, so components only ever deal with
 * loading / success / error state.
 */

import { useCallback } from 'react';
import {
  fetchApiIndex,
  fetchApiStatus,
  fetchAttribution,
  fetchPublications,
  fetchSources,
  fetchThreat,
  fetchThreats,
  fetchVulnerabilities,
} from '../api/endpoints';
import type {
  ApiIndex,
  ApiStatus,
  AttributionRegister,
  Paginated,
  Publication,
  Source,
  SourceQuery,
  Threat,
  ThreatDetail,
  ThreatQuery,
  Vulnerability,
  VulnerabilityQuery,
} from '../api/types';
import { COUNT_QUERY_LIMIT } from '../lib/constants';
import { useApiResource, type AsyncResource } from './useApiResource';

export function useThreats(
  query: ThreatQuery,
  options: { enabled?: boolean; fresh?: boolean } = {}
): AsyncResource<Paginated<Threat>> {
  const { enabled = true, fresh = false } = options;

  return useApiResource(
    ({ signal }) => fetchThreats(query, { signal, fresh }),
    [
      query.limit,
      query.offset,
      query.severity,
      query.exploitationStatus,
      query.cve,
      enabled,
      fresh,
    ],
    { enabled, keepPreviousData: true }
  );
}

export function useThreat(
  uuid: string | null,
  options: { fresh?: boolean } = {}
): AsyncResource<ThreatDetail> {
  const { fresh = false } = options;

  return useApiResource(
    ({ signal }) => fetchThreat(uuid ?? '', { signal, fresh }),
    [uuid, fresh],
    { enabled: typeof uuid === 'string' && uuid.trim() !== '' }
  );
}

export function useVulnerabilities(
  query: VulnerabilityQuery,
  options: { enabled?: boolean; fresh?: boolean } = {}
): AsyncResource<Paginated<Vulnerability>> {
  const { enabled = true, fresh = false } = options;

  return useApiResource(
    ({ signal }) => fetchVulnerabilities(query, { signal, fresh }),
    [
      query.limit,
      query.offset,
      query.cve,
      query.severity,
      query.kevListed,
      enabled,
      fresh,
    ],
    { enabled, keepPreviousData: true }
  );
}

export function useSources(
  query: SourceQuery = {},
  options: { fresh?: boolean } = {}
): AsyncResource<Paginated<Source>> {
  const { fresh = false } = options;

  return useApiResource(
    ({ signal }) => fetchSources(query, { signal, fresh }),
    [query.limit, query.offset, query.sourceKey, query.sourceType, fresh],
    { keepPreviousData: true }
  );
}

/**
 * The source and attribution register.
 *
 * Distinct from `useSources`: that is what contributed a threat, this is what the
 * product decided — including sources it deliberately does not ingest, which the
 * `sources` table can never show. Fetched whole rather than paginated, because a
 * reader wants the complete statement and a register is small.
 */
export function useAttribution(
  options: { fresh?: boolean } = {}
): AsyncResource<AttributionRegister> {
  const { fresh = false } = options;

  return useApiResource(
    ({ signal }) => fetchAttribution({ signal, fresh }),
    [fresh]
  );
}

export function usePublications(
  query: { limit?: number; offset?: number } = {},
  options: { fresh?: boolean } = {}
): AsyncResource<Paginated<Publication>> {
  const { fresh = false } = options;

  return useApiResource(
    ({ signal }) => fetchPublications(query, { signal, fresh }),
    [query.limit, query.offset, fresh],
    { keepPreviousData: true }
  );
}

export function useApiStatus(
  options: { fresh?: boolean } = {}
): AsyncResource<ApiStatus> {
  const { fresh = false } = options;

  return useApiResource(
    ({ signal }) => fetchApiStatus({ signal, fresh }),
    [fresh]
  );
}

export function useApiIndex(
  options: { fresh?: boolean } = {}
): AsyncResource<ApiIndex> {
  const { fresh = false } = options;

  return useApiResource(({ signal }) => fetchApiIndex({ signal, fresh }), [
    fresh,
  ]);
}

/** The live counts shown on the dashboard, all taken from the API. */
export interface DashboardKpis {
  totalThreats: number;
  criticalThreats: number;
  highThreats: number;
  confirmedExploitation: number;
  kevVulnerabilities: number;
  sources: number;
  latestPublication: Publication | null;
  /** Timestamp of the API response used for the counts. */
  observedAt: string | null;
}

/**
 * Loads the dashboard counts.
 *
 * Counts come from `pagination.total` with limit=1, so the payload stays
 * small and the numbers are never hard-coded or estimated.
 */
export function useDashboardKpis(
  options: { fresh?: boolean } = {}
): AsyncResource<DashboardKpis> {
  const { fresh = false } = options;

  const load = useCallback(
    async ({ signal }: { signal: AbortSignal }): Promise<DashboardKpis> => {
      const [
        all,
        critical,
        high,
        confirmed,
        kev,
        sources,
        publications,
      ] = await Promise.all([
        fetchThreats({ limit: COUNT_QUERY_LIMIT }, { signal, fresh }),
        fetchThreats(
          { limit: COUNT_QUERY_LIMIT, severity: 'critical' },
          { signal, fresh }
        ),
        fetchThreats(
          { limit: COUNT_QUERY_LIMIT, severity: 'high' },
          { signal, fresh }
        ),
        fetchThreats(
          {
            limit: COUNT_QUERY_LIMIT,
            exploitationStatus: 'confirmed',
          },
          { signal, fresh }
        ),
        fetchVulnerabilities(
          { limit: COUNT_QUERY_LIMIT, kevListed: true },
          { signal, fresh }
        ),
        fetchSources({ limit: COUNT_QUERY_LIMIT }, { signal, fresh }),
        fetchPublications({ limit: 1 }, { signal, fresh }),
      ]);

      return {
        totalThreats: all.pagination.total,
        criticalThreats: critical.pagination.total,
        highThreats: high.pagination.total,
        confirmedExploitation: confirmed.pagination.total,
        kevVulnerabilities: kev.pagination.total,
        sources: sources.pagination.total,
        latestPublication: publications.items[0] ?? null,
        observedAt: all.timestamp,
      };
    },
    [fresh]
  );

  return useApiResource(load, [fresh], { keepPreviousData: true });
}

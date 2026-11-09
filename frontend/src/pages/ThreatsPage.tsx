/*
 * Threats page.
 *
 * Filters are held in the URL, pagination is server-side, and the CVE filter
 * is offered only when the deployed API confirms it supports one. The
 * pre-enhancement API silently ignored unknown parameters, so a CVE filter is
 * never applied unless the contract says it will be honoured.
 */

import { Link } from 'react-router-dom';
import { useThreatFilters } from '../hooks/useFilters';
import { useApiIndex, useThreats } from '../hooks/useResources';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { useDisclaimer } from '../hooks/useDisclaimer';
import { detectContract } from '../api/validate';
import { DisclaimerGate } from '../components/legal/DisclaimerGate';
import { EmptyState, ErrorState, SkeletonList } from '../components/common/StateBlock';
import { Notice } from '../components/common/Notice';
import { PageHead } from '../components/common/PageHead';
import { Pagination } from '../components/common/Pagination';
import { ThreatFeed } from '../components/threat/ThreatFeed';
import { ThreatFilters } from '../components/threat/ThreatFilters';
import { formatCount } from '../lib/format';

export function ThreatsPage() {
  useDocumentMeta({
    title: 'Prioritised threats',
    description:
      'The ThreatPulse threat feed, ordered by the ThreatPulse Priority Score, with severity, exploitation and CVE filters.',
    path: '/threats',
  });

  const { filters, update, reset } = useThreatFilters();
  const index = useApiIndex();
  const contract = detectContract(index.data, []);

  const cveFilter = contract.cveToThreat && filters.cve !== '' ? filters.cve : null;

  const threats = useThreats({
    limit: filters.limit,
    offset: filters.offset,
    severity: filters.severity === 'all' ? null : filters.severity,
    exploitationStatus:
      filters.exploitation === 'all' ? null : filters.exploitation,
    cve: cveFilter,
  });

  const cveFilterUnavailable = filters.cve !== '' && !contract.cveToThreat;

  const disclaimer = useDisclaimer();

  if (!disclaimer.accepted) {
    return (
      <DisclaimerGate
        pageLabel="the prioritised threat feed"
        onAccept={disclaimer.accept}
      />
    );
  }

  return (
    <>
      <PageHead
        eyebrow="Threat intelligence"
        title="Prioritised threats"
        lead="Every record in the published set, ordered by the ThreatPulse Priority Score and then by how recently the signal was seen. Filtering and pagination are performed by the API."
        actions={
          <>
            <Link className="tp-button" to="/methodology">
              How priority is scored
            </Link>
            <Link className="tp-button tp-button--secondary" to="/vulnerabilities">
              Vulnerability lookup
            </Link>
          </>
        }
      />

      <section className="tp-section tp-section--tight">
        <div className="container tp-stack">
          {cveFilterUnavailable ? (
            <Notice tone="warning" title="CVE filtering is not available on this deployment">
              <p>
                The API this dashboard is connected to does not accept a CVE
                filter on the threat endpoint, so the list below is{' '}
                <strong>not filtered</strong> by {filters.cve}. Deploy the
                updated <span className="mono">threats.php</span> to enable
                CVE-based filtering, or look the CVE up under{' '}
                <Link to="/vulnerabilities">Vulnerabilities</Link>.
              </p>
            </Notice>
          ) : null}

          {filters.invalidCve ? (
            <Notice tone="warning">
              <p>
                The link contained a CVE identifier that is not valid, so it was
                ignored. Use the form CVE-YYYY-NNNN.
              </p>
            </Notice>
          ) : null}

          <ThreatFilters
            filters={filters}
            onChange={update}
            onReset={reset}
            cveSearchEnabled={contract.cveToThreat}
            isBusy={threats.isRefreshing}
          />
        </div>
      </section>

      <section className="tp-section" aria-labelledby="threat-list-heading">
        <div className="container">
          <h2 id="threat-list-heading" className="visually-hidden">
            Threat records
          </h2>

          {threats.data && threats.data.items.length > 0 ? (
            <>
              <ThreatFeed
                threats={threats.data.items}
                startRank={threats.data.pagination.offset + 1}
              />
              <Pagination
                pagination={threats.data.pagination}
                itemLabel="threats"
                isBusy={threats.isRefreshing}
                onOffsetChange={(offset) => update({ offset })}
                onLimitChange={(limit) => update({ limit, offset: 0 })}
              />
              <p className="tp-meta tp-meta--small">
                Data timestamp:{' '}
                {threats.data.timestamp ?? 'not reported by the API'}
              </p>
            </>
          ) : threats.data ? (
            <EmptyState
              title="No threats match these filters"
              action={
                <button
                  type="button"
                  className="tp-button tp-button--small"
                  onClick={reset}
                >
                  Reset filters
                </button>
              }
            >
              <p>
                The API returned zero records for the current combination of
                severity, exploitation status and CVE. That is a real result rather
                than a failure: the filters are combined, and some combinations have
                no records — no threat currently reports <em>suspected</em>
                exploitation, for example.
              </p>
              <p className="tp-meta tp-meta--small">
                {formatCount(threats.data.pagination.total)} records returned for
                this query.
              </p>
            </EmptyState>
          ) : threats.error ? (
            <ErrorState
              title="The threat list could not be loaded"
              error={threats.error}
              onRetry={threats.reload}
            />
          ) : (
            <SkeletonList label="Loading threat records" count={5} />
          )}
        </div>
      </section>
    </>
  );
}

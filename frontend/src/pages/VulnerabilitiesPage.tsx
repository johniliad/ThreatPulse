/*
 * Vulnerabilities page.
 *
 * The vulnerability record is the entry point for the CVE → threat
 * navigation added by the API enhancement: when the deployed API exposes the
 * relationship, each record links straight to its ThreatPulse threat records.
 */

import { Link } from 'react-router-dom';
import { useVulnerabilityFilters } from '../hooks/useFilters';
import { useVulnerabilities } from '../hooks/useResources';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { useDisclaimer } from '../hooks/useDisclaimer';
import { SEVERITY_LABELS, SEVERITY_VALUES } from '../lib/constants';
import { formatCount } from '../lib/format';
import {
  EmptyState,
  ErrorState,
  SkeletonList,
} from '../components/common/StateBlock';
import { Notice } from '../components/common/Notice';
import { PageHead } from '../components/common/PageHead';
import { Pagination } from '../components/common/Pagination';
import { CveSearchForm } from '../components/vuln/CveSearchForm';
import { VulnerabilityCard } from '../components/vuln/VulnerabilityCard';
import { DisclaimerGate } from '../components/legal/DisclaimerGate';

export function VulnerabilitiesPage() {
  useDocumentMeta({
    title: 'Vulnerability intelligence',
    description:
      'Look up a CVE and follow it to the ThreatPulse threat records it is associated with, with KEV status, exploitation evidence and provenance.',
    path: '/vulnerabilities',
  });

  const { filters, update, reset } = useVulnerabilityFilters();

  const vulnerabilities = useVulnerabilities({
    limit: filters.limit,
    offset: filters.offset,
    cve: filters.cve === '' ? null : filters.cve,
    severity: filters.severity === 'all' ? null : filters.severity,
    kevListed: filters.kevOnly ? true : null,
  });

  const firstRow = vulnerabilities.data?.items[0];
  const relationshipExposed = firstRow ? firstRow.threats !== undefined : null;

  const disclaimer = useDisclaimer();

  if (!disclaimer.accepted) {
    return (
      <DisclaimerGate
        pageLabel="the vulnerability records"
        onAccept={disclaimer.accept}
      />
    );
  }

  return (
    <>
      <PageHead
        eyebrow="Vulnerability intelligence"
        title="From a CVE to the intelligence behind it"
        lead="Search a CVE to see the vulnerability record, its KEV and exploitation status, and the ThreatPulse threat records it is associated with."
        actions={
          <Link className="tp-button tp-button--secondary" to="/threats">
            Browse prioritised threats
          </Link>
        }
      />

      <section className="tp-section tp-section--tight">
        <div className="container tp-stack">
          {relationshipExposed === false ? (
            <Notice
              tone="warning"
              title="Threat linkage is not available on this deployment"
            >
              <p>
                The API this dashboard is connected to does not return the
                vulnerability → threat relationship, so vulnerability records
                cannot be linked to ThreatPulse threat records here. The
                vulnerability data itself is complete and is shown below.
              </p>
            </Notice>
          ) : null}

          <form className="tp-filters" onSubmit={(event) => event.preventDefault()}>
            <CveSearchForm
              value={filters.cve}
              disabled={vulnerabilities.isRefreshing}
              urlInvalid={filters.invalidCve}
              hint="Exact-match lookup, validated before the request is sent."
              onSubmit={(cve) => update({ cve })}
              onClear={() => update({ cve: '' })}
            />

            <div className="tp-field">
              <label htmlFor="vulnerability-severity">Severity</label>
              <select
                id="vulnerability-severity"
                className="tp-select"
                value={filters.severity}
                disabled={vulnerabilities.isRefreshing}
                onChange={(event) =>
                  update({
                    severity: event.target.value as typeof filters.severity,
                  })
                }
              >
                <option value="all">All severities</option>
                {SEVERITY_VALUES.map((severity) => (
                  <option key={severity} value={severity}>
                    {SEVERITY_LABELS[severity]}
                  </option>
                ))}
              </select>
            </div>

            <div className="tp-field">
              <span className="tp-field__hint">Source catalogue</span>
              <label
                className={
                  filters.kevOnly ? 'tp-radio tp-radio--active' : 'tp-radio'
                }
                htmlFor="kev-only"
              >
                <input
                  id="kev-only"
                  type="checkbox"
                  checked={filters.kevOnly}
                  disabled={vulnerabilities.isRefreshing}
                  onChange={(event) => update({ kevOnly: event.target.checked })}
                />
                CISA KEV listed only
              </label>
            </div>

            <div className="tp-filters__actions">
              <button
                type="button"
                className="tp-button tp-button--quiet tp-button--small"
                onClick={reset}
                disabled={
                  vulnerabilities.isRefreshing ||
                  (filters.cve === '' &&
                    filters.severity === 'all' &&
                    !filters.kevOnly)
                }
              >
                Reset filters
              </button>
            </div>
          </form>
        </div>
      </section>

      <section
        className="tp-section"
        aria-labelledby="vulnerability-list-heading"
      >
        <div className="container">
          <h2 id="vulnerability-list-heading" className="visually-hidden">
            Vulnerability records
          </h2>

          {vulnerabilities.data && vulnerabilities.data.items.length > 0 ? (
            <>
              <ul className="tp-feed">
                {vulnerabilities.data.items.map((vulnerability) => (
                  <VulnerabilityCard
                    key={vulnerability.cve_id}
                    vulnerability={vulnerability}
                  />
                ))}
              </ul>
              <Pagination
                pagination={vulnerabilities.data.pagination}
                itemLabel="vulnerabilities"
                isBusy={vulnerabilities.isRefreshing}
                onOffsetChange={(offset) => update({ offset })}
                onLimitChange={(limit) => update({ limit, offset: 0 })}
              />
            </>
          ) : vulnerabilities.data ? (
            <EmptyState
              title="No vulnerability matches this query"
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
              {filters.cve ? (
                <p>
                  The API holds no vulnerability record for{' '}
                  <span className="mono">{filters.cve}</span>. That is a real
                  result: the published set only contains vulnerabilities from
                  the feeds that are currently collected.
                </p>
              ) : (
                <p>
                  The API returned no vulnerability records for the current
                  filters.
                </p>
              )}
              <p className="tp-meta tp-meta--small">
                {formatCount(vulnerabilities.data.pagination.total)} records
                returned for this query.
              </p>
            </EmptyState>
          ) : vulnerabilities.error ? (
            <ErrorState
              title="Vulnerability data could not be loaded"
              error={vulnerabilities.error}
              onRetry={vulnerabilities.reload}
            />
          ) : (
            <SkeletonList label="Loading vulnerability records" count={4} />
          )}
        </div>
      </section>
    </>
  );
}

/*
 * Dashboard — "what deserves attention now?"
 *
 * Live counts, the latest publication and the source attribution, read from the
 * API. The prioritised list itself is a view of its own at /threats; this page
 * shows the highest published score and links there, rather than duplicating the
 * feed on the landing page.
 */

import { Link } from 'react-router-dom';
import { useDashboardKpis, usePublications, useThreats } from '../hooks/useResources';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { AuthorStrip } from '../components/layout/AuthorStrip';
import { formatCount, formatDateTimeUtc, formatScore } from '../lib/format';
import { PRIORITY_BANDS } from '../lib/priority';
import { threatsPath } from '../lib/urls';
import { KpiCountCard } from '../components/kpi/KpiGrid';
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from '../components/common/StateBlock';
import { Notice } from '../components/common/Notice';
import { FreshnessIndicator } from '../components/common/FreshnessIndicator';

export function DashboardPage() {
  useDocumentMeta({
    title: 'Threat Intelligence & Vulnerability Prioritization',
    description:
      'ThreatPulse answers "What is happening?" — live threat intelligence and vulnerability prioritization to help security teams focus on the threats that matter first.',
    path: '/',
  });

  const kpis = useDashboardKpis();

  /*
   * One record, not a page of them: the only thing this page needs from the threat
   * list is the highest score currently published, which is a count-like fact. The
   * dashboard deliberately holds no feed of its own.
   */
  const highest = useThreats({ limit: 1, offset: 0 });
  const publications = usePublications({ limit: 3 });

  const latestPublication = kpis.data?.latestPublication ?? null;
  const topThreat = highest.data?.items[0] ?? null;

  return (
    <>
      <section className="tp-hero">
        <div className="container tp-hero__inner">
          <div>
            <p className="eyebrow">Public cyber threat intelligence</p>
            <h1>What deserves attention now — and why?</h1>
            <p className="tp-hero__positioning">
              Transparent Cyber Threat Intelligence
            </p>
            <p className="tp-hero__copy">
              ThreatPulse turns global threat signals into prioritised,
              source-attributed intelligence. Every score is produced by the
              ThreatPulse prioritisation model and every statement is traceable
              to the feed it came from — so a security team can move from
              priority to evidence to action without guesswork.
            </p>
            <div className="tp-hero__actions">
              <Link className="tp-button" to="/threats">
                Explore prioritised threats
              </Link>
              <Link className="tp-button tp-button--secondary" to="/methodology">
                How priority is scored
              </Link>
            </div>
          </div>

          <aside className="tp-hero__aside" aria-label="Data status">
            <h2 className="tp-meta">Data status</h2>
            {latestPublication ? (
              <>
                <p className="tp-meta">
                  Latest publication:{' '}
                  <strong>
                    {formatDateTimeUtc(latestPublication.generated_at) ??
                      'timestamp not reported'}
                  </strong>
                </p>
                <p className="tp-meta tp-meta--small">
                  {formatCount(latestPublication.threat_count)} threats and{' '}
                  {formatCount(latestPublication.vulnerability_count)}{' '}
                  vulnerabilities in the published set.
                </p>
              </>
            ) : (
              <p className="tp-meta">
                Publication history is not available from the API at the moment.
              </p>
            )}
            <FreshnessIndicator
              value={kpis.data?.observedAt}
              label="Counts observed"
            />
            <p className="tp-meta tp-meta--small">
              Aggregated from many independent sources. The{' '}
              <Link to="/sources">Sources page</Link> lists every one, with the
              count it currently contributes. Provenance is attribution, not
              endorsement.
            </p>
          </aside>
        </div>
        <div className="container">
          <figure className="tp-hero__banner">
            <img
              className="tp-hero__banner-image"
              src="/threatpulse-hero.jpg"
              width={1672}
              height={941}
              alt="ThreatPulse threat intelligence banner: actively exploited vulnerabilities, threat monitoring, risk prioritisation and actionable insights."
              loading="eager"
              decoding="async"
            />
          </figure>
        </div>
      </section>

      <AuthorStrip />

      <section className="tp-section" aria-labelledby="kpi-heading">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">Current volume</p>
              <h2 id="kpi-heading">The intelligence set right now</h2>
              <p className="section-lead">
                Counts are read live from the public API. Nothing on this page is
                estimated, and no figure is hard-coded.
              </p>
            </div>
            <Link className="text-link" to="/api">
              API reference
            </Link>
          </div>

          {kpis.data ? (
            <div className="tp-kpi-grid">
              <KpiCountCard
                label="Threats tracked"
                count={kpis.data.totalThreats}
                meta="All records in the published set"
                tone="accent"
              />
              <KpiCountCard
                label="Critical severity"
                count={kpis.data.criticalThreats}
                meta="Severity = critical"
                tone="critical"
              />
              <KpiCountCard
                label="High severity"
                count={kpis.data.highThreats}
                meta="Severity = high"
              />
              <KpiCountCard
                label="Exploitation confirmed"
                count={kpis.data.confirmedExploitation}
                meta="Exploitation status = confirmed"
              />
              <KpiCountCard
                label="CISA KEV vulnerabilities"
                count={kpis.data.kevVulnerabilities}
                meta="kev_listed = true"
              />
              <KpiCountCard
                label="Intelligence sources"
                count={kpis.data.sources}
                meta="Feeds contributing records"
              />
            </div>
          ) : kpis.error ? (
            <ErrorState
              title="Live counts unavailable"
              error={kpis.error}
              onRetry={kpis.reload}
            >
              <p>
                The counts could not be read from the ThreatPulse API, so they
                are not shown. No substitute figures are displayed.
              </p>
            </ErrorState>
          ) : (
            <LoadingState label="Loading live counts" lines={2} />
          )}
        </div>
      </section>

      <section className="tp-section" aria-labelledby="publications-heading">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">Pipeline</p>
              <h2 id="publications-heading">Publication history</h2>
              <p className="section-lead">
                Each publication is a versioned snapshot produced by the
                ThreatPulse collection and scoring pipeline.
              </p>
            </div>
          </div>

          {publications.data && publications.data.items.length > 0 ? (
            <div className="tp-grid tp-grid--2">
              {publications.data.items.map((publication) => (
                <article className="tp-card" key={publication.publication_uuid}>
                  <h3>
                    {formatDateTimeUtc(publication.generated_at) ??
                      'Timestamp not reported'}
                  </h3>
                  <p className="tp-meta tp-meta--small mono">
                    {publication.publication_uuid}
                  </p>
                  <ul className="tp-list">
                    <li>
                      <strong>{formatCount(publication.threat_count)}</strong>{' '}
                      threats
                    </li>
                    <li>
                      <strong>
                        {formatCount(publication.vulnerability_count)}
                      </strong>{' '}
                      vulnerabilities
                    </li>
                  </ul>
                  <p className="tp-meta tp-meta--small">
                    Schema version {publication.schema_version}
                  </p>
                </article>
              ))}
            </div>
          ) : publications.data ? (
            <EmptyState title="No publications are listed">
              <p>The API returned an empty publication history.</p>
            </EmptyState>
          ) : publications.error ? (
            <ErrorState
              title="Publication history unavailable"
              error={publications.error}
              onRetry={publications.reload}
            />
          ) : (
            <LoadingState label="Loading publication history" lines={2} />
          )}
        </div>
      </section>

      <section className="tp-section tp-section--alt">
        <div className="container">
          <div className="tp-split">
            <div>
              <p className="eyebrow">Scope and honesty</p>
              <h2>What ThreatPulse does not yet claim</h2>
              <p className="section-lead">
                The published set is aggregated from many sources, but correlation
                is CVE-centric: material that names no CVE cannot join a threat.
                Sector views are planned, not delivered.
              </p>
              <ul className="tp-list">
                <li>
                  The Priority Score is ThreatPulse's own deterministic model. It
                  is not CVSS and not an industry rating.
                </li>
                <li>
                  Where the source data omits a value — CVSS scores, publication
                  dates — the interface says so instead of implying a value.
                </li>
              </ul>
              <p className="section-footer-link">
                <Link to="/methodology">
                  Read the scoring and provenance methodology
                </Link>
              </p>
            </div>

            <div className="tp-card">
              <h3>Priority band reference</h3>
              <ul className="tp-list">
                {/*
                 * Derived from PRIORITY_BANDS rather than written out here. The
                 * ranges were previously duplicated across this legend, the band
                 * table in lib/priority.ts and the Methodology page, and drifted
                 * apart the first time the thresholds were recalibrated.
                 */}
                {PRIORITY_BANDS.map((band) => (
                  <li key={band.key}>
                    <strong>
                      {band.min}–{Math.floor(band.max)}
                    </strong>{' '}
                    · {band.label} — {band.guidance}
                  </li>
                ))}
              </ul>
              <p className="tp-meta tp-meta--small">
                Highest score currently published:{' '}
                <strong>
                  {topThreat ? formatScore(topThreat.priority_score) : 'not available'}
                </strong>
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="tp-section">
        <div className="container">
          <Notice tone="info" title="New here?">
            <p>
              Open <Link to={threatsPath()}>the prioritised threat list</Link> and
              then any record, to see the evidence: exploitation status, scoring
              factors, the reasoning produced by the pipeline, and the sources
              behind it.
            </p>
          </Notice>
        </div>
      </section>
    </>
  );
}

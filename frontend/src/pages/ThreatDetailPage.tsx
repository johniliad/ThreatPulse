/*
 * Threat detail.
 *
 * Answers, in order: what is it, why does it matter, how strong is the
 * evidence, where did it come from, what should be done. Everything shown is
 * either an API field or an explicit statement that a field was not reported.
 */

import { Link, useParams } from 'react-router-dom';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { useThreat } from '../hooks/useResources';
import { EXPLOITATION_LABELS, SEVERITY_LABELS } from '../lib/constants';
import { formatCvss, formatDateTimeUtc, formatScore } from '../lib/format';
import { cisaKevUrl, nvdUrlForCve, safeExternalUrl, vulnerabilitiesPath } from '../lib/urls';
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from '../components/common/StateBlock';
import { DefinitionList } from '../components/common/DefinitionList';
import { ExternalLink } from '../components/common/ExternalLink';
import { FreshnessIndicator } from '../components/common/FreshnessIndicator';
import { LinkifiedText } from '../components/common/LinkifiedText';
import { Notice } from '../components/common/Notice';
import { PageHead } from '../components/common/PageHead';
import {
  ConfidenceBadge,
  ExploitationBadge,
  SeverityBadge,
} from '../components/common/Badges';
import { PriorityScore } from '../components/threat/PriorityScore';
import { ScoreFactors } from '../components/threat/ScoreFactors';

export function ThreatDetailPage() {
  const { uuid } = useParams<{ uuid: string }>();
  const threat = useThreat(uuid ?? null);
  const record = threat.data;

  useDocumentMeta({
    title: record ? record.title : 'Threat record',
    description: record?.summary
      ? record.summary.slice(0, 155)
      : 'ThreatPulse threat record with prioritisation, evidence and provenance.',
    path: `/threats/${uuid ?? ''}`,
  });

  if (!uuid) {
    return (
      <>
        <PageHead eyebrow="Threat intelligence" title="Threat record" />
        <section className="tp-section">
          <div className="container">
            <EmptyState title="No threat identifier was supplied">
              <p>
                This page needs a ThreatPulse threat UUID. Return to the{' '}
                <Link to="/threats">threat list</Link> and open a record from
                there.
              </p>
            </EmptyState>
          </div>
        </section>
      </>
    );
  }

  if (!record && threat.error) {
    const notFound = threat.error.status === 404;

    return (
      <>
        <PageHead eyebrow="Threat intelligence" title="Threat record" />
        <section className="tp-section">
          <div className="container">
            {notFound ? (
              <EmptyState title="That threat record does not exist">
                <p>
                  The API returned no record for the identifier{' '}
                  <span className="mono">{uuid}</span>. It may have been
                  superseded by a later publication.
                </p>
                <Link className="tp-button tp-button--small" to="/threats">
                  Back to the threat list
                </Link>
              </EmptyState>
            ) : (
              <ErrorState
                title="This threat record could not be loaded"
                error={threat.error}
                onRetry={threat.reload}
              >
                <Link className="tp-button tp-button--small" to="/threats">
                  Back to the threat list
                </Link>
              </ErrorState>
            )}
          </div>
        </section>
      </>
    );
  }

  if (!record) {
    return (
      <>
        <PageHead eyebrow="Threat intelligence" title="Threat record" />
        <section className="tp-section">
          <div className="container">
            <LoadingState label="Loading the threat record" lines={4} />
          </div>
        </section>
      </>
    );
  }

  const metadata = record.metadata;
  const nvdUrl = nvdUrlForCve(record.external_id);
  const cwes = metadata?.cwes ?? [];
  const reasoning = metadata?.reasoning ?? [];

  return (
    <>
      <PageHead
        eyebrow={`${SEVERITY_LABELS[record.severity]} · ${record.threat_type}`}
        title={record.title}
        lead={record.summary ?? 'The API did not provide a summary for this record.'}
        actions={
          <>
            <Link className="tp-button tp-button--secondary" to="/threats">
              Back to the threat list
            </Link>
            {nvdUrl ? (
              <ExternalLink className="tp-button tp-button--secondary" href={nvdUrl}>
                NVD record
              </ExternalLink>
            ) : null}
          </>
        }
      />

      <section className="tp-section tp-section--tight">
        <div className="container tp-split">
          <div className="tp-stack">
            <p className="tp-meta-row">
              <SeverityBadge severity={record.severity} />
              <ExploitationBadge status={record.exploitation_status} verbose />
              <ConfidenceBadge
                level={record.confidence_level}
                score={record.confidence_score}
              />
              {record.external_id ? (
                <span className="tp-badge tp-badge--quiet mono">
                  {record.external_id}
                </span>
              ) : null}
            </p>

            <DefinitionList
              items={[
                {
                  term: 'External identifier',
                  description: record.external_id ?? 'Not reported',
                },
                { term: 'Threat type', description: record.threat_type },
                {
                  term: 'Vendor',
                  description: metadata?.vendor ?? 'Not reported',
                },
                {
                  term: 'Product',
                  description: metadata?.product ?? 'Not reported',
                },
                {
                  term: 'CWE',
                  description:
                    cwes.length > 0 ? cwes.join(', ') : 'Not reported',
                },
                {
                  term: 'First seen',
                  description:
                    formatDateTimeUtc(record.first_seen) ?? 'Not reported',
                },
                {
                  term: 'Last seen',
                  description:
                    formatDateTimeUtc(record.last_seen) ?? 'Not reported',
                },
                {
                  term: 'CISA remediation due',
                  description: metadata?.due_date ?? 'Not reported',
                },
                {
                  term: 'Forensic triage indicated',
                  description: metadata?.forensic_triage ?? 'Not reported',
                },
                {
                  term: 'Known ransomware campaign use',
                  description:
                    metadata?.known_ransomware_campaign_use ?? 'Not reported',
                },
              ]}
            />

            <p className="tp-meta-row">
              <FreshnessIndicator value={record.last_seen} label="Last seen" />
              <FreshnessIndicator
                value={record.first_seen}
                label="First seen"
                showAge={false}
              />
            </p>
          </div>

          <aside className="tp-card tp-card--accent" aria-label="Priority score">
            <h2 className="tp-meta">ThreatPulse Priority Score</h2>
            <PriorityScore score={record.priority_score} />
            <p className="tp-meta tp-meta--small">
              Produced by the ThreatPulse prioritisation model — not by the
              frontend and not by CVSS.
            </p>
          </aside>
        </div>
      </section>

      <section className="tp-section" aria-labelledby="vulns-heading">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">What it is</p>
              <h2 id="vulns-heading">Associated vulnerability records</h2>
              <p className="section-lead">
                Each CVE links to the full vulnerability record, so the CVE →
                threat relationship can be followed in both directions.
              </p>
            </div>
          </div>

          {record.vulnerabilities.length > 0 ? (
            <div className="tp-grid tp-grid--2">
              {record.vulnerabilities.map((vulnerability) => {
                const vulnerabilityNvd = nvdUrlForCve(vulnerability.cve_id);

                return (
                  <article className="tp-card" key={vulnerability.cve_id}>
                    <p className="tp-meta-row">
                      <span className="tp-badge tp-badge--quiet mono">
                        {vulnerability.cve_id}
                      </span>
                      <SeverityBadge severity={vulnerability.severity} />
                      <span className="tp-badge tp-badge--quiet">
                        {vulnerability.kev_listed
                          ? 'CISA KEV listed'
                          : 'Not in CISA KEV'}
                      </span>
                    </p>

                    <p>
                      {vulnerability.description ??
                        'The API did not provide a description for this vulnerability.'}
                    </p>

                    <DefinitionList
                      items={[
                        {
                          term: 'CVSS score',
                          description: formatCvss(vulnerability.cvss_score),
                        },
                        {
                          term: 'CVSS vector',
                          description:
                            vulnerability.cvss_vector ?? 'Not provided',
                        },
                        {
                          term: 'Vendor',
                          description: vulnerability.vendor ?? 'Not reported',
                        },
                        {
                          term: 'Product',
                          description: vulnerability.product ?? 'Not reported',
                        },
                        {
                          term: 'Exploited in the wild',
                          description: vulnerability.exploited_in_wild
                            ? 'Reported as exploited in the wild'
                            : 'Not reported as exploited',
                        },
                      ]}
                    />

                    <p className="tp-entry__actions">
                      <Link
                        className="tp-button tp-button--quiet tp-button--small"
                        to={vulnerabilitiesPath({ cve: vulnerability.cve_id })}
                      >
                        Open vulnerability record
                      </Link>
                      {vulnerabilityNvd ? (
                        <ExternalLink
                          className="tp-button tp-button--quiet tp-button--small"
                          href={vulnerabilityNvd}
                        >
                          NVD
                        </ExternalLink>
                      ) : null}
                    </p>
                  </article>
                );
              })}
            </div>
          ) : (
            <EmptyState title="No vulnerability record is associated">
              <p>
                This threat record has no linked CVE in the published set. That
                is reported as an absence, not as a score of zero.
              </p>
            </EmptyState>
          )}
        </div>
      </section>

      <section className="tp-section tp-section--alt" aria-labelledby="why-heading">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">Why it matters</p>
              <h2 id="why-heading">The pipeline's own reasoning</h2>
              <p className="section-lead">
                These statements are stored with the record by the ThreatPulse
                scoring pipeline. The dashboard does not generate, paraphrase or
                embellish them.
              </p>
            </div>
          </div>

          <div className="tp-split">
            <div className="tp-card">
              <h3>Reasoning recorded with this threat</h3>
              {reasoning.length > 0 ? (
                <ul className="tp-list">
                  {reasoning.map((statement) => (
                    <li key={statement}>{statement}</li>
                  ))}
                </ul>
              ) : (
                <p className="tp-meta">
                  This record does not include reasoning statements.
                </p>
              )}
            </div>

            <div className="tp-card">
              <h3>Scoring factors</h3>
              <ScoreFactors
                factors={metadata?.score_factors}
                weights={metadata?.score_weights}
                scoringModel={metadata?.scoring_model}
              />
            </div>
          </div>
        </div>
      </section>

      <section className="tp-section" aria-labelledby="evidence-heading">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">How strong is the evidence</p>
              <h2 id="evidence-heading">Confidence, sources and provenance</h2>
              <p className="section-lead">
                Every claim on this page can be traced back to the source
                recorded with the threat.
              </p>
            </div>
          </div>

          <div className="tp-split">
            <div className="tp-stack">
              <div className="tp-card">
                <h3>Intelligence sources</h3>
                {record.sources.length > 0 ? (
                  <ul className="tp-list">
                    {record.sources.map((source) => (
                      <li key={source.source_key}>
                        <strong>{source.name}</strong>{' '}
                        <span className="tp-meta tp-meta--small">
                          {source.provider ?? 'provider not reported'} ·{' '}
                          {source.source_type} · reliability{' '}
                          {source.reliability ?? 'not reported'} · relationship:{' '}
                          {source.relationship}
                        </span>
                        {safeExternalUrl(source.url) ? (
                          <>
                            {' '}
                            <ExternalLink href={source.url}>
                              Source reference
                            </ExternalLink>
                          </>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="tp-meta">
                    No source attribution is recorded for this threat.
                  </p>
                )}
              </div>

            </div>

            <div className="tp-stack">
              <div className="tp-card">
                <h3>Confidence assessment</h3>
                <DefinitionList
                  items={[
                    {
                      term: 'Confidence level',
                      description: record.confidence_level,
                    },
                    {
                      term: 'Confidence score',
                      description: formatScore(record.confidence_score),
                    },
                    {
                      term: 'Exploitation status',
                      description:
                        EXPLOITATION_LABELS[record.exploitation_status],
                    },
                  ]}
                />
              </div>

              <div className="tp-card">
                <h3>Publication history</h3>
                {record.publications.length > 0 ? (
                  <ul className="tp-list">
                    {record.publications.map((publication) => (
                      <li key={publication.publication_uuid}>
                        <strong>
                          {formatDateTimeUtc(publication.generated_at) ??
                            'Timestamp not reported'}
                        </strong>{' '}
                        <span className="tp-meta tp-meta--small">
                          schema {publication.schema_version}
                        </span>
                        <br />
                        <span className="tp-meta tp-meta--small mono">
                          {publication.publication_uuid}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="tp-meta">
                    No publication reference is recorded for this threat.
                  </p>
                )}
              </div>

              {metadata?.source_attribution ? (
                <div className="tp-card">
                  <h3>Source attribution</h3>
                  <DefinitionList
                    items={[
                      {
                        term: 'Source',
                        description:
                          metadata.source_attribution.source_name ??
                          'Not reported',
                      },
                      {
                        term: 'Source key',
                        description:
                          metadata.source_attribution.source_key ??
                          'Not reported',
                      },
                      {
                        term: 'Source record',
                        description:
                          metadata.source_attribution.source_record_id ??
                          'Not reported',
                      },
                      {
                        term: 'Retrieved at',
                        description:
                          formatDateTimeUtc(
                            metadata.source_attribution.retrieved_at
                          ) ?? 'Not reported',
                      },
                    ]}
                  />
                </div>
              ) : null}
            </div>
          </div>
        </div>
      </section>

      <section className="tp-section tp-section--alt" aria-labelledby="action-heading">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">What should I do</p>
              <h2 id="action-heading">Recommended action</h2>
              <p className="section-lead">
                Taken verbatim from the record's <span className="mono">recommended_action</span>{' '}
                field, which the publishing pipeline writes from the source
                advisory. ThreatPulse does not summarise or reinterpret it.
              </p>
            </div>
          </div>

          <div className="tp-split">
            <div className="tp-card">
              <h3>Guidance recorded with this threat</h3>
              {record.recommended_action ? (
                <p>{record.recommended_action}</p>
              ) : (
                <p className="tp-meta">
                  The API did not provide a recommended action for this record.
                  Consult the source advisory directly.
                </p>
              )}

              <p className="tp-entry__actions">
                {nvdUrl ? (
                  <ExternalLink className="tp-button tp-button--small" href={nvdUrl}>
                    Vulnerability detail (NVD)
                  </ExternalLink>
                ) : null}
                <ExternalLink
                  className="tp-button tp-button--quiet tp-button--small"
                  href={cisaKevUrl()}
                >
                  CISA KEV catalog
                </ExternalLink>
              </p>
            </div>

            <div className="tp-stack">
              {metadata?.cisa_notes ? (
                <div className="tp-card">
                  <h3>Source notes</h3>
                  <p>
                    <LinkifiedText text={metadata.cisa_notes} />
                  </p>
                </div>
              ) : null}

              <Notice tone="warning" title="Assess your own exposure">
                <p>
                  ThreatPulse reports the source's guidance verbatim. Whether a
                  remediation deadline, forensic triage obligation or reporting
                  duty applies to your organisation depends on your own asset
                  exposure and regulatory context.
                </p>
              </Notice>
            </div>
          </div>
        </div>
      </section>

      <section className="tp-section tp-section--tight">
        <div className="container">
          <p className="tp-meta tp-meta--small">
            Scoring model:{' '}
            <span className="mono">
              {metadata?.scoring_model ?? 'not reported'}
            </span>{' '}
            · Threat UUID: <span className="mono">{record.threat_uuid}</span> ·{' '}
            <Link to="/methodology">Methodology and provenance</Link>
          </p>
        </div>
      </section>
    </>
  );
}

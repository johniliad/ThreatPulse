/*
 * Sources page.
 *
 * Provenance, not endorsement. The page states plainly what each source is,
 * how it is classified and how many threat records it currently contributes.
 */

import { Link } from 'react-router-dom';
import { useAttribution, useSources } from '../hooks/useResources';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { formatCount } from '../lib/format';
import { safeExternalUrl } from '../lib/urls';
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from '../components/common/StateBlock';
import { ExternalLink } from '../components/common/ExternalLink';
import { Notice } from '../components/common/Notice';
import { PageHead } from '../components/common/PageHead';
import { Pagination } from '../components/common/Pagination';
import { useState } from 'react';

export function SourcesPage() {
  useDocumentMeta({
    title: 'Intelligence sources',
    description:
      'The feeds behind ThreatPulse: what each source is, how it is classified, and how many threat records it contributes.',
    path: '/sources',
  });

  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(25);

  const sources = useSources({ limit, offset });
  const attribution = useAttribution();

  /*
   * Declared sources that are not contributing to the current published set.
   *
   * Computed from the register minus the ingested list rather than hard-coded, so
   * it stays true as sources are fixed or added. It is only reliable while the
   * ingested list fits on one page, so the total is checked before the section is
   * shown.
   */
  const contributing = new Set(
    (sources.data?.items ?? []).map((item) => item.source_key),
  );

  const ingestedFullyLoaded =
    sources.data != null &&
    sources.data.items.length >= (sources.data.pagination?.total ?? 0);

  const silent = ingestedFullyLoaded
    ? (attribution.data?.sources ?? []).filter(
        (record) => record.ingested && !contributing.has(record.source_key ?? ''),
      )
    : [];

  return (
    <>
      <PageHead
        eyebrow="Provenance"
        title="Intelligence sources"
        lead="ThreatPulse publishes where each signal came from. Attribution is provenance — it is not an endorsement of any vendor, advisory or authority."
      />

      <section className="tp-section tp-section--tight">
        <div className="container">
          <Notice tone="neutral" title="How to read this page">
            <p>
              There are two statements here, and they answer different questions.
              <strong> Ingested sources</strong> is what contributed to the current
              published set, with the counts the API computes from the data itself.
              <strong> The attribution register</strong> is what the product
              decided — including sources it deliberately does not ingest, and the
              licence and terms behind every source.
            </p>
          </Notice>
        </div>
      </section>

      <section className="tp-section" aria-labelledby="selection-heading">
        <div className="container tp-prose">
          <p className="eyebrow">Selection</p>
          <h2 id="selection-heading">
            How sources are chosen — and why most of them contribute little
          </h2>
          <p>
            A declared source is not the same as a contributing source, and the gap
            between the two is wide on purpose. Five things stand between a feed and
            a published threat, and every one of them can remove material.
          </p>

          <h3>1. Only clear-marked material is accepted</h3>
          <p>
            ThreatPulse imposes a traffic-light restriction on itself. Only material
            marked <strong>TLP:CLEAR</strong> — or its predecessor TLP:WHITE — is
            ingested, stored or published. Anything marked GREEN, AMBER or RED is
            refused, and the refusal is enforced twice: when a record is read, and
            again against the finished publication before it is transmitted.
          </p>
          <p>
            This is a deliberate limit rather than a technical one. It is what makes
            the product safe to publish openly, and it is why some genuinely useful
            restricted advisories are knowingly excluded. A source that marks its
            output restrictively will contribute nothing, however good it is.
          </p>

          <h3>2. Material with no CVE cannot join a threat</h3>
          <p>
            Threats are grouped by CVE. An advisory that names no CVE — a campaign
            write-up, a product notice without an identifier, a set of indicators —
            has nothing to correlate against, so it cannot join a vulnerability
            record. This is the single largest reason a source that looks
            substantial contributes almost nothing: national CERT feeds, for
            example, publish a great deal of guidance and news alongside their
            advisories, and only the part that names a CVE can be used here.
          </p>
          <p>
            Such material is not discarded. It is collected and snapshotted, but it
            does not appear as a threat.
          </p>

          <h3>3. A CVE is necessary but not sufficient</h3>
          <p>
            Naming a CVE is not enough on its own. The group also has to carry
            evidence the scoring model can use — an exploitation assessment, EPSS, a
            CVSS or severity, an available fix, a remediation window — and at least
            two independent sources, unless one of them is the CISA KEV catalogue,
            which is a corroborated determination in its own right. A bare mention of
            a CVE in a news item produces a correlation group with nothing to score,
            and a group that cannot be scored is not published.
          </p>
          <p>
            This has become rare. The scoring model was unified so that a group is
            scored from whatever evidence it holds rather than only from KEV fields,
            and the last run refused three groups out of more than three thousand,
            where the earlier KEV-only model refused roughly half. What limits
            coverage today is not scoring but the two gates above: material that is
            not clear-marked, and material that names no CVE at all.
          </p>

          <h3>4. A source can fail, or never be configured</h3>
          <p>
            Some declared sources contribute nothing because they are not working:
            a credential is missing, a feed has moved, a rate limit was hit, or the
            endpoint is unreachable. Where a source has previously produced data,
            the last good snapshot is reused and the source is reported as
            degraded rather than silently contributing less. Where it has never
            produced data, it simply contributes nothing until it is fixed.
          </p>

          <h3>5. Some sources are declared and deliberately excluded</h3>
          <p>
            A few sources are registered with the product precisely so that the
            decision not to use them is visible. Their entries in the register below
            state the reason.
          </p>

          <h3>What this means for the counts</h3>
          <p>
            Expect the ratio between records collected and threats published to be
            large and to vary widely by source. A source that publishes
            vulnerability advisories with identifiers will convert a high proportion
            of its output; a source that publishes guidance or news will
            convert almost none. The counts in the section above are computed from
            the live data rather than typed here, so they reflect the current run
            rather than a snapshot of this text.
          </p>
          <p className="tp-meta tp-meta--small">
            A low count is not a fault report and a high count is not a quality
            ranking. It is a measure of how much of a source's output is
            CVE-addressable and scoreable, which is a property of the source's
            format, not of its value.
          </p>
        </div>
      </section>

      <section className="tp-section" aria-labelledby="source-list-heading">
        <div className="container">
          <h2 id="source-list-heading">Ingested sources</h2>
          <p className="tp-meta">
            Sources that currently contribute at least one record, with the count
            the API derives from the relationship between threats and sources.
          </p>

          {sources.data && sources.data.items.length > 0 ? (
            <>
              <div className="tp-grid tp-grid--2">
                {sources.data.items.map((source) => {
                  const url = safeExternalUrl(source.url);

                  return (
                    <article className="tp-card" key={source.source_key}>
                      <h3>{source.name}</h3>
                      <p className="tp-meta-row">
                        <span className="tp-badge tp-badge--quiet">
                          {source.source_type}
                        </span>
                        <span className="tp-badge tp-badge--quiet">
                          reliability {source.reliability ?? 'not reported'}
                        </span>
                        <span className="tp-badge tp-badge--accent mono">
                          {source.source_key}
                        </span>
                      </p>
                      <p>
                        Provider:{' '}
                        <strong>{source.provider ?? 'not reported'}</strong>
                      </p>
                      <p>
                        Contributes{' '}
                        <strong>{formatCount(source.threat_count)}</strong>{' '}
                        threat records to the current published set.
                      </p>
                      {url ? (
                        <p className="tp-entry__actions">
                          <ExternalLink
                            className="tp-button tp-button--quiet tp-button--small"
                            href={url}
                          >
                            Open the source
                          </ExternalLink>
                        </p>
                      ) : (
                        <p className="tp-meta tp-meta--small">
                          The API does not provide a URL for this source.
                        </p>
                      )}
                    </article>
                  );
                })}
              </div>

              <Pagination
                pagination={sources.data.pagination}
                itemLabel="sources"
                isBusy={sources.isRefreshing}
                onOffsetChange={setOffset}
                onLimitChange={(nextLimit) => {
                  setLimit(nextLimit);
                  setOffset(0);
                }}
              />
            </>
          ) : sources.data ? (
            <EmptyState title="No sources are listed">
              <p>
                The API returned no sources. ThreatPulse does not invent
                provenance, so nothing is displayed here.
              </p>
            </EmptyState>
          ) : sources.error ? (
            <ErrorState
              title="Sources could not be loaded"
              error={sources.error}
              onRetry={sources.reload}
            />
          ) : (
            <LoadingState label="Loading intelligence sources" lines={3} />
          )}

          <p className="section-footer-link">
            See <Link to="/methodology">Methodology</Link> for how sources are
            used in scoring, and <Link to="/api">API</Link> for the
            <span className="mono"> sources.php</span> contract.
          </p>
        </div>
      </section>

      {silent.length > 0 ? (
        <section className="tp-section" aria-labelledby="silent-heading">
          <div className="container">
            <h2 id="silent-heading">
              Declared sources that are not contributing
            </h2>
            <p className="tp-meta">
              These sources are registered and enabled, but no record of theirs is in
              the current published set. Each register entry below records what the
              product decided about the source; the run's own report — which source was
              ok, degraded or failed, and why — is published by the API, not guessed
              here. They are listed rather than omitted, because a source list that
              silently drops the ones that are not working is a source list a reader
              cannot audit.
            </p>

            <ul className="tp-list">
              {silent.map((record) => (
                <li key={record.source_key}>
                  <strong>{record.name}</strong>{' '}
                  <span className="mono tp-meta tp-meta--small">
                    {record.source_key}
                  </span>
                  {record.provider ? <> — {record.provider}</> : null}
                </li>
              ))}
            </ul>

            <p className="tp-meta tp-meta--small">
              A source that is declared but silent is not necessarily broken: some
              are deliberately not ingested, and some publish nothing that can be
              correlated. Read the register entry for the specific reason.
            </p>
          </div>
        </section>
      ) : null}

      <section className="tp-section" aria-labelledby="register-heading">
        <div className="container">
          <h2 id="register-heading">Attribution register</h2>
          <p className="tp-meta">
            What ThreatPulse uses, on what terms, and what it deliberately does not
            use. This is the product's own statement rather than a list derived from
            the data, so it includes sources that contribute nothing — and it is the
            only place a reader can see the licence and terms behind each one.
          </p>

          {attribution.data ? (
            attribution.data.stored ? (
              <>
                {attribution.data.policy ? (
                  <p className="tp-meta tp-meta--small">
                    {attribution.data.policy}
                  </p>
                ) : null}

                <div className="tp-grid tp-grid--2">
                  {attribution.data.sources.map((record) => {
                    const homepage = safeExternalUrl(record.homepage);
                    const terms = safeExternalUrl(record.terms_url);

                    return (
                      <article className="tp-card" key={record.source_key}>
                        <h3>{record.name}</h3>
                        <p className="tp-meta-row">
                          <span
                            className={
                              record.ingested
                                ? 'tp-badge tp-badge--accent'
                                : 'tp-badge tp-badge--quiet'
                            }
                          >
                            {record.ingested ? 'Ingested' : 'Not ingested'}
                          </span>
                          {record.tier !== null ? (
                            <span className="tp-badge tp-badge--quiet">
                              tier {record.tier}
                            </span>
                          ) : null}
                          {record.tlp_default ? (
                            <span className="tp-badge tp-badge--quiet mono">
                              TLP:{record.tlp_default}
                            </span>
                          ) : null}
                          <span className="tp-badge tp-badge--quiet mono">
                            {record.source_key}
                          </span>
                        </p>
                        <p>
                          Provider:{' '}
                          <strong>{record.provider ?? 'not reported'}</strong>
                        </p>
                        <p className="tp-meta tp-meta--small">
                          {record.licence ?? 'No licence recorded for this source.'}
                        </p>
                        {record.notes ? (
                          <p className="tp-meta tp-meta--small">{record.notes}</p>
                        ) : null}
                        {homepage || terms ? (
                          <p className="tp-entry__actions">
                            {homepage ? (
                              <ExternalLink
                                className="tp-button tp-button--quiet tp-button--small"
                                href={homepage}
                              >
                                Open the source
                              </ExternalLink>
                            ) : null}
                            {terms ? (
                              <ExternalLink
                                className="tp-button tp-button--quiet tp-button--small"
                                href={terms}
                              >
                                Terms
                              </ExternalLink>
                            ) : null}
                          </p>
                        ) : null}
                      </article>
                    );
                  })}
                </div>
              </>
            ) : (
              <Notice tone="neutral" title="The register has not been stored yet">
                <p>
                  {attribution.data.message ??
                    'This deployment has not stored the attribution register.'}
                </p>
                <p className="tp-meta tp-meta--small">
                  The register is not invented here: ThreatPulse would rather say
                  that it is missing than display a source list it cannot support.
                </p>
              </Notice>
            )
          ) : attribution.error ? (
            <ErrorState
              title="The attribution register could not be loaded"
              error={attribution.error}
              onRetry={attribution.reload}
            />
          ) : (
            <LoadingState label="Loading the attribution register" lines={3} />
          )}
        </div>
      </section>
    </>
  );
}

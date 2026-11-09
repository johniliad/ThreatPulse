/*
 * Methodology page.
 *
 * The canonical, complete description of the product: the pipeline, the
 * prioritisation model, the bands, provenance, the handling rule, correlation,
 * and — equally important — the limits of what the current data can support.
 *
 * This page absorbed the former "How it works" page. Everything stated here is
 * either delivered and observable on this site, or explicitly marked as not
 * delivered. Nothing is aspirational.
 */

import { Link } from 'react-router-dom';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { PRIORITY_BANDS, SCORE_FACTOR_EXPLANATIONS } from '../lib/priority';
import { Notice } from '../components/common/Notice';
import { PageHead } from '../components/common/PageHead';

const MODEL_WEIGHTS = [
  { factor: 'exploitation', weight: '28%' },
  { factor: 'epss', weight: '20%' },
  { factor: 'impact', weight: '18%' },
  { factor: 'evidence', weight: '10%' },
  { factor: 'urgency', weight: '8%' },
  { factor: 'ransomware', weight: '6%' },
  { factor: 'recency', weight: '5%' },
  { factor: 'first_seen', weight: '3%' },
  { factor: 'forensic', weight: '2%' },
];
const PIPELINE_STEPS = [
  {
    title: 'Collect',
    body: 'Independent collectors run on a separate server and fetch each source over HTTPS. Every collector reports ok, degraded or failed, and a source that cannot be reached degrades to its last known good snapshot rather than destroying intelligence from the sources that did respond.',
  },
  {
    title: 'Normalise',
    body: 'Feed content is untrusted, so every field is validated, bounded and sanitised. A record that cannot be trusted is rejected with a reason instead of being silently coerced.',
  },
  {
    title: 'Correlate',
    body: 'Observations about the same subject are merged into one intelligence object with all of their evidence attached. Identity is deterministic, so a threat keeps the same identifier across runs and a republication never duplicates it.',
  },
  {
    title: 'Score, validate, publish',
    body: 'A priority score is computed from the evidence, the whole document is checked by a fail-closed quality gate, and only then is it transmitted to the public API. A publication that fails the gate is never sent.',
  },
];



export function MethodologyPage() {
  useDocumentMeta({
    title: 'Methodology and provenance',
    description:
      'The complete description of ThreatPulse: the pipeline, the prioritisation model, the bands, provenance, the TLP handling rule, correlation, and the limits of what the data supports.',
    path: '/methodology',
  });

  return (
    <>
      <PageHead
        eyebrow="Transparency"
        title="Methodology and provenance"
        lead="The complete description of ThreatPulse: how intelligence reaches this page, how a score is produced, where the data comes from, the handling rule that governs what may be republished, and where the product's limits are."
      />

      <section className="tp-section tp-section--tight">
        <div className="container tp-prose">
          <div className="tp-card">
            <h2>The question it answers</h2>
            <p>
              ThreatPulse exists to answer one question: <strong>what deserves
              attention now — and why?</strong> Every threat record on this site
              carries the score, the factors behind it, and the evidence it rests
              on, so a decision can be reconstructed rather than taken on trust.
            </p>
            <p>
              This page describes the whole system: what it reads, the rule that
              governs what it may republish, how a score is produced, and where its
              limits are. It states nothing that is not either delivered or
              explicitly marked as not delivered.
            </p>
          </div>
        </div>
      </section>

      <section className="tp-section tp-section--alt" aria-labelledby="pipeline-heading">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">Pipeline</p>
              <h2 id="pipeline-heading">How intelligence reaches this page</h2>
              <p className="section-lead">
                This dashboard is a static site. It holds no data of its own and
                performs no scoring — it reads a public, read-only API, which is
                written to by a separate backend service.
              </p>
            </div>
          </div>

          <div className="tp-grid tp-grid--2">
            {PIPELINE_STEPS.map((step, position) => (
              <div className="tp-card" key={step.title}>
                <h3>
                  <span className="mono">{position + 1}.</span> {step.title}
                </h3>
                <p>{step.body}</p>
              </div>
            ))}
          </div>

          <Notice tone="neutral" title="Where the work happens">
            <p>
              Collection, correlation, scoring and validation all happen on the
              backend server, before anything is transmitted. The dashboard displays
              what the API returns and never recalculates a score or re-ranks a
              list.
            </p>
          </Notice>
        </div>
      </section>


      <section className="tp-section tp-section--tight">
        <div className="container tp-split">
          <div className="tp-stack">
            <div className="tp-card">
              <h2>The ThreatPulse Priority Score</h2>
              <p>
                Each threat receives a score from 0 to 100, produced by the
                ThreatPulse scoring pipeline and stored with the record. The
                dashboard displays that value; it never recalculates it and never
                re-ranks the list.
              </p>
              <p>
                One model scores every vulnerability, whether or not it appears in
                the CISA Known Exploited Vulnerabilities catalogue. It reads the
                evidence that actually exists: exploitation assessments, EPSS
                percentile, CVSS or a stated severity, how many independent sources
                corroborate the record, deadline pressure or an available fix, the
                source's own ransomware and forensic determinations, and how recent
                the signal is.
              </p>
              <p>
                Every factor is optional. The model reports only the factors present
                in the evidence and publishes their weights with each record, so a
                specific score can be reconstructed from the data. A record whose
                evidence is thin scores low rather than being filled in with
                defaults, and one the model cannot support is not published at all.
              </p>
              <p>
                Until the models were unified, most of the published set was scored
                by a KEV-derived model with six factors. That answer is still
                computed for KEV records and published beside the current score, so
                the change can be checked record by record.
              </p>
              <div className="tp-table-wrap">
                <table className="tp-table">
                  <caption>Documented model weights</caption>
                  <thead>
                    <tr>
                      <th scope="col">Factor</th>
                      <th scope="col">Weight</th>
                      <th scope="col">What it captures</th>
                    </tr>
                  </thead>
                  <tbody>
                    {MODEL_WEIGHTS.map((entry) => (
                      <tr key={entry.factor}>
                        <th scope="row">{entry.factor}</th>
                        <td className="mono">{entry.weight}</td>
                        <td>{SCORE_FACTOR_EXPLANATIONS[entry.factor]}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="tp-card">
              <h2>Bands</h2>
              <p>
                The band is a label for the score, not a separate judgement. It
                is derived by looking the score up in the table below.
              </p>
              <p>
                What that means in volume, on the publication of 2 November 2026
                (3,558 records): 3.5% critical, 27.5% high, 24% medium, 10% low and
                35% informational. A narrow critical band is the point — a label
                covering a quarter of the catalogue is not a prioritisation anyone can
                act on — and the large informational group is the honest cost of
                publishing records whose evidence is thin rather than withholding
                them. The published <em>severity</em> of a record is this same band.
              </p>
              <div className="tp-table-wrap">
                <table className="tp-table">
                  <caption>Priority score bands</caption>
                  <thead>
                    <tr>
                      <th scope="col">Score</th>
                      <th scope="col">Band</th>
                      <th scope="col">Guidance</th>
                    </tr>
                  </thead>
                  <tbody>
                    {PRIORITY_BANDS.map((band) => (
                      <tr key={band.key}>
                        <th scope="row" className="mono">
                          {band.min}–{band.max}
                        </th>
                        <td>{band.label}</td>
                        <td>{band.guidance}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <div className="tp-stack">
            <div className="tp-card">
              <h2>Provenance</h2>
              <p>
                The published set is aggregated from many independent sources —
                national CERT and CSIRT feeds, vendor advisories, exploitation
                catalogues, vulnerability databases and threat-intelligence feeds.
                No single feed is the product.
              </p>
              <ul className="tp-list">
                <li>
                  Each threat stores its source attribution: source key, source
                  name, source record identifier and retrieval timestamp.
                </li>
                <li>
                  Sources are classified by type and reliability, and the{' '}
                  <Link to="/sources">Sources page</Link> lists every source the
                  product declares — including the ones it deliberately does not
                  ingest, and the ones that are declared but currently contribute
                  nothing.
                </li>
                <li>
                  A record may rest on one source or on several. Where several
                  agree, the record says so rather than merging them into a single
                  unattributed claim.
                </li>
              </ul>
              <p>
                Where a source fails, the run reports it as failed and the previous
                good snapshot is used rather than silently publishing a thinner
                set.
              </p>
            </div>

            <div className="tp-card">
              <h2>Freshness</h2>
              <ul className="tp-list">
                <li>
                  Publication timestamps come from the publishing pipeline, not
                  from the browser.
                </li>
                <li>
                  Naive timestamps are interpreted as UTC and always displayed as
                  UTC, so a viewer's time zone cannot shift a date silently.
                </li>
                <li>
                  Relative ages ("6 hours ago") are computed from those
                  timestamps and never rounded in the optimistic direction.
                </li>
                <li>
                  API responses are cached for 60 seconds; the dashboard reuses
                  that window rather than forcing repeated requests.
                </li>
              </ul>
            </div>

            <div className="tp-card">
              <h2>Evidence, not assertion</h2>
              <ul className="tp-list">
                <li>
                  Exploitation status, confidence level and the score are taken
                  from the record.
                </li>
                <li>Reasoning statements are shown verbatim from the pipeline.</li>
                <li>
                  Where a value is missing — CVSS score, publication date — the
                  interface says so rather than implying a value.
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <section className="tp-section tp-section--alt" aria-labelledby="correlation-heading">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">Correlation</p>
              <h2 id="correlation-heading">How observations become a threat</h2>
              <p className="section-lead">
                A raw feed record is not a threat. ThreatPulse merges the
                observations that concern the same subject into one intelligence
                object, with all of the evidence attached.
              </p>
            </div>
          </div>

          <div className="tp-grid tp-grid--2">
            <div className="tp-card">
              <h3>One subject, one record</h3>
              <p>
                Observations are grouped by their subject — for a vulnerability,
                the CVE identifier. Several sources describing the same CVE produce{' '}
                <strong>one</strong> threat carrying every source's evidence, not
                several competing records.
              </p>
              <p>
                Identity is <strong>deterministic</strong>: it is derived from the
                subject, not from a counter or a timestamp. A republication
                therefore updates the existing record instead of creating a
                duplicate.
              </p>
            </div>
            <div className="tp-card">
              <h3>Correlation is CVE-centric</h3>
              <p>
                Because grouping is by CVE, material that names no CVE cannot join
                a vulnerability record — a campaign write-up, a product notice
                without an identifier, a set of indicators. That material is
                collected and snapshotted but does not appear as a threat.
              </p>
              <p>
                This is the single largest reason a source that looks substantial
                contributes almost nothing. The{' '}
                <Link to="/sources">Sources page</Link> works through it.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="tp-section" aria-labelledby="feeds-heading">
        <div className="container tp-prose">
          <p className="eyebrow">Provenance</p>
          <h2 id="feeds-heading">What is ingested</h2>
          <p>
            Every source is declared in a register before it may be read. A source
            that is not in the register cannot be ingested at all — an absence of
            paperwork is not permission.
          </p>
          <p>
            Every ingested source is recorded with its provider, its licence and the
            attribution text that must accompany anything derived from it.
            Attribution is <strong>provenance, not endorsement</strong> — listing a
            source states where a signal came from, not that the source endorses
            ThreatPulse or the reverse.
          </p>
          <p>
            Sources that were considered and are deliberately <strong>not</strong>{' '}
            ingested are recorded too, so the register describes what the product
            does and does not use rather than implying broader coverage than exists.
          </p>
          <p className="section-footer-link">
            The full list — with the current contribution of each source, and the
            ones that are declared but contributing nothing — is on{' '}
            <Link to="/sources">Sources</Link>.
          </p>
        </div>
      </section>


      <section className="tp-section tp-section--alt" aria-labelledby="tlp-heading">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">Handling rule</p>
              <h2 id="tlp-heading">Only TLP:CLEAR/WHITE is ingested</h2>
              <p className="section-lead">
                ThreatPulse publishes to an open, unauthenticated dashboard, so it
                may only republish material its originator released for
                unrestricted public use.
              </p>
            </div>
          </div>

          <div className="tp-grid tp-grid--2">
            <div className="tp-card">
              <h3>What is accepted</h3>
              <ul className="tp-list">
                <li>
                  <strong>TLP:CLEAR</strong> — and <strong>TLP:WHITE</strong>, its
                  predecessor spelling under TLP 1.0, treated identically.
                </li>
                <li>
                  Sources that publish openly carry no marking at all. Each declares
                  an explicit default of CLEAR in the register, which records the
                  justification for treating it as public.
                </li>
              </ul>
            </div>
            <div className="tp-card">
              <h3>What is refused</h3>
              <ul className="tp-list">
                <li>
                  <strong>TLP:GREEN</strong>, <strong>TLP:AMBER</strong>,{' '}
                  <strong>TLP:AMBER+STRICT</strong> and <strong>TLP:RED</strong> are
                  never ingested, never stored and never republished.
                </li>
                <li>
                  An item marked more restrictively than its source default is
                  rejected with a reason, so one over-marked advisory cannot discard
                  the rest of a feed.
                </li>
                <li>
                  An unrecognised marking is refused rather than assumed public, and
                  an undeclared source is refused outright.
                </li>
              </ul>
            </div>
          </div>

          <Notice tone="info" title="Enforced twice, and by the originator's own label">
            <p>
              Enforcement is fail-closed at ingest and again on the serialised
              publication, which is scanned for restrictive markings before anything
              is transmitted. Where a source states its own handling rule — CISA's
              CSAF advisories carry a{' '}
              <span className="mono">distribution.tlp.label</span> — that label
              governs the item rather than an assumption made on its behalf.
            </p>
          </Notice>
        </div>
      </section>

      <section className="tp-section" aria-labelledby="exposed-heading">
        <div className="container">
          <Notice tone="neutral" title="What is exposed, and what is not">
            <p>
              Correlation aggregates evidence into threat records, and each record
              carries the enrichment the pipeline attached to it — MITRE ATT&amp;CK
              context, weaknesses, vendor assessment and the source attribution
              behind every statement. What is <strong>not</strong> served is a
              queryable relationship graph: you cannot ask the API for every threat
              linked to a given actor, indicator or technique. The dashboard shows
              the relationships a record actually carries, and nothing more.
            </p>
            <p>
              Each record also carries its own publication history: when ThreatPulse
              first published it, how many times it has materially changed, and — when
              something moved — which tracked fields moved. The publication summary
              reports how many records are new, changed, unchanged or no longer
              reported since the previous run, and the API serves the changes
              themselves — which records were added, removed or changed, and which
              fields moved — not only the counts. Only substantive fields count as
              change; a retrieval timestamp is not a change.
            </p>
          </Notice>
        </div>
      </section>


      <section className="tp-section tp-section--alt">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">Limits</p>
              <h2>What this release does not do</h2>
              <p className="section-lead">
                Stating the limits is part of the methodology. These are the
                boundaries of the current published data.
              </p>
            </div>
          </div>

          <div className="tp-grid tp-grid--2">
            <div className="tp-card">
              <h3>Priority is not CVSS</h3>
              <p>
                CVSS describes severity. The ThreatPulse Priority Score combines
                exploitation evidence, EPSS probability, technical impact, how many
                independent sources corroborate the record, remediation deadline or
                fix availability, ransomware and forensic determinations, recency,
                and how recently ThreatPulse first observed it. They are not
                interchangeable, and the interface never presents one as the other.
              </p>
            </div>

            <div className="tp-card">
              <h3>False positives are expected</h3>
              <p>
                A high priority means the evidence ThreatPulse holds is strong — not
                that the vulnerability affects you. Feeds sometimes list products
                more broadly than the flaw warrants, a catalogue entry can describe a
                different edition or configuration than yours, and an exploitation
                report can be mistaken or later retracted. Treat every record as a
                lead to verify, not a finding.
              </p>
            </div>

            <div className="tp-card">
              <h3>False negatives are expected</h3>
              <p>
                A vulnerability absent from ThreatPulse is not a vulnerability that
                does not exist. Coverage depends entirely on what the sources
                publish, and sources do not cover everything: an unlisted flaw, a
                privately reported one, a product no feed tracks, or a disclosure
                falling between two publications all produce silence. Absence of a
                record carries no meaning.
              </p>
            </div>

            <div className="tp-card">
              <h3>Coverage is not uniform across sources</h3>
              <p>
                Most sources contribute very little to the published set, and some
                contribute nothing at all. Three reasons, all stated on the{' '}
                <Link to="/sources">Sources page</Link>: a feed can fail or need
                credentials it does not have; an advisory can describe a product or a
                campaign without naming a CVE, in which case there is nothing to
                correlate it to; and an observation that does name a CVE still has to
                carry evidence the scoring model can use before a threat is published
                at all.
              </p>
            </div>

            <div className="tp-card">
              <h3>Only clear-marked material is ingested</h3>
              <p>
                ThreatPulse imposes a traffic-light restriction on itself: only
                material marked TLP:CLEAR — or its predecessor TLP:WHITE — is
                ingested, stored or published. Anything marked GREEN, AMBER or RED is
                refused, and the refusal is enforced at ingest and again before
                publication. This is a deliberate limit: it makes the product safe to
                publish openly, and it means a genuinely useful restricted advisory
                is knowingly excluded.
              </p>
            </div>

            <div className="tp-card">
              <h3>Feed freshness varies, and lag is invisible</h3>
              <p>
                Sources update on their own schedules — some continuously, some
                daily, some monthly. A threat reflects what a feed said when it was
                last read, not necessarily what it says now. Publication timestamps
                are shown so the age is visible, but the lag between an event
                happening and a feed describing it is not measurable from here.
              </p>
            </div>

            <div className="tp-card">
              <h3>Confidence describes evidence, not probability</h3>
              <p>
                Confidence is a label on the evidence, not a statistical
                probability and not a measure of risk to you. It is driven by what
                the sources state: a record in the CISA KEV catalogue, or one
                reported as exploited in the wild, can reach “high”; anything else is
                capped at “medium”, however many feeds agree. Corroboration raises
                the priority score, not the confidence level — several feeds
                repeating one advisory are still one claim.
              </p>
            </div>

            <div className="tp-card">
              <h3>Attribution is name matching, not identification</h3>
              <p>
                Where a threat names an actor, a malware family or a technique, that
                is a match against a published vocabulary — it is not an intelligence
                judgement. A name matching two entries returns both rather than
                guessing, and the matched name is shown beside the result so the
                claim can be audited. Naming an actor is not an accusation, and it is
                not evidence that the actor was involved.
              </p>
            </div>

            <div className="tp-card">
              <h3>Automated extraction can be wrong</h3>
              <p>
                Records are parsed, normalised and joined by software. Extraction can
                misread a date, mis-join an identifier, drop a field a source
                published in an unexpected shape, or attribute a statement to the
                wrong record. Known classes of error are handled explicitly and
                reported rather than hidden, but the possibility is inherent to
                aggregating feeds that were not written to a common schema.
              </p>
            </div>

            <div className="tp-card">
              <h3>Publication is periodic, not real-time</h3>
              <p>
                ThreatPulse publishes in runs, not as a stream. There is no real-time
                feed, no push notification and no guaranteed interval between
                publications. A record can be hours old before it appears, and the
                set is replaced wholesale rather than patched.
              </p>
            </div>

            <div className="tp-card">
              <h3>No asset or environment context</h3>
              <p>
                ThreatPulse does not know what you run. It has no inventory, no
                telemetry, no exposure data and no knowledge of your compensating
                controls. It cannot tell you whether a vulnerability is exploitable in
                your environment, whether you are affected, or what to patch first —
                those are judgements only you can make.
              </p>
            </div>

            <div className="tp-card">
              <h3>Scores are heuristic and versioned</h3>
              <p>
                The model is deterministic — the same inputs always produce the same
                score — but it is a heuristic, not a measurement. Weights change as
                the model is revised, the version used is published with each record,
                and two comparable items can legitimately rank differently. A score is
                an ordering aid, not a verdict.
              </p>
            </div>

            <div className="tp-card">
              <h3>Some knowledge is retired</h3>
              <p>
                Where a knowledge base has since revoked or merged an entry — a
                technique ATT&amp;CK has retired, for example — it is published with
                that status visible rather than dropped or presented as current. The
                link may still be sound while the entry itself is superseded.
              </p>
            </div>

            <div className="tp-card">
              <h3>No warranty, no service level, no support</h3>
              <p>
                The service is offered as-is. Sources can change their terms, require
                credentials, rate-limit, break their format or disappear. There is no
                uptime commitment, no support obligation and no guaranteed continuity.
                See the <Link to="/about#disclaimer">terms of use</Link>.
              </p>
            </div>

            <div className="tp-card">
              <h3>It is not a detection system</h3>
              <p>
                ThreatPulse is a reading aid. It does not monitor, block, alert, scan
                or remediate anything, and nothing it publishes should be wired into
                an automated control without independent validation.
              </p>
            </div>
          </div>

          <Notice tone="info" title="Why the limits are stated here">
            <p>
              A threat intelligence product that hides its limits encourages bad
              decisions. ThreatPulse states them so that the intelligence it does
              publish can be trusted at exactly the level it supports.
            </p>
          </Notice>

          <p className="section-footer-link">
            See also: <Link to="/api">API reference</Link> ·{' '}
            <Link to="/sources">Sources</Link> ·{' '}
            <Link to="/threats">Prioritised threats</Link>
          </p>
        </div>
      </section>
    </>
  );
}

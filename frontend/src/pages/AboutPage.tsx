/*
 * About page.
 *
 * Who built ThreatPulse, why, and how — stated plainly and dated. A reader who is
 * deciding whether to trust the numbers should be able to see the person behind
 * them, the engineering discipline behind them, and the licence they are offered
 * under, without having to ask.
 *
 * The author's details are taken from https://www.iliadis.net so the page uses his
 * own words rather than a biography written for him.
 */

import { Link } from 'react-router-dom';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { ExternalLink } from '../components/common/ExternalLink';
import { PageHead } from '../components/common/PageHead';
import { Notice } from '../components/common/Notice';
import { AUTHOR_EDUCATION } from '../lib/constants';
import {
  DISCLAIMER_EFFECTIVE_DATE,
  DISCLAIMER_REQUIRED_TEXT,
  DISCLAIMER_SECTIONS,
  DISCLAIMER_VERSION,
} from '../lib/legal';

export function AboutPage() {
  useDocumentMeta({
    title: 'About — built by Dr. John Iliadis',
    description:
      'Who builds ThreatPulse, why it exists, how it is engineered, and the terms it is offered under.',
    path: '/about',
  });

  return (
    <>
      <PageHead
        eyebrow="About"
        title="Built by Dr. John Iliadis"
        lead="ThreatPulse is a public cyber threat intelligence product. This page states who builds it, why it exists, and how it is engineered — so that anyone reading the numbers can check where they come from."
      />

      <section className="tp-section">
        <div className="container tp-prose">
          <h2>The author</h2>
          <p>
            <strong>Dr. John Iliadis</strong> (Γιάννης Ηλιάδης) is a technology and
            cybersecurity executive based in Athens, Greece, and IT Infrastructure
            Director at TEIRESIAS S.A. He brings more than twenty years of
            technology and cybersecurity leadership across enterprise
            infrastructure, cyber operations, transformation and resilience in
            mission-critical environments.
          </p>
          <p>
            His credentials include PhD, CISSP, CISM, CRISC, C|CISO, COBIT, ITIL and
            CMgr MCMI, and he has served as President of the ISC2 Hellenic Chapter.
          </p>

          <dl className="tp-prose__facts">
            {AUTHOR_EDUCATION.map((entry) => (
              <div key={entry.award}>
                <dt>
                  {entry.year} · {entry.award}
                </dt>
                <dd>{entry.institution}</dd>
              </div>
            ))}
          </dl>

          <p>
            <ExternalLink href="https://www.iliadis.net">
              Full profile, publications and talks at iliadis.net
            </ExternalLink>
          </p>
        </div>
      </section>

      <section className="tp-section">
        <div className="container tp-prose">
          <h2>Why it exists</h2>
          <p>
            Threat intelligence is abundant and prioritisation is scarce. The
            question a security team actually has to answer is not “what
            vulnerabilities exist” but “what deserves attention now, and why”.
            ThreatPulse exists to answer that second question, and to show its work
            while doing it: every score is produced by a published model, and every
            statement is traceable to the feed it came from.
          </p>
          <p>
            Where the product cannot support a claim, it says so rather than filling
            the gap. A source that fails is reported as failed. An assessment the
            model cannot justify is not published at all.
          </p>
        </div>
      </section>

      <section className="tp-section tp-section--alt" id="disclaimer">
        <div className="container tp-prose">
          <p className="eyebrow">Terms of use</p>
          <h2>Legal disclaimer and terms of use</h2>
          <p className="tp-meta tp-meta--small">
            Version {DISCLAIMER_VERSION} · effective {DISCLAIMER_EFFECTIVE_DATE}
          </p>

          <Notice tone="neutral" title="In short">
            <p className="tp-gate__required">{DISCLAIMER_REQUIRED_TEXT}</p>
          </Notice>

          {DISCLAIMER_SECTIONS.map((section) => (
            <div key={section.heading} className="tp-disclaimer__section">
              <h3>{section.heading}</h3>
              {section.paragraphs.map((paragraph) => (
                <p key={paragraph}>{paragraph}</p>
              ))}
              {section.items ? (
                <ul className="tp-list">
                  {section.items.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ))}

          <p className="tp-meta tp-meta--small">
            Reading the Threats and Vulnerabilities pages requires acknowledging
            these terms once. The acknowledgement is stored in your browser only.
          </p>
        </div>
      </section>

      <section className="tp-section">
        <div className="container tp-prose">
          <h2>How it is engineered</h2>
          <p>
            The backend is a Python pipeline on a Linux VM — collect, normalise,
            correlate, enrich, score, quality-gate, publish — writing to a public,
            read-only JSON API. The frontend is React and TypeScript over that API.
          </p>
          <ul className="tp-list">
            <li>
              <strong>Every failure is classified.</strong> A source that fails
              transiently degrades to its last known good snapshot; a source that
              fails with nothing to fall back on is reported as failed, never as
              empty.
            </li>
            <li>
              <strong>Nothing publishes unless it passes a quality gate.</strong>{' '}
              Structure, provenance, handling markings, volume and request size are
              all checked against the exact bytes that would be sent.
            </li>
            <li>
              <strong>Handling markings fail closed.</strong> Only material released
              for unrestricted public use is ingested, per item, with a reason
              recorded for anything rejected.
            </li>
            <li>
              <strong>Secrets never enter the repository or a log.</strong> They live
              in a mode-0600 file outside it, and values are redacted wherever they
              could appear — including inside URLs.
            </li>
            <li>
              <strong>Claims in the repository are checked against the live
              services.</strong> Several have been found wrong — a retired download
              path, where a credential is carried, three feeds that answer a browser
              challenge instead of a document — and each is corrected where it was
              made, with the evidence and the original wording kept. When a source is
              retired the correction moves with it into the deployment notes rather
              than being deleted.
            </li>
          </ul>
          <p className="tp-meta tp-meta--small">
            Engineering evidence is dated rather than continuously restated: at
            2 November 2026 the backend carried 624 automated tests and the frontend
            112, with the PHP API endpoints lint-clean and the published API contract
            verified end to end.
          </p>
        </div>
      </section>

      <section className="tp-section">
        <div className="container tp-prose">
          <h2>Licence</h2>
          <p>
            No licence is declared yet. The intention is for ThreatPulse to be
            open-source, but an intention is not a licence, and claiming “open
            source” without one is a claim a knowledgeable reader will check. A{' '}
            <code>LICENSE</code> file will be added before that claim is made
            anywhere in the product.
          </p>
          <p>
            The intelligence ThreatPulse republishes belongs to its originators.
            Each source is recorded in a public attribution register with its
            provider, licence and terms, and the Sources page states which sources
            are ingested and which are deliberately not.{' '}
            <Link to="/sources">See the sources</Link>.
          </p>
        </div>
      </section>

      <section className="tp-section">
        <div className="container tp-prose">
          <h2>Contact</h2>
          <p>
            For corrections, source suggestions or anything else, use the contact
            details at{' '}
            <ExternalLink href="https://www.iliadis.net">iliadis.net</ExternalLink>.
            Corrections to published intelligence are welcome and are treated as
            defects rather than as opinions.
          </p>
        </div>
      </section>
    </>
  );
}

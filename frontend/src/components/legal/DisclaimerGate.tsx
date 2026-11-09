/*
 * The acknowledgement gate.
 *
 * Wraps the data pages. Until the reader accepts the terms of use, the page's
 * content is replaced by the gate — not merely covered by an overlay — so there is
 * no way to read the data without passing it.
 *
 * The gate is deliberately plain and unavoidable: the required sentence, the short
 * form of the terms, a link to the full statement, and a single button. It does not
 * offer a "continue without accepting" path, because the point is that reading the
 * data requires the acknowledgement.
 */

import { Link } from 'react-router-dom';
import {
  DISCLAIMER_ACKNOWLEDGEMENT,
  DISCLAIMER_REQUIRED_TEXT,
  DISCLAIMER_SUMMARY,
} from '../../lib/legal';

interface DisclaimerGateProps {
  /** What the reader is about to open, named so the gate is not abstract. */
  pageLabel: string;
  onAccept: () => void;
}

export function DisclaimerGate({ pageLabel, onAccept }: DisclaimerGateProps) {
  return (
    <section className="tp-section" aria-labelledby="disclaimer-gate-heading">
      <div className="container tp-container--narrow">
        <div className="tp-card tp-card--gate">
          <p className="eyebrow">Terms of use</p>
          <h1 id="disclaimer-gate-heading">
            Before you open {pageLabel}
          </h1>

          <p className="tp-gate__required">{DISCLAIMER_REQUIRED_TEXT}</p>

          <ul className="tp-list">
            {DISCLAIMER_SUMMARY.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>

          <p className="tp-meta tp-meta--small">
            The full statement, including the limitation of liability, is on the{' '}
            <Link to="/about#disclaimer">About page</Link>. ThreatPulse is an
            independent, non-commercial tool. It is not a substitute for your own
            judgement or for professional advice.
          </p>

          <p className="tp-gate__actions">
            <button
              type="button"
              className="tp-button tp-button--primary"
              onClick={onAccept}
            >
              {DISCLAIMER_ACKNOWLEDGEMENT}
            </button>
          </p>

          <p className="tp-meta tp-meta--small">
            Accepting stores this acknowledgement in your browser only. ThreatPulse
            sets no cookies, has no accounts and records no personal data.
          </p>
        </div>
      </div>
    </section>
  );
}

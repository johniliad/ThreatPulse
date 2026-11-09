/*
 * Site footer.
 *
 * Carries the provenance and scope statements: what the data is, where it
 * comes from, and what ThreatPulse does not yet claim. No fabricated
 * intelligence, no implied authority.
 */

import { Link } from 'react-router-dom';
import { CISA_KEV_URL } from '../../lib/urls';
import { AUTHOR_NAME, AUTHOR_URL, ECOSYSTEM_URL } from '../../lib/constants';

const FOOTER_LINKS = [
  { to: '/threats', label: 'Threats' },
  { to: '/vulnerabilities', label: 'Vulnerabilities' },
  { to: '/sources', label: 'Sources' },
  { to: '/methodology', label: 'Methodology' },
  { to: '/api', label: 'API' },
];

export function SiteFooter() {
  return (
    <footer className="tp-footer">
      <div className="container tp-footer__inner">
        <div className="tp-footer__col">
          <p>
            <strong>ThreatPulse</strong> is a public cyber threat intelligence
            product from the{' '}
            <a
              href={ECOSYSTEM_URL}
              target="_blank"
              rel="noopener noreferrer external"
            >
              iliadis.net
              <span className="visually-hidden"> (opens in a new tab)</span>
            </a>{' '}
            ecosystem. It presents prioritised, source-attributed intelligence
            so that security teams can see what deserves attention now.
          </p>
          <p>
            Current data provenance: many independent sources, each named in the
            register. One of them is the{' '}
            <a
              href={CISA_KEV_URL}
              target="_blank"
              rel="noopener noreferrer external"
            >
              CISA Known Exploited Vulnerabilities catalog
              <span className="visually-hidden"> (opens in a new tab)</span>
            </a>
            . Attribution is provenance, not endorsement.
          </p>
        </div>

        <div className="tp-footer__col">
          <nav className="tp-footer__nav" aria-label="Footer navigation">
            {FOOTER_LINKS.map((link) => (
              <Link key={link.to} to={link.to}>
                {link.label}
              </Link>
            ))}
          </nav>
          <p className="tp-meta tp-meta--small">
            ThreatPulse is an independent product. It is not a national CERT, a
            regulatory authority, or a certification body.
          </p>
        </div>
      </div>

      {/*
        The identity line.
        The dashboard carries the live counts; here the statement is deliberately
        static, because repeating the API calls on every page would cost a request
        per navigation for a line that does not change.
      */}
      <div className="container tp-footer__author">
        <p>
          Built by{' '}
          <a
            href={AUTHOR_URL}
            target="_blank"
            rel="noopener noreferrer external"
          >
            {AUTHOR_NAME}
            <span className="visually-hidden"> (opens in a new tab)</span>
          </a>{' '}
          · Public threat intelligence ·{' '}
          <Link to="/about">About this product</Link>
        </p>
      </div>
    </footer>
  );
}

/*
 * Site header.
 *
 * Deliberately restrained: brand mark, product name, positioning line, and a
 * short primary navigation. The ecosystem link to iliadis.net is the only
 * external link in the header.
 */

import { NavLink } from 'react-router-dom';
import { ECOSYSTEM_LABEL, ECOSYSTEM_URL, PRODUCT_POSITIONING } from '../../lib/constants';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/threats', label: 'Threats', end: false },
  { to: '/vulnerabilities', label: 'Vulnerabilities', end: false },
  { to: '/sources', label: 'Sources', end: false },
  { to: '/api', label: 'API', end: false },
  { to: '/methodology', label: 'Methodology', end: false },
  { to: '/about', label: 'About', end: false },
];

export function SiteHeader() {
  return (
    <header className="tp-header">
      <div className="container tp-header__inner">
        <NavLink className="tp-brand" to="/">
          <span className="tp-brand__mark" aria-hidden="true">
            TP
          </span>
          <span className="tp-brand__name">
            ThreatPulse
            <span className="tp-brand__tagline">{PRODUCT_POSITIONING}</span>
          </span>
        </NavLink>

        <nav className="tp-nav" aria-label="Main navigation">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className="tp-nav__link"
            >
              {item.label}
            </NavLink>
          ))}

          <a
            className="tp-nav__link"
            href={ECOSYSTEM_URL}
            target="_blank"
            rel="noopener noreferrer external"
          >
            {ECOSYSTEM_LABEL}
            <span className="visually-hidden"> (opens in a new tab)</span>
          </a>
        </nav>
      </div>
    </header>
  );
}

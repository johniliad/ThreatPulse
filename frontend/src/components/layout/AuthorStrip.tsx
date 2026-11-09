/*
 * The author strip.
 *
 * One compact band, under the hero and repeated in the footer, answering the four
 * things a first-time visitor decides within a few seconds: who built this, what it
 * is, whether the numbers are real, and where to look next.
 *
 * The counts are read from the API rather than typed in. A hard-coded "1,766
 * threats" is a claim; a number that arrives from the API is evidence, and that
 * difference is the entire reason the strip exists. The engineering evidence — test
 * counts, architecture, licence — lives on the About page with a date, because a
 * number that drifts is worse than no number at all.
 */

import { Link } from 'react-router-dom';
import { usePublications, useSources } from '../../hooks/useResources';
import { formatCount } from '../../lib/format';
import {
  AUTHOR_NAME,
  AUTHOR_URL,
  PRODUCT_LICENCE,
  PRODUCT_REPOSITORY_URL,
} from '../../lib/constants';

export function AuthorStrip() {
  const publications = usePublications({ limit: 1 });
  const sources = useSources({ limit: 1 });

  const latest = publications.data?.items?.[0] ?? null;
  const sourceCount = sources.data?.pagination?.total ?? null;

  const metrics: Array<{ value: number | null; label: string }> = [
    { value: sourceCount, label: 'sources' },
    { value: latest?.threat_count ?? null, label: 'tracked threats' },
    { value: latest?.vulnerability_count ?? null, label: 'vulnerabilities' },
  ];

  const reported = metrics.filter((metric) => metric.value !== null);

  return (
    <section className="tp-author" aria-label="About this product">
      <div className="container tp-author__inner">
        <div className="tp-author__who">
          <p className="tp-author__built">
            Built by{' '}
            <a
              href={AUTHOR_URL}
              target="_blank"
              rel="noopener noreferrer external"
            >
              {AUTHOR_NAME}
              <span className="visually-hidden"> (opens in a new tab)</span>
            </a>{' '}
            ·{' '}
            <span className="tp-author__claim">
              Public threat intelligence
            </span>
            {PRODUCT_LICENCE ? ` · ${PRODUCT_LICENCE}` : ''}
          </p>

          {reported.length > 0 ? (
            <ul className="tp-author__metrics">
              {reported.map((metric) => (
                <li key={metric.label}>
                  <strong>{formatCount(metric.value as number)}</strong>{' '}
                  {metric.label}
                </li>
              ))}
            </ul>
          ) : null}
        </div>

        <nav className="tp-author__links" aria-label="More about this product">
          <Link to="/about">About</Link>
          <Link to="/methodology">Methodology</Link>
          <Link to="/api">API</Link>
          {PRODUCT_REPOSITORY_URL ? (
            <a
              href={PRODUCT_REPOSITORY_URL}
              target="_blank"
              rel="noopener noreferrer external"
            >
              Source
            </a>
          ) : null}
        </nav>
      </div>
    </section>
  );
}

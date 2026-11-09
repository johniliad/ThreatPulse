/*
 * 404 page.
 *
 * Not indexed, and it offers the two most useful next steps rather than a
 * generic error message.
 */

import { Link } from 'react-router-dom';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { PageHead } from '../components/common/PageHead';

export function NotFoundPage() {
  useDocumentMeta({
    title: 'Page not found',
    description: 'The requested ThreatPulse page does not exist.',
    path: '/404',
    noIndex: true,
  });

  return (
    <>
      <PageHead
        eyebrow="404"
        title="That page does not exist"
        lead="The address you followed is not part of ThreatPulse. Nothing was loaded, and no substitute content is shown in its place."
      />

      <section className="tp-section">
        <div className="container tp-stack">
          <p>
            Threat records are addressed by their UUID and are never enumerated
            as individual pages, so a stale or mistyped link will land here.
          </p>
          <p className="tp-entry__actions">
            <Link className="tp-button" to="/">
              Back to the dashboard
            </Link>
            <Link className="tp-button tp-button--secondary" to="/threats">
              Prioritised threats
            </Link>
            <Link className="tp-button tp-button--secondary" to="/vulnerabilities">
              Vulnerability lookup
            </Link>
          </p>
        </div>
      </section>
    </>
  );
}

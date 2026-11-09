/*
 * API reference page.
 *
 * Documents the public contract as it is actually consumed: GET-only, no
 * authentication, paginated, with the CVE capability reported live from the
 * deployment so integrators can see what this instance supports.
 */

import { Link } from 'react-router-dom';
import { API_ENDPOINTS } from '../api/endpoints';
import { getApiBaseUrl } from '../api/client';
import { detectContract } from '../api/validate';
import { useApiIndex, useApiStatus } from '../hooks/useResources';
import { useDocumentMeta } from '../hooks/useDocumentMeta';
import { ErrorState, LoadingState } from '../components/common/StateBlock';
import { Notice } from '../components/common/Notice';
import { PageHead } from '../components/common/PageHead';
import { ExternalLink } from '../components/common/ExternalLink';

const SAMPLE_REQUESTS = [
  'GET /api/cti/v1/threats.php?limit=25&offset=0',
  'GET /api/cti/v1/threats.php?severity=critical&limit=25',
  'GET /api/cti/v1/threats.php?cve=CVE-2026-109619',
  'GET /api/cti/v1/threat.php?uuid={threat_uuid}',
  'GET /api/cti/v1/vulnerabilities.php?cve=CVE-2026-109619',
  'GET /api/cti/v1/sources.php',
  'GET /api/cti/v1/publications.php?limit=10',
  'GET /api/cti/v1/changes.php?kind=added&limit=25',
  'GET /api/cti/v1/source_health.php?status=failed',
];

export function ApiPage() {
  useDocumentMeta({
    title: 'Public CTI API',
    description:
      'The read-only ThreatPulse CTI API: endpoints, parameters, pagination and capabilities, as consumed by this dashboard.',
    path: '/api',
  });

  const status = useApiStatus();
  const index = useApiIndex();
  const contract = detectContract(index.data, []);

  return (
    <>
      <PageHead
        eyebrow="Integrators"
        title="Public CTI API"
        lead="ThreatPulse is a thin client over a public, read-only JSON API. Everything the dashboard shows is available to any integrator under the same contract."
      />

      <section className="tp-section tp-section--tight">
        <div className="container tp-split">
          <div className="tp-stack">
            <Notice tone="neutral" title="Access model">
              <ul>
                <li>
                  Read-only. GET and OPTIONS only; other methods return 405.
                </li>
                <li>No authentication and no API keys.</li>
                <li>
                  One write endpoint exists —{' '}
                  <span className="mono">publish.php</span>, used by the ThreatPulse
                  pipeline — and it is not part of this contract: it requires a bearer
                  token and is restricted by source address.
                </li>
                <li>
                  Responses are cached by the API for 60 seconds (
                  <span className="mono">Cache-Control: public, max-age=60</span>
                  ).
                </li>
                <li>
                  Pagination is server-side; <span className="mono">limit</span>{' '}
                  is capped at 100.
                </li>
                <li>
                  No credentials, tokens or secrets are used by this frontend.
                </li>
              </ul>
            </Notice>

            <div className="tp-card">
              <h2>Base URL</h2>
              <pre className="tp-code">{getApiBaseUrl()}</pre>
              <p className="tp-meta tp-meta--small">
                Relative in this deployment, because the dashboard and the API
                share an origin. An absolute URL is equally valid.
              </p>
            </div>
          </div>

          <div className="tp-stack">
            <div className="tp-card">
              <h2>Service status</h2>
              {status.data ? (
                <dl className="tp-dl">
                  <dt>Status</dt>
                  <dd>{status.data.status}</dd>
                  <dt>Service</dt>
                  <dd className="mono">{status.data.service}</dd>
                  <dt>Version</dt>
                  <dd className="mono">{status.data.version}</dd>
                </dl>
              ) : status.error ? (
                <ErrorState
                  title="Status unavailable"
                  error={status.error}
                  onRetry={status.reload}
                />
              ) : (
                <LoadingState label="Loading API status" lines={2} />
              )}
            </div>

            <div className="tp-card">
              <h2>Capabilities of this deployment</h2>
              {index.data ? (
                <ul className="tp-list">
                  <li>
                    CVE → threat resolution:{' '}
                    <strong>
                      {contract.cveToThreat ? 'supported' : 'not supported'}
                    </strong>
                  </li>
                  <li>
                    Vulnerability → threat relationship:{' '}
                    <strong>
                      {contract.vulnerabilityThreatRelationship
                        ? 'supported'
                        : 'not supported'}
                    </strong>
                  </li>
                  <li>
                    Publication delta feed:{' '}
                    <strong>
                      {contract.publicationDelta ? 'supported' : 'not supported'}
                    </strong>
                  </li>
                  <li>
                    Source health report:{' '}
                    <strong>
                      {contract.sourceHealth ? 'supported' : 'not supported'}
                    </strong>
                  </li>
                  <li>
                    Primary data provenance:{' '}
                    <strong>
                      {index.data.data_provenance?.primary_source ??
                        'not reported'}
                    </strong>
                  </li>
                </ul>
              ) : index.error ? (
                <ErrorState
                  title="Capabilities unavailable"
                  error={index.error}
                  onRetry={index.reload}
                />
              ) : (
                <LoadingState label="Loading API capabilities" lines={2} />
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="tp-section" aria-labelledby="endpoints-heading">
        <div className="container">
          <div className="tp-section__head">
            <div>
              <p className="eyebrow">Contract</p>
              <h2 id="endpoints-heading">Endpoints</h2>
              <p className="section-lead">
                The parameters listed here are the ones this dashboard sends, and
                they match the server-side validation rules.
              </p>
            </div>
          </div>

          <div className="tp-table-wrap">
            <table className="tp-table">
              <caption>
                ThreatPulse public CTI API endpoints and their parameters
              </caption>
              <thead>
                <tr>
                  <th scope="col">Endpoint</th>
                  <th scope="col">Purpose</th>
                  <th scope="col">Parameters</th>
                </tr>
              </thead>
              <tbody>
                {API_ENDPOINTS.map((endpoint) => (
                  <tr key={endpoint.key}>
                    <th scope="row" className="mono">
                      {endpoint.path}
                    </th>
                    <td>
                      {endpoint.summary}
                      <br />
                      <span className="tp-meta tp-meta--small">
                        {endpoint.notes}
                      </span>
                    </td>
                    <td>
                      {endpoint.parameters.length > 0 ? (
                        <ul className="tp-list">
                          {endpoint.parameters.map((parameter) => (
                            <li key={parameter}>
                              <span className="mono">{parameter}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <span className="tp-meta tp-meta--small">None</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="tp-section tp-section--alt">
        <div className="container tp-split">
          <div>
            <h2>Example requests</h2>
            <p className="section-lead">
              These are the exact request shapes used by the dashboard.
            </p>
            <pre className="tp-code">{SAMPLE_REQUESTS.join('\n')}</pre>
          </div>

          <div className="tp-stack">
            <h2>Further reading</h2>
            <ul className="tp-list">
              <li>
                <Link to="/methodology">Methodology</Link> — how the Priority
                Score is produced and what the bands mean.
              </li>
              <li>
                <Link to="/sources">Sources</Link> — provenance of the current
                published set.
              </li>
              <li>
                <ExternalLink href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">
                  CISA Known Exploited Vulnerabilities catalog
                </ExternalLink>{' '}
                — one of the sources behind the current data, and the catalogue
                that supplies the exploitation status.
              </li>
            </ul>
            <Notice tone="neutral">
              <p>
                The API is public but not unlimited. If you integrate with it,
                respect the 60-second cache window and paginate rather than
                requesting the whole dataset.
              </p>
            </Notice>
          </div>
        </div>
      </section>
    </>
  );
}

/*
 * Threat feed row.
 *
 * Answers the product question at row level: how high is the priority, how
 * severe is it, is it being exploited, how confident are we, where did it come
 * from, how fresh is it, and what should be done.
 */

import { Link } from 'react-router-dom';
import type { Threat } from '../../api/types';
import { firstSentence } from '../../lib/format';
import { nvdUrlForCve, threatPath } from '../../lib/urls';
import { ExternalLink } from '../common/ExternalLink';
import { FreshnessIndicator } from '../common/FreshnessIndicator';
import {
  ConfidenceBadge,
  ExploitationBadge,
  SeverityBadge,
} from '../common/Badges';
import { PriorityScore } from './PriorityScore';

interface ThreatCardProps {
  threat: Threat;
  /** 1-based position in the API's priority ordering. */
  rank?: number;
  /** Show the first two backend reasoning statements. */
  showReasoning?: boolean;
}

export function ThreatCard({
  threat,
  rank,
  showReasoning = true,
}: ThreatCardProps) {
  const metadata = threat.metadata;
  const reasoning = metadata?.reasoning ?? [];
  const vendor = metadata?.vendor ?? null;
  const product = metadata?.product ?? null;
  const dueDate = metadata?.due_date ?? null;
  const nvdUrl = nvdUrlForCve(threat.external_id);
  const action = firstSentence(threat.recommended_action);

  const contextParts = [
    vendor && product ? `${vendor} · ${product}` : (vendor ?? product),
    dueDate ? `CISA remediation due ${dueDate}` : null,
  ].filter((part): part is string => Boolean(part));

  return (
    <li className="tp-entry">
      <div className="tp-entry__head">
        <div className="tp-stack tp-stack--tight">
          <p className="tp-meta-row">
            {typeof rank === 'number' ? (
              <span className="tp-badge tp-badge--quiet">#{rank}</span>
            ) : null}
            <SeverityBadge severity={threat.severity} />
            <ExploitationBadge status={threat.exploitation_status} />
            <ConfidenceBadge
              level={threat.confidence_level}
              score={threat.confidence_score}
            />
            {threat.external_id ? (
              <span className="tp-badge tp-badge--quiet mono">
                {threat.external_id}
              </span>
            ) : (
              <span className="tp-badge tp-badge--quiet">
                No external identifier
              </span>
            )}
          </p>

          <h3 className="tp-entry__title">
            <Link to={threatPath(threat.threat_uuid)}>{threat.title}</Link>
          </h3>
        </div>

        <PriorityScore score={threat.priority_score} compact />
      </div>

      {threat.summary ? (
        <p className="tp-entry__summary">{threat.summary}</p>
      ) : null}

      {showReasoning && reasoning.length > 0 ? (
        <div>
          <h4 className="tp-meta tp-meta--small">Why it ranks here</h4>
          <ul className="tp-list">
            {reasoning.slice(0, 3).map((statement) => (
              <li key={statement}>{statement}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {action ? (
        <p className="tp-entry__summary">
          <strong>Recommended action:</strong> {action}
        </p>
      ) : null}

      <div className="tp-entry__footer">
        <span className="tp-meta-row">
          {contextParts.length > 0 ? (
            <span className="tp-meta tp-meta--small">
              {contextParts.join(' · ')}
            </span>
          ) : null}
          <FreshnessIndicator value={threat.last_seen} label="Last seen" />
        </span>

        <span className="tp-entry__actions">
          <Link
            className="tp-button tp-button--quiet tp-button--small"
            to={threatPath(threat.threat_uuid)}
          >
            View intelligence
          </Link>
          {nvdUrl ? (
            <ExternalLink
              className="tp-button tp-button--quiet tp-button--small"
              href={nvdUrl}
            >
              NVD record
            </ExternalLink>
          ) : null}
        </span>
      </div>
    </li>
  );
}

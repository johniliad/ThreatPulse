/*
 * Threat feed.
 *
 * An ordered list because the API already ranks the records: the position in
 * the list is meaningful and is shown as such.
 */

import type { Threat } from '../../api/types';
import { ThreatCard } from './ThreatCard';

interface ThreatFeedProps {
  threats: Threat[];
  /** 1-based index of the first item, so pagination keeps ranking honest. */
  startRank?: number;
  showReasoning?: boolean;
}

export function ThreatFeed({
  threats,
  startRank = 1,
  showReasoning = true,
}: ThreatFeedProps) {
  return (
    <ol className="tp-feed">
      {threats.map((threat, index) => (
        <ThreatCard
          key={threat.threat_uuid}
          threat={threat}
          rank={startRank + index}
          showReasoning={showReasoning}
        />
      ))}
    </ol>
  );
}

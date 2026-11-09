/*
 * Definition list.
 *
 * Used for the evidence panels on the threat detail page, where label/value
 * pairs read better than a table. Null entries are dropped so callers can
 * build the list conditionally without empty rows.
 */

import { Fragment, type ReactNode } from 'react';

export interface DefinitionItem {
  term: string;
  description: ReactNode;
}

interface DefinitionListProps {
  items: Array<DefinitionItem | null>;
  className?: string;
}

export function DefinitionList({ items, className }: DefinitionListProps) {
  const visible = items.filter(
    (item): item is DefinitionItem => item !== null
  );

  if (visible.length === 0) {
    return null;
  }

  return (
    <dl className={className ? `tp-dl ${className}` : 'tp-dl'}>
      {visible.map((item) => (
        <Fragment key={item.term}>
          <dt>{item.term}</dt>
          <dd>{item.description}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

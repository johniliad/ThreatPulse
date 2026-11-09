/*
 * Page head.
 *
 * A single h1 per page, an optional lead paragraph, and an optional actions
 * slot, so every route starts with a clear, consistent hierarchy.
 */

import type { ReactNode } from 'react';

interface PageHeadProps {
  eyebrow?: string;
  title: string;
  lead?: ReactNode;
  actions?: ReactNode;
}

export function PageHead({ eyebrow, title, lead, actions }: PageHeadProps) {
  return (
    <section className="tp-page-head">
      <div className="container">
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1>{title}</h1>
        {lead ? <p>{lead}</p> : null}
        {actions ? <div className="tp-hero__actions">{actions}</div> : null}
      </div>
    </section>
  );
}

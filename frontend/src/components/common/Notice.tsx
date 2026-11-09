/*
 * Notice panel.
 *
 * Used for honest, non-alarming explanations: provenance limits, capability
 * gaps, degraded states. Mirrors the iliadis.net `.notice` treatment.
 */

import type { ReactNode } from 'react';

interface NoticeProps {
  children: ReactNode;
  tone?: 'info' | 'warning' | 'neutral';
  title?: string;
}

export function Notice({ children, tone = 'info', title }: NoticeProps) {
  const toneClass = tone === 'info' ? '' : ` tp-notice--${tone}`;

  return (
    <div className={`tp-notice${toneClass}`}>
      {title ? <h3 className="tp-notice__title">{title}</h3> : null}
      {children}
    </div>
  );
}

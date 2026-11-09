/*
 * Dashboard KPI cards.
 *
 * Every number is an API value (`pagination.total`, or a publication record).
 * Nothing is estimated, extrapolated or hard-coded.
 */

import type { ReactNode } from 'react';
import { formatCount } from '../../lib/format';

interface KpiCardProps {
  label: string;
  value: ReactNode;
  meta?: ReactNode;
  tone?: 'default' | 'accent' | 'critical';
}

export function KpiCard({ label, value, meta, tone = 'default' }: KpiCardProps) {
  const toneClass = tone === 'default' ? '' : ` tp-kpi--${tone}`;

  return (
    <div className={`tp-kpi${toneClass}`}>
      <span className="tp-kpi__label">{label}</span>
      <span className="tp-kpi__value">{value}</span>
      {meta ? <span className="tp-kpi__meta">{meta}</span> : null}
    </div>
  );
}

interface KpiCountCardProps {
  label: string;
  count: number;
  meta?: string;
  tone?: 'default' | 'accent' | 'critical';
}

export function KpiCountCard({
  label,
  count,
  meta,
  tone = 'default',
}: KpiCountCardProps) {
  return (
    <KpiCard
      label={label}
      value={formatCount(count)}
      meta={meta}
      tone={tone}
    />
  );
}

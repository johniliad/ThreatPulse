/*
 * Threat card tests.
 *
 * Covers the information a SOC analyst must be able to read at a glance, plus
 * the guarantee that API text is rendered as text and never as markup.
 */

import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { parseThreat } from '../../api/validate';
import { threatPayload } from '../../api/validate.test';
import { ThreatCard } from './ThreatCard';

const THREAT_UUID = '11111111-1111-4111-8111-111111111111';

function renderCard(overrides: Record<string, unknown> = {}) {
  return render(
    <MemoryRouter>
      <ol>
        <ThreatCard threat={parseThreat(threatPayload(overrides))} rank={1} />
      </ol>
    </MemoryRouter>
  );
}

describe('ThreatCard', () => {
  it('surfaces priority, severity, exploitation status, confidence and identifier', () => {
    renderCard();

    expect(screen.getByText('92.5')).toBeInTheDocument();
    expect(screen.getByText(/Critical band/i)).toBeInTheDocument();
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('Confirmed')).toBeInTheDocument();
    expect(screen.getByText(/High confidence/i)).toBeInTheDocument();
    expect(screen.getByText('CVE-2026-109619')).toBeInTheDocument();
  });

  it('shows the pipeline reasoning so the ranking is explainable', () => {
    renderCard();

    expect(screen.getByText(/Why it ranks here/i)).toBeInTheDocument();
    expect(
      screen.getByText('Listed in the CISA KEV catalog.')
    ).toBeInTheDocument();
  });

  it('links to the threat record', () => {
    renderCard();

    const link = screen.getByRole('link', { name: 'Fixture threat' });

    expect(link).toHaveAttribute('href', `/threats/${THREAT_UUID}`);
  });

  it('renders API text as text, never as markup', () => {
    const { container } = renderCard({
      title: '<img src=x onerror="alert(1)">Suspicious title',
      summary: '<script>alert(2)</script>',
    });

    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(
      screen.getByText('<img src=x onerror="alert(1)">Suspicious title')
    ).toBeInTheDocument();
  });

  it('states when no external identifier is present', () => {
    renderCard({ external_id: null });

    expect(screen.getByText('No external identifier')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /NVD record/i })).toBeNull();
  });

  it('reports a missing last-seen timestamp instead of implying freshness', () => {
    renderCard({ last_seen: null });

    expect(
      screen.getByText(/Last seen: not reported by the API/i)
    ).toBeInTheDocument();
  });
});

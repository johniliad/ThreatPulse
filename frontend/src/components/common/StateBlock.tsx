/*
 * Loading, error and empty states.
 *
 * Every data surface uses these so that the UI is never blank, never shows a
 * stack trace, and never invents fallback intelligence.
 */

import type { ReactNode } from 'react';
import type { ApiError } from '../../api/errors';

interface LoadingStateProps {
  label: string;
  lines?: number;
}

export function LoadingState({ label, lines = 3 }: LoadingStateProps) {
  return (
    <div className="tp-state" role="status" aria-live="polite">
      <p className="visually-hidden">{label}</p>
      <div className="tp-skeleton" aria-hidden="true">
        {Array.from({ length: lines }).map((_, index) => (
          <span
            key={index}
            className={
              index === 0
                ? 'tp-skeleton__line tp-skeleton__line--title'
                : 'tp-skeleton__line'
            }
          />
        ))}
        <span className="tp-skeleton__line tp-skeleton__line--short" />
      </div>
    </div>
  );
}

interface SkeletonListProps {
  label: string;
  count?: number;
}

export function SkeletonList({ label, count = 3 }: SkeletonListProps) {
  return (
    <div role="status" aria-live="polite">
      <p className="visually-hidden">{label}</p>
      <div className="tp-skeleton" aria-hidden="true">
        {Array.from({ length: count }).map((_, index) => (
          <div key={index} className="tp-state">
            <span className="tp-skeleton__line tp-skeleton__line--title" />
            <span className="tp-skeleton__line" />
            <span className="tp-skeleton__line tp-skeleton__line--short" />
          </div>
        ))}
      </div>
    </div>
  );
}

interface ErrorStateProps {
  title: string;
  error: ApiError;
  onRetry?: () => void;
  /** Extra guidance shown under the message. */
  children?: ReactNode;
}

export function ErrorState({
  title,
  error,
  onRetry,
  children,
}: ErrorStateProps) {
  return (
    <div className="tp-state tp-state--error" role="alert">
      <h3>{title}</h3>
      <p>{error.userMessage}</p>
      {error.detail ? (
        <p className="tp-meta tp-meta--small">API message: {error.detail}</p>
      ) : null}
      {children}
      {onRetry ? (
        <button type="button" className="tp-button tp-button--small" onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

interface EmptyStateProps {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}

export function EmptyState({ title, children, action }: EmptyStateProps) {
  return (
    <div className="tp-state" role="status">
      <h3>{title}</h3>
      {children}
      {action}
    </div>
  );
}

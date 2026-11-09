/*
 * External link.
 *
 * The href is validated before use (http/https only). When the value is not a
 * safe URL, the children are rendered as plain text instead of a link, so API
 * data can never become a javascript: or data: target.
 */

import type { ReactNode } from 'react';
import { safeExternalUrl } from '../../lib/urls';

interface ExternalLinkProps {
  href: string | null | undefined;
  children?: ReactNode;
  className?: string;
  /** Rendered when the URL is missing or unsafe. */
  fallback?: ReactNode;
}

export function ExternalLink({
  href,
  children,
  className,
  fallback,
}: ExternalLinkProps) {
  const safeHref = safeExternalUrl(href);

  if (!safeHref) {
    return <>{fallback ?? children ?? null}</>;
  }

  return (
    <a
      className={className}
      href={safeHref}
      target="_blank"
      rel="noopener noreferrer external"
    >
      {children}
      <span className="visually-hidden"> (opens in a new tab)</span>
    </a>
  );
}

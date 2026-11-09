/*
 * Per-route document metadata.
 *
 * The frontend is a static SPA, so titles, descriptions, canonical URLs and
 * social metadata are managed at runtime. The homepage values are also
 * present in index.html so crawlers and link previewers see them without
 * executing JavaScript.
 */

import { useEffect } from 'react';

export const SITE_URL = 'https://threatpulse.iliadis.net';
export const SITE_NAME = 'ThreatPulse';

export interface DocumentMeta {
  /** Page title, without the site suffix. */
  title: string;
  description: string;
  /** Absolute path, for example "/threats". */
  path: string;
  /** Set to true for pages that must not be indexed (for example 404). */
  noIndex?: boolean;
}

function setMetaTag(attribute: 'name' | 'property', key: string, content: string): void {
  let element = document.head.querySelector<HTMLMetaElement>(
    `meta[${attribute}="${key}"]`
  );

  if (!element) {
    element = document.createElement('meta');
    element.setAttribute(attribute, key);
    document.head.appendChild(element);
  }

  element.setAttribute('content', content);
}

function setCanonical(href: string): void {
  let element = document.head.querySelector<HTMLLinkElement>(
    'link[rel="canonical"]'
  );

  if (!element) {
    element = document.createElement('link');
    element.setAttribute('rel', 'canonical');
    document.head.appendChild(element);
  }

  element.setAttribute('href', href);
}

export function useDocumentMeta(meta: DocumentMeta): void {
  const { title, description, path, noIndex = false } = meta;

  useEffect(() => {
    const fullTitle =
      path === '/' ? `${SITE_NAME} | ${title}` : `${title} — ${SITE_NAME}`;
    const canonical = `${SITE_URL}${path}`;

    document.title = fullTitle;

    setMetaTag('name', 'description', description);
    setMetaTag(
      'name',
      'robots',
      noIndex ? 'noindex, follow' : 'index, follow'
    );
    setCanonical(canonical);

    setMetaTag('property', 'og:title', fullTitle);
    setMetaTag('property', 'og:description', description);
    setMetaTag('property', 'og:url', canonical);
    setMetaTag('name', 'twitter:title', fullTitle);
    setMetaTag('name', 'twitter:description', description);
  }, [title, description, path, noIndex]);
}

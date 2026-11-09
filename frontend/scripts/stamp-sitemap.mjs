/*
 * Stamp the sitemap's lastmod dates at build time.
 *
 * A sitemap whose dates never move tells a crawler nothing: it cannot distinguish
 * a page that changed from one that did not. Running this as part of the build
 * means `lastmod` reflects the deploy rather than the day someone last edited the
 * XML by hand.
 *
 * Deliberately dependency-free and non-fatal. A sitemap that cannot be stamped is
 * not a reason to fail a deploy, so a missing file or a read-only filesystem is
 * reported and stepped over.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const sitemapPath = resolve(here, '..', 'public', 'sitemap.xml');

try {
  const xml = readFileSync(sitemapPath, 'utf8');
  const today = new Date().toISOString().slice(0, 10);

  const stamped = xml.replace(
    /<lastmod>[^<]*<\/lastmod>/g,
    `<lastmod>${today}</lastmod>`,
  );

  if (stamped === xml) {
    console.log(`sitemap: lastmod already ${today}`);
  } else {
    writeFileSync(sitemapPath, stamped, 'utf8');
    console.log(`sitemap: lastmod stamped ${today}`);
  }
} catch (error) {
  console.warn(`sitemap: not stamped (${error.message})`);
}

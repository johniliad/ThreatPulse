#!/usr/bin/env node
/*
 * Stamp Subresource Integrity (SRI) hashes into the HTML documents that load
 * build output.
 *
 * The broker that serves a script or a stylesheet decides what runs on the
 * page, so the document should say what it expects the file to be. Without an
 * `integrity` attribute a modified — or substituted — asset is accepted
 * silently; scanners report `<script src>` and `<link rel="stylesheet">`
 * without one, and rightly so.
 *
 * Two documents are covered, and each is stamped from the file on disk rather
 * than from a manifest:
 *
 *   frontend/dist/index.html  the built entry script and stylesheet
 *                             (run by `npm run build`, after `vite build`)
 *   api/index.html            the API documentation page's stylesheet
 *                             (re-run after editing api/docs.css)
 *
 * The hash is SHA-384, base64, as the specification and the browser examples
 * prefer. Only same-origin references are stamped: an absolute URL, `data:` or
 * a protocol-relative path is somebody else's asset and is left alone.
 *
 * `--check` reports what would change without writing, and exits non-zero on a
 * stale or missing hash, so a deploy can be gated on it.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const CHECK = process.argv.includes('--check');
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const TARGETS = [
  {
    label: 'frontend/dist/index.html',
    html: join(repoRoot, 'frontend', 'dist', 'index.html'),
    root: join(repoRoot, 'frontend', 'dist'),
  },
  {
    label: 'api/index.html',
    html: join(repoRoot, 'api', 'index.html'),
    root: join(repoRoot, 'api'),
  },
];

const TAG_PATTERN = /<(?:script|link)\b[^>]*>/gi;
const ATTRIBUTE_PATTERN = /\b([a-z][a-z0-9-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
/* Elements for which the SRI specification defines an integrity attribute. */
const LINK_RELS_WITH_INTEGRITY = new Set(['stylesheet', 'preload', 'modulepreload']);

function parseAttributes(tag) {
  const attributes = new Map();
  let match;

  ATTRIBUTE_PATTERN.lastIndex = 0;
  while ((match = ATTRIBUTE_PATTERN.exec(tag)) !== null) {
    attributes.set(match[1].toLowerCase(), match[2] ?? match[3] ?? '');
  }

  return attributes;
}

function referencedUrl(name, attributes) {
  if (name === 'script') return attributes.get('src') ?? null;

  const rel = (attributes.get('rel') ?? '').toLowerCase().split(/\s+/);
  if (!rel.some((value) => LINK_RELS_WITH_INTEGRITY.has(value))) return null;

  return attributes.get('href') ?? null;
}

function localFile(url, htmlDir, rootDir) {
  const path = url.split(/[?#]/)[0];

  if (!path) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(path)) return null; // https:, data:, ...
  if (path.startsWith('//')) return null;

  return path.startsWith('/') ? join(rootDir, path) : resolve(htmlDir, path);
}

function integrityOf(file) {
  return `sha384-${createHash('sha384').update(readFileSync(file)).digest('base64')}`;
}

function withIntegrity(tag, integrity) {
  let out = tag.replace(/\s+integrity\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');

  // `crossorigin` is what makes the browser check the hash on a fetch that is
  // already CORS-enabled; add it only when the tag does not carry it.
  const cors = /\scrossorigin(?=[\s/>=])/i.test(out) ? '' : ' crossorigin="anonymous"';

  return out.replace(/\s*(\/?)>$/, (_match, slash) =>
    slash
      ? ` integrity="${integrity}"${cors} />`
      : ` integrity="${integrity}"${cors}>`,
  );
}

function stampTarget(target) {
  if (!existsSync(target.html)) {
    throw new Error(`${target.label} is missing — build the frontend first`);
  }

  const html = readFileSync(target.html, 'utf8');
  const htmlDir = dirname(target.html);
  const results = [];
  let changed = false;

  const stamped = html.replace(TAG_PATTERN, (tag) => {
    const name = /^<([a-z]+)/i.exec(tag)[1].toLowerCase();
    const attributes = parseAttributes(tag);
    const url = referencedUrl(name, attributes);

    if (url === null) return tag;

    const file = localFile(url, htmlDir, target.root);
    if (file === null) return tag; // another origin: not ours to pin

    if (!existsSync(file)) {
      throw new Error(`${target.label}: ${url} is referenced but ${file} does not exist`);
    }

    const integrity = integrityOf(file);
    const already = attributes.get('integrity') === integrity;

    results.push({ url, integrity, already });

    if (already) return tag;

    changed = true;
    return withIntegrity(tag, integrity);
  });

  if (results.length === 0) {
    throw new Error(`${target.label}: no script or stylesheet to pin`);
  }

  if (CHECK) {
    return { results, changed };
  }

  if (changed) {
    writeFileSync(target.html, stamped, 'utf8');
  }

  return { results, changed };
}

try {
  let stale = 0;

  for (const target of TARGETS) {
    const { results, changed } = stampTarget(target);

    const state = changed ? (CHECK ? 'STALE' : 'stamped') : 'up to date';
    console.log(`${target.label}: ${state} (${results.length} reference${results.length === 1 ? '' : 's'})`);

    for (const result of results) {
      console.log(`  ${result.already ? '=' : '+'} ${result.url} ${result.integrity}`);
    }

    if (CHECK && changed) stale += 1;
  }

  if (CHECK && stale > 0) {
    console.error('');
    console.error('stamp-sri: integrity attributes are missing or stale.');
    console.error('  Run `npm run sri` (from frontend/) and commit the result.');
    process.exit(1);
  }
} catch (error) {
  console.error(`stamp-sri: ${error.message}`);
  process.exit(1);
}

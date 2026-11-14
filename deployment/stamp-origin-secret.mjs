#!/usr/bin/env node
/*
 * Stamp the Cloudflare origin secret into the deployable .htaccess files.
 *
 * The header check that restricts this site to Cloudflare is identical in both
 * files that get deployed, and both templates are tracked with a placeholder so
 * the real value never reaches git:
 *
 *   frontend/public/.htaccess  --(vite build)-->  frontend/dist/.htaccess
 *   api/.htaccess              --(this script)--> deployment/build/api/.htaccess
 *
 * Vite copies public/.htaccess to dist/ verbatim, so this script rewrites that
 * copy afterwards and produces the API copy under deployment/build/ (ignored by
 * git). Upload the generated files; never upload the tracked templates — they
 * still contain the placeholder and would lock every visitor out.
 *
 * The secret comes from THREATPULSE_ORIGIN_SECRET, or from
 * threatpulse-secrets/origin-secret.env (same variable name). Neither is in git.
 *
 * Hex only, by design: the value is interpolated into a PCRE inside .htaccess
 * (^...$), so any character with regex meaning — "+" and "/" from base64, "."
 * from a passphrase — would weaken the comparison or break it outright.
 *
 * A missing secret is fatal. A build that cannot enforce the requirement must
 * not produce something that looks deployable. --allow-placeholder exists for
 * local `npm run preview` builds only and leaves the placeholder untouched.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const PLACEHOLDER = '__CF_ORIGIN_SECRET__';
const ENV_VAR = 'THREATPULSE_ORIGIN_SECRET';
const SECRET_PATTERN = /^[0-9a-f]{64}$/i;
const ALLOW_PLACEHOLDER = process.argv.includes('--allow-placeholder');

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

const frontendDist = join(repoRoot, 'frontend', 'dist', '.htaccess');
const apiTemplate = join(repoRoot, 'api', '.htaccess');
const apiOutput = join(repoRoot, 'deployment', 'build', 'api', '.htaccess');

function readSecretFromEnvFile(file) {
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const separator = trimmed.indexOf('=');
    if (separator === -1) continue;
    if (trimmed.slice(0, separator).trim() !== ENV_VAR) continue;

    const value = trimmed
      .slice(separator + 1)
      .trim()
      .replace(/^["']|["']$/g, '');
    if (value) return value;
  }
  return null;
}

function resolveSecret() {
  const fromEnv = (process.env[ENV_VAR] ?? '').trim();
  if (fromEnv) return { value: fromEnv, source: `environment variable ${ENV_VAR}` };

  const envFile = join(repoRoot, 'threatpulse-secrets', 'origin-secret.env');
  if (existsSync(envFile)) {
    const value = readSecretFromEnvFile(envFile);
    if (value) return { value, source: 'threatpulse-secrets/origin-secret.env' };
  }
  return null;
}

function mask(secret) {
  return `${secret.slice(0, 4)}…${secret.slice(-2)} (${secret.length} hex chars)`;
}

function stamp(target, secret) {
  const original = readFileSync(target, 'utf8');
  const relative = target.slice(repoRoot.length + 1).replace(/\\/g, '/');

  if (original.includes(PLACEHOLDER)) {
    writeFileSync(target, original.split(PLACEHOLDER).join(secret), 'utf8');
    return `${relative}: stamped`;
  }

  // No placeholder: either already stamped by an earlier run, or the header
  // check has gone missing from the template. The second case is a silent
  // security regression, so it is an error and not a note.
  if (original.includes('X-Origin-Secret')) {
    return `${relative}: already stamped (unchanged)`;
  }
  throw new Error(`${relative}: no X-Origin-Secret rule found — the template lost the Cloudflare check`);
}

function verify(target, secret) {
  const text = readFileSync(target, 'utf8');
  if (text.includes(PLACEHOLDER)) {
    throw new Error(`${target}: placeholder still present after stamping`);
  }
  if (!text.includes(`RewriteCond %{HTTP:X-Origin-Secret} !^${secret}$`)) {
    throw new Error(`${target}: stamped comparison not found — Apache would refuse every request`);
  }
}

const resolved = resolveSecret();

if (!resolved) {
  if (!ALLOW_PLACEHOLDER) {
    console.error('');
    console.error('stamp-origin-secret: no secret available.');
    console.error('');
    console.error(`  Set ${ENV_VAR} or create threatpulse-secrets/origin-secret.env with:`);
    console.error(`    ${ENV_VAR}=<64 hex characters>`);
    console.error('');
    console.error('  Generate one with:  openssl rand -hex 32');
    console.error('  PowerShell:        -join ((1..64) | ForEach-Object { \'{0:x}\' -f (Get-Random -Maximum 16) })');
    console.error('');
    console.error('  The same value must be set in the Cloudflare Transform Rule');
    console.error('  (Rules > Transform Rules > Modify Request Header > Set static).');
    console.error('');
    console.error('  Local preview only: --allow-placeholder leaves the placeholder in place.');
    process.exit(1);
  }

  console.warn('stamp-origin-secret: WARNING — no secret, placeholder left in place.');
  console.warn('stamp-origin-secret: this build returns 403 for every request once deployed.');
  process.exit(0);
}

const secret = resolved.value;

if (!SECRET_PATTERN.test(secret)) {
  console.error('stamp-origin-secret: the secret is not 64 hex characters.');
  console.error('  The value is used inside a PCRE in .htaccess, so anything outside');
  console.error('  [0-9a-f] can widen or break the comparison. Regenerate it with');
  console.error('  `openssl rand -hex 32` and update the Cloudflare Transform Rule.');
  process.exit(1);
}

try {
  const results = [];

  if (existsSync(frontendDist)) {
    results.push(stamp(frontendDist, secret));
    verify(frontendDist, secret);
  } else {
    results.push('frontend/dist/.htaccess: absent (run `npm run build` first) — skipped');
  }

  mkdirSync(dirname(apiOutput), { recursive: true });
  writeFileSync(apiOutput, readFileSync(apiTemplate, 'utf8'), 'utf8');
  results.push(stamp(apiOutput, secret));
  verify(apiOutput, secret);

  console.log(`stamp-origin-secret: secret ${mask(secret)} from ${resolved.source}`);
  for (const line of results) console.log(`  ${line}`);
  console.log('  upload deployment/build/api/.htaccess, not api/.htaccess');
} catch (error) {
  console.error(`stamp-origin-secret: ${error.message}`);
  process.exit(1);
}

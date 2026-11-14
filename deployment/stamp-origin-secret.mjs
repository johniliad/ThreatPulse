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
 *
 * --check reports where the value would come from, whether it is usable and
 * which files would be written, without writing anything.
 *
 * THREATPULSE_ORIGIN_SECRET_FILE may point at an explicit file, which keeps the
 * value out of the OneDrive-synced repository tree entirely.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const PLACEHOLDER = '__CF_ORIGIN_SECRET__';
const ENV_VAR = 'THREATPULSE_ORIGIN_SECRET';
const SECRET_FILE_VAR = 'THREATPULSE_ORIGIN_SECRET_FILE';
// Only characters that are literal in a PCRE: letters, digits, "-" and "_".
// Anything else would need escaping inside the RewriteCond, so it is refused
// rather than silently producing a weaker or broken comparison. 32 characters
// is the floor for a value that is meant to be unguessable.
const SECRET_PATTERN = /^[A-Za-z0-9_-]{32,128}$/;
const ALLOW_PLACEHOLDER = process.argv.includes('--allow-placeholder');
const CHECK = process.argv.includes('--check');

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

const frontendDist = join(repoRoot, 'frontend', 'dist', '.htaccess');
const apiTemplate = join(repoRoot, 'api', '.htaccess');
const apiOutput = join(repoRoot, 'deployment', 'build', 'api', '.htaccess');

const defaultEnvFile = join(repoRoot, 'threatpulse-secrets', 'origin-secret.env');

function parseEnvFile(file) {
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const separator = trimmed.indexOf('=');
    if (separator === -1) continue;
    if (trimmed.slice(0, separator).trim() !== ENV_VAR) continue;

    return {
      found: true,
      value: trimmed.slice(separator + 1).trim().replace(/^["']|["']$/g, ''),
    };
  }
  return { found: false, value: '' };
}

/**
 * Resolve the secret, or explain precisely why there is none.
 *
 * The empty-value case is separated from the missing-key case on purpose: an
 * empty `THREATPULSE_ORIGIN_SECRET=` line is the most common mistake, and it
 * used to be reported as "no secret available", which reads like the file was
 * not found at all.
 */
function resolveSecret() {
  if (process.env[ENV_VAR] !== undefined) {
    const value = process.env[ENV_VAR].trim();
    return value
      ? { value, source: `environment variable ${ENV_VAR}` }
      : { problem: `${ENV_VAR} is set in the environment but empty` };
  }

  const override = (process.env[SECRET_FILE_VAR] ?? '').trim();
  const file = override || defaultEnvFile;
  const shown = override || 'threatpulse-secrets/origin-secret.env';

  if (!existsSync(file)) return { problem: `${shown} does not exist` };

  const parsed = parseEnvFile(file);
  if (!parsed.found) return { problem: `${shown} has no ${ENV_VAR}= line` };
  if (!parsed.value) {
    return { problem: `${shown}: the ${ENV_VAR}= line exists but is empty — paste the value after the "="` };
  }

  return { value: parsed.value, source: shown };
}
function mask(secret) {
  return `${secret.slice(0, 4)}…${secret.slice(-2)} (${secret.length} chars)`;
}

function stamp(target, secret, dryRun = false) {
  const original = readFileSync(target, 'utf8');
  const relative = target.slice(repoRoot.length + 1).replace(/\\/g, '/');

  if (original.includes(PLACEHOLDER)) {
    if (!dryRun) writeFileSync(target, original.split(PLACEHOLDER).join(secret), 'utf8');
    return `${relative}: ${dryRun ? 'would be stamped' : 'stamped'}`;
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

if (resolved.problem && !ALLOW_PLACEHOLDER) {
  console.error('');
  console.error(`stamp-origin-secret: ${resolved.problem}.`);
  console.error('');
  console.error('  Supply the value in one of these places:');
  console.error(`    environment:          ${ENV_VAR}=<value>`);
  console.error('    threatpulse-secrets/origin-secret.env, one line:');
  console.error(`      ${ENV_VAR}=<value>`);
  console.error(`    or point at a file:   ${SECRET_FILE_VAR}=<path>`);
  console.error('');
  console.error('  Accepted: A-Z a-z 0-9 - _ , 32 to 128 characters. Generate with');
  console.error('    openssl rand -hex 32      (64 hex characters, recommended)');
  console.error('    openssl rand -base64 32   (drop the trailing =, keep - and _)');
  console.error('');
  console.error('  The identical string must be the Cloudflare Transform Rule value');
  console.error('  (Rules, Transform Rules, Modify Request Header, Set static).');
  console.error('');
  console.error('  Local preview only: --allow-placeholder leaves the placeholder in place.');
  process.exit(1);
}

if (resolved.problem) {
  console.warn(`stamp-origin-secret: WARNING — ${resolved.problem}; placeholder left in place.`);
  console.warn('stamp-origin-secret: this build returns 403 for every request once deployed.');
  process.exit(0);
}

const secret = resolved.value;

if (!SECRET_PATTERN.test(secret)) {
  console.error(`stamp-origin-secret: the value is ${secret.length} characters and cannot be used.`);
  console.error('  It is compared inside a PCRE in .htaccess, so only A-Z a-z 0-9 - _');
  console.error('  are accepted, 32 to 128 characters. Standard base64 adds +, / and =,');
  console.error('  and a passphrase adds . or $ — all of which break or weaken the match.');
  console.error('  Regenerate with `openssl rand -hex 32`, then set the same value in the');
  console.error('  Cloudflare Transform Rule.');
  process.exit(1);
}

try {
  const results = [];

  // A missing dist is fatal, not a note: stamping only the API copy would exit 0
  // and leave a placeholder-bearing frontend that looks deployable.
  if (!existsSync(frontendDist)) {
    throw new Error('frontend/dist/.htaccess is missing — run `npm run build` first; an unstamped dist must not be uploaded');
  }

  results.push(stamp(frontendDist, secret, CHECK));
  if (!CHECK) verify(frontendDist, secret);

  if (CHECK) {
    const template = readFileSync(apiTemplate, 'utf8');
    if (!template.includes(PLACEHOLDER)) {
      throw new Error('api/.htaccess carries no placeholder — the template lost the Cloudflare check');
    }
    results.push('deployment/build/api/.htaccess: would be generated from api/.htaccess');
  } else {
    mkdirSync(dirname(apiOutput), { recursive: true });
    writeFileSync(apiOutput, readFileSync(apiTemplate, 'utf8'), 'utf8');
    results.push(stamp(apiOutput, secret));
    verify(apiOutput, secret);
  }

  const prefix = CHECK ? 'CHECK ONLY, nothing written. ' : '';
  console.log(`stamp-origin-secret: ${prefix}value ${mask(secret)} from ${resolved.source}`);
  for (const line of results) console.log(`  ${line}`);
  if (!CHECK) console.log('  upload deployment/build/api/.htaccess, not api/.htaccess');
} catch (error) {
  console.error(`stamp-origin-secret: ${error.message}`);
  process.exit(1);
}
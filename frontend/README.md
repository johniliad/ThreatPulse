# ThreatPulse frontend

Public dashboard for **ThreatPulse — Transparent Cyber Threat Intelligence**.

React + TypeScript + Vite. The production output is a set of static files that can be
deployed to cPanel next to the existing PHP API. There is no Node runtime, no
server-side rendering, no database and no authentication anywhere in this project.

---

## Requirements

- Node.js 20 or newer (development and build only)
- The ThreatPulse public CTI API, reachable at `/api/cti/v1/` on the same origin in
  production

## Commands

```bash
npm install          # install dependencies
npm run dev          # development server on http://localhost:5173
npm run build        # type-check (tsc -b) then produce dist/
npm run preview      # serve the built dist/ locally
npm run typecheck    # type-check only
npm test             # run the unit tests (Vitest)
npm run verify:api        # contract tests against a local PHP + SQLite harness
npm run verify:api:live   # contract tests against the deployed API
```

## Configuration

| Variable | Development | Production | Meaning |
| --- | --- | --- | --- |
| `VITE_API_BASE_URL` | `/api/cti/v1/` | `/api/cti/v1/` | Base URL of the public CTI API |

In development the relative path is served by the Vite proxy declared in
`vite.config.ts`, which forwards `/api` to `https://threatpulse.iliadis.net`.

**The proxy is not optional.** `publications.php` returns no CORS headers, so a
direct cross-origin request from the dev server would be blocked by the browser.
An absolute API URL is supported for other setups.

The Cloudflare origin secret is not a frontend variable: it never reaches the
bundle. It is read at build time only, to stamp `dist/.htaccess` and the API
`.htaccess` — see
[`../requirements/ThreatPulse_Cloudflare_Origin_Restriction.md`](../requirements/ThreatPulse_Cloudflare_Origin_Restriction.md).

## Deployment (cPanel)

1. Put the Cloudflare origin secret in `threatpulse-secrets/origin-secret.env`
   (or export `THREATPULSE_ORIGIN_SECRET`). Tracked files only ever carry the
   `__CF_ORIGIN_SECRET__` placeholder.
2. `npm ci && npm run build` — the build stamps the secret into
   `dist/.htaccess` and `../deployment/build/api/.htaccess`, and fails if the
   secret is missing or malformed.
3. Upload the **contents** of `dist/` to the web root of `threatpulse.iliadis.net`
   (merging with the existing `api/` directory — do not upload `dist/` itself).
4. Upload `../deployment/build/api/.htaccess` to `~/public_html/api/.htaccess`.
   Never upload the tracked `api/.htaccess`: its placeholder would refuse every
   request, Cloudflare included.
5. `dist/.htaccess` handles the SPA rewrite, cache headers and compression, and
   refuses any request that did not arrive through Cloudflare. It never rewrites
   `/api/`.
6. No Node.js, npm, Docker or long-running process is required on the server.

Rollback is a file copy: keep the previous build's contents.

## Project layout

```text
src/
  api/         typed API client: client, endpoints, types, validate, errors
  hooks/       resource hooks, URL-synced filters, document metadata
  components/  layout, common, threat, kpi, vuln
  pages/       dashboard, threats, threat detail, vulnerabilities, sources, api, methodology, 404
  lib/         constants, priority model, formatting, dates, URL safety
  styles/      tokens.css, base.css, components.css
  test/        Vitest setup
```

Design decisions and the discovery record are in
[`DASHBOARD_IMPLEMENTATION_NOTES.md`](./DASHBOARD_IMPLEMENTATION_NOTES.md) — read it as
a dated record of how the frontend was built, not as the current API contract. The
contract itself is documented in [`../api/index.html`](../api/index.html) for humans,
`../api/cti/v1/index.php` for machines, and exercised by `api-tests/`. The delivery
report is in [`FINAL_REPORT.md`](./FINAL_REPORT.md).

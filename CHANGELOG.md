# Changelog

All notable changes to ThreatPulse are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-15

### Fixed

- The `/api` page no longer reports "Capabilities unavailable". The discovery
  document is now requested as `/api/cti/v1/index.php`; the directory form
  (`/api/cti/v1/`) answered `403` under `Options -Indexes` with
  `DirectoryIndex index.html`, and the HTML error page was being reported as an
  invalid contract payload.
- `api/.htaccess` and `deployment/build/api/.htaccess` now set
  `DirectoryIndex index.php index.html`, so the documented base URL
  `/api/cti/v1/` serves the discovery document.
- API client: a non-JSON error body (for example a proxy's HTML `403`) is
  reported as an HTTP error carrying its status, instead of as an
  `invalid-response`, and `403` has its own message.
- `api-tests/verify-api.mjs` probes `index.php` by name, so the contract suite no
  longer reports a deployed enhancement as missing.

### Security

Hardening of the HTTP surface after a passive scan of the deployed site.

- Security headers are set with `Header always set` in both `.htaccess` files,
  so they cover the error documents Apache generates itself — the `403` from the
  `publish.php` allowlist, a `404` — and not only successful responses:
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`,
  `X-Permitted-Cross-Domain-Policies: none`, a `Content-Security-Policy` that
  defines `base-uri`, `form-action` and `frame-ancestors` and contains no
  `'unsafe-inline'`, and `Strict-Transport-Security:
  max-age=31536000; includeSubDomains` on HTTPS responses. The PHP endpoints no
  longer set them a second time; the request-dependent part lives in the new
  `api/cti/v1/http.php`.
- The inline `style` attributes in `index.html` and `api/index.html` are gone
  (a stylesheet class, and `api/docs.css`), so `style-src` needs no
  `'unsafe-inline'`. The `<style>` block on the API documentation page moved to
  that file.
- `Access-Control-Allow-Origin: *` is removed from the read endpoints. An
  `Origin` is echoed only for the product's own hostnames, `Vary: Origin` is
  set, and `Access-Control-Allow-Credentials` is never sent.
  `publications.php` now answers CORS on the same terms as the other endpoints
  instead of sending none.
- `HttpOnly`, `Secure` (over TLS) and `SameSite=Lax` are appended to any
  `Set-Cookie` the origin emits when the script that set it omitted them, and
  PHP's session cookie parameters are hardened before a session can start.
- `frontend/dist/index.html` and `api/index.html` pin their script and
  stylesheet references with SHA-384 Subresource Integrity hashes, stamped by
  `deployment/stamp-sri.mjs` as part of `npm run build`; `npm run sri:check`
  fails on a stale hash.
- `/api/cti/v1` without the trailing slash is answered directly with the
  discovery document instead of a `301` carrying a generated body. `/api` keeps
  its canonical redirect to `/api/`: a directory URL is meant to redirect, and
  Apache's stub body (~290 bytes) is well below the size the scanner rule treats
  as a leak.
- `http.php` is denied as a URL, alongside `db.php`.
- Residual: the Cloudflare Transform Rule still sends
  `Strict-Transport-Security: max-age=0` at the edge, which disables HSTS for
  the host whatever the origin sends. It has to be set to the same max-age, or
  removed, before that finding can clear; see `deployment/DEPLOYMENT.md`. A
  redirect with a large body was not reproducible from the origin either, so any
  remaining report of one points at a redirect added at the edge.

## [1.0.0] - 2026-11-14

First public release.

### Added

- Public dashboard (React 19 + Vite, static build) with threat, vulnerability,
source, methodology and API pages, shareable URLs and no client-side secrets.
- Public read-only API, schema 1.0, under `/api/cti/v1/`: threats, threat,
vulnerabilities, sources, attribution, publications, changes, source_health and
status, with a machine-readable discovery document and an offline contract suite.
- Backend pipeline: 20 collectors, normalisation, correlation, ATT&CK/CAPEC
enrichment, a scored priority model (`threatpulse_priority_v0.3`) and a quality
gate that refuses to transmit an invalid publication.
- 624 backend unit tests, run with `python3 -m unittest discover -s tests -t .`.
- Cloudflare origin restriction: the deployed `.htaccess` files refuse any request
that did not arrive through the edge, with the value stamped at build time so it
never enters git.

### Security

- Write endpoint `publish.php` restricted to an address allowlist and a bearer
token; `db.php` denied outright; read APIs remain public by design.
- Apache-level dot-file deny (`^.\\.(?!well-known)`) asserted by both `.htaccess`
files rather than inherited from the host, with `/.well-known/` kept reachable
for certificate renewal.
- Least-privilege MySQL accounts (read-only and read/write) and secrets held
outside the web root in mode-0600 files.

### Documentation

- `LICENSE` (Apache-2.0), `NOTICE`, `THIRD-PARTY-NOTICES.md` and a served copy of
the runtime notices at `/THIRD-PARTY-NOTICES.txt`.
- `SECURITY.md` for private vulnerability reporting.
- `deployment/DEPLOYMENT.md` covering the origin gate, the stamping step and the
verification matrix; `backend/docs/` for architecture, installation, operations,
publication verification and troubleshooting.

### Known limitations

- The origin gate is a shared static secret: it proves knowledge of a value, not
that the caller is Cloudflare. Cloudflare IP allowlisting or Authenticated Origin
Pulls is the intended next layer.
- No CI pipeline: builds and the origin secret are run and held locally by design.
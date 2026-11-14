# Changelog

All notable changes to ThreatPulse are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
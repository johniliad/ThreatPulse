# ThreatPulse dashboard — implementation notes

> **Status: a dated record, not current documentation.** Sections 3–6 describe the API
> as it was verified on 30 Oct 2026 and are kept exactly as written. Since then:
>
> * `indicators.php` and the whole indicator layer were removed (2 Nov 2026). The
>   product is CVE-keyed; no endpoint returns indicators, and `publications.php` no
>   longer reports `indicator_count`;
> * `changes.php` (the publication delta) and `source_health.php` (per-source run
>   health) were added, with the `publication_delta` and `source_health` capability
>   flags on `index.php`.
>
> The current contract is [`../api/index.html`](../api/index.html) for humans and
> `api/cti/v1/index.php` for machines. This file remains useful for *why* the
> frontend detects capabilities instead of assuming them.

This document records what was discovered before coding, what was reused, what was
changed and why. It is written to be readable by a future maintainer who has only the
repository.

---

## 1. Phase 0 — discovery

### What existed before this work

```text
ThreatPulse/
├── api/cti/v1/          PHP public CTI API (9 files)
├── frontend/            empty directory
├── requirements/        ThreatPulse_Dashboard_Requirements.md (978 lines)
└── ThreatPulse_Dashboard_Development_Plan.md (1007 lines)
```

- **No version control** (`git status` → "not a git repository"). Because the API had
  to be changed, pre-change copies were taken to `api-backups/` before any edit.
- **No package files, assets, HTML or CSS existed** for the frontend, so nothing was
  reused from a previous frontend and nothing was deleted.
- **No local database, and no access to production MySQL** — and none was attempted.
  `api/cti/v1/db.php` reads its credentials from
  `/home/iliadis/threatpulse-secrets/threatpulse-db-config.php`, which exists only on
  the server. That constraint is what motivated the local SQLite harness (§5).
- **PHP 8.5.12 CLI is available locally**, so `php -l` syntax validation and local
  endpoint execution (with the `sqlite3`/`pdo_sqlite` extensions enabled at runtime)
  were both possible.

### API files and their role

| File | Role | Changed? |
| --- | --- | --- |
| `index.php` | service discovery (documentation, capabilities, provenance) | **yes** (additive) |
| `status.php` | health/version | no |
| `threats.php` | prioritised threat list | **yes** (additive) |
| `threat.php` | single threat with relationships | no |
| `vulnerabilities.php` | vulnerability list | **yes** (additive) |
| `sources.php` | sources with threat counts | no |
| `publications.php` | publication history | no |
| `publish.php` | **write endpoint** (publisher token) | no — and the frontend never references it |
| `db.php` | PDO bootstrap from a secrets file | no |

`publish.php` was read only to confirm the database schema (see §4). It is a write
endpoint and is deliberately excluded from the local test harness so it can never be
invoked accidentally.

---

## 2. Phase 1 — iliadis.net design language

The live site and its stylesheet (`https://www.iliadis.net/assets/css/site.css`) were
inspected. The following tokens were extracted and are used **verbatim** in
`src/styles/tokens.css`:

```css
--color-ink:#142b3b; --color-heading:#102a3a; --color-muted:#526675;
--color-paper:#ffffff; --color-canvas:#f3f7f8; --color-border:#dce6e9;
--color-accent:#087e83; --color-accent-strong:#075e65; --color-accent-soft:#e7f4f2;
--color-focus:#8a4b00; --color-focus-ring:#f2c078; --color-danger:#a32d2d;
--space-1..9:.25/.5/.75/1/1.5/2/3/4/5rem;
--content-width:70rem; --reading-width:48rem; --page-gutter:1.5rem;
--radius-control:.25rem; --radius-card:.25rem; --radius-image:.5rem;
--shadow-image:0 12px 32px #19374614;
--focus-outline:3px solid var(--color-focus); --focus-offset:3px;
--breakpoint-narrow:30rem; --breakpoint-tablet:47.5rem;
font-family: system-ui,-apple-system,"Segoe UI",sans-serif; line-height:1.7;
```

Patterns reproduced: 82px header with a 1px bottom border; a 42px solid brand mark; nav
links with 44px minimum height that gain the accent-soft pill on hover and on
`aria-current`; hero on the canvas colour; uppercase `.eyebrow` labels; `h1` clamp
(2.5→4rem) with −0.04em tracking; `h2` clamp (1.75→2.25rem); cards of 1px border +
0.25rem radius on paper; solid accent-strong buttons with 650 weight; entry rows built
from border + radius + paper with the timestamp in the right column; a 4px left-accent
notice; a single-row footer; breakpoints at 47.5rem and 30rem; and a global
`prefers-reduced-motion` override.

**No web fonts** are loaded (the ecosystem uses the system stack), and no icon library
is used — the few icons are inline SVG or typographic marks.

### ThreatPulse-specific extensions (deliberately minimal)

- Type stacks (`--font-sans`, `--font-mono`) for CVE identifiers, UUIDs and API paths.
- A desaturated severity scale and a matching evidence scale. Every badge pairs a
  colour with a **text label** and an `aria-hidden` glyph, so severity is never
  communicated by colour alone.
- Priority band colours, a score bar and factor bars for data density.
- A `--row-padding-*` pair so list density can be tuned in one place.

ThreatPulse therefore reads as a sibling of the ecosystem's other products
(CyberPulse, EU Cyber Incident) rather than a generic SaaS dashboard: light, editorial,
restrained, typographic.

---

## 3. Phase 2 — API reconnaissance (verified against the live API)

Every endpoint was inspected in source **and** exercised live before any UI code was
written. Nothing about the contract is guessed.

| Endpoint | Verified behaviour |
| --- | --- |
| `GET /api/cti/v1/` | 200; `documentation`, `capabilities`, `data_provenance`, `timestamp`. Sets `Access-Control-Allow-Origin: *` but has **no OPTIONS handling**. |
| `GET status.php` | 200 `{status, service:"iliadis-cti-api", version:"0.1.0"}` |
| `GET threats.php` | `limit` (default 50, capped 100), `offset`, `severity` ∈ 5 values, `exploitation_status` ∈ 4 values. Invalid filter → **400** with `allowed_values`. Order: `priority_score DESC, last_seen DESC, id DESC`. Envelope: `data.threats[]`, `pagination{limit,offset,returned,total,has_more}`, `timestamp`. |
| `GET threat.php?uuid=` | **400** missing/malformed UUID, **404** unknown UUID, 200 with `vulnerabilities[]`, `indicators[]`, `sources[]`, `publications[]`. The internal database `id` is stripped. |
| `GET vulnerabilities.php` | `cve` (regex-validated, else 400), `severity`, `kev_listed` (true/false). Order `cve_id DESC`. |
| `GET sources.php` | `source_key`, `source_type` (regex-validated); `threat_count` computed from the relationship table. |
| `GET publications.php` | `limit` (default 20), `offset`; computed `threat_count`, `vulnerability_count`, `indicator_count`. |
| Non-GET | 405 with `Allow: GET, OPTIONS` (except `publications.php`, which has no method guard, and `index.php`). The frontend only ever issues GET. |

### Data reality at the time of writing (30 Oct 2026)

- 1,764 threats; severities present: critical 25, high 837, medium 902; **low and
  informational are both 0**.
- **Every** record has `exploitation_status: "confirmed"`; suspected / unknown /
  not_exploited all return 0.
- 1 source (`cisa_kev`), 1 publication, 0 indicators.
- `cvss_score`, `cvss_vector`, `published_at` and `modified_at` are `null` in the
  published set.
- `metadata` carries `cwes[]`, `vendor`, `product`, `due_date`, `reasoning[]`,
  `cisa_notes`, `score_factors{}`, `score_weights{}`, `scoring_model`,
  `forensic_triage`, `source_attribution{}`, `known_ransomware_campaign_use`.
- A page of 25 threats is ≈65 KB, because `metadata` is large. This is why pagination
  stays strictly server-side.

These facts drive several deliberate UI decisions: filters that currently return
nothing produce real empty states; missing CVSS renders "Not provided"; regional
relevance is presented as not-yet-available rather than inferred.

### Two findings that shaped the architecture

1. **`publications.php` sends no CORS headers** (only `Content-Type`). A direct
   cross-origin call from the dev server is blocked by the browser, so the Vite dev
   proxy is a functional requirement, not a convenience.
2. **Unknown query parameters are silently ignored.** `threats.php?cve=X` returned
   **200 with all 1,764 unfiltered threats**. A frontend that assumed filtering had
   happened would silently present unrelated threats as CVE matches — the worst
   possible failure mode for a CTI product. This is why the frontend implements
   explicit **contract detection** (§6) and never assumes a filter was applied.

---

## 4. Schema confirmation (read-only, no database access)

Table and column names were confirmed from the SQL in `publish.php`, which writes them:

```text
threat_vulnerabilities (threat_id, vulnerability_id, relationship)
vulnerabilities       (id, cve_id, description, cvss_score, cvss_vector, severity,
                       kev_listed, exploited_in_wild, published_at, modified_at,
                       vendor, product, metadata)
threats               (id, threat_uuid, external_id, title, threat_type, severity,
                       priority_score, confidence_score, confidence_level,
                       exploitation_status,
                       first_seen, last_seen, summary, recommended_action, metadata)
sources / threat_sources / publications / publication_threats / indicators / threat_indicators
```

The relationship needed for CVE → threat navigation already existed in
`threat_vulnerabilities`; the gap was purely one of API exposure.

---

## 5. API enhancement (three files, additive only)

Implemented per `ThreatPulse_API_Enhancements_CVE_Threat_Resolution.md`, with
pre-change copies in `api-backups/` (this project has no version control).

### Change A — `threats.php` accepts `cve`

- `$cve` is read, trimmed and uppercased, then validated against
  `/^CVE-\d{4}-\d{4,}$/`; invalid input returns **400**
  `{"status":"error","message":"Invalid CVE identifier."}` before any database work.
- When `cve` is present the query joins `threat_vulnerabilities` and
  `vulnerabilities`, with the predicate `v.cve_id = ?` appended to the existing
  whitelisted `$where[]` array (prepared statements only, no string interpolation of
  request input).
- `COUNT(DISTINCT t.id)` and `SELECT DISTINCT` are used **only** on the CVE path,
  because a threat may be associated with more than one vulnerability.
- The threats table is always aliased as `t`; the non-CVE SQL is otherwise unchanged,
  so existing requests behave exactly as before.
- The response envelope is unchanged: `data.threats[]` + `pagination` + `timestamp`.
- A valid but unmatched CVE returns **200** with an empty `threats[]` — never 404.

### Change B — `vulnerabilities.php` exposes `threats[]`

- After the page query, the page's vulnerability ids are collected and resolved in
  **one batched query** (`WHERE tv.vulnerability_id IN (?,?,…)`, bound with
  `PDO::PARAM_INT`) and grouped in PHP. There is no per-row query, so no N+1 pattern.
- Each vulnerability gains a `threats` array containing exactly the documented fields:
  `threat_uuid`, `external_id`, `title`, `severity`, `priority_score`,
  `confidence_level`, `exploitation_status`.
- Every pre-existing field is untouched.

### Change C — `index.php` discovery

- `capabilities.cve_to_threat: true` and
  `capabilities.vulnerability_threat_relationship: true` were added, together with
  `documentation.threats_by_cve`. Only capabilities that are actually implemented are
  advertised.

### Local verification of the API change

Production MySQL is unreachable from a development machine, so `api-tests/` contains a
harness that copies the endpoints into a temporary directory, swaps `db.php` for a
SQLite fixture (`db-fixture.php`) and serves them with the PHP built-in server
(`publish.php` is excluded so a write endpoint can never be invoked).

```bash
node api-tests/verify-api.mjs                                  # local harness
node api-tests/verify-api.mjs --base https://threatpulse.iliadis.net/api/cti/v1/   # deployed
```

22 data-independent assertions cover: the existing envelope, severity/exploitation
filters and ordering (regression safety), CVE validation, SQL-injection rejection,
uppercase normalisation, empty-CVE backward compatibility, pagination with a CVE
filter, deduplication, multi-threat resolution, cross-endpoint consistency between
`vulnerabilities.php` and `threats.php?cve=`, discovery, and `threat.php` /
`vulnerabilities.php` regressions.

```text
22 passed, 0 failed   (local PHP + SQLite fixture)
```

Against the deployed API the same runner **skips** the capability-dependent
assertions (11 passed, 0 failed, 11 skipped) and prints the pre-flight evidence
plus the exact upload checklist. Skipping rather than failing is deliberate: the
pre-enhancement API silently ignores unknown query parameters, so treating "not
deployed yet" as a failure would report a target state as a code defect — and
previously produced misleading downstream errors such as
`Cannot read properties of undefined`. `--require-contract` turns skipped
assertions into failures for CI use once the enhancement is expected to be live.
An earlier revision of the matrix could also pass some CVE assertions
*spuriously* against the unfiltered API; that weakness was found and fixed too,
so the runner now produces neither a false pass nor a false failure.

### Frontend consequence: contract detection

Because the old API silently ignored `cve`, the frontend detects the contract before
offering CVE navigation:

- `vulnerabilities.php` rows carrying a `threats` key (even an empty array) prove the
  relationship is exposed.
- `index.php` capability flags are a second signal, used for the CVE search field.

Three vulnerability states are rendered distinctly and never conflated:
`undefined` → "this deployment does not expose the relationship";
`[]` → "no ThreatPulse threat is currently associated";
one or more → direct links to each threat record.

---

## 6. Frontend architecture

### Layering

```text
pages → components → hooks → api (endpoints → validate → client) → fetch
                                     ↓
                                   lib (format, dates, priority, urls, constants)
```

- **`api/client.ts`** — the only place `fetch` is called. GET only,
  `credentials: 'omit'`, a 15s timeout, a 60s response cache aligned with the API's own
  `Cache-Control`, and in-flight de-duplication so React StrictMode's double-mount does
  not double the request count. Caller cancellation via `AbortSignal` never cancels the
  shared request, so a navigating component cannot starve the cache.
- **`api/errors.ts`** — an explicit taxonomy: `network`, `timeout`, `aborted`,
  `invalid-request`, `http`, `invalid-response`. Each maps to a specific user message
  and a retryability flag; components never render a raw exception.
- **`api/validate.ts`** — every response is normalised before it reaches a component.
  Structural violations throw `invalid-response`, so malformed payloads are reported as
  "not displayed" rather than rendered as if trustworthy.
- **`hooks/useApiResource.ts`** — one loading/success/error state machine with abort on
  unmount and a `reload()` for retry buttons.
- **`hooks/useFilters.ts`** — filters live in the query string. Serialisation reuses the
  same builders as the shareable links, so the two cannot drift.

### Deliberate decisions

| Decision | Rationale |
| --- | --- |
| Native `fetch`, no data-fetching library | The API is a handful of GETs; a caching library would add weight without changing behaviour. |
| No state-management library | All state is URL state, resource state or component state. |
| No CSS framework; plain CSS + tokens | Keeps the ecosystem's design language intact and the bundle small. |
| `react-router-dom` with a real `.htaccess` rewrite | Real, shareable, canonical URLs instead of hash routing. |
| Hand-written type guards instead of a schema library | Avoids a runtime dependency; the guards are unit-tested. |
| Route-level code splitting | The shell stays small; each page is fetched on demand. |
| Naive timestamps interpreted as UTC | Verified against live data; prevents a viewer's time zone from silently shifting a date. |
| Score bands looked up, never recomputed | The requirement is explicit: the frontend must not calculate a new score. |
| Colour never the sole signal | Every badge carries a text label plus an `aria-hidden` glyph (WCAG 2.2 AA). |

### Accessibility

Skip link; one `main` landmark; route-change focus management (focus moves to `main`
and the page scrolls to top, because an SPA does not do this by itself); `aria-live`
status regions for loading and result counts; `fieldset`/`legend` radio groups; labelled
inputs with `aria-invalid` and `aria-describedby` on validation errors; 44px minimum
touch targets; a single 3px `#8a4b00` focus treatment with a 3px offset; `scope`d table
headers with `caption`s; `prefers-reduced-motion` honoured globally.

### Security

- No `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `new Function` or `document.write`
  anywhere in `src/` (verified by scan).
- All API text is rendered as React text nodes; hostile strings such as
  `<img src=x onerror=…>` are asserted to render as literal text in the tests.
- Outbound links pass through `safeExternalUrl()` (http/https, absolute only), so
  `javascript:` and `data:` values can never become an `href`. External anchors use
  `target="_blank"` with `rel="noopener noreferrer external"`.
- CVE identifiers are validated before they are placed in an NVD path.
- API prose containing URLs is split and linkified; no HTML is produced.
- No secrets, tokens or credentials exist in the frontend; `publish.php` is never
  referenced; no database access of any kind.
- A scan of `dist/` for secret-like strings (`publisher_token`, `password`, `secret`,
  `Bearer`, `DB_PASSWORD`, `mysql:`, `db.php`) returns nothing.

### SEO

Per-route `document.title`, description, canonical URL, `robots` and Open Graph /
Twitter tags via `useDocumentMeta`; the homepage values are also present statically in
`index.html` so crawlers and link previewers see them without executing JavaScript;
`robots.txt` and a `sitemap.xml` covering the six product pages. Individual threat
records are **not** enumerated as pages, and the 404 route is `noindex`.

**Known limitation:** `public/og-image.svg` is a placeholder. Most social platforms do
not render SVG Open Graph images, so it should be replaced with a 1200×630 PNG/JPEG
before launch.

---

## 7. Verification performed

| Check | Command | Result |
| --- | --- | --- |
| PHP syntax | `php -l` on the three changed files | no syntax errors |
| API contract (local, SQLite fixture) | `node api-tests/verify-api.mjs` | **22 passed, 0 failed, 0 skipped** (exit 0) |
| API contract (deployed) | `node api-tests/verify-api.mjs --base …` | 11 passed, 0 failed, **11 skipped** with the "not deployed" state + upload checklist (exit 0) |
| API contract (deployed, strict) | `… --require-contract` | exit 1 while the enhancement is undeployed, as intended for CI |
| Type checking | `npm run build` (`tsc -b`) | clean, zero errors |
| Unit tests | `npm test` | **97 passed** across 7 files |
| Production build | `npm run build` | success; `index.html` 2.93 kB, CSS 19.27 kB (4.10 kB gzip), entry JS 282.92 kB (89.41 kB gzip), page chunks 1–14 kB |
| Dev server + API proxy | `npm run dev`, then requests through the proxy | index 200 with `#root`; `status.php` 200; `threats.php` 200 (`total=1764`); `vulnerabilities.php` 200 with the `threats` key absent (correct pre-deployment detection) |
| Secret scan | `Select-String` over `dist/` | no matches |
| Dangerous-API scan | `Select-String` over `src/` | no matches |
| Build output | `Get-ChildItem dist/` | `.htaccess`, `favicon.svg`, `og-image.svg`, `robots.txt`, `sitemap.xml`, `index.html`, `assets/*` |

Not verifiable from here: a real browser pass (keyboard traversal, screen-reader output,
visual review at each breakpoint) and rendering the deployed build on cPanel. Both
require the deployment step below.

---

## 8. Deployment

1. `cd frontend && npm ci && npm run build`
2. Upload the **contents** of `frontend/dist/` into the web root of
   `threatpulse.iliadis.net`, merging with the existing `api/` directory.
3. Upload the three changed PHP files (`threats.php`, `vulnerabilities.php`,
   `index.php`) to `api/cti/v1/`.
4. Re-run
   `node api-tests/verify-api.mjs --base https://threatpulse.iliadis.net/api/cti/v1/`
   to confirm all 22 assertions pass against production.

`dist/.htaccess` handles the SPA rewrite (never rewriting `/api/`), immutable caching
for hashed assets, revalidation for HTML, security headers for static responses only,
and gzip. A Content-Security-Policy is included as a commented-out line, to be enabled
after confirming the site still works.

Do **not** deploy `api-backups/` or `api-tests/`.

---

## 9. Known limitations

1. **Threat linkage requires the API enhancement to be deployed.** Until then the
   Vulnerabilities page states this explicitly instead of making an empty promise.
2. **Superseded — "single source".** At the time of writing, provenance was the CISA
   KEV catalogue only. It is now 26 ingested sources correlated across feeds, and
   since 1 Nov 2026 the published set also includes vulnerabilities outside the KEV
   catalogue, scored by the universal model (`threatpulse_priority_v0.2`).
4. **Superseded — "filters with no data".** `low` and `informational` severity
   filters now return records: the universal model publishes vulnerabilities the
   KEV-only set could not score. `suspected`/`unknown`/`not_exploited` may still be
   empty.
5. **Superseded — "cvss_score is null throughout".** CVSS is now supplied by CISA
   Vulnrichment, MSRC, Red Hat, OSV and CIRCL where a source states it; it is still
   absent where none does, and the UI reads "Not provided" there.
6. **OG image is SVG** (see §6 SEO).
7. **No end-to-end browser automation** in this repository; route/UX checks were manual
   plus unit tests.
8. **`publications.php` has no method guard and `index.php` has no OPTIONS handler.**
   Not changed here, because the frontend only issues GET and the brief was to keep the
   change additive and minimal. Worth addressing in the next API pass.

---

## 10. Files added or changed

**API (3 changed, backups in `api-backups/`)**

```text
api/cti/v1/threats.php           + cve filter (Change A)
api/cti/v1/vulnerabilities.php   + threats[] relationship (Change B)
api/cti/v1/index.php             + capability discovery (Change C)
```

**API tooling (new)**

```text
api-tests/README.md
api-tests/verify-api.mjs
api-tests/db-fixture.php
api-backups/README.md
api-backups/*.before-*
```

**Frontend (new)** — see `FINAL_REPORT.md` for the complete file list with purposes.





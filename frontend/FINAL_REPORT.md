# ThreatPulse dashboard — final report

> **Superseded in one respect.** Indicator surfaces (`/indicators`, the indicator count
> on the dashboard and the author strip, the "Indicators of compromise" section on a
> threat) were removed on 2 Nov 2026 with the indicator layer itself. The rest of this
> report describes the delivered frontend as it stands.

Delivered: a static React + TypeScript + Vite frontend in `frontend/`, consuming the
existing public PHP CTI API, plus the additive API enhancement required for CVE → threat
navigation.

---

## Implemented

### Product surfaces

| Route | What it does |
| --- | --- |
| `/` | Answers "what deserves attention now?" — live KPI counts, the top 25 threats in the API's priority order with the pipeline's reasoning, publication pulse, data-status panel, and an explicit statement of current scope limits. |
| `/threats` | Server-paginated threat feed with severity, exploitation-status and CVE filters. All filter state lives in the URL. |
| `/threats/:uuid` | Threat record answering, in order: what is it, why it matters, how strong is the evidence, what should be done — with the Priority Score breakdown, backend reasoning, CWE, CVSS, KEV/exploitation status, sources, indicators, publications and source attribution. |
| `/vulnerabilities` | CVE search (validated locally before the request), severity filter, KEV-only filter, and the CVE → ThreatPulse threat navigation with three explicitly distinguished states. |
| `/sources` | Provenance: each source's type, reliability, provider, contributed threat count and official reference. |
| `/api` | Live contract documentation: base URL, service status, **capabilities actually supported by this deployment**, endpoint/parameter tables and sample requests. |
| `/methodology` | The scoring model and weights, the band table, provenance, freshness rules, and a "what this release does not do" section. |
| `*` | A 404 page that offers the two useful next steps and is `noindex`. |

### Cross-cutting behaviour

- **Never fabricates intelligence.** No invented regional relevance, no substitute
  figures, no sample records, no estimated counts.
- **Honest states.** Loading (skeletons), empty (with the reason), error (with a retry
  and the server's own message), and "not reported" for absent fields.
- **Contract detection.** CVE navigation is offered only when the deployed API proves it
  supports it; otherwise the UI says so.
- **Transparent prioritisation.** Score, band, factor values, factor weights and the
  backend's own reasoning are all displayed; the frontend never recomputes a score.

### API enhancement (additive, backward compatible)

- `threats.php?cve={CVE}` — validated, normalised, prepared-statement join, distinct
  counting, unchanged envelope, 400 on invalid input, 200 + empty on no match.
- `vulnerabilities.php` — each record now carries a `threats[]` array, resolved with a
  single batched query (no N+1).
- `index.php` — advertises the new capabilities and documents the new parameter.

---

## Files created / changed

### API — changed (3 files, originals preserved in `api-backups/`)

```text
api/cti/v1/threats.php           + optional cve filter
api/cti/v1/vulnerabilities.php   + threats[] relationship (batched)
api/cti/v1/index.php             + capabilities/documentation
```

Untouched: `db.php`, `status.php`, `threat.php`, `sources.php`, `publications.php`,
`publish.php`.

### API tooling — new (4 files)

```text
api-tests/README.md         how to run the contract verifier
api-tests/verify-api.mjs    22-assertion contract matrix + local PHP/SQLite harness
api-tests/db-fixture.php    SQLite stand-in for db.php with fixed fixture data
api-backups/README.md       rollback instructions and "do not deploy" warning
```

### Frontend — new (73 files, ~7,000 lines of source + ~900 lines of tests)

```text
frontend/
├─ package.json, package-lock.json, tsconfig.json, tsconfig.app.json, tsconfig.node.json
├─ vite.config.ts, index.html, .env.development, .env.production, .gitignore, README.md
├─ DASHBOARD_IMPLEMENTATION_NOTES.md, FINAL_REPORT.md
├─ public/  .htaccess, robots.txt, sitemap.xml, favicon.svg, og-image.svg
└─ src/
   ├─ main.tsx, App.tsx, vite-env.d.ts
   ├─ api/       client.ts (+test), endpoints.ts, errors.ts, types.ts, validate.ts (+test)
   ├─ hooks/     useApiResource.ts, useResources.ts, useFilters.ts, useDocumentMeta.ts
   ├─ components/ common/ (Badges, StateBlock, Pagination, Notice, PageHead,
   │              ExternalLink, LinkifiedText, DefinitionList, FreshnessIndicator)
   │              layout/ (Layout, SiteHeader, SiteFooter)
   │              threat/ (ThreatCard (+test), ThreatFeed, ThreatFilters,
   │              PriorityScore, ScoreFactors)
   │              vuln/ (VulnerabilityCard (+test), CveSearchForm)
   │              kpi/ (KpiGrid)
   ├─ pages/     DashboardPage, ThreatsPage, ThreatDetailPage, VulnerabilitiesPage,
   │             SourcesPage, ApiPage, MethodologyPage, NotFoundPage
   ├─ lib/       constants.ts, priority.ts (+test), format.ts, dates.ts (+test),
   │             urls.ts (+test)
   ├─ styles/    tokens.css, base.css, components.css
   └─ test/      setup.ts
```

Nothing outside `frontend/`, `api-tests/` and `api-backups/` was created or deleted, and
no unrelated file was modified.

---

## Dependencies

**Runtime (3):** `react`, `react-dom`, `react-router-dom`.

| Dependency | Justification |
| --- | --- |
| `react` / `react-dom` | Mandated by the requirements. |
| `react-router-dom` | Real, shareable, canonical URLs with `aria-current` navigation state. Hash routing would have avoided one dependency at the cost of SEO, link sharing and canonical URLs. |

**Development only:** `vite`, `@vitejs/plugin-react`, `typescript`, `vitest`, `jsdom`,
`@testing-library/react`, `@testing-library/user-event`, `@testing-library/jest-dom`,
`@types/react`, `@types/react-dom`. No test dependency ships in the build.

**Deliberately not used:** any state-management library, CSS framework, data-fetching
library, schema-validation library, icon library, chart library, web font or analytics
package.

---

## API endpoints consumed

| Endpoint | Used by |
| --- | --- |
| `GET /api/cti/v1/` (index) | capability detection; `/api` page |
| `GET /api/cti/v1/status.php` | `/api` page service status |
| `GET /api/cti/v1/threats.php` | dashboard feed, `/threats`, KPIs; `cve` filter used by the threat list |
| `GET /api/cti/v1/threat.php?uuid=` | `/threats/:uuid` |
| `GET /api/cti/v1/vulnerabilities.php` | `/vulnerabilities`, KPI count, CVE lookup |
| `GET /api/cti/v1/sources.php` | `/sources`, KPI source count |
| `GET /api/cti/v1/publications.php` | dashboard publication history and latest publication |

Not consumed: `publish.php` (write endpoint). All requests are GET; no authentication is
used or required.

---

## Design

The design language of `iliadis.net` was extracted from its live stylesheet and reused
verbatim: the palette (`#142b3b`, `#102a3a`, `#526675`, `#f3f7f8`, `#dce6e9`, `#087e83`,
`#075e65`, `#e7f4f2`, `#8a4b00`), the 9-step spacing scale, the 70rem content width, the
0.25rem control/card radii, the 3px focus outline with a 3px offset, the 47.5rem/30rem
breakpoints, the `system-ui` font stack, the 82px header, the accent-soft navigation pill,
the uppercase eyebrow, the 1px-border cards and the 4px left-accent notice.

ThreatPulse adds only what the product needs: a desaturated severity/evidence scale, a
Priority Score bar with factor bars, and data-density tokens. It looks like a product from
the same ecosystem rather than a template: light, editorial, typographic, executive — with
no neon, no terminal chrome and no dark "hacker" aesthetic.

Both the header and the footer reinforce the ecosystem relationship, and the footer states
provenance and scope explicitly.

---

## Security

| Check | Result |
| --- | --- |
| Secrets in source or build | none; scan of `dist/` for `publisher_token`, `password`, `secret`, `Bearer`, `DB_PASSWORD`, `mysql:`, `db.php` → no matches |
| Database access from the frontend | none (API only) |
| Write endpoint referenced | no; `publish.php` is never called and is excluded from the test harness |
| Unsafe HTML | no `dangerouslySetInnerHTML` / `innerHTML` / `document.write`; API text is rendered as React text nodes, with a test asserting that `<img src=x onerror=…>` renders as literal text |
| Dynamic code execution | no `eval` / `new Function` |
| External URLs | every outbound link passes `safeExternalUrl()` (absolute http/https only); `javascript:` and `data:` cannot become an `href`; `target="_blank"` pairs with `rel="noopener noreferrer external"` |
| CVE handling | validated against the same regex as the API before being used in a path or query; the API rejects injection attempts with 400 |
| Request surface | GET only, `credentials: 'omit'`, no cookies, no auth headers |
| Error exposure | no stack traces or internal errors are rendered; only the API's own user-facing message |
| API change safety | prepared statements only; no request input is interpolated into SQL; the enhancement is additive |

---

## Accessibility

Target: WCAG 2.2 AA. Implemented: skip link; single `main` landmark; focus moved to `main`
on route change with scroll-to-top; `aria-live` status regions for loading and result
counts; `fieldset`/`legend` for filter groups; labels, `aria-invalid` and
`aria-describedby` on validated inputs; 44px minimum interactive targets; visible 3px focus
ring on every focusable element; severity, exploitation status and confidence always
carry a text label plus an `aria-hidden` glyph, so colour is never the sole signal;
`scope`d table headers with `caption`s; `time` elements with `dateTime`; a global
`prefers-reduced-motion` override; and "opens in a new tab" announcements on external
links.

Verified by: unit tests asserting accessible names and roles, and code review of every
component. **Not yet verified by a real screen reader or automated axe pass** — see
Limitations.

---

## Performance

- Server-side pagination everywhere; KPI counts use `limit=1`.
- No web fonts, no icon font, no chart library; icons are inline SVG or typographic.
- Route-level code splitting.
- A 60-second client cache aligned with the API's `Cache-Control`, plus in-flight
  de-duplication (which also absorbs React StrictMode's double-mount).

Measured production build:

```text
dist/index.html                 2.93 kB   (gzip  0.92 kB)
dist/assets/index-*.css        19.27 kB   (gzip  4.10 kB)
dist/assets/index-*.js        282.92 kB   (gzip 89.41 kB)   ← shell + React + router
per-route chunks                1.1–14.1 kB (gzip 0.6–3.7 kB)
```

Initial payload is therefore ≈94 kB gzipped, and a page of 25 threats from the API is
≈65 kB (dominated by the API's own `metadata` field, which the UI needs for reasoning and
scoring display).

---

## Build

```bash
cd frontend
npm run build        # tsc -b && vite build
```

Result: **success**, zero TypeScript errors, `dist/` produced as listed above. `tsc -b`
runs in the build script, so a type error fails the build rather than being reported
after it.

```bash
npm test             # 97 tests, 7 files — all passing
```

---

## Deployment

Production output: **`frontend/dist/`** — static files only.

1. Upload the contents of `dist/` into the web root of `threatpulse.iliadis.net`,
   merging with the existing `api/` directory.
2. Upload `threats.php`, `vulnerabilities.php` and `index.php` to `api/cti/v1/`.
3. Verify with
   `node api-tests/verify-api.mjs --base https://threatpulse.iliadis.net/api/cti/v1/`.

Requirements on the server: Apache with `mod_rewrite` (already in use by the API), PHP
for the API, and **nothing else** — no Node.js, no npm, no Docker, no application server,
no persistent process, no database for the frontend.

`dist/.htaccess` provides the SPA fallback (never rewriting `/api/`), immutable caching
for hashed assets, revalidation for HTML, static-only security headers and gzip.

---

## Limitations

1. **Threat linkage needs the API enhancement deployed.** Until then the Vulnerabilities
   page states the limitation explicitly rather than showing a broken link.
2. **Superseded — "single source".** At the time of writing, provenance was the CISA
   KEV catalogue only, and multi-feed correlation was roadmap. Both have since
   landed: 26 sources are ingested and correlated, and since 1 Nov 2026
   vulnerabilities outside the KEV catalogue are published too, scored by the
   universal model.
4. **Superseded — "filters that return zero records".** `low` and `informational`
   severities now carry records, because the universal model publishes what the
   KEV-only set could not score. `suspected`/`unknown`/`not_exploited` may still be
   empty.
5. **Superseded — "CVSS is null throughout".** CVSS is now supplied by CISA
   Vulnrichment, MSRC, Red Hat, OSV and CIRCL where a source states it, and remains
   absent where none does.
6. **`og-image.svg` should be replaced with a PNG/JPEG** before launch (social platforms
   do not render SVG Open Graph images).
7. **No automated accessibility audit or real screen-reader pass** was possible in this
   environment; the implementation follows WCAG 2.2 AA practices and unit tests assert
   accessible names and roles, but an axe/Lighthouse pass on the deployed site is still
   advisable.
8. **No end-to-end browser automation** is included (no Playwright/Cypress), to avoid
   adding a heavy test dependency that the requirements did not ask for.
9. **`publications.php` has no HTTP method guard and `index.php` has no OPTIONS handler.**
   Left unchanged deliberately (additive-only brief, frontend issues GET only); worth
   fixing in a future API pass.
10. **The API enhancement cannot be fully verified from a development machine** because
    production credentials live on the server. It is verified by syntax check plus 22
    contract assertions against a SQLite-backed local execution of the real endpoint code.
    Against the deployed API, the verifier reports 11 passed / 0 failed / 11 skipped with
    a "not deployed" state and an upload checklist (use `--require-contract` to make that
    a hard failure in CI). The final proof is the deployed run reporting 0 skipped.

---

## Next step

**Highest-value next enhancement: broaden the collection and correlation pipeline.**

The published set is derived from a single authoritative feed. Adding sources,
correlating them and attributing every statement to the feed it came from is what
deepens the product, and the score model, the threat detail evidence panel and the
methodology page already have a place for the evidence each new source contributes.

Regional relevance was evaluated and **deliberately not built**: the citable evidence
available today would have produced a non-zero regional score on fewer than 1% of
published threats, and a field that is zero almost everywhere states a capability the
product does not have. The fields were removed rather than left at zero.

A close second, and independent of new data, is deploying the CVE enhancement so that
vulnerability → threat navigation becomes live end-to-end.



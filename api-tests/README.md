# api-tests — ThreatPulse API contract verifier

Development-only tooling. **Never deploy this directory to the web root.**

It exists because the production API depends on a secrets file
(`/home/iliadis/threatpulse-secrets/threatpulse-db-config.php`) that is not
available on a development machine, so the endpoints cannot be executed
against MySQL locally.

## What it does

`verify-api.mjs` runs one data-independent contract matrix (24 assertions)
covering:

- the existing `threats.php` envelope, severity/exploitation filters,
  ordering and error responses (regression safety);
- the new optional `cve` filter: validation, uppercase normalisation,
  unmatched CVEs, SQL-injection rejection, pagination, deduplication and
  combination with other filters;
- the new `vulnerabilities.php` `threats[]` relationship, including
  field-level shape and cross-endpoint consistency with
  `threats.php?cve=`;
- `index.php` capability discovery;
- `threat.php` and `vulnerabilities.php` regression checks;
- `changes.php`: that added, changed and unchanged partition the publication,
  that each `kind` returns only its own kind, and that a changed entry names at
  least one field;
- `source_health.php`: per-source shape, status filtering, and that an
  unavailable report is answered rather than errored.

Assertions are structural rather than count-based, so the same matrix is
valid against the local fixture and against production.

## Deployed vs not deployed

Before the matrix runs, the verifier probes the target **behaviourally**:

| Probe | Proves |
| --- | --- |
| `threats.php?cve=not-a-cve` → 400 | the `cve` parameter is implemented and validated |
| `vulnerabilities.php?limit=1` row has `threats` | the relationship is exposed |
| `index.php` `capabilities.cve_to_threat === true` | discovery is updated |
| `changes.php` → 200 with `data.changes` | the delta feed is deployed |
| `source_health.php` → 200 with `data.available` | source health is deployed |

An assertion that needs a capability which is not present is reported as
**`[SKIP]`** with the reason, not as a failure. This distinction matters: the
pre-enhancement API *silently ignores* unknown query parameters, so treating
"not deployed yet" as a failure would report a target state as a code defect
(and previously produced misleading downstream errors such as
`Cannot read properties of undefined`).

The five probes are printed as pre-flight evidence, and the runner lists
exactly which files to upload.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | no real failures (skipped assertions may be present; the state is printed) |
| `1` | at least one genuine assertion failed, **or** `--require-contract` was set and anything was skipped |

Use `--require-contract` in CI once the enhancement is expected to be live, so
a missing deployment fails the pipeline instead of quietly skipping.

## Local mode (no database, no credentials)

```bash
node api-tests/verify-api.mjs
```

It copies the public endpoints into a temporary directory, replaces `db.php`
with `db-fixture.php` (SQLite, seeded with a small fixed data set) and serves
them with the PHP built-in server. `publish.php` is deliberately excluded —
it is a write endpoint and is never part of the public contract.

Expected result: `24 passed, 0 failed, 0 skipped`.

Requirements: Node.js 18+, a PHP CLI binary on `PATH` (or pass `--php <path>`)
with the `sqlite3` and `pdo_sqlite` extensions available. The script enables
both at runtime with `-d extension=...`, so a default PHP build is usually
enough.

## Deployed mode

```bash
node api-tests/verify-api.mjs --base https://threatpulse.iliadis.net/api/cti/v1/
```

Until the updated `threats.php`, `vulnerabilities.php`, `index.php`,
`changes.php` and `source_health.php` are deployed, the capability-dependent
assertions are skipped and the runner prints the upload checklist. Once deployed,
the same command must report `24 passed, 0 failed, 0 skipped`.

## Options

| Option | Effect |
| --- | --- |
| `--base <url>` | verify a deployed API instead of the local harness |
| `--require-contract` | treat skipped assertions as failures (for CI) |
| `--php <path>` | PHP binary to use for the local harness |
| `--keep` | keep the temporary harness directory for inspection |

## Files

| File | Purpose |
| --- | --- |
| `verify-api.mjs` | pre-flight probes, contract matrix and local harness (Node, no dependencies) |
| `db-fixture.php` | SQLite stand-in for `api/cti/v1/db.php`, with fixture data. The database is written to `fixture.sqlite` in the repository root (gitignored); delete that file to force a reseed after changing the fixture. |


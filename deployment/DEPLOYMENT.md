# ThreatPulse — deployment checklist

Exact steps to bring the code in this repository to the servers. Nothing here is
optional unless marked.

| Target | Path | What runs there |
| --- | --- | --- |
| cPanel public API | `~/public_html/api/` | `index.html` (docs) + `.htaccess` (access control) |
| cPanel public API | `~/public_html/api/cti/v1/` | PHP read endpoints + `publish.php` |
| cPanel secrets | `/home/iliadis/threatpulse-secrets/` | DB credentials, publisher token |
| VM backend | `/home/ubnt/ThreatPulse/` | Python collectors, scoring, publication |
| Static frontend | web root | `frontend/dist/` |

---

## 0. cPanel — API documentation and access control (`api/`)

Two files sit at the API root, not inside `cti/v1/`. Both are required.

| File | Purpose |
| --- | --- |
| `api/index.html` | the API documentation page served at `/api/` |
| `api/.htaccess` | keeps the read API public and restricts the write endpoint |

`.htaccess` also sets `Options -Indexes`, so `/api/` no longer exposes a bare
directory listing and serves `index.html` instead.

### What is public and what is not

| Request | Access |
| --- | --- |
| `GET /api/` and `GET /api/cti/v1/` | public |
| every read endpoint (`threats`, `vulnerabilities`, `sources`, `attribution`, `publications`, `changes`, `source_health`, `status`) | public |
| `POST /api/cti/v1/publish.php` | allowlist **and** bearer token |
| `/api/cti/v1/db.php` | denied outright |

The read endpoints must stay public: the React frontend calls them from the
visitor's browser, so any restriction there takes the whole site down for
everyone outside it.

The allowlist on `publish.php`:

```text
10.0.0.0/8
192.168.0.0/16
172.20.0.0/16
johniliadotefiber.fortiddns.com   (forward-dns, currently 85.75.30.118)
```

`Require forward-dns` is deliberate, not `Require host`: `host` matches on reverse
DNS, which the DDNS provider does not maintain, while `forward-dns` resolves the
name and compares the result to the client address. It requires httpd **2.4.19+**
and is documented as the provider for clients "which use a dynamic DNS service".

The rule lives in a `<Files "publish.php">` section, which carries its own
authorization and applies in place of the directory-level public grant. Apache has
only two merge modes for this — replace (the default) or AND — so the section can
only narrow access, never widen it.

### Verify after upload

The endpoints answer with different statuses, which makes the rule self-checking:
a blocked request never reaches PHP, so it cannot return `401`.

```bash
# Blocked address -> 403 from Apache, never 401 from PHP
curl -sS -o /dev/null -w "%{http_code}\n" -X POST \
  https://threatpulse.iliadis.net/api/cti/v1/publish.php

# Allowed address without a token -> 401, i.e. PHP ran and rejected the caller
# (run this from the VM)
curl -sS -o /dev/null -w "%{http_code}\n" -X POST \
  https://threatpulse.iliadis.net/api/cti/v1/publish.php

# Anywhere -> 200, the read API is still public
curl -sS -o /dev/null -w "%{http_code}\n" \
  "https://threatpulse.iliadis.net/api/cti/v1/threats.php?limit=1"

# Anywhere -> 403, db.php is not reachable
curl -sS -o /dev/null -w "%{http_code}\n" \
  https://threatpulse.iliadis.net/api/cti/v1/db.php
```

A `401` from a disallowed address means the restriction is not taking effect. A
temporary publish outage with `403` means the VM's egress address no longer
matches — check that the DDNS record is current.

If httpd rejects `forward-dns` (symptom: **500** on the entire API, with
`Invalid command 'Require'` or `unknown provider` in the error log), pin the
address instead and re-check it when the DDNS changes:

```apache
Require ip 85.75.30.118
```


---

## 1. cPanel — public API (`api/cti/v1/`)

| File | Status | Notes |
| --- | --- | --- |
| `db.php` | **CHANGED** | read/write connection split. Required by *every* endpoint. |
| `publish.php` | **CHANGED** | now uses `threatpulse_db_write()`; also stores `source_health` |
| `threats.php` | unchanged this phase | CVE → threat resolution (`?cve=`) |
| `vulnerabilities.php` | unchanged this phase | `threats[]` per vulnerability |
| `index.php` | **CHANGED** | advertises `changes.php` and `source_health.php` |
| `changes.php` | **NEW** | the delta against the previous publication |
| `source_health.php` | **NEW** | per-source run health |
| `threat.php`, `sources.php`, `publications.php`, `status.php` | unchanged | upload only if missing |

Upload `threats.php`, `vulnerabilities.php` and `index.php` too if you have not
already, otherwise the live contract check reports skips. Backups of the
pre-change files are in `api-backups/`.

### Verify immediately after upload

`db.php` fails closed: if a secrets file is unreadable or malformed, **every**
endpoint returns HTTP 500. Check at once:

```bash
curl -sS -o /dev/null -w "%{http_code}\n" "https://threatpulse.iliadis.net/api/cti/v1/threats.php?limit=1"
curl -sS -o /dev/null -w "%{http_code}\n" "https://threatpulse.iliadis.net/api/cti/v1/sources.php"
```

Both must be `200`. If they are `500`, check the two new secrets files (mode,
ownership, array keys) — see `deployment/mysql/least_privilege_users.sql`
section 6. `publish.php` is only exercised by a real publish, verified in step 4.

---

## 2. cPanel — secrets

Already done:

* `threatpulse-db-read-config.php` — `tp_read` (SELECT only)
* `threatpulse-db-write-config.php` — `tp_write` (SELECT/INSERT/UPDATE)

Confirm the modes:

```bash
chmod 0600 /home/iliadis/threatpulse-secrets/threatpulse-db-*-config.php
ls -l /home/iliadis/threatpulse-secrets/
```

Keep `threatpulse-db-config.php` in place for now. It is unused once both new
files exist, but keeping it means an instant rollback. Remove it only after a
successful publish.

`publisher-config.php` (the bearer token used by `publish.php`) is unchanged and
still required.

**Outstanding: rotate the publisher token**, then update it in *both* places:

* `/home/iliadis/threatpulse-secrets/publisher-config.php` on cPanel
* `/etc/threatpulse/threatpulse.env` on the VM (`THREATPULSE_PUBLISHER_TOKEN`)

---

## 3. VM — backend (`/home/ubnt/ThreatPulse/`)

> **The service does not run from `/opt/threatpulse`.** The tree is
> `/home/ubnt/ThreatPulse`, owned by `ubnt`, and `threatpulse.service` runs as that
> account from that directory. Earlier revisions of this file described
> `/opt/threatpulse` owned by a dedicated `threatpulse` system account — a stronger
> posture, and what a fresh install elsewhere should use, but not what this host
> runs. Everything below reflects the real host.
>
> Two consequences worth knowing. `ProtectHome=no` is deliberate: the code lives
> under `/home`, and with `ProtectHome=yes` systemd mounts `/home` empty, so the unit
> cannot even reach its own `WorkingDirectory`. And because the units are installed
> verbatim rather than templated, `deployment/install.sh` now fails if its
> `APP_ROOT`/`SERVICE_USER` disagree with the unit file, instead of installing a
> schedule that points at a tree that is not there.

> **The upload must delete, not only overwrite.** A plain copy leaves behind every
> file a release *removed*, and the next `unittest discover` imports them. That is not
> hypothetical: uploading the abuse.ch retirement with `scp`/`cp` left the three
> deleted `tests/` modules in place, and the suite failed with three `ImportError`s
> from normalisers that no longer exist in the repository. Use `rsync -av --delete`
> (with `--exclude state/ --exclude data/ --exclude logs/` so runtime state survives),
> or delete first and copy second.
>
> The suite count is the gate: `python3 -m unittest discover -s tests -t .` must report
> **exactly `Ran 624 tests` and `OK`**. A higher count means orphaned test modules are
> still present; a lower one means files did not arrive.

Upload the whole `backend/` tree. The files that matter:

**New this phase**

| File | Why |
| --- | --- |
| `lib/tlp.py` | TLP classification and fail-closed enforcement |
| `lib/attribution.py` | source/attribution register loader |
| `data/attribution.json` | **required at runtime** — the pipeline refuses to run without it |
| `normalization/rss.py` | RSS/Atom parsing with XML hardening |
| `collectors/rss_feed.py` | generic advisory collector |
| `normalization/epss.py`, `collectors/epss.py` | EPSS scores |
| `normalization/ransomware_live.py`, `collectors/ransomware_live.py` | observed victim aggregates |
| `tests/test_policy_tlp_attribution.py` | policy tests |
| `tests/test_collectors_rss.py` | RSS tests |
| `tests/test_collectors_epss_ransomware.py` | EPSS + ransomware tests |
| `tests/test_pipeline_wiring.py` | registry and publication-gate tests |

**Changed this phase**

| File | Why |
| --- | --- |
| `run_pipeline.py` | collector registry, register check, TLP gate, **and the missing `if __name__ == "__main__"` entry point** |
| `publication/quality_gate.py` | TLP marking scan + source permission check |
| `lib/config.py` | per-source `tier` and `feeds` |
| `config/settings.json` | 22 sources declared, 15 enabled |

**Also upload** if not already present: `lib/{atomic,http,ids,logging_setup}.py`,
`models/intelligence.py`, `collectors/{base,cisa_kev}.py`,
`normalization/cisa.py`, `correlation/engine.py`, `enrichment/base.py`,
`scoring/{priority,confidence}.py`, `publication/builder.py`, `state/store.py`,
`publisher.py`.

**Phase 4a additions** (upload with the rest):

| File | What it adds |
| --- | --- |
| `normalization/csaf.py`, `collectors/cisa_csaf.py` | CISA CSAF advisory trees — replaces the RSS feed, which answers HTTP 403 to server-side clients |
| `normalization/euvd.py`, `collectors/enisa_euvd.py` | ENISA EUVD, the EU-authoritative vulnerability record |
| `normalization/vulnrichment.py`, `collectors/cisa_vulnrichment.py` | CISA SSVC decision points and CISA-assigned CVSS |
| `normalization/exploitdb.py`, `collectors/exploit_availability.py` | Exploit-DB public exploits, matched to the CVEs we track |
| `normalization/redhat.py`, `collectors/redhat_security.py` | Red Hat errata, fix states and a vendor CVSS fallback |
| `normalization/osv.py`, `collectors/osv_dev.py` | OSV affected open-source packages and fixed versions |
| `normalization/circl.py`, `collectors/circl_vulnerability_lookup.py` | CIRCL sightings, counts and dates only |
| `normalization/attack.py`, `collectors/mitre_attack.py`, `enrichment/attack.py` | MITRE ATT&CK as a knowledge base: 867 techniques, 15 tactics, 845 software, 193 groups |
| `collectors/cve_lookup.py` | the shared bounded-lookup algorithm all four dependent sources use |
| `state/record_cache.py` | the shared record cache (replaces `state/vulnrichment_cache.py`) |
| `correlation/engine.py` | the enrichment merge — secondary evidence may fill a CVSS gap and is published per source, never changing a score |
| `config/settings.json`, `run_pipeline.py` | the sources above enabled, registered and ordered |

Per-source cache files are created on first run and are **not** disposable: each is
the accumulated data for that source, re-emitted in full on every run so the
publication snapshot stays complete. Deleting one costs a sweep of re-fetching and
loses nothing else. A normaliser change reaches already-cached records only after
that source's refresh interval, so a payload-shape change is best accompanied by
deleting the corresponding cache file.

**Remove stale artifacts** (demo data, not pipeline output):

```bash
cd /home/ubnt/ThreatPulse
rm -f data/publication.json data/test-record.json threatpulse-publication-v1.0.json
mkdir -p legacy && mv models/publication.py legacy/ 2>/dev/null || true
```

`models/publication.py` is the original reference implementation. Nothing imports
it now, but it documents the identity and scoring behaviour that had to be
reproduced, so archive it rather than delete it.

### Secrets and permissions

```bash
sudo install -m 0600 /dev/null /etc/threatpulse/threatpulse.env
sudo tee /etc/threatpulse/threatpulse.env >/dev/null <<'EOF'
THREATPULSE_PUBLISHER_TOKEN=<the rotated token>
EOF
sudo chown ubnt:ubnt /etc/threatpulse/threatpulse.env
sudo chown -R ubnt:ubnt /home/ubnt/ThreatPulse
```

The publisher token is the only secret the pipeline reads. If
`THREATPULSE_ABUSE_CH_AUTH_KEY` is still in this file from an earlier deployment,
delete the line: the abuse.ch sources were retired on 2 Nov 2026 and nothing reads
that key any more (see *Retired sources* below). Leaving it there is dead
configuration that still has to be protected.

Never put a credential in `settings.json`, a feed URL in the register, a log line,
a state file or an issue. The register records the source and its terms; values
live only in the `0600` environment file.

### Scoring: one model, and the audit trail

Every vulnerability threat is scored by `threatpulse_priority_v0.3`, from the
evidence the group actually holds. Before this, a KEV-derived model
(`threatpulse_priority_v0.1`) scored KEV-listed CVEs, everything else was dropped —
half the correlated intelligence — and the KEV records were scored without EPSS,
CVSS or corroboration because that model predates those sources.

**The first run after this deploy will move published scores.** That is deliberate,
and it is why the audit trail exists: every KEV record also carries
`metadata.legacy_score`, the v0.1 answer, so the change can be checked record by
record and reversed without recomputing anything. Expect the published threat count
to roughly double and the publication to need more chunks.

`state/cve_first_seen.json` is new. It records the first run in which each CVE was
collected — the only date the pipeline owns rather than borrows — and is published as
the `first_seen` scoring factor. It is created on the first run; deleting it only
restarts those dates. On the very first run every CVE is new, so every record takes
the maximum `first_seen` contribution once.

### Change tracking between publications

A publication is a full snapshot, so on its own it cannot say what changed. Two
additions close that:

* **`state/threat_history.json`** records, per threat, when it was first published,
  how many times it has materially changed, and which fields moved. Each threat now
  carries `metadata.temporal` with its `first_published_at`, `revision`, and — when
  something moved — `changed_since_previous`. Only seven named fields count as
  change (severity, score, confidence, exploitation status, source keys, and the
  vulnerability count); retrieval timestamps move on every run and
  are deliberately ignored.
* **`summary.changes`** in each publication: `new`, `changed`, `unchanged`,
  `disappeared`, `pruned`. Entries are kept for 90 days after their last
  publication, so a threat that disappears and returns is recognised as returning
  rather than reported as new.

Both files are created on the first run and are safe to delete — the only effect is
that history restarts. Neither is required for a publication to be valid.

**The publication summary's `title` and `description` changed.** They read
"ThreatPulse CISA KEV Intelligence" and "derived from the CISA Known Exploited
Vulnerabilities Catalog", which stopped being true when the published set became a
multi-source aggregate. The summary is served to every API client, so it now
describes the product and points at the attribution register.

### Chunked publishing

`publication.max_payload_bytes` is **7 MiB** and applies to each **request**, not to
the publication as a whole. A publication larger than that is split by
`publication/chunking.py` and sent as several requests, each under the limit.

The ceiling is deliberately below a common 8 MB `post_max_size`: when a request
body is too large PHP discards it and the API reports an empty request, which is far
harder to diagnose than a refusal before transmission. The first run that carried
bulk infrastructure data produced a 10.5 MB publication, which is the case this
exists for.

Two things to check on the server before the first chunked run:

```bash
php -i | grep -E 'post_max_size|upload_max_filesize|memory_limit|max_input_time'
```

`post_max_size` must be comfortably above 7 MiB, and `max_input_time` /
`max_execution_time` must allow for a request that writes a few thousand rows.

Then confirm the status column can store every status the endpoint writes:

```sql
SHOW COLUMNS FROM publications LIKE 'status';
SELECT status, COUNT(*) FROM publications GROUP BY status;
```

It must be able to hold `receiving`, `published` and `superseded`. An `ENUM` without
`receiving` does **not** fail: a non-strict `sql_mode` truncates it to the empty
string, so chunk 0 stores with a blank status and every later chunk is refused as
"already complete". `VARCHAR(20)` is the safe type — `ENUM` is what caused this:

```sql
ALTER TABLE publications MODIFY COLUMN status VARCHAR(20) NOT NULL DEFAULT 'published';
```

See TROUBLESHOOTING for the full account, including why the affected rows must not be
relabelled `published`.

If a run is interrupted part-way through, the publication is left with
`status = 'receiving'` and appears in `publications.php?include_incomplete=1`. The
default listing returns only completed publications, so a partial row cannot be
mistaken for the published set — its counters cover a fraction of the snapshot.
Nothing needs repairing by hand: the next scheduled run publishes the full snapshot
again under a new `publication_uuid`, and threats are upserted rather than duplicated.

**Deploy `api/cti/v1/publish.php` before the backend that chunks.** An older
`publish.php` ignores the `chunk` block and treats every chunk as its own
publication, so it stores the first chunk and answers the rest with `409` — a
partial publication that looks like a success. The publisher detects exactly that
case and now fails with a message naming it, rather than reporting success, but the
ordering still matters:

1. upload `api/cti/v1/publish.php` to cPanel, and **delete
   `api/cti/v1/indicators.php`** (see *Retired sources*);
2. then upload the backend to the VM.

A publication that fits in one request is unaffected either way, because `chunk` is
optional and absent means a single request.

### Required schema: the attribution register

`publish.php` stores the backend's source register so the public Sources page can
state what the product uses, on what terms, and what it deliberately does not use.
That needs one table:

```sql
CREATE TABLE IF NOT EXISTS source_attribution (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    source_key VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(255) NULL,
    homepage VARCHAR(512) NULL,
    licence TEXT NULL,
    licence_url VARCHAR(512) NULL,
    terms_url VARCHAR(512) NULL,
    tlp_default VARCHAR(32) NULL,
    ingested TINYINT(1) NOT NULL DEFAULT 0,
    attribution_text TEXT NULL,
    tier INT NULL,
    notes TEXT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_source_attribution_key (source_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

If the least-privilege users from `deployment/mysql/least_privilege_users.sql`
are in place, the table also needs its own grants. Those users hold privileges on
**named tables only**, so a table created after that file was applied is invisible
to them — and the failure is easy to misread, because it produces the *same*
response as a missing table:

```sql
GRANT SELECT ON `iliadis_threatpulse`.`source_attribution`                 TO 'tp_read'@'localhost';
GRANT SELECT, INSERT, UPDATE ON `iliadis_threatpulse`.`source_attribution` TO 'tp_write'@'localhost';
FLUSH PRIVILEGES;
```

Both cases report `attribution_stored: false` (from `publish.php`) or `stored:
false` (from `attribution.php`). The difference is only in the PHP error log:

* `INSERT command denied to user 'tp_write'@'localhost' for table
  'source_attribution'` — the grants above are missing;
* `Base table or view not found` — this DDL has not been applied.

This table is **optional but recommended**. Publishing works without it — the
register is provenance *about* the product, not intelligence *in* it, and refusing
to publish the intelligence because a reference table is missing would be a
disproportionate failure. When it is absent:

* `publish.php` logs the failure and reports `"attribution_stored": false` in its
  response, so the absence is visible rather than silent;
* `attribution.php` reports `"stored": false` with a message naming this section,
  rather than returning an empty register that would look like a product with no
  sources.

### Required schema: source health

`source_health.php` reports how each source behaved on the run that produced the
publication being served — `ok`, `degraded` (a retrieval failure that fell back to
a last-known-good snapshot) or `failed`, with the counts that justify the verdict
and the reason where there is one. It reads one column:

```sql
ALTER TABLE publications
    ADD COLUMN source_health LONGTEXT NULL;
```

`#1060 Duplicate column name` means it is already in place — that is the expected
answer on a host where this has been applied before, not a failure. Confirm with
`SHOW COLUMNS FROM publications LIKE 'source_health';` rather than guessing.

The column is nullable and both sides tolerate its absence, so unlike the chunking
change the deployment order does not matter:

* **column missing** — `publish.php` logs `Unknown column 'source_health'`,
  reports `"source_health_stored": false`, and the publication still lands.
  `source_health.php` answers 200 with `"available": false` and an empty source
  list, which is a missing report rather than a broken API;
* **column present, publication predates it** — `"available": false` for that
  publication, and `true` again as soon as one is published by a backend that
  sends health.

No grant is needed. `least_privilege_users.sql` grants on the `publications`
table rather than on individual columns, so `tp_read` and `tp_write` already cover
a column added later.

Why one column and not a table of its own: source health is a per-run snapshot,
always read whole and never joined or filtered in SQL. One row per source would
add a join and a lifecycle to maintain for data that is only ever selected as a
document.

### No schema change for the delta feed

`changes.php` compares the two most recent completed publications through
`publication_threats`, and reads `metadata.temporal.changed_since_previous` — both
written by the backend at publish time. Where nothing recorded a change, nothing
is reported as changed.

### Retired columns: `threats.greece_relevance` and `threats.europe_relevance`

These two columns are **no longer written or read**. Regional relevance was evaluated
and declined — the citable evidence available produced a non-zero score on fewer than
1% of published threats, so the fields were removed rather than published as zero.

Leaving the columns in place is harmless: nothing selects, inserts or validates them.
To drop them, run this once (it is destructive and irreversible, so take a backup
first):

```sql
ALTER TABLE threats
    DROP COLUMN greece_relevance,
    DROP COLUMN europe_relevance;
```

Apply this **after** deploying the updated `publish.php`, `threat.php` and
`threats.php`. Dropping the columns first would break the deployed endpoints, which
still reference them until the new files are in place.

Apply it once, then publish: the backend sends its register with every publication.

---

## 4. Verify on the VM

```bash
cd /home/ubnt/ThreatPulse

# 1. The suite must pass. Expect 624 tests, OK.
python3 -m unittest discover -s tests -t . 2>&1 | tail -5

# 2. A real run that never transmits.
python3 run_pipeline.py --dry-run
```

`--dry-run` is the first live exercise of the pipeline: it fetches every enabled
source, validates, correlates, scores, and writes `data/latest_publication.json`
and `data/run_report.json` without sending anything.

Read `data/run_report.json` and check every source's `status`:

* `ok` — fresh data collected.
* `degraded` — retrieval failed but a previous snapshot was reused. The run
  continues; investigate the feed.
* `failed` — no data and no snapshot. `cisa_kev` is `required`, so this aborts.

```bash
python3 -c "import json;r=json.load(open('data/run_report.json'));[print(f\"{s['source_key']:26} {s['status']:9} {s['observations']:5}\") for s in r['sources']]"
```

Expected on a first run:

* `epss_first` issues roughly 18 batched requests (about 1,764 CVEs from KEV at
  100 per request), so allow a few minutes.
* `cisa_vulnrichment` issues up to 150 requests — one per CVE, bounded by
  `MAX_FETCHES_PER_RUN` — and keeps what it finds in
  `state/vulnrichment_cache.json`. It sweeps the whole KEV catalogue over roughly
  twelve runs. Measured coverage is near-total: every record carries SSVC decision
  points and about 60% carry a CISA-assigned CVSS, which the KEV catalogue itself
  never provides. A second run over the same CVEs makes **no** requests: the cache
  is re-emitted so the published snapshot stays complete.
* `circl_vulnerability_lookup` is declared but has no collector yet. It is
  reported as "no collector implemented" and skipped — **not** counted as a
  failure.

Then publish, only once the dry run looks right:

```bash
python3 run_pipeline.py --publish
```

---

## 5. Verify the published contract

```bash
node api-tests/verify-api.mjs --base https://threatpulse.iliadis.net/api/cti/v1/
```

Expect **24 passed, 0 failed, 0 skipped**. A skip names a capability the target does
not have — the delta feed, source health, the CVE filter, the vulnerability→threat
relationship or the discovery flags — so a skip means one of the files in step 1 is
not uploaded. A failure is a real contract break.

---

## 6. Static frontend

```bash
cd frontend && npm ci && npm run build
# upload the contents of frontend/dist/ to the web root
```

The frontend changed in this phase — the favicon, the priority band reference on the
dashboard, and the scoring and confidence wording on Methodology and About — so
rebuild and re-upload `frontend/dist/` even if it was deployed before.

---

## Rollback

* **API:** restore the pre-change files from `api-backups/`. `db.php` falls back
  to `threatpulse-db-config.php` automatically, so restoring only `db.php` is
  usually enough to undo the privilege split.
* **Backend:** the pipeline replaces `data/latest_publication.json` only after
  the quality gate passes, atomically. A failed run cannot corrupt it. To
  republish an earlier snapshot: `python3 publisher.py <snapshot.json>`.
* Publications are append-only on the API. A bad publication is superseded by
  publishing a corrected one, never by editing history.

---

## 7. Scheduling and operations

```bash
sudo ./deployment/install.sh
```

The installer is idempotent and non-interactive. It uses the account that owns the
tree — `ubnt` on this host — creating it only if it does not already exist, sets
ownership on `state/`, `data/` and `logs/`, prepares
`/etc/threatpulse/threatpulse.env` (**never overwriting an existing one**), runs
the test suite as a gate, installs both systemd units, verifies the pipeline runs
as the service account, and only then starts the timer. It also fails if the
installed unit's paths or account disagree with `APP_ROOT` and `SERVICE_USER`.

It deliberately refuses to start the timer when the publisher token is empty, so a
half-configured host cannot publish a run with no credential.

```bash
sudo ./deployment/install.sh --skip-tests     # schedule without the test gate
sudo ./deployment/install.sh --dry-run-only   # install and verify, do not schedule
```

| | |
| --- | --- |
| Runs | daily at 05:20 UTC, up to 20 minutes of jitter |
| Catches up | `Persistent=true` — a missed run starts shortly after boot |
| User | `ubnt` — the account that owns `/home/ubnt/ThreatPulse`. A dedicated `nologin` system account is the stronger posture and is what a fresh install on another host should use; this host runs from a home directory, which is why `ProtectHome` is relaxed |
| Timeout | `TimeoutStartSec=2700`; systemd's 90-second default for `oneshot` would kill a legitimate run |
| Retries | at most 3 per hour on failure, then waits for the next day |
| Secrets | read by the application from `0600` `/etc/threatpulse/threatpulse.env`. `EnvironmentFile=` is **not** used — it would copy the token into systemd's environment, readable via `/proc/<pid>/environ` |
| Filesystem | `ProtectSystem=strict` with `ReadWritePaths` limited to `state/`, `data/`, `logs/` |
| Network | outbound only (`AF_INET`, `AF_INET6`, `AF_UNIX`); no inbound socket |

```bash
journalctl -u threatpulse.service -f        # watch a run
sudo systemctl start threatpulse.service    # run one now
systemctl list-timers threatpulse.timer     # next scheduled run
sudo systemctl disable --now threatpulse.timer
```

Both units pass `systemd-analyze verify`. If a run fails with a permission or
"failed to execute" error, `MemoryDenyWriteExecute` and `SystemCallFilter` are the
two most restrictive directives and the first to relax — the comment block in the
unit says so.

---

## What still needs building

* **the correlation layer** (`entities` / `entity_links`) — the engine already
  correlates on CVE and vendor/product and supports url/ip/domain/malware/software/
  actor/technique keys, but no collector produces those entities yet and they are
  not persisted. This is where a future indicator or infrastructure feed would
  plug in: the entity keys still exist, only the sources do not;
* **Tier 4 knowledge mappings** — MITRE ATT&CK is ingested as a knowledge base and
  is now doing work: the last published run attached ATT&CK context to 377 threats
  with 1,760 technique references, routed through CIRCL MISP OSINT (which does tag
  events with techniques) and MISP Galaxy's alias bridge. Remaining gap: MISP Galaxy
  contributes aliases only, and the ransomware and threat-actor galaxies carry no
  `external_id`, so they cannot bridge to ATT&CK at all.

**Built since this list was written**: the delta feed (`changes.php`) and the
source-health endpoint (`source_health.php`), both of which travel with the
publication rather than being derived from it.

### Retired sources: the abuse.ch trio and the indicator layer

The three abuse.ch sources — `feodo_tracker`, `threatfox` and `urlhaus` — were
**removed on 2 Nov 2026**, together with the indicator layer they fed. They are gone
from `config/settings.json`, from the attribution register, and from the collectors.
There is nothing to disable: a key that no longer exists cannot be re-enabled by
accident.

**Why they went.** Measured on the live data before deciding:

* the three of them contributed **218 of 3,776 threats (5.8%)**, and every one of
  those was `indicator_cluster` — the only non-CVE object the product published;
* they contributed **11,729 of 11,729 indicators (100%)**; nothing else in the
  catalogue publishes an indicator;
* `feodo_tracker` alone was 7 clusters and roughly a quarter of the indicators, so
  "keep Feodo" was never a coherent middle option: it would have kept 3% of the
  clusters and the entire indicator machinery, the `/indicators` endpoint and the
  documentation for it, alive for 3% of the value.

The product is now a **CVE-keyed vulnerability intelligence** service. Every
published threat is backed by a CVE, and the `indicator_cluster` threat type no
longer exists.

**What was removed, so nothing is left half-alive:**

| Surface | State |
| --- | --- |
| `collectors/{feodo_tracker,threatfox,urlhaus}.py`, `normalization/{feodo,threatfox,urlhaus}.py` | deleted |
| `scoring/indicators.py`, `state/indicator_accumulator.py` | deleted |
| `api/cti/v1/indicators.php` | deleted — **remove it from the server too** |
| `models.Indicator`, `Threat.indicators`, `summary.indicator_count` | removed from the document |
| `publications.indicator_count` in `publications.php` | no longer read |
| `THREATPULSE_ABUSE_CH_AUTH_KEY` | no longer read |

**Remove the endpoint file from cPanel.** `indicators.php` is gone from the
repository, but a deployed copy keeps answering with whatever rows are still in the
table — stale data, presented as current. Delete it:

```bash
# on the cPanel host
rm ~/public_html/api/cti/v1/indicators.php
```

**Clean up the rows.** The API is append-only — `publish.php` never deletes — so the
threats these sources published and their indicators remain in the database and keep
being served by `threats.php` and `threat.php` until they are removed. Run this
**once**, after the new `publish.php` is deployed and a publication has landed:

```sql
-- 1. Links first: the join rows reference both tables.
DELETE ti FROM threat_indicators ti
  JOIN threats t ON t.id = ti.threat_id
  WHERE t.threat_type = 'indicator_cluster';

-- 2. Publication membership, so publication counts stop including them.
DELETE pt FROM publication_threats pt
  JOIN threats t ON t.id = pt.threat_id
  WHERE t.threat_type = 'indicator_cluster';

-- 3. Threat → source links.
DELETE ts FROM threat_sources ts
  JOIN threats t ON t.id = ts.threat_id
  WHERE t.threat_type = 'indicator_cluster';

-- 4. The threats themselves.
DELETE FROM threats WHERE threat_type = 'indicator_cluster';

-- 5. The indicators no longer linked to anything.
DELETE i FROM indicators i
  LEFT JOIN threat_indicators ti ON ti.indicator_id = i.id
  WHERE ti.indicator_id IS NULL;
```

Then, optionally, drop what is now unused. `publish.php` no longer references either
table, so this is safe once the cleanup above has run:

```sql
DROP TABLE IF EXISTS threat_indicators;
DROP TABLE IF EXISTS indicators;
ALTER TABLE publications DROP COLUMN indicator_count;
```

Taking a backup first is cheap and this is irreversible.

**The unrelated half of the same change**: the URLhaus endpoint research, the
Fair Use polling limit and the Auth-Key handling that used to be documented in this
section all went with the sources. `TROUBLESHOOTING.md` no longer has an `abuse.ch
Auth-Key is not configured` entry, because no source can produce that error.



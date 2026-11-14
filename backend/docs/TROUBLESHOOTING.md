# Troubleshooting

Every entry here is a failure that has actually happened on this deployment, in the
order they cost the most time. Reading the exit code first saves the most.

| Exit | Meaning | Start here |
| --- | --- | --- |
| 1 | A stage failed | The `ERROR` line in the log, or the quality-gate message |
| 2 | Configuration invalid | `lib/config.py` names the field it expected |
| 3 | Another run holds the lock | `state/` lock; a killed run releases it on the next start |
| 4 | The API refused the publication | The `Body:` in the log names the reason exactly |

## Publishing

### `HTTP 409` on a later chunk of N

The endpoint answers **three** different 409s and they call for different actions.
The run log now quotes the API's own words, on the line
`publication refused by the API as a duplicate`, with `api_message` and
`api_publication_status`. Read that line before anything else — the status code on
its own cannot tell these apart, and treating them as one cause is what sent several
runs after a stale endpoint when the fault was in the schema.

| `api_message` | Cause | Fix |
| --- | --- | --- |
| `Publication already exists` | The deployed `publish.php` predates chunked publishing: it ignores the `chunk` block, treats each chunk as its own publication and rejects the repeated `publication_uuid` | Upload the current `api/cti/v1/publish.php`, then re-run |
| `Publication is already complete` | The row exists but its status is not `receiving`. Either a late chunk arrived after finalisation, or the status column cannot store `receiving` — the case below | See below |
| `Chunk received before chunk 0` | Chunks were sent out of order, so the request that creates the publication never arrived first | A publisher bug, not a schema one |

**The status column.** This one cost fourteen runs. `publications.status` was
`enum('draft','published','superseded')`, which has no `receiving` member. MySQL in a
non-strict `sql_mode` does not fail on that: it stores the empty string. Chunk 0 then
succeeded with `202` and a blank status, and every later chunk found a status that
was not `receiving` and was refused — while each individual request looked correct.
Confirm it with:

```sql
SHOW COLUMNS FROM publications LIKE 'status';
SELECT status, COUNT(*) FROM publications GROUP BY status;
```

A blank value in the second result is the signature: completed publications carry
`published`, interrupted ones carry nothing. Fix it with:

```sql
ALTER TABLE publications MODIFY COLUMN status VARCHAR(20) NOT NULL DEFAULT 'published';
UPDATE publications SET status = 'superseded' WHERE status = '';
```

`publish.php` now reads the status back inside the transaction and answers `500`
naming the column if the value did not survive, so this cannot pass unnoticed again.

Do **not** relabel those rows as `published`: `changes.php` and `source_health.php`
treat the newest `published` row as their baseline, so a partial publication would
become the baseline for the next delta and report thousands of phantom additions.

### `HTTP 403` on publish

Two requirements refuse a publish, and they look identical to the caller.

**Cause 1 — source address.** `/api/` is restricted by source address
(`api/.htaccess`). Either the VM's egress address is not on the allowlist, or the
dynamic DNS record has not caught up with a changed WAN address.

**Fix.** Compare the VM's public egress with what the DDNS name resolves to. Note
that the private ranges in the allowlist only match traffic arriving from inside
those networks — a request to the public hostname from the same LAN still arrives
with the public source address.

**Cause 2 — the Cloudflare origin gate.** The same file refuses any request that
does not carry the `X-Origin-Secret` header Cloudflare adds. A `403` with a
correct allowlist means the header is missing, or the deployed `.htaccess` holds a
different value than the Cloudflare Transform Rule.

**Fix.** Tell the two apart with a read endpoint: a `403` on
`GET /api/cti/v1/threats.php` affects every visitor, not just the publisher, so it
is the gate and not the allowlist. Check that the Transform Rule action is
**Set static**, then rebuild and upload `deployment/build/api/.htaccess`. Never
upload the tracked `api/.htaccess` — it still contains the
`__CF_ORIGIN_SECRET__` placeholder, which refuses Cloudflare as well. See
[`../../deployment/ORIGIN_RESTRICTION.md`](../../deployment/ORIGIN_RESTRICTION.md).

### `HTTP 401` on publish

The token is missing or wrong. It lives in `/etc/threatpulse/threatpulse.env` on the
VM and `publisher-config.php` on the API host, and the two must match.

### `409` from a *disallowed* address, or `401` from one that should be blocked

That ordering is the diagnostic for the allowlist itself: a blocked request never
reaches PHP, so it cannot return `401`. A `401` from a disallowed address means the
restriction is not taking effect.

## Sources

### `refusing to buffer` / `returned more than N bytes`

**Cause.** The endpoint is not the document we asked for. This is what a wrong route
looks like: not a clean 404, but an enormous body — the retired abuse.ch URLhaus
path behaved exactly this way before it was diagnosed.

**Fix.** Probe the documented URL without a credential. `401` means the route exists
and only the key is missing; `404` means the route is wrong.

### `every <source> lookup was empty`

The pipeline warns because **a wrong lookup path looks identical to a source that
does not cover those CVEs**. Do not assume either. Probe one CVE the source *should*
cover and one it just missed:

```
CVE the collector has stored  → expect @odata.count: 1
CVE from the all-miss batch   → expect @odata.count: 0
```

If both return what they should, the misses are real coverage and the warning is a
true negative. Verified this way for Red Hat and MSRC; both paths were correct.

### A feed answers `403` with a browser challenge

A challenge page — Cloudflare's "Just a moment…", a proof-of-work interstitial, a
WAF "Request Rejected" — cannot be read by a plain HTTP client, and sending a browser
`User-Agent` does not change that. Retrying adds noise to the run report and traffic
to a service that asked to be left alone. Exclude the feed from the register rather
than retrying it.

### A source is enabled but reports "no collector implemented"

An enabled source with no collector is reported and skipped, never silently treated
as having produced nothing. Either add the collector or disable the source.

## Quality gate

The gate checks the exact bytes that would be sent. A refusal is a run failure, not a
warning, because a bad publication is worse than no publication.

| Message | Cause |
| --- | --- |
| `threat_count dropped N%` | A collector broke. Read the run report and find which source changed status |
| `threat_count … below the configured minimum` | The same, more severely |
| provenance error naming a threat | A record reached the gate without a source attribution |
| TLP rejection | A record carried a marking that is not CLEAR/WHITE |
| request size | `publication.max_payload_bytes` is above what PHP will accept |

Override a **volume** refusal only with `--allow-volume-drop`, and only after you have
explained the drop. Never widen the ceiling instead: a body PHP discards surfaces as
an empty request, which is far harder to diagnose than a refusal before transmission.

## Correlation and scoring

### `cve_groups_without_scoreable_evidence` is large

This counts groups the model refused to score. It should be a small number: the model
scores from whatever evidence a group holds, so a refusal means fewer than two
independent sources and no KEV listing, or no exploitation/EPSS/impact signal at all.
A sudden jump means either the collectors are returning thin payloads or something
has stopped populating the factors — check `score_factors` on a few records before
touching the model.

### `KeyError` inside `build_vulnerability` or `build_threat`

A payload field that a builder assumed. Not every source carries every field: CISA
CSAF lists the CVEs it covers in `cve_ids` and has no `cve_id` at all, so a builder
must take identity from the caller rather than from the record. If a new source
produces this, fix the builder, not the normaliser.

### A score moved and nobody changed the model

Check `metadata.scoring_model` on the record. If it changed, the model changed. If it
did not, check `score_factors`: a factor appearing or disappearing moves the score by
its weight, and that is usually a source starting or stopping coverage rather than a
defect. `metadata.legacy_score` is present on KEV records and shows what the previous
model says about the same evidence.

### A pruner never fires

Retention logic in this codebase treats an **undatable** value as "keep", because
discarding a record on the strength of a parsing failure is worse. So a wrong
timestamp format fails silently: the pruner keeps everything and nothing reports it.
If a `pruned_*` counter is always zero, check the format before the logic.

## Configuration and state

| Symptom | Cause |
| --- | --- |
| `Unknown source_key: …` | A source key in the payload or register that `settings.json` does not declare |
| Run refuses to start, names the register | `data/attribution.json` is missing, or an enabled source is not declared in it. Absence of a record is not permission |
| Config error naming a field | `lib/config.py` validates strictly and reports the key it expected |
| `EXIT_LOCKED` | A previous run is still going, or died holding the lock. The next start clears a stale lock |

Deleting `state/` is safe except for `identity_aliases.json`; the consequence is that
caches refetch, first-seen dates restart and publication history restarts. See
[ARCHITECTURE.md](ARCHITECTURE.md#state).


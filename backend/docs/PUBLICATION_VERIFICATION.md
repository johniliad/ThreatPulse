# Publication verification

## Why this document exists

A run can succeed locally and still not reach the API. The publisher can report `202`
per chunk and the API can store nothing. **A local success is not a published
publication**, and the only honest way to claim propagation is to query the API and
compare what it serves against what you sent.

`backend/scripts/verify_publication.py` does exactly that. It is standard library
only and needs no credentials — every endpoint it calls is public.

## Running it

```bash
cd /home/ubnt/ThreatPulse
python3 scripts/verify_publication.py
```

| Flag | Effect |
| --- | --- |
| `--snapshot PATH` | Verify a specific snapshot instead of `data/latest_publication.json` |
| `--base URL` | Verify a different API deployment |

Exit code `0` means every check passed; non-zero names what did not.

## What it checks

1. **The publication UUID is present** in `publications.php`. This is the single
   strongest proof: the API is serving the exact run you are holding.
2. **The threat count matches.** The API's `pagination.total` for `threats.php`
   equals the snapshot's `summary.threat_count`.
3. **A sampled threat round-trips** with the same identifier, priority score and
   source list. A count can match while records differ; this catches that.
4. **Every source in the snapshot is listed** by `sources.php` with a non-zero count.

## The two blocks `verify_publication.py` does not cover

The script proves the threats arrived. Two newer blocks travel with the same
document and are **not** part of its checks, because each has its own endpoint and
each can fail independently of the threat data:

| Block | Endpoint | What a missing block looks like |
| --- | --- | --- |
| `attribution` — the source register | `attribution.php` | `"stored": false` with a message; the register is empty |
| `source_health` — per-source run status | `source_health.php` | `"available": false`, an empty source list |

Both are **optional by design**: refusing to publish intelligence because reference
data could not be stored would be a disproportionate failure. That makes them the
one thing that can silently not arrive while every other check still passes — so
check them once after a deployment or a schema change:

```bash
BASE=https://threatpulse.iliadis.net/api/cti/v1

# Did the register land, and does it list the sources the snapshot declares?
curl -s "$BASE/attribution.php?limit=100" | grep -o '"stored":[a-z]*'

# Did this run's health land, and does it describe the same run?
curl -s "$BASE/source_health.php" | head -c 400
```

The authority on what *should* be there is the publish response, not the document.
`publish.php` reports `attribution_stored` and `source_health_stored` per chunk; a
`false` there is the failure, and it is visible in the run log even though the
publication succeeded.

`source_health.php` also carries `publication_uuid`, so the check has a single
honest question: does it name the run you just published? If it names an older one,
the health block was not stored for this run.

## Verifying the delta feed

`changes.php` compares the two most recent completed publications, so it can only be
verified once **two** have landed:

```bash
# Which two publications is it diffing, and do the counts partition the set?
curl -s "$BASE/changes.php?limit=1"
```

A first publication reports `previous_publication_uuid: null` and every threat as
added — that is correct, not a failure. After the second run, check that
`added + changed + unchanged == published`: the three lists partition the
publication, and a total that does not add up means the two snapshots disagree about
which threats they contain.

## Doing it by hand

```bash
BASE=https://threatpulse.iliadis.net/api/cti/v1

# Is the publication recorded?
curl -s "$BASE/publications.php?limit=1" | head -c 400

# Does the count agree?
curl -s "$BASE/threats.php?limit=1" | grep -o '"total":[0-9]*'

# Does a specific threat agree?
curl -s "$BASE/threat.php?uuid=<uuid-from-the-snapshot>"
```

## Reading the results

| Observation | Meaning |
| --- | --- |
| UUID absent from `publications.php` | Nothing landed. Read the publisher's log for the HTTP status |
| `publications.php?include_incomplete=1` lists a publication with `status` of `receiving` | An earlier run was interrupted mid-chunk. The next run supersedes it — no repair needed |
| `publications.php` lists nothing for a run that just reported success | Only completed publications are listed. A `publication_uuid` that is missing from the default listing is still there under `?include_incomplete=1` |
| Count lower than the snapshot | Not every chunk was stored. Usually an API that predates chunking — see TROUBLESHOOTING |
| Count matches, a sampled threat does not | The API stored an older publication; check which UUID it reports |
| A source is missing from `sources.php` | The source produced nothing this run, so it is absent from `sources[]` |

## What "complete" means for a chunked publication

A document over `publication.max_payload_bytes` is sent as several requests sharing
one `publication_uuid`. The API answers `202` per chunk and reports `complete` when
the last one arrives. A publication is only complete when **every** chunk was
accepted — the publisher fails the run rather than reporting success on a partial
store, because a silent partial publication is worse than a visible failure.

## Verification after a model change

Two extra checks are worth running once after a scoring change, because they are the
only way to confirm the transition behaved as intended:

```bash
# Did the model actually change, and is the audit trail there?
python3 - <<'EOF'
import json
d = json.load(open('data/latest_publication.json'))
print('model    :', d['threats'][0]['metadata']['scoring_model'])
print('legacy   :', bool(d['threats'][0]['metadata'].get('legacy_score')))
print('changes  :', d['summary'].get('changes'))
EOF
```

A KEV record must carry the current `scoring_model` **and** a `legacy_score`. A
non-KEV record must carry the current model and no legacy score — the previous model
cannot score it, and inventing a comparison would be worse than omitting one.

# Architecture

## The shape of a run

`run_pipeline.py` is the only entry point. It runs seven stages in order and stops
at the first one that cannot succeed.

```
collect → normalise → correlate → enrich → score → quality gate → publish
```

Two properties hold throughout: the run is **deterministic** (same inputs, same
document) and it is **fail-closed** (anything uncertain is refused, not guessed).

### 1. Collect — `collectors/`

23 modules. Most wrap one source family; two are shared engines:

* `cve_lookup.py` — the dependent, per-CVE lookup algorithm (cache, TTL, absent
  tracking, batch abandonment). Used by Vulnrichment, Red Hat, OSV, MSRC and CIRCL.
* `rss_feed.py` — the generic advisory collector, which serves nine source keys
  (`ncsa_greece`, `national_cert_feeds`, `cert_eu_*`, vendor PSIRTs, WordPress) with
  TLP enforcement and per-feed failure isolation.

Each collector returns a `SourceResult` with a status of `ok`, `degraded` or
`failed`. `degraded` means retrieval failed but a last-known-good snapshot was
reused. A source declared `required` aborts the run when it fails.

Three sources are **knowledge bases** rather than feeds — ATT&CK, MISP Galaxy and
CAPEC — and `sigma` is a detection-coverage index. They produce no observations;
they answer questions about other sources' output.

### 2. Normalise — `normalization/`

21 modules, one per source family. Each turns a source payload into typed
`Observation` objects carrying:

| Field | Meaning |
| --- | --- |
| `source_key`, `source_record_id` | Where it came from |
| `external_id` | The source's own record identifier |
| `observed_at`, `retrieved_at` | When the source published it; when we fetched it |
| `entities` | `(kind, value, normalized)` — cve, malware, actor, country, sector, technique… |
| `payload` | The normalised record, with a `tlp_label` |

Normalisers validate strictly and raise with **the shape they actually received**
rather than coercing. A source whose payload changed shape fails loudly; it does not
quietly contribute nothing.

### 3. Correlate — `correlation/engine.py`

Observations that declare an entity join the group for that entity. An observation
can join several groups: a national advisory naming two CVEs is evidence about both.
Only the highest-priority entity kind an observation carries is used, which prevents
one advisory from being counted once per CVE it mentions *and* per vendor.

One kind of published object comes out:

* **Vulnerability threats** — one per CVE group, scored by `scoring/universal.py`.

Malware-family sources were retired on 2 Nov 2026 along with the indicator clusters
they produced, so **every published threat is now keyed on a CVE**. Groups keyed on
anything else (an actor, a country) are counted and reported, not scored. The
entity keys (`url`, `ip`, `domain`, `malware`, `software`, `actor`) are still
supported by the engine; nothing produces them yet.

### Identity

A vulnerability threat's identifier is derived from **the CVE alone**:

```
threat_uuid = sha256("threatpulse:cisa_kev:" + CVE)[:32] as a UUID
```

The namespace is a compatibility constant. It is `cisa_kev` because that is what the
API has published since the product was KEV-only, and every identifier already
published must keep working. It is deliberately **not** the source key, because:

* a CVE first published from enrichment evidence must keep the same identifier when
  it later enters the KEV catalogue — otherwise the database would hold two threats
  for one vulnerability;
* which source wins the scoring contest is an implementation detail, and an
  identifier must not move because of it.

`cve_id` is passed into the builders explicitly rather than read from a payload,
because a source's own identifier is sometimes a tracking number (CISA CSAF
publishes `VA-26-216-01`) and an advisory can describe several CVEs while naming
none of them in a way the pipeline can key on.

Indicator clusters used a separate synthetic namespace while they existed; it was
removed with them. Threat identity is `threatpulse:cisa_kev` for every published
record, and the compatibility vectors in `lib/ids.IDENTITY_VECTORS` still pin it.

### 4. Enrich — `enrichment/`

ATT&CK context (techniques, actors, detection coverage) is attached to every threat
that names a technique or a malware family. CAPEC supplies the CWE → technique route.
Sigma supplies detection coverage. Enrichment is **context, never proof of activity**:
it cannot set exploitation status and cannot move a score on its own.

### 5. Score — `scoring/`

Three models, all publishing their own name in `metadata.scoring_model`:

| Model | Scores | Where |
| --- | --- | --- |
| `threatpulse_priority_v0.3` | every vulnerability threat | `scoring/universal.py` |
| `threatpulse_priority_v0.1` | KEV-shaped records, for audit only | `scoring/priority.py` |

**v0.3** takes nine factors, each optional, with weights that sum to 1.0 across all
of them:

```
exploitation 28  epss 20  impact 18  evidence 10  urgency 8
ransomware 6  recency 5  first_seen 3  forensic 2
```

A factor the evidence does not support contributes nothing and is **not reported**.
`score_factors` names exactly what produced the number and `score_weights` holds only
those weights, so a reader can see how thin the evidence was. The score therefore
*falls* when evidence is missing rather than being redistributed — a thin record
scores low, which is the right answer for priority.

Two rules keep it honest:

* **A refusal beats a guess.** Fewer than two independent sources raises
  `InsufficientEvidence`, unless one of them is the CISA KEV catalogue, which is a
  corroborated determination in its own right. So does the absence of any
  exploitation, EPSS or impact signal.
* **Exploitation is never low.** A record whose exploitation factor is at or above
  90 is floored at 50 so it cannot rank below an unremarkable record that happens to
  carry a CVSS.

**v0.1** still runs for KEV-shaped records and its answer is published beside the
current one as `metadata.legacy_score`. It is the audit trail for the unification:
the change can be checked record by record and reversed without recomputing anything.
Its code is untouched.

Bands are derived in `priority_band()` with thresholds `90 / 75 / 50 / 25`. They are
**provisional**: they were recalibrated when the models were unified because the old
`85 / 70` split labelled 23% of a publication "critical".

### 6. Quality gate — `publication/quality_gate.py`

Checks the exact bytes that would be sent: structure against schema 1.0, provenance
on every record, TLP markings, volume against the configured minimum and against the
previous run's count, and request size. A refusal is a run failure, not a warning.

### 7. Publish — `publisher.py` and `publication/chunking.py`

The document is split so every request stays under `publication.max_payload_bytes`
(7 MiB), deliberately below a common 8 MB `post_max_size` — a body PHP discards is
far harder to diagnose than a refusal before transmission. Every chunk carries the
same `publication_uuid` and a `chunk` block, so the API can assemble them into one
publication and upsert rather than duplicate.

## State

Everything the pipeline remembers lives in `state/`, written atomically.

| File | Purpose | Safe to delete |
| --- | --- | --- |
| `record caches` (`*_cache.json`) | Per-CVE lookups with a refresh interval | Yes — refetches |
| `cve_first_seen.json` | First run that observed each CVE | Yes — dates restart |
| `threat_history.json` | Per-threat publication history | Yes — history restarts |
| `identity_aliases.json` | Migrated identifiers | **No** — identity depends on it |
| `previous_publication.json` | Last accepted summary, for the volume guard | Yes — guard goes quiet |
| `*_last_known_good` snapshots | Reused when a source fails | Yes — degrade turns into fail |

Every reader treats a missing or unreadable file as empty rather than as an error:
refusing to run because a state file is corrupt would be worse than restarting it.
The exception is `identity_aliases.json`, which is not regenerable.

## What a run publishes

`data/latest_publication.json` — schema 1.0, replaced wholesale.

```
publication_uuid, schema_version, generated_at
summary:  threats, bands, sources, top_threats, changes
sources:  declared sources with provider, licence and terms
threats:  the records, each with vulnerabilities, evidence and metadata
attribution: the full source register
source_health: per-source run status, observation count and failure reason
```

`metadata.temporal` on each threat carries `first_published_at`, `revision` and —
when something moved — `changed_since_previous`. `summary.changes` carries the
run-level `new` / `changed` / `unchanged` / `disappeared` counts, and the API
serves the field-level version of the same thing from `changes.php`.

`source_health` is the run report for the sources themselves, not for the
intelligence: `ok`, `degraded` (a retrieval failure that fell back to a
last-known-good snapshot) or `failed`, plus the observation count that justifies
the verdict. It travels with the publication because the publication is what the
public can read — a health report that stays on the VM cannot answer "why is
today's count low?" for anyone but the operator.



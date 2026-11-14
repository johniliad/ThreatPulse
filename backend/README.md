# ThreatPulse backend

The pipeline behind [threatpulse.iliadis.net](https://threatpulse.iliadis.net). It
collects cyber threat intelligence from independent sources, correlates it into
threat records, scores it, validates the finished document and publishes a snapshot
to a public read-only API.

**Python standard library only.** No third-party packages, no build step, no
lockfile, nothing to install. A Python 3 interpreter and this directory are the whole
dependency set, which is deliberate: the pipeline runs unattended on a small VM and
should not break because a transitive dependency moved.

## What it does, in order

```
collect → normalise → correlate → enrich → score → quality gate → publish
```

| Stage | Module | Result |
| --- | --- | --- |
| Collect | `collectors/` | `SourceResult` per source: ok, degraded or failed, with metrics |
| Normalise | `normalization/` | Typed `Observation` objects with entities, TLP marking and a payload |
| Correlate | `correlation/engine.py` | Threat records from groups of observations, one per CVE group |
| Enrich | `enrichment/` | MITRE ATT&CK context, CAPEC routes, detection coverage |
| Score | `scoring/` | A priority score, band and confidence, with the factors that produced them |
| Quality gate | `publication/quality_gate.py` | Refuses to transmit a document that fails a structural, provenance, TLP or volume check |
| Publish | `publisher.py` | Chunked HTTPS POST to `api/cti/v1/publish.php` |

## Quick start

```bash
cd backend
python3 -m unittest discover -s tests -t .   # expect 629 tests, OK
python3 run_pipeline.py --dry-run            # fetch, correlate, score, write a snapshot
python3 run_pipeline.py --publish            # the same, then transmit it
```

`--dry-run` is the safe way to see what a run would publish. It writes
`data/latest_publication.json` and `data/run_report.json` and sends nothing.

| Flag | Effect |
| --- | --- |
| `--publish` | Transmit after the quality gate passes |
| `--dry-run` | Build and validate, never transmit |
| `--allow-volume-drop` | Override the volume guard, after reviewing why the count fell |
| `--log-level` | `INFO` by default |

| Exit code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | A stage failed |
| 2 | Configuration is invalid |
| 3 | Another run holds the lock |
| 4 | The publication was not accepted by the API |

## Layout

```
backend/
  collectors/      20 modules — one per source family, plus the shared CVE-lookup engine
  normalization/   18 modules — source payloads to observations
  correlation/     the engine that groups observations into threats
  enrichment/      ATT&CK, CAPEC and detection coverage
  scoring/         priority, confidence, the universal model
  publication/     builder, chunking, quality gate
  state/           persistent state: caches, first-seen dates, change history
  lib/             config, HTTP, identity, atomic writes, attribution, TLP, logging
  scripts/         analysis and verification tools
  tests/           26 files, 629 tests
  config/          settings.json — sources, timeouts, publication limits
  data/            snapshots and the attribution register (register is tracked)
```

## Documentation

| Document | Read it when |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | You need to understand how the stages fit together |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | You are setting up a host |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | You run it and something needs looking at |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | A specific source or stage misbehaves |
| [docs/PUBLICATION_VERIFICATION.md](docs/PUBLICATION_VERIFICATION.md) | You need to prove what was published reached the API |
| [../deployment/DEPLOYMENT.md](../deployment/DEPLOYMENT.md) | You are deploying the API and the VM together |

## Ground rules

These are enforced by the code, not by convention.

1. **Never claim propagation without querying the API.** `scripts/verify_publication.py`
   exists for this and the deployment checklist calls it.
2. **Feeds are untrusted.** Every payload is validated; a shape that does not match
   fails the source with the shape it actually received.
3. **Never invent a number.** A score factor that the evidence does not support is
   omitted and contributes nothing. A record the model cannot support is not
   published at all.
4. **A failure is reported, never disguised as emptiness.** A source that fails
   without a snapshot is `failed`; one that degrades is `degraded`.
5. **Only TLP:CLEAR material is ingested**, enforced at read time and again against
   the finished publication.
6. **Secrets live in a mode-0600 file outside the repository** and are registered
   with the log redactor.
7. **Identity is stable.** A threat's identifier does not change because a different
   source won the scoring contest, or because the model changed.

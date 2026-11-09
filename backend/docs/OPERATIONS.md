# Operations

## What a normal run looks like

```
ThreatPulse — pipeline
Sources:         capec, cert_eu_advisories, …, ubuntu_security
Threats:         3772
Critical:        868
High:            698
Medium:          518
Vulnerabilities: 3558
Changes:         new 0, changed 34, disappeared 12
Publication:     549e8fb0-b018-4ae3-b031-773140783c45
Snapshot:        /home/ubnt/ThreatPulse/data/latest_publication.json
```

`Changes` is the answer to "what is different since last time" and is usually the
only line worth reading on a quiet day.

## Reading the log

| Line | Means |
| --- | --- |
| `… collected` with a source key | The source answered; the metrics are its own |
| `http resource not modified` | A conditional GET was honoured; the cached copy is used |
| `using last known good snapshot` | The source failed; a previous snapshot was reused. Run continues |
| `source failed` | No data and no snapshot. A `required` source aborts the run |
| `every … lookup was empty` | Every lookup in a batch 404'd. Usually genuine coverage, occasionally a wrong path — see TROUBLESHOOTING |
| `observations without a correlatable entity were skipped` | Advisories naming no CVE. Counted, not lost |
| `publication split into chunks` | The document exceeded the request ceiling |
| `publication chunk transmitted` | One request accepted (`202`) |
| `publication refused by the API as a duplicate` | `409`. The same line carries `api_message`, `api_publication_status` and `meaning`; there are three distinct causes — see TROUBLESHOOTING |
| `the API accepted a chunk but did not report it as one` | The endpoint ignored the chunk block. The run stops before uploading the remaining chunks |

The dependent CVE sources report `pending`, `cache_hits` and `known_absent`. A run
with `fetched=0` is not idle: `cache_hits` is how many records were re-emitted from
cache, and `known_absent` is the steady-state count of identifiers the upstream does
not cover.

## State

`state/` is the pipeline's memory and is written atomically, so a killed run cannot
corrupt it. What each file does, and whether deleting it is safe, is in
[ARCHITECTURE.md](ARCHITECTURE.md#state). In short: everything except
`identity_aliases.json` regenerates.

A run that is interrupted mid-publish leaves the API publication in
`status='receiving'`. Nothing needs repairing: the next run publishes a fresh
snapshot under a new `publication_uuid`, and threats are upserted rather than
duplicated.

## Running by hand

```bash
sudo systemctl start threatpulse.service   # one run, on the timer's terms
journalctl -u threatpulse.service -f       # watch it
```

```bash
cd /home/ubnt/ThreatPulse
sudo -u ubnt python3 run_pipeline.py --dry-run    # never transmits
sudo -u ubnt python3 run_pipeline.py --publish    # transmits after the gate
```

`--dry-run` is the safe way to see what a change would publish. It writes the same
snapshot and report and sends nothing.

## When the volume guard fires

The gate refuses a publication whose threat count fell further than
`publication.maximum_drop_ratio`. That guard exists because a broken collector
usually looks like a *smaller* publication, not a failed run.

Do not override it immediately. Read `run_report.json`, find which sources changed
status, and fix the cause. `--allow-volume-drop` is for a drop you have explained —
a source retired on purpose, a feed that legitimately shrank — not for a drop you
have not.

## Rotating secrets

1. Issue the new token at the API side (`publisher-config.php` on the cPanel host).
2. Update `/etc/threatpulse/threatpulse.env`.
3. `systemctl start threatpulse.service` and confirm a `202`.

The old token keeps working until step 1, so rotate in that order. It is the only
secret the pipeline reads; the abuse.ch Auth-Key that used to rotate alongside it
was retired with its sources on 2 Nov 2026 and can be deleted from the environment
file.

## Health checks worth automating

| Check | Expected |
| --- | --- |
| `systemctl is-active threatpulse.timer` | `active` |
| Last run exit code in `journalctl` | `0` |
| `data/run_report.json` — no source `failed` | true |
| `source_health.php` — no source `status: failed` | true (the same fact, from outside the VM) |
| `scripts/verify_publication.py` | exit `0` |
| `publications.php` newest record | recent, and `complete` |

The last one matters most: a run that succeeded locally and was not stored by the API
is the failure mode that looks like success.

## Housekeeping

* `data/` and `logs/` grow. `latest_publication.json` is replaced each run, but
  `logs/` accumulates.
* The publication is append-only on the API. A wrong publication is superseded by
  publishing a corrected one, never by editing history.
* `state/known_exploited_vulnerabilities.json` and the `*_last_known_good` snapshots
  are the reason a transient outage does not empty the product.

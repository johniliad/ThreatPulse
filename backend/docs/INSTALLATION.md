# Installation

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Python 3 | Standard library only. No `pip install`, no virtualenv strictly required |
| Outbound HTTPS | Every source is fetched over TLS; there is no inbound listener |
| A filesystem path | The pipeline writes `state/`, `data/` and `logs/` |
| Publisher token | Matches `publish.php` on the cPanel host |

There is nothing to compile. `python3 -m unittest discover -s tests -t .` from
`backend/` is a complete smoke test — it uses no network and no credentials.

## 1. Place the code

```bash
mkdir -p /home/ubnt/ThreatPulse
cp -r backend/* /home/ubnt/ThreatPulse/
```

The tree lives under `/home` on this host, owned by `ubnt`, and that is what the
systemd unit expects (`WorkingDirectory=`, `User=`, `ProtectHome=no`). An earlier
revision of this page used `/opt/threatpulse` and a dedicated `threatpulse` system
account; both are stronger on a shared host but are not what runs here. If you move
the tree, change the unit, `install.sh` and this page together — `install.sh` fails
if the installed unit disagrees with `APP_ROOT` or `SERVICE_USER`.

`backend/data/attribution.json` **must** be present. It is the source register, and
the pipeline refuses to run without it: an enabled source that the register does not
declare fails the run, because absence of a record is not permission.

## 2. Configuration

`config/settings.json` holds everything except secrets: the declared sources and
whether each is enabled, HTTP timeouts and retry policy, publication limits, and
directory paths. It is tracked in the repository and safe to read.

Two values matter before a first run:

* `publication.max_payload_bytes` — 7 MiB. Deliberately below a common 8 MB
  `post_max_size`, because PHP silently discards an oversized body. Raise it only
  after raising the PHP limit.
* `publication.maximum_drop_ratio` — how large a fall in published volume the quality
  gate tolerates before refusing. `--allow-volume-drop` overrides it for one run.

## 3. Secrets

```bash
sudo install -m 0600 /dev/null /etc/threatpulse/threatpulse.env
sudo tee /etc/threatpulse/threatpulse.env >/dev/null <<'EOF'
THREATPULSE_PUBLISHER_TOKEN=<the token publish.php expects>
EOF
sudo chown ubnt:ubnt /etc/threatpulse/threatpulse.env
```

The file is read by the application, **not** by systemd's `EnvironmentFile=`, which
would copy the token into systemd's environment where `/proc/<pid>/environ` exposes
it. Both values are registered with the log redactor on load, so a credential cannot
reach a log line even if a caller formats it into a message.

Never put either value in `settings.json`, the register, a feed URL, a state file or
an issue.

## 4. Ownership

```bash
sudo chown -R ubnt:ubnt /home/ubnt/ThreatPulse
sudo -u ubnt python3 -m unittest discover -s tests -t .
```

Running the suite as the service account proves it can write `state/`, `data/` and
`logs/` before the timer is enabled.

## 5. First run, without transmitting

```bash
cd /home/ubnt/ThreatPulse
sudo -u ubnt python3 run_pipeline.py --dry-run
```

Expect several minutes: the dependent CVE sources (Vulnrichment, Red Hat, OSV, MSRC,
CIRCL) sweep a bounded batch per run and cache what they find. The first run is the
slowest; later runs re-use the caches.

Then read `data/run_report.json` and check every source's status. `ok` and `degraded`
are expected; `failed` on a `required` source aborts the run.

## 6. Schedule it

```bash
sudo ./deployment/install.sh
```

Idempotent and non-interactive. It uses the account that owns the tree, sets
ownership, prepares the environment file **without overwriting an existing one**, runs
the test suite as a gate, installs both systemd units, verifies the pipeline runs as
the service account, and only then starts the timer. It refuses to start the timer
when the publisher token is empty, so a half-configured host cannot publish a run
with no credential.

| | |
| --- | --- |
| Runs | daily, up to 20 minutes of jitter |
| Catches up | `Persistent=true` — a missed run starts shortly after boot |
| User | `ubnt` — the account that owns the tree. A dedicated `nologin` system account is the stronger posture for a fresh install elsewhere; this host runs from a home directory, which is why `ProtectHome` is relaxed |
| Timeout | `TimeoutStartSec=2700`; systemd's 90-second default for `oneshot` would kill a legitimate run |
| Retries | at most 3 per hour on failure, then waits for the next day |
| Filesystem | `ProtectSystem=strict` with `ReadWritePaths` limited to `state/`, `data/`, `logs/` |
| Network | outbound only; no inbound socket |

## 7. Confirm it works

```bash
journalctl -u threatpulse.service -f        # watch a run
systemctl list-timers threatpulse.timer     # next scheduled run
python3 scripts/verify_publication.py       # proves what you published reached the API
```

See [PUBLICATION_VERIFICATION.md](PUBLICATION_VERIFICATION.md) for what the last
command checks and why it is the only claim of success that counts.

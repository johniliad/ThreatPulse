#!/usr/bin/env python3
"""OSV collector — open-source packages affected by the CVEs we track.

A **dependent, per-CVE** source: OSV answers about the CVEs the pipeline already
tracks. It covers open-source ecosystems, so a large share of product-oriented KEV
CVEs are simply absent and answer HTTP 404 — which the shared lookup algorithm
records as a miss rather than retrying forever.

Records are refreshed monthly: an advisory's affected ranges and fixed versions are
updated as maintainers publish fixes.

A response ceiling is set explicitly because an OSV record can be large — the log4j
record is 115 KB, most of it CPE ranges this normaliser does not read — and a
misbehaving endpoint must not be able to make the collector buffer an unbounded
body.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/osv_dev.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.cve_lookup import CveLookupCollector  # noqa: E402
from lib.attribution import load_register  # noqa: E402
from lib.config import load_settings  # noqa: E402
from lib.http import HttpClient  # noqa: E402
from lib.logging_setup import configure_logging  # noqa: E402
from normalization.osv import build_observation, parse_osv_record, record_url  # noqa: E402
from state.record_cache import RecordCache  # noqa: E402
from state.store import StateStore, utc_now_iso  # noqa: E402

CACHE_FILENAME = "osv_cache.json"

#: Affected ranges and fixed versions change as maintainers ship fixes.
REFRESH_AFTER_DAYS = 30

#: A generous ceiling for one record; the largest seen was 115 KB.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class OsvCollector(CveLookupCollector):
    """Fetches OSV records for the CVEs the pipeline discovered."""

    label = "osv"

    def build_cache(self, state: StateStore) -> RecordCache:
        return RecordCache(
            state, filename=CACHE_FILENAME, refresh_after_days=REFRESH_AFTER_DAYS
        )

    def lookup_url(self, cve_id: str) -> str:
        return record_url(self.config.feed_url, cve_id)

    def parse_record(self, payload: object) -> dict:
        return parse_osv_record(payload)

    def build_observation(self, payload: dict, *, retrieved_at: str):
        return build_observation(
            payload, source_key=self.config.key, retrieved_at=retrieved_at
        )

    def tlp_scan_texts(self, payload: dict) -> tuple[str, ...]:
        return (payload.get("summary") or "", payload.get("details") or "")

    def request_max_bytes(self) -> int | None:
        return MAX_RESPONSE_BYTES

    def extra_metrics(self, observations: list) -> dict:
        ecosystems = {
            ecosystem
            for observation in observations
            for ecosystem in observation.payload.get("ecosystems") or []
        }

        return {
            "records_with_packages": sum(
                1 for observation in observations if observation.payload.get("packages")
            ),
            "distinct_ecosystems": len(ecosystems),
        }


def build_collector(settings, *, cve_ids=()) -> OsvCollector:
    """Factory used by both the CLI and the pipeline."""

    state = StateStore(settings.state_directory, settings.data_directory)

    http = HttpClient(
        user_agent=settings.http.user_agent,
        connect_timeout_seconds=settings.http.connect_timeout_seconds,
        read_timeout_seconds=settings.http.read_timeout_seconds,
        max_attempts=settings.http.max_attempts,
        backoff_seconds=settings.http.backoff_seconds,
        backoff_multiplier=settings.http.backoff_multiplier,
    )

    return OsvCollector(
        settings.source("osv_dev"),
        http,
        state,
        register=load_register(),
        cve_ids=cve_ids,
    )


def main() -> int:
    """CLI: looks up the CVEs supplied as arguments, or the KEV snapshot."""

    import json

    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    cve_ids = [argument for argument in sys.argv[1:] if argument]

    if not cve_ids:
        snapshot = settings.data_directory / "known_exploited_vulnerabilities.json"
        raw = (
            json.loads(snapshot.read_text(encoding="utf-8"))
            if snapshot.exists()
            else {}
        )

        cve_ids = [
            str(record.get("cve_id"))
            for record in (raw.get("records") or [])
            if isinstance(record, dict) and record.get("cve_id")
        ]

        print(f"No CVEs given; using {len(cve_ids)} from the KEV snapshot.")

    result = build_collector(settings, cve_ids=cve_ids).collect(utc_now_iso())

    print("ThreatPulse — OSV collector")
    print("---------------------------")
    print(f"Status:  {result.status}")
    print(f"Records: {len(result.observations)}")

    for key in (
        "cves_candidates",
        "fetches_attempted",
        "fetches_ok",
        "absent",
        "rejected_malformed",
        "rejected_tlp",
        "fetch_failures",
        "cached_records",
        "records_with_packages",
        "distinct_ecosystems",
        "cache_absent",
    ):
        if key in result.metrics:
            print(f"{key}: {result.metrics[key]}")

    if result.failure_reason:
        print(f"Reason:  {result.failure_reason}")

    if not result.usable:
        print("ERROR: no usable observations.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

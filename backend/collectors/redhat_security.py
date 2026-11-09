#!/usr/bin/env python3
"""Red Hat Security Data collector — vendor assessment, errata and fix states.

A **dependent, per-CVE** source: Red Hat answers about the CVEs the pipeline
already tracks rather than streaming its catalogue. Records are refreshed monthly,
because errata and severities are added after a CVE is first published, and a
permanently cached record would freeze that.

The CVSS it supplies is a **vendor** assessment — Red Hat scores a CVE in the
context of its own products — so the correlation engine uses it only where CISA has
no assessment, and the published metadata names whichever source supplied the
number. Its errata list is the operationally useful part: not "a fix exists" but
"RHSA-2021:5137 fixes this for OpenShift Logging 5.0".

The lookup algorithm lives in ``collectors/cve_lookup.py``; this module supplies the
URL, the validation and the refresh policy.

**Most KEV CVEs have no Red Hat record, and that is correct.** Red Hat answers about
its own products, so a Microsoft, Adobe or Oracle CVE is genuinely absent. On this
deployment 441 of 2,264 candidates are covered and 1,823 are not; a twelve-CVE
sample of the absent set returned **404** from the live endpoint, so the lookup path
is right and the misses are real. A high ``absent`` count is therefore an expected
steady state, not a fault — the ``SUSPICIOUS_ABSENT_FETCHES`` warning only fires when
an entire run comes back empty, which is the signature of a wrong path.

**A warm cache is not an idle source.** The full record set is emitted from cache on
every run, so a run that needed no fetches logs ``fetched=0`` alongside a
``cache_hits`` equal to the record count. Read the two together before concluding
that the source did nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/redhat_security.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.cve_lookup import CveLookupCollector  # noqa: E402
from lib.attribution import load_register  # noqa: E402
from lib.config import load_settings  # noqa: E402
from lib.http import HttpClient  # noqa: E402
from lib.logging_setup import configure_logging  # noqa: E402
from normalization.redhat import build_observation, parse_redhat_record, record_url  # noqa: E402
from state.record_cache import RecordCache  # noqa: E402
from state.store import StateStore, utc_now_iso  # noqa: E402

CACHE_FILENAME = "redhat_cache.json"

#: Errata and severity assessments are added over time, so a record is re-read
#: monthly rather than kept forever.
REFRESH_AFTER_DAYS = 30


class RedhatSecurityCollector(CveLookupCollector):
    """Fetches Red Hat Security Data records for the CVEs the pipeline discovered."""

    label = "redhat security"

    def build_cache(self, state: StateStore) -> RecordCache:
        return RecordCache(
            state, filename=CACHE_FILENAME, refresh_after_days=REFRESH_AFTER_DAYS
        )

    def lookup_url(self, cve_id: str) -> str:
        return record_url(self.config.feed_url, cve_id)

    def parse_record(self, payload: object) -> dict:
        return parse_redhat_record(payload)

    def build_observation(self, payload: dict, *, retrieved_at: str):
        return build_observation(
            payload, source_key=self.config.key, retrieved_at=retrieved_at
        )

    def tlp_scan_texts(self, payload: dict) -> tuple[str, ...]:
        return (
            payload.get("details") or "",
            payload.get("statement") or "",
            payload.get("mitigation") or "",
        )

    def extra_metrics(self, observations: list) -> dict:
        return {
            "records_with_errata": sum(
                1 for observation in observations if observation.payload.get("advisories")
            ),
            "records_with_cvss": sum(
                1 for observation in observations if observation.payload.get("cvss")
            ),
        }


def build_collector(settings, *, cve_ids=()) -> RedhatSecurityCollector:
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

    return RedhatSecurityCollector(
        settings.source("redhat_security"),
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

    print("ThreatPulse — Red Hat Security Data collector")
    print("---------------------------------------------")
    print(f"Status:  {result.status}")
    print(f"Records: {len(result.observations)}")

    for key in (
        "cves_candidates",
        "fetches_attempted",
        "fetches_ok",
        "cache_hits",
        "absent",
        "rejected_malformed",
        "rejected_tlp",
        "fetch_failures",
        "cached_records",
        "records_with_errata",
        "records_with_cvss",
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

#!/usr/bin/env python3
"""Microsoft Security Update Guide collector — Microsoft's own assessment.

A **dependent, per-CVE** source: Microsoft answers about the CVEs the pipeline
already tracks rather than streaming its catalogue. Records are refreshed monthly,
because Microsoft revises a vulnerability's severity, its fixed builds and its
affected-product list after first publication, and a permanently cached record
would freeze that.

Why the Security Update Guide API rather than CVRF
--------------------------------------------------

Both are Microsoft's own data. CVRF is the standard document, but it is **XML** and
**per-release**: the October 2026 document is 46.7 MB, so covering a year means
parsing twelve of them to find the handful of CVEs the pipeline tracks. The
Security Update Guide API is JSON, filterable, and answers about one CVE in about
1.5 KB. That is the shape ``collectors/cve_lookup.py`` already provides.

What it adds that no other source does: Microsoft's **first-party** severity and
CVSS for its own products, the **fixed build numbers** an operator actually needs,
and the affected-product list. A CVE record alone says a vulnerability exists; this
says which Microsoft products are affected and what build fixes them.

**An all-miss run is expected, and was verified.** The pipeline warns when every
lookup in a batch comes back empty, because a wrong lookup path looks identical to
a source that does not cover those CVEs. For this source the common cause is
coverage: it only answers about Microsoft's own products, and a batch of newly
discovered CVEs is usually not. Verified on 2 November 2026 against the live
endpoint — a CVE the collector had stored (`CVE-2013-2094`) returns
``@odata.count: 1``, and a CVE from an all-miss batch (`CVE-2026-90717`) returns
``@odata.count: 0``. The path is right; the misses are real.

The lookup algorithm lives in ``collectors/cve_lookup.py``; this module supplies the
URL, the validation and the refresh policy.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/msrc.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.cve_lookup import CveLookupCollector  # noqa: E402
from lib.attribution import load_register  # noqa: E402
from lib.config import load_settings  # noqa: E402
from lib.http import HttpClient  # noqa: E402
from lib.logging_setup import configure_logging  # noqa: E402
from normalization.msrc import (  # noqa: E402
    build_observation,
    parse_msrc_record,
    record_url,
)
from state.record_cache import RecordCache  # noqa: E402
from state.store import StateStore, utc_now_iso  # noqa: E402

CACHE_FILENAME = "msrc_cache.json"

#: Microsoft revises severities, builds and affected products after publication,
#: so a record is re-read monthly rather than kept forever.
REFRESH_AFTER_DAYS = 30


class MsrcCollector(CveLookupCollector):
    """Fetches Microsoft's assessment for the CVEs the pipeline discovered."""

    label = "msrc"

    def build_cache(self, state: StateStore) -> RecordCache:
        return RecordCache(
            state, filename=CACHE_FILENAME, refresh_after_days=REFRESH_AFTER_DAYS
        )

    def lookup_url(self, cve_id: str) -> str:
        return record_url(self.config.feed_url, cve_id)

    def parse_record(self, payload: object) -> dict:
        return parse_msrc_record(payload)

    def build_observation(self, payload: dict, *, retrieved_at: str):
        return build_observation(
            payload, source_key=self.config.key, retrieved_at=retrieved_at
        )

    def tlp_scan_texts(self, payload: dict) -> tuple[str, ...]:
        return (payload.get("details") or "",)

    def extra_metrics(self, observations: list) -> dict:
        return {
            "records_with_cvss": sum(
                1 for observation in observations if observation.payload.get("cvss")
            ),
            "records_with_fixed_builds": sum(
                1
                for observation in observations
                if observation.payload.get("fixed_builds")
            ),
            "records_requiring_action": sum(
                1
                for observation in observations
                if observation.payload.get("customer_action_required") is True
            ),
        }


def build_collector(settings, *, cve_ids=()) -> MsrcCollector:
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

    return MsrcCollector(
        settings.source("msrc"),
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

    print("ThreatPulse — Microsoft Security Update Guide collector")
    print("------------------------------------------------------")
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
        "records_with_cvss",
        "records_with_fixed_builds",
        "records_requiring_action",
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

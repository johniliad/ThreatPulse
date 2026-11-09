#!/usr/bin/env python3
"""CISA Vulnrichment collector — SSVC decision points and CISA-assigned CVSS.

Vulnrichment is CISA's Authorized Data Publisher enrichment of public CVE records:
three SSVC decision points for every CVE it analyses, plus a CWE and a CVSS
assessment of its own wherever CISA had enough evidence to assert one.

**This source is enrichment, never exploitation evidence.** The published payload
carries no ``kev_listed``, ``exploited_in_wild``, ``date_added`` or ``due_date``
field — those four are what the correlation engine and the priority model read to
decide that something is exploited and how urgent it is, and CISA's SSVC
assessment is not a ThreatPulse observation of exploitation. Their absence is what
makes this source incapable of moving an existing threat's score. See
``normalization/vulnrichment.py``.

The lookup algorithm — the bounded batch, the miss handling, the re-emission of
everything cached, the TLP gate and last-known-good fallback — lives in
``collectors/cve_lookup.py``. This module supplies only what is specific to
Vulnrichment: the record URL and the record validation.

Verified against the live repository on 31 Oct 2026: the derived record path is
correct for ``0xxx``, ``3xxx``, ``25xxx`` and ``109xxx`` number blocks; a 59-CVE
sample spanning the whole KEV catalogue (``CVE-2002-0367`` to ``CVE-2026-97229``)
was covered **entirely**, all 59 carrying SSVC decision points and 35 carrying a
CVSS the KEV catalogue never provides.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/cisa_vulnrichment.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.cve_lookup import CveLookupCollector  # noqa: E402
from lib.attribution import load_register  # noqa: E402
from lib.config import load_settings  # noqa: E402
from lib.http import HttpClient  # noqa: E402
from lib.logging_setup import configure_logging  # noqa: E402
from normalization.vulnrichment import (  # noqa: E402
    build_observation,
    parse_vulnrichment_record,
    record_url,
)
from state.record_cache import RecordCache  # noqa: E402
from state.store import StateStore, utc_now_iso  # noqa: E402

#: The cache file. CISA's assessment of a CVE does not change with time the way a
#: sighting count or an errata list does, so records are kept for a long time —
#: but not forever. A 90-day refresh exists so that a **change to the normaliser**
#: eventually reaches records already cached: without it, a payload shape change
#: would apply only to newly fetched CVEs and the cache would silently hold two
#: generations of data.
CACHE_FILENAME = "vulnrichment_cache.json"
REFRESH_AFTER_DAYS = 90


class CisaVulnrichmentCollector(CveLookupCollector):
    """Fetches CISA Vulnrichment records for the CVEs the pipeline discovered."""

    label = "cisa vulnrichment"

    def build_cache(self, state: StateStore) -> RecordCache:
        return RecordCache(
            state, filename=CACHE_FILENAME, refresh_after_days=REFRESH_AFTER_DAYS
        )

    def lookup_url(self, cve_id: str) -> str:
        # ``feed_url`` is the repository base: the record path is derived per CVE.
        return record_url(self.config.feed_url, cve_id)

    def parse_record(self, payload: object) -> dict:
        return parse_vulnrichment_record(payload).to_payload(
            source_key=self.config.key
        )

    def build_observation(self, payload: dict, *, retrieved_at: str):
        return build_observation(
            payload, source_key=self.config.key, retrieved_at=retrieved_at
        )

    def tlp_scan_texts(self, payload: dict) -> tuple[str, ...]:
        # CVE records carry no handling caveat, but a stray marking in the prose
        # must not reach the publication's TLP scan, which blocks the whole run.
        return (
            payload.get("title") or "",
            payload.get("description") or "",
        )

    def extra_metrics(self, observations: list) -> dict:
        return {
            "records_with_cvss": sum(
                1 for observation in observations if observation.payload.get("cvss")
            ),
            "records_with_ssvc": sum(
                1 for observation in observations if observation.payload.get("ssvc")
            ),
        }


def build_collector(settings, *, cve_ids=()) -> CisaVulnrichmentCollector:
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

    return CisaVulnrichmentCollector(
        settings.source("cisa_vulnrichment"),
        http,
        state,
        register=load_register(),
        cve_ids=cve_ids,
    )


def main() -> int:
    """CLI: enriches the CVEs supplied as arguments, or the KEV snapshot."""

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

    print("ThreatPulse — CISA Vulnrichment collector")
    print("-----------------------------------------")
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
        "records_with_ssvc",
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

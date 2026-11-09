#!/usr/bin/env python3
"""ENISA EUVD collector — the EU-authoritative vulnerability record.

Two verified endpoints:

* ``/api/exploitedvulnerabilities`` — ENISA's own exploited-in-the-wild list,
  carrying an ``exploitedSince`` date;
* ``/api/lastvulnerabilities`` — the most recently published EUVD records.

Both return at most eight records, so this is a **recent window** rather than a
full enricher. That is stated plainly rather than hidden: it enriches the KEV
threats whose CVEs appear in that window, and nothing more.

Every record is CVE-keyed (the identifier is extracted from the ``aliases``
string), so it joins the existing KEV-scored threats as evidence.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/enisa_euvd.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import source_from_config  # noqa: E402
from lib.attribution import AttributionRegister, load_register  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402
from normalization.euvd import (  # noqa: E402
    EuvdRecord,
    build_observation,
    parse_euvd_payload,
)
from state.store import StateStore, utc_now_iso  # noqa: E402

LOGGER = get_logger("collectors.enisa_euvd")

MAX_REPORTED_FAILURES = 10


def is_exploited_endpoint(url: str) -> bool:
    """Whether a configured endpoint is the exploited-in-the-wild list."""

    return "exploited" in (url or "").lower()


def deduplicate(records: list[EuvdRecord]) -> list[EuvdRecord]:
    """One record per EUVD id, preferring the exploited variant.

    The same vulnerability can appear on both endpoints. The exploited record
    carries the ``exploitedSince`` date, so it is the more informative one.
    """

    best: dict[str, EuvdRecord] = {}

    for record in records:
        existing = best.get(record.euvd_id)

        if existing is None or (record.exploited and not existing.exploited):
            best[record.euvd_id] = record

    return [best[key] for key in sorted(best)]


class EuvdCollector:
    """Collects ENISA EUVD records from one or more verified endpoints."""

    def __init__(
        self,
        config: SourceConfig,
        http: HttpClient,
        state: StateStore,
        *,
        register: AttributionRegister,
    ) -> None:
        self.config = config
        self.source = source_from_config(config)
        self._http = http
        self._state = state

        record = register.require(config.key)

        self._tlp_default = record.tlp_default
        self._feed_urls = list(config.feed_urls)

    def collect(self, retrieved_at: str) -> SourceResult:
        records: list[EuvdRecord] = []

        endpoints_ok = 0
        failures: list[dict[str, str]] = []
        records_seen = 0
        rejected_records = 0

        for feed_url in self._feed_urls:
            try:
                payload = self._http.get(
                    feed_url, timeout_seconds=self.config.timeout_seconds
                ).json()
                parsed, rejected = parse_euvd_payload(
                    payload, exploited=is_exploited_endpoint(feed_url)
                )
            except (HttpError, NormalizationError) as error:
                failures.append({"feed_url": feed_url, "reason": str(error)})
                continue

            endpoints_ok += 1
            records_seen += len(parsed)
            rejected_records += len(rejected)
            records.extend(parsed)

        unique = deduplicate(records)

        with_cve = [record for record in unique if record.cve_ids]
        exploited = [record for record in unique if record.exploited]

        metrics = {
            "endpoints_configured": len(self._feed_urls),
            "endpoints_ok": endpoints_ok,
            "endpoints_failed": len(self._feed_urls) - endpoints_ok,
            "records_seen": records_seen,
            "records_accepted": len(unique),
            "records_with_cve": len(with_cve),
            "records_without_cve": len(unique) - len(with_cve),
            "exploited_records": len(exploited),
            "cve_ids_extracted": sum(len(record.cve_ids) for record in unique),
            "rejected_records": rejected_records,
            "tlp_default": self._tlp_default,
            "failures": failures[:MAX_REPORTED_FAILURES],
        }

        if not unique:
            return self._degrade_or_fail(
                reason=(
                    "no EUVD records retrieved: "
                    f"{endpoints_ok}/{len(self._feed_urls)} endpoints succeeded, "
                    f"{records_seen} records seen"
                ),
                transient=endpoints_ok == 0 and bool(failures),
                metrics=metrics,
            )

        observations = [
            build_observation(
                record,
                source_key=self.config.key,
                retrieved_at=retrieved_at,
            )
            for record in unique
        ]

        self._state.save_last_known_good(
            self.config.key,
            observations,
            retrieved_at=retrieved_at,
            metrics=metrics,
        )

        log_event(
            LOGGER,
            logging.INFO,
            "euvd records collected",
            source_key=self.config.key,
            records=len(unique),
            with_cve=len(with_cve),
            exploited=len(exploited),
            cves=metrics["cve_ids_extracted"],
        )

        return SourceResult(
            source=self.source,
            status="ok",
            observations=observations,
            metrics=metrics,
        )

    def _degrade_or_fail(
        self, *, reason: str, transient: bool, metrics: dict
    ) -> SourceResult:
        log_event(
            LOGGER,
            logging.WARNING,
            "euvd collection failed",
            source_key=self.config.key,
            reason=reason,
        )

        snapshot = self._state.load_last_known_good(self.config.key)

        if snapshot:
            log_event(
                LOGGER,
                logging.WARNING,
                "using last known good snapshot",
                source_key=self.config.key,
                observations=len(snapshot["observations"]),
                snapshot_retrieved_at=snapshot.get("retrieved_at"),
            )

            return SourceResult(
                source=self.source,
                status="degraded",
                observations=snapshot["observations"],
                metrics={
                    **metrics,
                    "snapshot_retrieved_at": snapshot.get("retrieved_at"),
                },
                failure_reason=reason,
                failure_transient=transient,
                used_last_known_good=True,
            )

        return SourceResult(
            source=self.source,
            status="failed",
            metrics=metrics,
            failure_reason=reason,
            failure_transient=transient,
        )


def build_collector(settings) -> EuvdCollector:
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

    return EuvdCollector(
        settings.source("enisa_euvd"),
        http,
        state,
        register=load_register(),
    )


def main() -> int:
    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    result = build_collector(settings).collect(utc_now_iso())

    print("ThreatPulse — ENISA EUVD collector")
    print("----------------------------------")
    print(f"Status:  {result.status}")
    print(f"Records: {len(result.observations)}")

    for key in (
        "endpoints_ok",
        "endpoints_failed",
        "records_seen",
        "records_with_cve",
        "exploited_records",
        "cve_ids_extracted",
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


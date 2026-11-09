#!/usr/bin/env python3
"""CISA KEV collector.

Migrated from the pre-existing ``collectors/cisa_kev.py`` script. Behaviour
preserved deliberately:

* the same feed URL, the same required-field validation and the same normalized
  field names (``cve_id``, ``vendor``, ``product``, ``vulnerability_name``,
  ``date_added``, ``description``, ``required_action``, ``due_date``,
  ``known_ransomware_campaign_use``, ``forensic_triage``, ``notes``, ``cwes``,
  ``source``, ``exploited_in_wild``, ``kev_listed``);
* the same normalized snapshot file
  (``data/known_exploited_vulnerabilities.json``) so existing tooling works;
* a CLI entry point with the same exit-code contract.

Added: configurable timeouts, structured logging, bounded retries, per-record
rejection with reasons, last-known-good fallback and collection metrics.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/cisa_kev.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from models.intelligence import Observation, Source  # noqa: E402
from normalization.cisa import (  # noqa: E402
    NormalizationError,
    build_entities,
    parse_kev_record,
)
from state.store import StateStore, utc_now_iso  # noqa: E402

LOGGER = get_logger("collectors.cisa_kev")

MAX_REJECTION_RATIO = 0.20
MAX_REPORTED_REJECTIONS = 5


class FeedRejected(RuntimeError):
    """The feed was retrieved but could not be trusted."""


def source_from_config(config: SourceConfig) -> Source:
    return Source(
        key=config.key,
        name=config.name,
        source_type=config.source_type,
        url=config.url,
        provider=config.provider,
        reliability=config.reliability,
    )


class CisaKevCollector:
    """Collects, validates and normalises the CISA KEV catalogue."""

    def __init__(
        self, config: SourceConfig, http: HttpClient, state: StateStore
    ) -> None:
        self.config = config
        self.source = source_from_config(config)
        self._http = http
        self._state = state

    def collect(self, retrieved_at: str) -> SourceResult:
        try:
            payload = self._http.get(
                self.config.feed_url,
                timeout_seconds=self.config.timeout_seconds,
            ).json()
            observations, metrics = self._interpret(payload, retrieved_at)
        except HttpError as error:
            return self._degrade_or_fail(
                reason=f"feed retrieval failed: {error}", transient=error.transient
            )
        except FeedRejected as error:
            return self._degrade_or_fail(reason=str(error), transient=False)

        self._state.save_last_known_good(
            self.config.key,
            observations,
            retrieved_at=retrieved_at,
            metrics=metrics,
        )

        log_event(
            LOGGER,
            logging.INFO,
            "cisa kev collected",
            observations=len(observations),
            **metrics,
        )

        return SourceResult(
            source=self.source,
            status="ok",
            observations=observations,
            metrics=metrics,
        )

    # -- internals ---------------------------------------------------------

    def _interpret(self, payload, retrieved_at: str):
        if not isinstance(payload, dict):
            raise FeedRejected("feed root is not a JSON object")

        records = payload.get("vulnerabilities")

        if not isinstance(records, list) or not records:
            raise FeedRejected("feed has no 'vulnerabilities' array")

        observations: list[Observation] = []
        rejections: list[str] = []

        for entry in records:
            try:
                record = parse_kev_record(entry)
            except NormalizationError as error:
                if len(rejections) < MAX_REPORTED_REJECTIONS:
                    rejections.append(str(error))
                continue

            observations.append(
                Observation(
                    source_key=self.config.key,
                    external_id=record.cve_id,
                    observed_at=record.date_added or retrieved_at,
                    retrieved_at=retrieved_at,
                    source_record_id=record.cve_id,
                    payload=record.to_payload(),
                    entities=build_entities(record),
                )
            )

        rejected = len(records) - len(observations)

        if not observations:
            raise FeedRejected(
                f"no usable records ({rejected} rejected): " + "; ".join(rejections)
            )

        if rejected / len(records) > MAX_REJECTION_RATIO:
            raise FeedRejected(
                f"rejection ratio {rejected / len(records):.0%} exceeds "
                f"{MAX_REJECTION_RATIO:.0%} — the feed shape may have changed"
            )

        declared = payload.get("count")

        metrics = {
            "feed_records": len(records),
            "declared_count": declared if isinstance(declared, int) else None,
            "accepted": len(observations),
            "rejected": rejected,
            "rejection_examples": rejections,
            "catalog_version": payload.get("catalogVersion"),
            "date_released": payload.get("dateReleased"),
        }

        if isinstance(declared, int) and declared != len(records):
            metrics["count_mismatch"] = True
            log_event(
                LOGGER,
                logging.WARNING,
                "declared count differs from array length",
                declared_count=declared,
                actual=len(records),
            )

        return observations, metrics

    def _degrade_or_fail(self, *, reason: str, transient: bool) -> SourceResult:
        log_event(LOGGER, logging.WARNING, "cisa kev collection failed", reason=reason)

        snapshot = self._state.load_last_known_good(self.config.key)

        if snapshot:
            log_event(
                LOGGER,
                logging.WARNING,
                "using last known good snapshot",
                observations=len(snapshot["observations"]),
                snapshot_retrieved_at=snapshot.get("retrieved_at"),
            )

            return SourceResult(
                source=self.source,
                status="degraded",
                observations=snapshot["observations"],
                metrics={
                    "snapshot_retrieved_at": snapshot.get("retrieved_at"),
                    "snapshot_metrics": snapshot.get("metrics") or {},
                },
                failure_reason=reason,
                failure_transient=transient,
                used_last_known_good=True,
            )

        return SourceResult(
            source=self.source,
            status="failed",
            failure_reason=reason,
            failure_transient=transient,
        )


def write_normalized_snapshot(path: Path, result: SourceResult, collected_at: str) -> None:
    """Writes the normalized snapshot in the format existing tooling expects."""

    from lib.atomic import write_json_atomic

    write_json_atomic(
        path,
        {
            "collector": result.source.key,
            "collector_version": "0.2.0",
            "source_url": result.source.url,
            "collected_at": collected_at,
            "status": result.status,
            "record_count": len(result.observations),
            "metrics": result.metrics,
            "records": [observation.payload for observation in result.observations],
        },
    )


def build_collector(settings) -> CisaKevCollector:
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

    return CisaKevCollector(settings.source("cisa_kev"), http, state)


def main() -> int:
    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    collected_at = utc_now_iso()
    result = build_collector(settings).collect(collected_at)

    print("ThreatPulse — CISA KEV collector")
    print("--------------------------------")
    print(f"Status:  {result.status}")
    print(f"Records: {len(result.observations)}")

    if result.failure_reason:
        print(f"Reason:  {result.failure_reason}")

    if not result.usable:
        print("ERROR: no usable observations.", file=sys.stderr)
        return 1

    output = settings.data_directory / "known_exploited_vulnerabilities.json"
    write_normalized_snapshot(output, result, collected_at)
    print(f"Normalized snapshot written to: {output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


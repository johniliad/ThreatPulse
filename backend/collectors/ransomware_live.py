#!/usr/bin/env python3
"""Ransomware.live collector — observed victim aggregates for regional relevance.

This is the primary **observed** evidence for regional scoring: it reports where
ransomware victims have actually been claimed, by country and sector, instead of
inferring relevance from vendor or product prevalence.

Three rules are enforced here:

* **Privacy.** Victim identities are reduced to aggregates before anything is
  stored, logged or published (see ``normalization.ransomware_live``).
* **Counts must not be lost.** Several victims claimed by one group in one
  country and sector become a single observation with a count, so the signal
  survives while the identities do not.
* **Counts must not be inflated.** Overlapping feeds report the same claims.
  Counts are merged with ``max()``, never ``sum()``, so adding a country-specific
  feed cannot double the apparent intensity of a regional signal.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/ransomware_live.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import source_from_config  # noqa: E402
from lib.attribution import AttributionRegister, load_register  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402
from normalization.ransomware_live import (  # noqa: E402
    VictimObservation,
    aggregate_victims,
    build_observation,
    parse_victims,
)
from state.store import StateStore, utc_now_iso  # noqa: E402

LOGGER = get_logger("collectors.ransomware_live")

MAX_REPORTED_FAILURES = 10

#: The country whose victims are counted separately in metrics, so the country-scoped
#: pull can be verified in the run report.
PRIMARY_COUNTRY = "GR"


def _aggregate_key(observation: VictimObservation) -> tuple[str, str, str, str]:
    return (
        observation.group.lower(),
        observation.country,
        (observation.sector or "").lower(),
        observation.attack_date or "",
    )


def merge_feeds(
    per_feed: list[list[VictimObservation]],
) -> list[VictimObservation]:
    """Merges per-feed aggregates using the maximum count per key.

    Overlapping feeds describe the same victim claims. Summing them would
    overstate a regional signal; taking the maximum keeps a conservative floor.
    """

    merged: dict[tuple[str, str, str, str], VictimObservation] = {}

    for observations in per_feed:
        for observation in observations:
            key = _aggregate_key(observation)
            existing = merged.get(key)

            if existing is None or observation.victim_count > existing.victim_count:
                merged[key] = observation

    return [merged[key] for key in sorted(merged)]


class RansomwareLiveCollector:
    """Collects observed victim aggregates from one or more endpoints."""

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
        per_feed: list[list[VictimObservation]] = []
        failures: list[dict[str, str]] = []
        rejections: list[str] = []
        feeds_ok = 0
        claims_seen = 0

        for feed_url in self._feed_urls:
            try:
                payload = self._http.get(
                    feed_url, timeout_seconds=self.config.timeout_seconds
                ).json()
                parsed, rejected = parse_victims(payload)
            except (HttpError, NormalizationError) as error:
                failures.append({"feed_url": feed_url, "reason": str(error)})
                continue

            feeds_ok += 1
            claims_seen += len(parsed)
            rejections.extend(rejected)

            per_feed.append(aggregate_victims(parsed))

        aggregates = merge_feeds(per_feed)

        primary_country = [
            observation
            for observation in aggregates
            if observation.country == PRIMARY_COUNTRY
        ]

        metrics = {
            "feeds_configured": len(self._feed_urls),
            "feeds_ok": feeds_ok,
            "feeds_failed": len(failures),
            "victim_claims_seen": claims_seen,
            "aggregates": len(aggregates),
            "victim_count_total": sum(
                observation.victim_count for observation in aggregates
            ),
            "countries_observed": len(
                {observation.country for observation in aggregates}
            ),
            "primary_country_aggregates": len(primary_country),
            "primary_country_victim_count": sum(
                observation.victim_count for observation in primary_country
            ),
            "rejected_records": len(rejections),
            "tlp_default": self._tlp_default,
            "partial": bool(failures) and feeds_ok > 0,
            "failures": failures[:MAX_REPORTED_FAILURES],
        }

        if not aggregates:
            return self._degrade_or_fail(
                reason=(
                    "no victim aggregates retrieved: "
                    f"{feeds_ok}/{len(self._feed_urls)} endpoints succeeded, "
                    f"{claims_seen} claims seen, {len(rejections)} rejected"
                ),
                transient=feeds_ok == 0 and bool(failures),
                metrics=metrics,
            )

        observations = [
            build_observation(
                observation,
                source_key=self.config.key,
                retrieved_at=retrieved_at,
            )
            for observation in aggregates
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
            "ransomware victim aggregates collected",
            source_key=self.config.key,
            aggregates=len(aggregates),
            countries=metrics["countries_observed"],
            primary_country_aggregates=metrics["primary_country_aggregates"],
            feeds_failed=len(failures),
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
            "ransomware.live collection failed",
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


def build_collector(settings) -> RansomwareLiveCollector:
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

    return RansomwareLiveCollector(
        settings.source("ransomware_live"),
        http,
        state,
        register=load_register(),
    )


def main() -> int:
    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    result = build_collector(settings).collect(utc_now_iso())

    print("ThreatPulse — ransomware.live collector")
    print("---------------------------------------")
    print(f"Status:  {result.status}")
    print(f"Records: {len(result.observations)}")

    for key in (
        "feeds_ok",
        "feeds_failed",
        "victim_claims_seen",
        "countries_observed",
        "primary_country_aggregates",
        "primary_country_victim_count",
    ):
        if key in result.metrics:
            print(f"{key}: {result.metrics[key]}")

    if result.failure_reason:
        print(f"Reason:  {result.failure_reason}")

    if not result.usable:
        print("ERROR: no usable observations.", file=sys.stderr)
        return 1

    print("\nNote: victim identities are withheld by design. Only country, sector,")
    print("group and date aggregates are stored and published.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())



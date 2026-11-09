#!/usr/bin/env python3
"""EPSS collector — exploitation probability for CVEs the pipeline knows about.

This source is **dependent**: it is queried with the CVE identifiers already
discovered by the other collectors, rather than fetched wholesale. That is
deliberate — EPSS covers hundreds of thousands of vulnerabilities, and
ThreatPulse publishes intelligence, not a vulnerability index.

Consequences of being dependent:

* an empty CVE list is a **no-op, not a failure** — nothing is fetched, nothing
  is written to state, and the run continues;
* batching respects the API's 100-row limit;
* one failed batch does not discard the batches that succeeded.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/epss.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import source_from_config  # noqa: E402
from lib.attribution import AttributionRegister, load_register  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402
from normalization.epss import (  # noqa: E402
    MAX_BATCH_SIZE,
    build_epss_observation,
    parse_epss_payload,
)
from state.store import StateStore, utc_now_iso  # noqa: E402

LOGGER = get_logger("collectors.epss")

#: Maximum per-batch failures reported in metrics, to bound report size.
MAX_REPORTED_FAILURES = 10


class EpssCollector:
    """Fetches EPSS scores for a supplied set of CVE identifiers."""

    def __init__(
        self,
        config: SourceConfig,
        http: HttpClient,
        state: StateStore,
        *,
        register: AttributionRegister,
        cve_ids: object = (),
        batch_size: int = MAX_BATCH_SIZE,
    ) -> None:
        self.config = config
        self.source = source_from_config(config)
        self._http = http
        self._state = state

        record = register.require(config.key)

        self._tlp_default = record.tlp_default
        self._cve_ids = sorted(
            {
                str(cve).strip().upper()
                for cve in (cve_ids or ())
                if str(cve).strip()
            }
        )
        self._batch_size = max(1, min(int(batch_size), MAX_BATCH_SIZE))

    def collect(self, retrieved_at: str) -> SourceResult:
        if not self._cve_ids:
            log_event(
                LOGGER,
                logging.INFO,
                "epss collection skipped",
                source_key=self.config.key,
                reason="no CVE identifiers supplied",
            )

            return SourceResult(
                source=self.source,
                status="ok",
                observations=[],
                metrics={
                    "skipped": True,
                    "reason": "no CVE identifiers supplied",
                    "cves_requested": 0,
                    "tlp_default": self._tlp_default,
                },
            )

        observations = []
        returned: set[str] = set()
        rejections: list[str] = []
        failures: list[dict[str, object]] = []
        batches_total = 0

        for start in range(0, len(self._cve_ids), self._batch_size):
            batch = self._cve_ids[start : start + self._batch_size]
            batches_total += 1

            url = (
                f"{self.config.feed_url}"
                f"?cve={','.join(batch)}&limit={self._batch_size}"
            )

            try:
                payload = self._http.get(
                    url, timeout_seconds=self.config.timeout_seconds
                ).json()
                records, rejected = parse_epss_payload(payload)
            except (HttpError, NormalizationError) as error:
                failures.append({"batch": batches_total, "reason": str(error)})
                continue

            rejections.extend(rejected)

            for record in records:
                returned.add(record.cve_id)

                observations.append(
                    build_epss_observation(
                        record,
                        source_key=self.config.key,
                        retrieved_at=retrieved_at,
                    )
                )

        batches_ok = batches_total - len(failures)

        metrics = {
            "cves_requested": len(self._cve_ids),
            "cves_returned": len(returned),
            "cves_missing": len(self._cve_ids) - len(returned),
            "batches_total": batches_total,
            "batches_ok": batches_ok,
            "batches_failed": len(failures),
            "rejected_records": len(rejections),
            "tlp_default": self._tlp_default,
            "failures": failures[:MAX_REPORTED_FAILURES],
        }

        if not observations:
            return self._degrade_or_fail(
                reason=(
                    "no EPSS scores retrieved: "
                    f"{batches_ok}/{batches_total} batches succeeded"
                ),
                transient=batches_ok == 0,
                metrics=metrics,
            )

        self._state.save_last_known_good(
            self.config.key,
            observations,
            retrieved_at=retrieved_at,
            metrics=metrics,
        )

        log_event(
            LOGGER,
            logging.INFO,
            "epss scores collected",
            source_key=self.config.key,
            observations=len(observations),
            missing=metrics["cves_missing"],
            batches_failed=len(failures),
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
            "epss collection failed",
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


def build_collector(settings, *, cve_ids=()) -> EpssCollector:
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

    return EpssCollector(
        settings.source("epss_first"),
        http,
        state,
        register=load_register(),
        cve_ids=cve_ids,
    )


def main() -> int:
    """CLI: scores the CVEs supplied as arguments, or the KEV snapshot."""

    import json

    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    cve_ids = [argument for argument in sys.argv[1:] if argument]

    if not cve_ids:
        snapshot = settings.data_directory / "known_exploited_vulnerabilities.json"
        raw = json.loads(snapshot.read_text(encoding="utf-8")) if snapshot.exists() else {}

        cve_ids = [
            str(record.get("cve_id"))
            for record in (raw.get("records") or [])
            if isinstance(record, dict) and record.get("cve_id")
        ]

        print(f"No CVEs given; using {len(cve_ids)} from the KEV snapshot.")

    retrieved_at = utc_now_iso()
    result = build_collector(settings, cve_ids=cve_ids).collect(retrieved_at)

    print("ThreatPulse — EPSS collector")
    print("----------------------------")
    print(f"Status:  {result.status}")
    print(f"Records: {len(result.observations)}")

    for key in ("cves_requested", "cves_returned", "cves_missing", "batches_failed"):
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


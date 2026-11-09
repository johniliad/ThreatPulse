#!/usr/bin/env python3
"""CISA CSAF collector — the IT and OT advisory streams, machine-readable.

Replaces the CISA RSS feed, which answers HTTP 403 to server-side clients. CISA
publishes the same advisories as CSAF 2.0 documents in the ``cisagov/CSAF``
repository, which also carries the standard discovery files:

* ``changes.csv`` — every advisory path with its revision timestamp, newest first
* ``index.txt`` — the CSAF index
* ``cisa-csaf-*-feed-tlp-white.json`` — a ROLIE feed

``changes.csv`` is fetched once per tree, then only the most recent advisories are
retrieved. That keeps a run to a bounded number of requests and avoids cloning a
multi-megabyte repository.

**TLP is enforced from the document itself.** Each CSAF document states its own
handling marking in ``document.distribution.tlp.label``, so the gate enforces
what the publisher declared rather than a default we assume on its behalf. Note
that CSAF uses the TLP 1.0 spelling (``WHITE``), which is normalised before the
gate sees it — otherwise ``WHITE`` would not match the ingestible level
``CLEAR`` and every advisory would be wrongly rejected.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/cisa_csaf.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import source_from_config  # noqa: E402
from lib.attribution import AttributionRegister, load_register  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from lib.tlp import evaluate, normalize_marking  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402
from normalization.csaf import (  # noqa: E402
    build_observation,
    parse_changes_csv,
    parse_csaf_advisory,
)
from state.store import StateStore, utc_now_iso  # noqa: E402

LOGGER = get_logger("collectors.cisa_csaf")

#: Advisories retrieved per tree per run.
MAX_ADVISORIES_PER_FEED = 40

#: Per-document failures reported in metrics, to bound report size.
MAX_REPORTED_FAILURES = 10


def item_markings(label: str | None) -> list[str]:
    """Normalises a CSAF TLP label for the gate.

    ``WHITE`` becomes ``CLEAR`` (the TLP 2.0 spelling). An unrecognised label
    becomes ``UNKNOWN`` so the gate refuses it rather than treating the document
    as unmarked and therefore public.
    """

    if not label:
        return []

    normalised = normalize_marking(label)

    return [normalised] if normalised else ["UNKNOWN"]


class CisaCsafCollector:
    """Collects CISA CSAF advisories from one or more discovery trees."""

    def __init__(
        self,
        config: SourceConfig,
        http: HttpClient,
        state: StateStore,
        *,
        register: AttributionRegister,
        max_advisories: int = MAX_ADVISORIES_PER_FEED,
    ) -> None:
        self.config = config
        self.source = source_from_config(config)
        self._http = http
        self._state = state

        record = register.require(config.key)

        self._tlp_default = record.tlp_default
        self._changes_urls = list(config.feed_urls)
        self._max_advisories = max(1, int(max_advisories))

    def collect(self, retrieved_at: str) -> SourceResult:
        observations = []
        seen_tracking_ids: set[str] = set()

        feeds_ok = 0
        failures: list[dict[str, str]] = []
        advisories_seen = 0
        rejected_tlp = 0
        rejected_malformed = 0
        cves_extracted = 0
        advisories_without_cve = 0

        for changes_url in self._changes_urls:
            base = changes_url.rsplit("/", 1)[0]

            try:
                body = self._http.get(
                    changes_url,
                    timeout_seconds=self.config.timeout_seconds,
                    headers={"Accept": "text/csv, text/plain, */*"},
                ).body
                rows = parse_changes_csv(body, limit=self._max_advisories)
            except (HttpError, NormalizationError) as error:
                failures.append({"changes_url": changes_url, "reason": str(error)})
                continue

            feeds_ok += 1

            for path, _timestamp in rows:
                document_url = f"{base}/{path}"

                try:
                    payload = self._http.get(
                        document_url, timeout_seconds=self.config.timeout_seconds
                    ).json()
                    advisory = parse_csaf_advisory(
                        payload, document_url=document_url
                    )
                except (HttpError, NormalizationError) as error:
                    rejected_malformed += 1
                    failures.append(
                        {"document_url": document_url, "reason": str(error)}
                    )
                    continue

                advisories_seen += 1

                allowed, reason = evaluate(
                    source_default=self._tlp_default,
                    item_markings=item_markings(advisory.tlp_label),
                )

                if not allowed:
                    rejected_tlp += 1

                    log_event(
                        LOGGER,
                        logging.WARNING,
                        "CSAF advisory rejected by the TLP gate",
                        source_key=self.config.key,
                        tracking_id=advisory.tracking_id,
                        reason=reason,
                    )
                    continue

                if advisory.tracking_id in seen_tracking_ids:
                    continue

                seen_tracking_ids.add(advisory.tracking_id)

                if advisory.cve_ids:
                    cves_extracted += len(advisory.cve_ids)
                else:
                    advisories_without_cve += 1

                observations.append(
                    build_observation(
                        advisory,
                        source_key=self.config.key,
                        retrieved_at=retrieved_at,
                    )
                )

        metrics = {
            "feeds_configured": len(self._changes_urls),
            "feeds_ok": feeds_ok,
            "feeds_failed": len(self._changes_urls) - feeds_ok,
            "advisories_seen": advisories_seen,
            "advisories_accepted": len(observations),
            "advisories_without_cve": advisories_without_cve,
            "cves_extracted": cves_extracted,
            "rejected_tlp": rejected_tlp,
            "rejected_malformed": rejected_malformed,
            "tlp_default": self._tlp_default,
            "failures": failures[:MAX_REPORTED_FAILURES],
        }

        if not observations:
            return self._degrade_or_fail(
                reason=(
                    "no CSAF advisories retrieved: "
                    f"{feeds_ok}/{len(self._changes_urls)} trees succeeded, "
                    f"{advisories_seen} documents seen, {rejected_tlp} rejected by "
                    "the TLP gate"
                ),
                transient=feeds_ok == 0 and bool(failures),
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
            "cisa csaf advisories collected",
            source_key=self.config.key,
            advisories=len(observations),
            cves=cves_extracted,
            without_cve=advisories_without_cve,
            rejected_tlp=rejected_tlp,
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
            "cisa csaf collection failed",
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


def build_collector(settings) -> CisaCsafCollector:
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

    return CisaCsafCollector(
        settings.source("cisa_csaf"),
        http,
        state,
        register=load_register(),
    )


def main() -> int:
    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    result = build_collector(settings).collect(utc_now_iso())

    print("ThreatPulse — CISA CSAF collector")
    print("---------------------------------")
    print(f"Status:  {result.status}")
    print(f"Records: {len(result.observations)}")

    for key in (
        "feeds_ok",
        "feeds_failed",
        "advisories_seen",
        "advisories_accepted",
        "advisories_without_cve",
        "cves_extracted",
        "rejected_tlp",
        "rejected_malformed",
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



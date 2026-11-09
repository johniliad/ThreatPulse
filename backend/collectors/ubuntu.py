#!/usr/bin/env python3
"""Ubuntu Security Notices collector — Canonical's own advisory record.

A **first-party vendor** source. Canonical states which of its releases a CVE affects
and which packages fix it, which no upstream CVE record says.

One request, and that is by design
----------------------------------

``notices.json`` returns the notices *with* the CVEs they address, so a single bounded
fetch yields a CVE-to-advisory mapping. The detail endpoint is not needed, and Ubuntu
offers no per-CVE lookup at all — ``/security/CVE-2021-44228.json`` returns 404 for a
CVE that certainly exists — so the dependent lookup pattern Red Hat and MSRC use is not
available here. Both facts were checked before this was written.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/ubuntu.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import source_from_config  # noqa: E402
from lib.attribution import AttributionRegister, load_register  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from lib.tlp import evaluate  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402
from normalization.ubuntu import build_observations, parse_notices  # noqa: E402
from state.store import StateStore, utc_now_iso  # noqa: E402

LOGGER = get_logger("collectors.ubuntu")

#: The API's hard maximum. ``limit=21`` returns HTTP 422, so this is not a choice.
PAGE_SIZE = 20

#: Pages requested per run, so a run is bounded at ``PAGE_SIZE * DEFAULT_PAGES``
#: notices. Each page is one request.
DEFAULT_PAGES = 10

MAX_BODY_BYTES = 16 * 1024 * 1024


class UbuntuSecurityCollector:
    """Fetches Ubuntu security notices and emits one observation per CVE."""

    key = "ubuntu_security"

    def __init__(
        self,
        config: SourceConfig,
        http: HttpClient,
        state: StateStore,
        *,
        register: AttributionRegister,
        pages: int = DEFAULT_PAGES,
    ) -> None:
        self.config = config
        self.source = source_from_config(config)
        self._http = http
        self._state = state
        self._pages = max(1, int(pages))

        record = register.require(config.key)

        self._tlp_default = record.tlp_default

    def page_url(self, offset: int) -> str:
        base = (self.config.feed_url or "").rstrip("/")

        return f"{base}?limit={PAGE_SIZE}&offset={max(0, int(offset))}"

    def collect(self, retrieved_at: str) -> SourceResult:
        allowed, reason = evaluate(source_default=self._tlp_default, item_markings=())

        if not allowed:
            return self._degrade_or_fail(
                reason=f"the TLP gate refuses this source: {reason}",
                transient=False,
                metrics={"tlp_default": self._tlp_default},
            )

        notices: list[dict] = []
        failures: list[str] = []
        pages_fetched = 0

        for page in range(self._pages):
            url = self.page_url(page * PAGE_SIZE)

            try:
                payload = self._http.get(
                    url,
                    timeout_seconds=self.config.timeout_seconds,
                    max_bytes=MAX_BODY_BYTES,
                ).json()
            except (HttpError, ValueError) as error:
                failures.append(f"offset={page * PAGE_SIZE}: {error}")
                # A failed page stops the sweep rather than skipping it: pages are
                # contiguous, so a gap would silently drop a slice of the history.
                break

            try:
                batch = parse_notices(payload)
            except NormalizationError as error:
                failures.append(f"offset={page * PAGE_SIZE}: {error}")
                break

            pages_fetched += 1
            notices.extend(batch)

            # A short page is the end of the history.
            if len(batch) < PAGE_SIZE:
                break

        if not notices:
            return self._degrade_or_fail(
                reason=(
                    "no Ubuntu notices retrieved: "
                    f"{pages_fetched} pages fetched, {len(failures)} failures"
                ),
                transient=bool(failures),
                metrics={
                    "pages_requested": self._pages,
                    "pages_fetched": pages_fetched,
                    "failures": failures[:5],
                },
            )

        observations = build_observations(
            notices, source_key=self.config.key, retrieved_at=retrieved_at
        )

        with_cves = sum(1 for notice in notices if notice.get("cves"))

        metrics = {
            "feed_url": self.page_url(0),
            "page_size": PAGE_SIZE,
            "pages_requested": self._pages,
            "pages_fetched": pages_fetched,
            "notices_parsed": len(notices),
            "notices_with_cves": with_cves,
            "notices_without_cves": len(notices) - with_cves,
            "records": len(observations),
            "distinct_cves": len({item.external_id for item in observations}),
            "releases_seen": len(
                {
                    release
                    for notice in notices
                    for release in notice.get("releases") or []
                }
            ),
            "tlp_default": self._tlp_default,
        }

        if failures:
            metrics["failures"] = failures[:5]

        if not observations:
            return self._degrade_or_fail(
                reason=(
                    f"no Ubuntu observations: {len(notices)} notices parsed, "
                    f"{with_cves} naming a CVE"
                ),
                transient=False,
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
            "ubuntu notices collected",
            source_key=self.config.key,
            notices=len(notices),
            records=len(observations),
            distinct_cves=metrics["distinct_cves"],
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
            "ubuntu collection failed",
            source_key=self.config.key,
            reason=reason,
        )

        snapshot = self._state.load_last_known_good(self.config.key)

        if snapshot:
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


def build_collector(settings, *, pages: int = DEFAULT_PAGES):
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

    return UbuntuSecurityCollector(
        settings.source("ubuntu_security"),
        http,
        state,
        register=load_register(),
        pages=pages,
    )


def main() -> int:
    """CLI: one bounded sweep of the notices list."""

    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    pages = DEFAULT_PAGES

    for argument in sys.argv[1:]:
        if argument.startswith("--pages="):
            pages = int(argument.split("=", 1)[1])

    result = build_collector(settings, pages=pages).collect(utc_now_iso())

    print("ThreatPulse — Ubuntu Security Notices collector")
    print("-----------------------------------------------")
    print(f"Status:  {result.status}")
    print(f"Records: {len(result.observations)}")

    for key in (
        "page_size",
        "pages_requested",
        "pages_fetched",
        "notices_parsed",
        "notices_with_cves",
        "notices_without_cves",
        "records",
        "distinct_cves",
        "releases_seen",
    ):
        if key in result.metrics:
            print(f"{key}: {result.metrics[key]}")

    for failure in result.metrics.get("failures") or ():
        print(f"failure: {failure}")

    if result.failure_reason:
        print(f"Reason:  {result.failure_reason}")

    if not result.usable:
        print("ERROR: no usable observations.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

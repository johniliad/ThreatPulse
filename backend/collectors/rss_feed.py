#!/usr/bin/env python3
"""Generic RSS/Atom advisory collector.

One collector serves many feeds: CERT-EU advisories and threat intelligence,
CISA advisories, the Greek NCSA feed, and the European national CERT/CSIRT
feeds. Each item is attributed to the feed it came from.

Operational behaviour that matters:

* **Per-item TLP enforcement** — an item marked more restrictively than the
  source's declared ``tlp_default`` is rejected with a reason, so one over-marked
  advisory cannot destroy the rest of a feed.
* **Partial failure is not total failure** — if some feeds in a multi-feed source
  fail, the successful ones still produce intelligence, and the failure is
  reported in the metrics.
* **Zero accepted items is failure, not success** — a feed that suddenly parses
  to nothing (format change, TLP storm, truncation) must not overwrite good
  published intelligence with an empty set.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/rss_feed.py <source_key>`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import source_from_config  # noqa: E402
from lib.attribution import AttributionRegister, load_register  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from lib.tlp import evaluate  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402
from normalization.rss import build_observation, parse_feed  # noqa: E402
from state.store import StateStore, utc_now_iso  # noqa: E402

LOGGER = get_logger("collectors.rss_feed")

#: Maximum per-feed failures reported in metrics, to bound log/report size.
MAX_REPORTED_FAILURES = 10

#: Advisories are XML. The shared HTTP client defaults to
#: ``Accept: application/json``, which a feed behind a web application firewall
#: can answer with HTTP 403. Ask for XML, with a permissive fallback so a feed
#: serving an unexpected content type is still accepted. A feed that answers a
#: browser challenge rather than a document cannot be read this way at all, and is
#: excluded from the register rather than retried.
FEED_ACCEPT_HEADER = (
    "application/rss+xml, application/atom+xml, application/xml, text/xml, "
    "text/plain, */*"
)


class RssFeedCollector:
    """Collects validated observations from one or more RSS/Atom feeds."""

    def __init__(
        self,
        config: SourceConfig,
        http: HttpClient,
        state: StateStore,
        *,
        register: AttributionRegister,
        feed_urls: list[str] | None = None,
    ) -> None:
        self.config = config
        self.source = source_from_config(config)
        self._http = http
        self._state = state
        self._register = register

        record = register.require(config.key)

        self._tlp_default = record.tlp_default
        self._attribution_text = record.attribution_text
        self._feed_urls = list(feed_urls or config.feed_urls)

        if not self._feed_urls:
            raise ValueError(f"{config.key}: no feed URLs configured")

    def collect(self, retrieved_at: str) -> SourceResult:
        observations = []
        seen_external_ids: set[str] = set()

        feeds_ok = 0
        failures: list[dict[str, str]] = []
        items_seen = 0
        rejected_tlp = 0
        rejected_duplicate = 0

        for feed_url in self._feed_urls:
            try:
                body = self._http.get(
                    feed_url,
                    timeout_seconds=self.config.timeout_seconds,
                    headers={"Accept": FEED_ACCEPT_HEADER},
                ).body
                items = parse_feed(body)
            except (HttpError, NormalizationError) as error:
                failures.append({"feed_url": feed_url, "reason": str(error)})
                continue

            feeds_ok += 1
            items_seen += len(items)

            for item in items:
                allowed, reason = evaluate(
                    source_default=self._tlp_default,
                    item_markings=item.tlp_markings,
                )

                if not allowed:
                    rejected_tlp += 1

                    log_event(
                        LOGGER,
                        logging.WARNING,
                        "feed item rejected by the TLP gate",
                        source_key=self.config.key,
                        feed_url=feed_url,
                        reason=reason,
                    )
                    continue

                if item.external_id in seen_external_ids:
                    rejected_duplicate += 1
                    continue

                seen_external_ids.add(item.external_id)

                observations.append(
                    build_observation(
                        item,
                        source_key=self.config.key,
                        retrieved_at=retrieved_at,
                        feed_url=feed_url,
                    )
                )

        metrics = {
            "feeds_configured": len(self._feed_urls),
            "feeds_ok": feeds_ok,
            "feeds_failed": len(failures),
            "items_seen": items_seen,
            "items_accepted": len(observations),
            "rejected_tlp": rejected_tlp,
            "rejected_duplicate": rejected_duplicate,
            "tlp_default": self._tlp_default,
            "partial": bool(failures) and feeds_ok > 0,
            "failures": failures[:MAX_REPORTED_FAILURES],
        }

        if not observations:
            reason = (
                "no usable observations: "
                f"{feeds_ok}/{len(self._feed_urls)} feeds retrieved, "
                f"{items_seen} items seen, {rejected_tlp} rejected by the TLP gate"
            )

            return self._degrade_or_fail(
                reason=reason,
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
            "rss feed collected",
            source_key=self.config.key,
            observations=len(observations),
            feeds_ok=feeds_ok,
            feeds_failed=len(failures),
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
            "rss feed collection failed",
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


def build_collector(settings, source_key: str = "cert_eu_advisories") -> RssFeedCollector:
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

    return RssFeedCollector(
        settings.source(source_key),
        http,
        state,
        register=load_register(),
    )


def main() -> int:
    source_key = sys.argv[1] if len(sys.argv) > 1 else "cert_eu_advisories"

    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    retrieved_at = utc_now_iso()
    result = build_collector(settings, source_key).collect(retrieved_at)

    print("ThreatPulse — RSS/Atom advisory collector")
    print("-----------------------------------------")
    print(f"Source:  {result.source.key}")
    print(f"Status:  {result.status}")
    print(f"Records: {len(result.observations)}")

    for key in ("feeds_ok", "feeds_failed", "items_seen", "rejected_tlp"):
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



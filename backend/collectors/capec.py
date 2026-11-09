#!/usr/bin/env python3
"""CAPEC collector — the CWE-to-technique route.

A **knowledge base**, not a feed: it publishes no observations. It builds
``data/capec_index.json``, which lets a threat carrying a CWE reach the ATT&CK
techniques that weakness enables.

The chain is ``CWE -> CAPEC -> ATT&CK technique``, and both hops are measured:

* CAPEC's catalogue holds **615 patterns**, **450 of them carrying a CWE** — 1,214
  links across **336 distinct CWEs**;
* the ATT&CK bundle references **32 CAPEC patterns**, covering **36 techniques**;
* so **31 of 336 CWEs** reach a technique;
* against the pipeline's own output, **316 of 1,773 threats carry a CWE** and **71**
  carry one of those 31.

Seventy-one threats is what justifies a 3.85 MB fetch. The index reports the narrow
reach (31 CWEs of 336) alongside it, so the chain is never implied to be broad.

The ATT&CK index is read at build time to resolve the second hop, because CAPEC's own
ATT&CK taxonomy mappings name no technique — a point ``normalization/capec.py`` records
as a correction to an earlier note in this repository.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/capec.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import source_from_config  # noqa: E402
from lib.atomic import write_json_atomic  # noqa: E402
from lib.attribution import AttributionRegister, load_register  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from lib.tlp import evaluate  # noqa: E402
from normalization.attack import INDEX_FILENAME as ATTACK_INDEX_FILENAME  # noqa: E402
from normalization.attack import load_index as load_attack_index  # noqa: E402
from normalization.capec import (  # noqa: E402
    INDEX_FILENAME,
    build_index,
    load_index,
)
from normalization.cisa import NormalizationError  # noqa: E402
from state.store import StateStore  # noqa: E402

LOGGER = get_logger("collectors.capec")

#: The catalogue is 3.85 MB. A generous ceiling still refuses a surprise.
MAX_CATALOGUE_BYTES = 24 * 1024 * 1024


class CapecCollector:
    """Fetches the CAPEC catalogue and builds the CWE-to-technique index."""

    key = "capec"

    def __init__(
        self,
        config: SourceConfig,
        http: HttpClient,
        state: StateStore,
        *,
        register: AttributionRegister,
        index_path=None,
    ) -> None:
        self.config = config
        self.source = source_from_config(config)
        self._http = http
        self._state = state
        self._index_path = index_path or (state.data_directory / INDEX_FILENAME)

        record = register.require(config.key)

        self._tlp_default = record.tlp_default

    def collect(self, retrieved_at: str) -> SourceResult:
        allowed, reason = evaluate(source_default=self._tlp_default, item_markings=())

        if not allowed:
            return self._degrade_or_fail(
                reason=f"the TLP gate refuses this source: {reason}",
                transient=False,
                metrics={"tlp_default": self._tlp_default},
            )

        try:
            body = self._http.get(
                self.config.feed_url,
                timeout_seconds=self.config.timeout_seconds,
                max_bytes=MAX_CATALOGUE_BYTES,
            ).body
        except HttpError as error:
            return self._degrade_or_fail(
                reason=f"CAPEC catalogue retrieval failed: {error}",
                transient=error.transient,
                metrics={"feed_url": self.config.feed_url},
            )

        # The second hop is resolved from the ATT&CK index, so a missing index means
        # the chain cannot be closed. That is reported rather than silently producing
        # a catalogue with no techniques in it.
        attack_index = load_attack_index(
            self._state.data_directory / ATTACK_INDEX_FILENAME
        )

        if attack_index is None:
            return self._degrade_or_fail(
                reason=(
                    "no ATT&CK index on disk, so the CAPEC-to-technique hop cannot be "
                    "resolved. Run the ATT&CK collector first."
                ),
                transient=False,
                metrics={
                    "feed_url": self.config.feed_url,
                    "catalogue_bytes": len(body),
                },
            )

        try:
            index = build_index(
                body,
                attack_index=attack_index,
                source_url=self.config.feed_url,
                generated_at=retrieved_at,
            )
        except NormalizationError as error:
            return self._degrade_or_fail(
                reason=f"CAPEC catalogue rejected: {error}",
                transient=False,
                metrics={
                    "feed_url": self.config.feed_url,
                    "catalogue_bytes": len(body),
                },
            )

        write_json_atomic(self._index_path, index)

        metrics = {
            "feed_url": self.config.feed_url,
            "catalogue_bytes": len(body),
            "index_path": str(self._index_path),
            "tlp_default": self._tlp_default,
            **(index.get("counts") or {}),
        }

        log_event(
            LOGGER,
            logging.INFO,
            "capec index built",
            source_key=self.config.key,
            patterns=(index.get("counts") or {}).get("patterns"),
            reachable_cwes=(index.get("counts") or {}).get("reachable_cwes"),
            reachable_techniques=(index.get("counts") or {}).get("reachable_techniques"),
        )

        return SourceResult(
            source=self.source,
            status="ok",
            observations=[],
            metrics=metrics,
        )

    def _degrade_or_fail(
        self, *, reason: str, transient: bool, metrics: dict
    ) -> SourceResult:
        log_event(
            LOGGER,
            logging.WARNING,
            "CAPEC collection failed",
            source_key=self.config.key,
            reason=reason,
        )

        existing = load_index(self._index_path)

        if existing:
            return SourceResult(
                source=self.source,
                status="degraded",
                observations=[],
                metrics={
                    **metrics,
                    "using_previous_index": True,
                    "previous_index_generated_at": existing.get("generated_at"),
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


def build_collector(settings) -> CapecCollector:
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

    return CapecCollector(
        settings.source("capec"),
        http,
        state,
        register=load_register(),
    )


def main() -> int:
    """CLI: builds the CWE-to-technique index from the CAPEC catalogue."""

    from state.store import utc_now_iso

    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    result = build_collector(settings).collect(utc_now_iso())

    print("ThreatPulse — CAPEC collector")
    print("-----------------------------")
    print(f"Status:  {result.status}")

    for key in (
        "catalogue_bytes",
        "patterns",
        "patterns_with_cwes",
        "patterns_with_techniques",
        "cwe_links",
        "distinct_cwes",
        "reachable_cwes",
        "reachable_techniques",
        "index_path",
    ):
        if key in result.metrics:
            print(f"{key}: {result.metrics[key]}")

    if result.failure_reason:
        print(f"Reason:  {result.failure_reason}")

    if result.status == "failed":
        print("ERROR: the CAPEC index was not built.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

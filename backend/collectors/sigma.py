#!/usr/bin/env python3
"""Sigma collector — detection coverage for the techniques this pipeline publishes.

A **knowledge base**, not a feed: it publishes no observations. It builds
``data/sigma_index.json``, which lets the ATT&CK enrichment say, beside a technique,
whether a detection rule exists for it.

Why it is worth 9.1 MB
----------------------

Measured before building: the archive holds **3,161 rule files**, **2,817** of them
carrying an ``attack.t`` tag, covering **390 distinct techniques** through **3,819
rule-to-technique mappings**. Of the **174 techniques this pipeline publishes**, **128
have a rule** — 74% detection coverage on real output. The 46 that do not are as
useful as the 128: they are the techniques nothing detects yet.

No YAML parser is used. Only four things are read, all line-oriented: the ``tags``
list entries and the ``title``, ``level`` and ``status`` scalars. See
``normalization/sigma.py`` for why that is sufficient and what ``regression_data``
cost when it was not excluded.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/sigma.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import source_from_config  # noqa: E402
from lib.atomic import write_json_atomic  # noqa: E402
from lib.attribution import AttributionRegister, load_register  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from lib.tlp import evaluate  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402
from normalization.sigma import INDEX_FILENAME, build_index, load_index  # noqa: E402
from state.store import StateStore  # noqa: E402

LOGGER = get_logger("collectors.sigma")

#: The archive is 9.1 MB. A generous ceiling still refuses a surprise.
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


class SigmaCollector:
    """Fetches the Sigma rule archive and builds the technique-to-rules index."""

    key = "sigma"

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
                max_bytes=MAX_ARCHIVE_BYTES,
            ).body
        except HttpError as error:
            return self._degrade_or_fail(
                reason=f"Sigma archive retrieval failed: {error}",
                transient=error.transient,
                metrics={"feed_url": self.config.feed_url},
            )

        try:
            index = build_index(
                body,
                source_url=self.config.feed_url,
                generated_at=retrieved_at,
            )
        except NormalizationError as error:
            return self._degrade_or_fail(
                reason=f"Sigma archive rejected: {error}",
                transient=False,
                metrics={
                    "feed_url": self.config.feed_url,
                    "archive_bytes": len(body),
                },
            )

        write_json_atomic(self._index_path, index)

        metrics = {
            "feed_url": self.config.feed_url,
            "archive_bytes": len(body),
            "index_path": str(self._index_path),
            "tlp_default": self._tlp_default,
            **(index.get("counts") or {}),
        }

        log_event(
            LOGGER,
            logging.INFO,
            "sigma detection index built",
            source_key=self.config.key,
            rules=(index.get("counts") or {}).get("rules"),
            techniques_covered=(index.get("counts") or {}).get("techniques_covered"),
            mappings=(index.get("counts") or {}).get("mappings"),
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
            "Sigma collection failed",
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


def build_collector(settings) -> SigmaCollector:
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

    return SigmaCollector(
        settings.source("sigma"),
        http,
        state,
        register=load_register(),
    )


def main() -> int:
    """CLI: builds the detection-coverage index from the Sigma archive."""

    from state.store import utc_now_iso

    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    result = build_collector(settings).collect(utc_now_iso())

    print("ThreatPulse — Sigma collector")
    print("-----------------------------")
    print(f"Status:  {result.status}")

    for key in (
        "archive_bytes",
        "rules",
        "techniques_covered",
        "mappings",
        "index_path",
    ):
        if key in result.metrics:
            print(f"{key}: {result.metrics[key]}")

    if result.failure_reason:
        print(f"Reason:  {result.failure_reason}")

    if result.status == "failed":
        print("ERROR: the Sigma index was not built.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

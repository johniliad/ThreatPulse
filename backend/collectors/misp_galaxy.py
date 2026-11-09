#!/usr/bin/env python3
"""MISP Galaxy collector — the alias bridge that widens ATT&CK matching.

A **knowledge base**, not a feed. It publishes no observations; it builds
``data/misp_galaxy_index.json``, which the ATT&CK enricher folds into the ATT&CK
index so a malware family named on a threat resolves to its ATT&CK
identifier even when ATT&CK's own alias list does not carry the name.

Which files are fetched was decided by measurement
--------------------------------------------------

Three of the forty galaxy files carry an ATT&CK identifier, and those three are the
only ones fetched:

* ``mitre-enterprise-attack-malware`` (188 values), ``-tool`` (45) and
  ``-intrusion-set`` (69) each carry ``meta.external_id``, and every one of those
  identifiers is already in the ATT&CK index — so they add **aliases, never new
  identifiers**: 121 names ATT&CK does not carry, such as ``havex`` for S0093,
  ``black energy`` for S0089, ``schtasks.exe`` for S0111 and ``cobalt gypsy`` for
  G0059.
* ``ransomware`` (2,179 values) and ``threat-actor`` (1,114 values) carry **zero**
  ``external_id`` values. They cannot bridge to ATT&CK at all, so 3.4 MB of them is
  deliberately not fetched.

The gain is modest and is reported as modest. It is taken because it is measured,
because it is free after one 346 KB fetch, and because the failure it prevents — a
family that plainly maps to an ATT&CK entry going unmatched because a feed spelled
the name differently — is invisible when it happens.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/misp_galaxy.py`
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
from normalization.galaxy import (
    INDEX_FILENAME,
    GALAXY_FILES,
    build_index,
    load_index,
)
from state.store import StateStore  # noqa: E402

LOGGER = get_logger("collectors.misp_galaxy")

#: The three files total about 346 KB. A generous ceiling still refuses a surprise.
MAX_FILE_BYTES = 8 * 1024 * 1024


class MispGalaxyCollector:
    """Fetches the bridgeable galaxy clusters and builds the alias index."""

    key = "misp_galaxy"

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

    def file_url(self, filename: str) -> str:
        return f"{(self.config.feed_url or '').rstrip('/')}/{filename}"

    def collect(self, retrieved_at: str) -> SourceResult:
        allowed, reason = evaluate(source_default=self._tlp_default, item_markings=())

        if not allowed:
            return self._degrade_or_fail(
                reason=f"the TLP gate refuses this source: {reason}",
                transient=False,
                metrics={"tlp_default": self._tlp_default},
            )

        payloads = []
        failures: list[str] = []

        for filename in GALAXY_FILES:
            url = self.file_url(filename)

            try:
                body = self._http.get(
                    url,
                    timeout_seconds=self.config.timeout_seconds,
                    max_bytes=MAX_FILE_BYTES,
                ).body
            except HttpError as error:
                failures.append(f"{filename}: {error}")
                continue

            try:
                payloads.append(json.loads(body.decode("utf-8")))
            except ValueError as error:
                failures.append(f"{filename}: not JSON ({error})")
                continue

        try:
            index = build_index(
                payloads,
                source_url=(self.config.feed_url or "").rstrip("/"),
                generated_at=retrieved_at,
            )
        except NormalizationError as error:
            return self._degrade_or_fail(
                reason=f"MISP Galaxy files rejected: {error}",
                transient=False,
                metrics={"files_ok": len(payloads), "files_failed": len(failures)},
            )

        # Written only after a successful build, so a failed fetch can never replace
        # a working alias index with a broken one.
        write_json_atomic(self._index_path, index)

        metrics = {
            "feed_url": (self.config.feed_url or "").rstrip("/"),
            "files_attempted": len(GALAXY_FILES),
            "files_ok": len(payloads),
            "files_failed": len(failures),
            "index_path": str(self._index_path),
            "tlp_default": self._tlp_default,
            **(index.get("counts") or {}),
        }

        if failures:
            metrics["failures"] = failures

        log_event(
            LOGGER,
            logging.INFO,
            "misp galaxy alias index built",
            source_key=self.config.key,
            entries=(index.get("counts") or {}).get("entries"),
            synonyms=(index.get("counts") or {}).get("synonyms"),
            files_ok=len(payloads),
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
            "misp galaxy collection failed",
            source_key=self.config.key,
            reason=reason,
        )

        existing = load_index(self._index_path)

        if existing:
            # The previous alias index is still usable, so enrichment continues on a
            # slightly older vocabulary rather than losing the aliases entirely.
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


def build_collector(settings) -> MispGalaxyCollector:
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

    return MispGalaxyCollector(
        settings.source("misp_galaxy"),
        http,
        state,
        register=load_register(),
    )


def main() -> int:
    """CLI: builds the alias index from the galaxy files."""

    from state.store import utc_now_iso

    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    result = build_collector(settings).collect(utc_now_iso())

    print("ThreatPulse — MISP Galaxy collector")
    print("-----------------------------------")
    print(f"Status:  {result.status}")

    for key in (
        "files_attempted",
        "files_ok",
        "files_failed",
        "entries",
        "synonyms",
        "with_synonyms",
        "software",
        "groups",
        "index_path",
    ):
        if key in result.metrics:
            print(f"{key}: {result.metrics[key]}")

    for failure in result.metrics.get("failures") or ():
        print(f"failure: {failure}")

    if result.failure_reason:
        print(f"Reason:  {result.failure_reason}")

    if result.status == "failed":
        print("ERROR: the alias index was not built.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""MITRE ATT&CK collector — the technique vocabulary, kept as a knowledge base.

ATT&CK is not an observation feed. Nothing in it is a statement about a specific
incident, so this collector publishes **no observations**: it fetches the STIX
bundle, validates it, and writes a compact index that the enrichment stage uses to
resolve technique references made by *other* sources. The source still appears in
the publication's ``sources[]``, because its content is published — as context on
threats — and attribution should say so.

Measured against the live bundle on 31 Oct 2026:

* the bundle is **52.7 MB** and **26,690 objects**, of which 21,819 are graph edges;
* only **18 objects reference a CVE**, so ATT&CK cannot enrich a KEV CVE by
  identifier — its value is naming techniques that other sources reference;
* the index it reduces to is **815 KB**, which is what gets written to
  ``data/attack_index.json``.

The version is resolved through the collection's own ``index.json`` so the index
records which ATT&CK release it came from, and so a version bump is visible rather
than silent. If that resolution fails, the configured feed URL is used directly.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/mitre_attack.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import source_from_config  # noqa: E402
from lib.atomic import write_json_atomic  # noqa: E402
from lib.attribution import AttributionRegister, load_register  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from lib.tlp import evaluate  # noqa: E402
from normalization.attack import INDEX_FILENAME, build_index, load_index  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402
from state.store import StateStore, utc_now_iso  # noqa: E402

LOGGER = get_logger("collectors.mitre_attack")

#: The live bundle was 52.7 MB. The ceiling leaves room for growth while still
#: refusing an unbounded stream.
MAX_BUNDLE_BYTES = 96 * 1024 * 1024

#: ``index.json`` lists every collection and version; it is small.
MAX_INDEX_BYTES = 2 * 1024 * 1024

#: The domain this pipeline uses. Mobile and ICS bundles are not ingested.
COLLECTION_MARKER = "/enterprise-attack/"


def version_sort_key(entry: dict) -> tuple:
    """Sort key for a release entry, newest last.

    **The index's ordering is not relied on.** The live ``index.json`` happens to
    list releases newest-first, so taking the last element silently selected ATT&CK
    version 1.0 from 2018 — a 2,781-object bundle instead of a 26,690-object one.
    The ``modified`` timestamp decides, with the numeric version as a tiebreak for
    entries that carry no timestamp.
    """

    modified = entry.get("modified")
    version = str(entry.get("version") or "")

    parts = tuple(
        int(part) if part.isdigit() else 0 for part in re.split(r"[.\-]", version)
    )

    return (modified if isinstance(modified, str) else "", parts)


class MitreAttackCollector:
    """Fetches the ATT&CK bundle and writes a compact, versioned index."""

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
        self._index_path = state.data_path(INDEX_FILENAME)

    def index_url(self) -> str:
        """The collection index that lists every ATT&CK release.

        Derived from the configured bundle URL by replacing its last two path
        segments — ``<collection>/<file>.json`` — with ``index.json``, which is where
        the repository publishes it at its root. Getting this wrong would silently
        fall back to the unversioned URL, so it is asserted by a test.
        """

        parts = self.config.feed_url.rsplit("/", 2)

        if len(parts) < 3:
            return self.config.feed_url

        return parts[0] + "/index.json"

    def resolve_latest(self) -> tuple[str | None, str]:
        """``(version, bundle_url)`` for the newest Enterprise ATT&CK release.

        The collection is identified by its URL path rather than its display name,
        so a rename in the index cannot silently switch the pipeline to Mobile or
        ICS ATT&CK.
        """

        try:
            index = self._http.get(
                self.index_url(),
                timeout_seconds=self.config.timeout_seconds,
                max_bytes=MAX_INDEX_BYTES,
            ).json()
        except (HttpError, NormalizationError, ValueError) as error:
            log_event(
                LOGGER,
                logging.WARNING,
                "could not resolve the latest ATT&CK version; using the configured URL",
                source_key=self.config.key,
                reason=str(error),
            )
            return None, self.config.feed_url

        collections = index.get("collections") if isinstance(index, dict) else None

        for collection in collections if isinstance(collections, list) else []:
            if not isinstance(collection, dict):
                continue

            versions = collection.get("versions")

            if not isinstance(versions, list) or not versions:
                continue

            candidates = [
                entry
                for entry in versions
                if isinstance(entry, dict)
                and isinstance(entry.get("url"), str)
                and COLLECTION_MARKER in entry["url"]
            ]

            if not candidates:
                continue

            latest = max(candidates, key=version_sort_key)

            return latest.get("version"), latest["url"]

        return None, self.config.feed_url

    def collect(self, retrieved_at: str) -> SourceResult:
        allowed, reason = evaluate(source_default=self._tlp_default, item_markings=())

        if not allowed:
            return self._degrade_or_fail(
                reason=f"the TLP gate refuses this source: {reason}",
                transient=False,
                metrics={"tlp_default": self._tlp_default},
            )

        version, bundle_url = self.resolve_latest()

        try:
            body = self._http.get(
                bundle_url,
                timeout_seconds=self.config.timeout_seconds,
                max_bytes=MAX_BUNDLE_BYTES,
            ).body
        except HttpError as error:
            return self._degrade_or_fail(
                reason=f"ATT&CK bundle retrieval failed: {error}",
                transient=error.transient,
                metrics={"bundle_url": bundle_url, "bundle_version": version},
            )

        try:
            bundle = json.loads(body.decode("utf-8"))
            index = build_index(
                bundle,
                version=version,
                source_url=bundle_url,
                generated_at=retrieved_at,
            )
        except (ValueError, NormalizationError) as error:
            return self._degrade_or_fail(
                reason=f"ATT&CK bundle rejected: {error}",
                transient=False,
                metrics={"bundle_url": bundle_url, "bundle_version": version},
            )

        # Written only after a successful build, so a failed fetch can never
        # replace a working knowledge base with a broken one.
        write_json_atomic(self._index_path, index)

        metrics = {
            "bundle_url": bundle_url,
            "bundle_bytes": len(body),
            "bundle_version": index.get("version"),
            "index_path": str(self._index_path),
            "tlp_default": self._tlp_default,
            **(index.get("counts") or {}),
        }

        log_event(
            LOGGER,
            logging.INFO,
            "mitre attack knowledge base built",
            source_key=self.config.key,
            version=index.get("version"),
            techniques=(index.get("counts") or {}).get("techniques"),
            groups=(index.get("counts") or {}).get("groups"),
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
            "mitre attack collection failed",
            source_key=self.config.key,
            reason=reason,
        )

        # The index on disk is only replaced after a successful build, so a failed
        # fetch leaves the previous knowledge base intact and enrichment keeps
        # working. That makes "degraded" the honest status whenever one exists.
        existing = load_index(self._index_path)

        if existing:
            return SourceResult(
                source=self.source,
                status="degraded",
                observations=[],
                metrics={
                    **metrics,
                    "using_existing_index": True,
                    "existing_index_version": existing.get("version"),
                    "existing_index_generated_at": existing.get("generated_at"),
                    **(existing.get("counts") or {}),
                },
                failure_reason=reason,
                failure_transient=transient,
                used_last_known_good=True,
            )

        return SourceResult(
            source=self.source,
            status="failed",
            observations=[],
            metrics=metrics,
            failure_reason=reason,
            failure_transient=transient,
        )


def build_collector(settings) -> MitreAttackCollector:
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

    return MitreAttackCollector(
        settings.source("mitre_attack"),
        http,
        state,
        register=load_register(),
    )


def main() -> int:
    """CLI: builds the knowledge base and reports what it contains."""

    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    result = build_collector(settings).collect(utc_now_iso())

    print("ThreatPulse — MITRE ATT&CK collector")
    print("------------------------------------")
    print(f"Status:  {result.status}")

    for key in (
        "bundle_version",
        "bundle_bytes",
        "objects_read",
        "techniques",
        "tactics",
        "software",
        "groups",
        "index_path",
        "using_existing_index",
    ):
        if key in result.metrics:
            print(f"{key}: {result.metrics[key]}")

    if result.failure_reason:
        print(f"Reason:  {result.failure_reason}")

    if result.status == "failed":
        print("ERROR: no knowledge base available.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

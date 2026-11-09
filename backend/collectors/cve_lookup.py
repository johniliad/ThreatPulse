#!/usr/bin/env python3
"""Shared machinery for dependent sources that look a record up one CVE at a time.

CISA Vulnrichment, Red Hat, OSV and CIRCL sightings all answer the same question —
"what do you have for this CVE?" — and all share the same four constraints: a run
must be bounded, the publication is a full snapshot, a miss is permanent, and some
answers go stale. ``state/record_cache.py`` holds the memory; this holds the
algorithm, so the rules cannot drift between four near-identical collectors.

A subclass supplies only what is genuinely source-specific:

* :meth:`build_cache` — the cache, and whether its records expire;
* :meth:`lookup_url` — the URL for one CVE;
* :meth:`parse_record` — validation and normalisation, returning a payload whose
  ``cve_id`` must match the CVE that was asked for;
* :meth:`build_observation` — how the payload becomes an observation;
* optionally :meth:`tlp_scan_texts`, :meth:`request_max_bytes` and
  :meth:`extra_metrics`.

Everything else — the batch, the miss handling, the TLP gate, the re-emission of
everything cached, last-known-good fallback and the metrics — is here.
"""

from __future__ import annotations

import logging

from collectors.base import SourceResult
from collectors.cisa_kev import source_from_config
from lib.attribution import AttributionRegister
from lib.config import SourceConfig
from lib.http import HttpClient, HttpError
from lib.ids import CVE_PATTERN
from lib.logging_setup import get_logger, log_event
from lib.tlp import evaluate, find_markings
from normalization.cisa import NormalizationError, RecordUnavailable
from state.store import StateStore
from state.record_cache import RecordCache

LOGGER = get_logger("collectors.cve_lookup")

#: Identifiers retrieved per run: one HTTP request each, so this bounds a run.
MAX_FETCHES_PER_RUN = 150

#: Per-identifier failures reported in metrics, to bound report size.
MAX_REPORTED_FAILURES = 10

NOT_FOUND_STATUS = 404

#: A batch this size with no success at all is reported loudly. Measured coverage
#: for these sources is high, so it is a fault signal rather than a data signal.
SUSPICIOUS_ABSENT_FETCHES = 25

#: Consecutive transport failures that abandon the rest of a batch.
#:
#: Without this, a source that is unreachable costs the entire budget in retries
#: and backoff: 150 identifiers at three attempts each is the better part of an
#: hour spent confirming something the first five failures already established.
#: A miss resets the count — a 404 proves the endpoint is answering.
MAX_CONSECUTIVE_FAILURES = 5


class CveLookupCollector:
    """Base for a source that answers one CVE at a time and caches what it finds."""

    #: Used in metrics and log lines; a subclass overrides it.
    label = "cve lookup"

    def __init__(
        self,
        config: SourceConfig,
        http: HttpClient,
        state: StateStore,
        *,
        register: AttributionRegister,
        cache: RecordCache | None = None,
        cve_ids: object = (),
        max_fetches: int = MAX_FETCHES_PER_RUN,
    ) -> None:
        self.config = config
        self.source = source_from_config(config)
        self._http = http
        self._state = state

        record = register.require(config.key)

        self._tlp_default = record.tlp_default
        self._cache = cache if cache is not None else self.build_cache(state)
        self._max_fetches = max(1, int(max_fetches))
        self._cve_ids = sorted(
            {
                str(cve).strip().upper()
                for cve in (cve_ids or ())
                if CVE_PATTERN.match(str(cve).strip().upper())
            }
        )

    # -- hooks -------------------------------------------------------------

    def build_cache(self, state: StateStore) -> RecordCache:  # pragma: no cover
        raise NotImplementedError

    def lookup_url(self, cve_id: str) -> str:  # pragma: no cover
        raise NotImplementedError

    def parse_record(self, payload: object) -> dict:  # pragma: no cover
        """Validate one response and return a payload carrying its own ``cve_id``."""

        raise NotImplementedError

    def build_observation(self, payload: dict, *, retrieved_at: str):  # pragma: no cover
        raise NotImplementedError

    def tlp_scan_texts(self, payload: dict) -> tuple[str, ...]:
        """Texts to scan for a TLP marking before the record is cached.

        Default is none: these are machine-readable records with no handling
        caveat field. A source whose records carry prose overrides this.
        """

        return ()

    def request_max_bytes(self) -> int | None:
        """Per-request response ceiling, or None for the client's default."""

        return None

    def extra_metrics(self, observations: list) -> dict:
        """Source-specific counts added to the run metrics."""

        return {}

    # -- the algorithm -----------------------------------------------------

    def collect(self, retrieved_at: str) -> SourceResult:
        self._cache.load()

        if not self._cve_ids:
            log_event(
                LOGGER,
                logging.INFO,
                f"{self.label} collection skipped",
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
                    "cves_candidates": 0,
                    "cached_records": self._cache.record_count,
                    "tlp_default": self._tlp_default,
                },
            )

        pending = self._cache.pending(
            self._cve_ids, limit=self._max_fetches, now=retrieved_at
        )

        fetched_ok = 0
        absent = 0
        rejected_malformed = 0
        rejected_tlp = 0
        unreachable = 0
        abandoned = False
        failures: list[dict[str, str]] = []

        for cve_id in pending:
            try:
                payload = self._http.get(
                    self.lookup_url(cve_id),
                    timeout_seconds=self.config.timeout_seconds,
                    max_bytes=self.request_max_bytes(),
                ).json()
                record = self.parse_record(payload)

                if record.get("cve_id") != cve_id:
                    # The URL is derived from the CVE, so a mismatch means the wrong
                    # document was served. Caching it would attach one CVE's data to
                    # another.
                    raise NormalizationError(
                        f"record is for {record.get('cve_id')!r}, not {cve_id}"
                    )
            except RecordUnavailable as error:
                # A permanent answer: the upstream has nothing for this CVE.
                absent += 1
                unreachable = 0
                self._cache.mark_absent(cve_id, at=retrieved_at)
                log_event(
                    LOGGER,
                    logging.DEBUG,
                    f"{self.label} has no record",
                    source_key=self.config.key,
                    cve_id=cve_id,
                    reason=str(error),
                )
                continue
            except HttpError as error:
                if error.status == NOT_FOUND_STATUS:
                    absent += 1
                    unreachable = 0
                    self._cache.mark_absent(cve_id, at=retrieved_at)
                    continue

                failures.append({"cve_id": cve_id, "reason": str(error)})
                unreachable += 1

                if unreachable >= MAX_CONSECUTIVE_FAILURES and fetched_ok == 0:
                    abandoned = True

                    log_event(
                        LOGGER,
                        logging.WARNING,
                        f"{self.label} looks unreachable; abandoning the batch",
                        source_key=self.config.key,
                        consecutive_failures=unreachable,
                        attempted=len(failures),
                        of=len(pending),
                        last_reason=str(error),
                    )
                    break

                continue
            except NormalizationError as error:
                # Not cached: a malformed record is a defect worth retrying, not a
                # permanent answer.
                rejected_malformed += 1
                failures.append({"cve_id": cve_id, "reason": str(error)})
                continue

            allowed, reason = evaluate(
                source_default=self._tlp_default,
                item_markings=find_markings(*self.tlp_scan_texts(record)),
            )

            if not allowed:
                rejected_tlp += 1

                log_event(
                    LOGGER,
                    logging.WARNING,
                    f"{self.label} record rejected by the TLP gate",
                    source_key=self.config.key,
                    cve_id=cve_id,
                    reason=reason,
                )
                continue

            self._cache.add(cve_id, record, fetched_at=retrieved_at)
            fetched_ok += 1

        if self._cache.dirty:
            self._cache.save()

        observations = [
            self.build_observation(payload, retrieved_at=retrieved_at)
            for payload in self._cache.payloads()
        ]

        metrics = {
            "cves_candidates": len(self._cve_ids),
            "fetches_attempted": len(pending),
            "fetches_ok": fetched_ok,
            #: Records served from the cache without being fetched this run. Without
            #: this, a warm cache logged ``fetched=0 absent=0`` and read exactly like
            #: a source that had done nothing, which is how a healthy collector was
            #: twice mistaken for a broken lookup path.
            "cache_hits": max(0, len(observations) - fetched_ok),
            "absent": absent,
            "absent_ratio": round(absent / len(pending), 3) if pending else 0.0,
            "rejected_malformed": rejected_malformed,
            "rejected_tlp": rejected_tlp,
            "fetch_failures": len(failures),
            "cached_records": len(observations),
            "cache_absent": self._cache.absent_count,
            "batch_abandoned": abandoned,
            "max_fetches_per_run": self._max_fetches,
            "tlp_default": self._tlp_default,
            "failures": failures[:MAX_REPORTED_FAILURES],
            **self.extra_metrics(observations),
        }

        if not observations:
            return self._degrade_or_fail(
                reason=(
                    f"no {self.label} records available: "
                    f"{len(self._cve_ids)} candidate CVEs, {len(pending)} fetched, "
                    f"{absent} not covered upstream, {rejected_malformed} malformed, "
                    f"{len(failures)} retrieval failures"
                    + (
                        " (the batch was abandoned after "
                        f"{unreachable} consecutive failures: the endpoint looks "
                        "unreachable)"
                        if abandoned
                        else ""
                    )
                ),
                transient=bool(failures),
                metrics=metrics,
            )

        if fetched_ok == 0 and absent >= SUSPICIOUS_ABSENT_FETCHES:
            log_event(
                LOGGER,
                logging.WARNING,
                f"every {self.label} lookup was empty",
                source_key=self.config.key,
                fetches=len(pending),
                note=(
                    "Expected for identifiers the upstream does not cover, but a "
                    "wrong lookup path looks identical. Verify the endpoint before "
                    "trusting the miss counts."
                ),
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
            f"{self.label} records collected",
            source_key=self.config.key,
            records=len(observations),
            fetched=fetched_ok,
            absent=absent,
            pending=len(pending),
            cache_hits=metrics["cache_hits"],
            known_absent=self._cache.absent_count,
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
            f"{self.label} collection failed",
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

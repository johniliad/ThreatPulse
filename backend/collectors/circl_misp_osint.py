#!/usr/bin/env python3
"""CIRCL MISP OSINT collector — the source that puts ATT&CK on a vulnerability.

Every other route to a technique is blocked. ATT&CK does not map CVEs (18 of its
26,690 objects carry one), and the advisory feeds this pipeline ingests do not cite
technique identifiers. The MISP OSINT feed does: its events carry
``misp-galaxy:mitre-attack-pattern="Hooking - T1179"`` tags, giving both the name and
the identifier.

What it is and is not
---------------------

A **community** feed. CIRCL publishes what its contributors share, so an event is
evidence that *someone reported* a campaign, not a vendor assessment. The
attribution register says so, and the observations carry the event's own metadata so
the claim can be traced back to it.

Design, driven by what the feed actually looks like
---------------------------------------------------

* **The manifest carries the tags but not the attributes.** Techniques are therefore
  readable from one request, while CVEs need each event's own file.
  The manifest is fetched every run; the event files are bounded per run and
  remembered in a cache, so a first run sweeps a slice and later runs continue.
* **The feed is not uniformly clear.** 77 of its events are TLP:GREEN or TLP:AMBER,
  so the marking is read **per event** and the gate is applied to each — never
  inherited from the source as a whole.
* **Only an event that references a CVE can join a threat.** An event tagged with
  techniques but carrying only phone numbers or hashes correlates to nothing, so it
  is counted rather than forced into a group.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 collectors/circl_misp_osint.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import source_from_config  # noqa: E402
from lib.attribution import AttributionRegister, load_register  # noqa: E402
from lib.config import SourceConfig, load_settings  # noqa: E402
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from lib.tlp import evaluate, find_markings  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402
from normalization.misp import (  # noqa: E402
    build_observations,
    event_candidates,
    parse_event,
    scan_texts,
    techniques_from_tags,
    tlp_markings,
)
from state.record_cache import RecordCache  # noqa: E402
from state.store import StateStore, utc_now_iso  # noqa: E402

LOGGER = get_logger("collectors.circl_misp_osint")

CACHE_FILENAME = "circl_misp_osint_cache.json"

#: Event files fetched per run: one request each, so this bounds a run. The
#: manifest is a single request whatever this is set to.
MAX_EVENT_FETCHES = 120

#: Events are re-read after this long, because a contributor can amend an event.
REFRESH_AFTER_DAYS = 90

#: Consecutive transport failures that abandon the rest of a batch.
MAX_CONSECUTIVE_FAILURES = 5

#: Reported failures, to bound report size.
MAX_REPORTED_FAILURES = 10

#: Recorded in metrics instead of the gate's own reason string.
#:
#: The gate's reason spells out the marking it refused ("item is marked TLP:..."),
#: and source metrics travel with the published document — so quoting it would
#: republish the very marking the gate exists to keep out. The full reason is logged,
#: where it is not published, and this stands in where it would be.
TLP_REJECTION_NOTE = "an event carried a restrictive traffic-light marking"


class CirclMispOsintCollector:
    """Fetches technique-tagged MISP events and emits one observation per CVE."""

    key = "circl_misp_osint"

    def __init__(
        self,
        config: SourceConfig,
        http: HttpClient,
        state: StateStore,
        *,
        register: AttributionRegister,
        cache: RecordCache | None = None,
        max_fetches: int = MAX_EVENT_FETCHES,
    ) -> None:
        self.config = config
        self.source = source_from_config(config)
        self._http = http
        self._state = state

        record = register.require(config.key)

        self._tlp_default = record.tlp_default
        self._cache = cache if cache is not None else self.build_cache(state)
        self._max_fetches = max(1, int(max_fetches))

    def build_cache(self, state: StateStore) -> RecordCache:
        return RecordCache(
            state, filename=CACHE_FILENAME, refresh_after_days=REFRESH_AFTER_DAYS
        )

    def event_url(self, event_uuid: str) -> str:
        """The URL for one event file.

        Lower-cased here rather than trusted from the caller. ``RecordCache``
        upper-cases every identifier it is given — it was built for CVE identifiers,
        which are conventionally upper-case — so a UUID that passes through the cache
        comes back as ``8CC5335E-…`` while the file is named ``8cc5335e-…``. The feed
        serves 404 for the upper-case spelling, which is indistinguishable from an
        event that has been withdrawn.
        """

        return (
            f"{(self.config.feed_url or '').rstrip('/')}/"
            f"{str(event_uuid).strip().lower()}.json"
        )

    def manifest_url(self) -> str:
        base = (self.config.feed_url or "").rstrip("/")

        # The manifest sits beside the event files rather than below them.
        return base + "/manifest.json" if base.endswith("feed-osint") else base

    def collect(self, retrieved_at: str) -> SourceResult:
        self._cache.load()

        try:
            manifest = self._http.get(
                self.manifest_url(),
                timeout_seconds=self.config.timeout_seconds,
            ).json()
        except (HttpError, ValueError) as error:
            return self._degrade_or_fail(
                reason=f"MISP OSINT manifest retrieval failed: {error}",
                transient=isinstance(error, HttpError) and error.transient,
                metrics={"manifest_url": self.manifest_url()},
            )

        try:
            candidates = event_candidates(manifest)
        except NormalizationError as error:
            return self._degrade_or_fail(
                reason=f"MISP OSINT manifest rejected: {error}",
                transient=False,
                metrics={"manifest_url": self.manifest_url()},
            )

        tagged = [
            candidate
            for candidate in candidates
            if techniques_from_tags(candidate.get("tags"))
        ]

        # The gate is applied per event. The feed carries 77 events marked
        # TLP:GREEN or TLP:AMBER, so a source-wide default would publish them.
        allowed: list[dict] = []
        rejected_tlp = 0
        rejected_reason = None

        for candidate in tagged:
            permitted, reason = evaluate(
                source_default=self._tlp_default,
                item_markings=[
                    *tlp_markings(candidate.get("tags")),
                    # The title is available before the fetch, and a marking in it is
                    # as binding as one in a tag.
                    *sorted(find_markings(candidate.get("info") or "")),
                ],
            )

            if permitted:
                allowed.append(candidate)
            else:
                rejected_tlp += 1
                rejected_reason = rejected_reason or reason

        allowed_uuids = [candidate["uuid"] for candidate in allowed]

        pending = self._cache.pending(
            allowed_uuids, limit=self._max_fetches, now=retrieved_at
        )

        failures: list[str] = []
        consecutive = 0
        fetched_ok = 0
        abandoned = False
        events_with_cves = 0
        rejected_after_fetch = 0

        for event_uuid in pending:
            try:
                payload = self._http.get(
                    self.event_url(event_uuid),
                    timeout_seconds=self.config.timeout_seconds,
                ).json()
            except (HttpError, ValueError) as error:
                failures.append(f"{event_uuid}: {error}")

                if isinstance(error, HttpError) and not error.transient:
                    self._cache.mark_absent(event_uuid, at=retrieved_at)
                    consecutive = 0
                    continue

                consecutive += 1

                if consecutive >= MAX_CONSECUTIVE_FAILURES:
                    abandoned = True
                    break

                continue

            consecutive = 0

            try:
                event = parse_event(payload)
            except NormalizationError as error:
                failures.append(f"{event_uuid}: {error}")
                continue

            # The text is only available now, and a marking in it binds. Two live
            # events were tagged clear while their comments named TLP:AMBER and
            # TLP:GREEN; publishing either would have been a real leak, and the
            # quality gate refused the whole publication rather than let it through.
            # Checking here means the event is not even cached.
            permitted, reason = evaluate(
                source_default=self._tlp_default,
                item_markings=[
                    *tlp_markings(event.get("tlp_markings")),
                    *sorted(find_markings(*scan_texts(event))),
                ],
            )

            if not permitted:
                rejected_tlp += 1
                rejected_reason = rejected_reason or reason
                rejected_after_fetch += 1
                continue

            # Recorded whether or not it names a CVE: the technique tags are worth
            # keeping, and re-fetching an event that will never correlate wastes the
            # whole batch budget.
            self._cache.add(event_uuid, event, fetched_at=retrieved_at)
            fetched_ok += 1

            if event.get("cves"):
                events_with_cves += 1

        self._cache.save()

        observations = self._observations_from_cache(retrieved_at)

        metrics = {
            "manifest_events": len(candidates),
            "technique_tagged_events": len(tagged),
            "events_allowed": len(allowed),
            "fetches_attempted": len(pending),
            "fetches_ok": fetched_ok,
            "events_with_cves": events_with_cves,
            "events_rejected_tlp_after_fetch": rejected_after_fetch,
            "cached_events": self._cache.record_count,
            "cached_absent": self._cache.absent_count,
            "fetch_failures": len(failures),
            "rejected_tlp": rejected_tlp,
            "records": len(observations),
            "distinct_techniques": len(
                {
                    technique
                    for event in self._cache.payloads()
                    for technique in event.get("techniques") or []
                }
            ),
            "distinct_cves": len(
                {observation.external_id for observation in observations}
            ),
        }

        if rejected_tlp:
            metrics["tlp_rejection_reason"] = TLP_REJECTION_NOTE

        if failures:
            metrics["failures"] = failures[:MAX_REPORTED_FAILURES]

        if abandoned:
            log_event(
                LOGGER,
                logging.WARNING,
                "MISP OSINT batch abandoned",
                source_key=self.config.key,
                consecutive_failures=consecutive,
            )

        if not observations:
            return self._degrade_or_fail(
                reason=(
                    f"no MISP OSINT observations: {len(tagged)} technique-tagged "
                    f"events, {len(pending)} fetched, {fetched_ok} ok, "
                    f"{len(failures)} failures"
                ),
                transient=bool(failures),
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
            "MISP OSINT observations collected",
            source_key=self.config.key,
            records=len(observations),
            technique_tagged_events=len(tagged),
            rejected_tlp=rejected_tlp,
            cached_events=self._cache.record_count,
        )

        return SourceResult(
            source=self.source,
            status="ok",
            observations=observations,
            metrics=metrics,
        )

    def _observations_from_cache(self, retrieved_at: str) -> list:
        """Everything cached, re-emitted — the publication is a full snapshot."""

        observations = []

        for event in self._cache.payloads():
            observations.extend(
                build_observations(
                    event, source_key=self.config.key, retrieved_at=retrieved_at
                )
            )

        return observations

    def _degrade_or_fail(
        self, *, reason: str, transient: bool, metrics: dict
    ) -> SourceResult:
        log_event(
            LOGGER,
            logging.WARNING,
            "MISP OSINT collection failed",
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


def build_collector(settings, *, max_fetches: int = MAX_EVENT_FETCHES):
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

    return CirclMispOsintCollector(
        settings.source("circl_misp_osint"),
        http,
        state,
        register=load_register(),
        max_fetches=max_fetches,
    )


def main() -> int:
    """CLI: one bounded sweep of the technique-tagged events."""

    settings = load_settings()
    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    max_fetches = MAX_EVENT_FETCHES

    for argument in sys.argv[1:]:
        if argument.startswith("--max-fetches="):
            max_fetches = int(argument.split("=", 1)[1])

    result = build_collector(settings, max_fetches=max_fetches).collect(utc_now_iso())

    print("ThreatPulse — CIRCL MISP OSINT collector")
    print("----------------------------------------")
    print(f"Status:  {result.status}")
    print(f"Records: {len(result.observations)}")

    for key in (
        "manifest_events",
        "technique_tagged_events",
        "events_allowed",
        "events_rejected_tlp",
        "fetches_attempted",
        "fetches_ok",
        "events_with_cves",
        "cached_events",
        "cached_absent",
        "fetch_failures",
        "records",
        "distinct_techniques",
        "distinct_cves",
    ):
        if key in result.metrics:
            print(f"{key}: {result.metrics[key]}")

    if result.metrics.get("tlp_rejection_reason"):
        print(f"tlp_rejection_reason: {result.metrics['tlp_rejection_reason']}")

    if result.failure_reason:
        print(f"Reason:  {result.failure_reason}")

    if not result.usable:
        print("ERROR: no usable observations.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

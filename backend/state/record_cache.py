"""Incremental record cache for dependent, per-identifier sources.

Several sources look a record up one identifier at a time rather than downloading
a bulk file: CISA Vulnrichment, Red Hat, OSV and CIRCL sightings. They share four
properties, and this module exists because those properties are subtle enough that
four copies of the logic would drift apart.

* **A run must be bounded.** Fetching a document for every CVE the pipeline knows
  about would be thousands of requests in one run. A collector asks this cache for
  a bounded batch and fetches only that.
* **The publication is a full snapshot.** Every run republishes the complete
  threat set, so a record fetched once must be re-emitted on every later run. This
  cache is the accumulating store of what has been learned, not a per-run working
  set: collectors emit everything in it.
* **A miss has to be remembered.** A 404 is a permanent answer for as long as the
  upstream leaves it alone. Without a memory of it, the same lookups would be
  re-requested every run and the bounded batch would never sweep forward. Misses
  are retried after ``absent_retry_days``.
* **Some answers go stale, others never do.** CISA's SSVC assessment of a CVE is
  immutable enrichment; CIRCL's sighting count and Red Hat's errata list grow over
  time. A collector that needs its records refreshed passes ``refresh_after_days``,
  and after that interval a cached identifier becomes eligible again — behind the
  never-seen ones, so a refresh can never starve the sweep.

A missing or unreadable cache is treated as empty rather than as an error: the
worst outcome is re-fetching, and refusing to run because a state file is
unreadable would be worse.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from lib.atomic import read_json, write_json_atomic
from lib.logging_setup import get_logger, log_event
from state.store import StateStore, utc_now_iso

LOGGER = get_logger("state.record_cache")

CACHE_SCHEMA = 2

#: How long a miss is left alone before the identifier is asked about again.
DEFAULT_ABSENT_RETRY_DAYS = 30

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError:
        return None

    return parsed.replace(tzinfo=timezone.utc)


def _age_seconds(fetched_at: object, now: str) -> float | None:
    """Seconds between a recorded timestamp and ``now``, or None if unreadable."""

    previous = _parse_timestamp(fetched_at)
    current = _parse_timestamp(now)

    if previous is None or current is None:
        return None

    return (current - previous).total_seconds()


class RecordCache:
    """Remembers which identifiers have a record, and which have none."""

    def __init__(
        self,
        state: StateStore,
        *,
        filename: str,
        absent_retry_days: float = DEFAULT_ABSENT_RETRY_DAYS,
        refresh_after_days: float | None = None,
    ) -> None:
        self._path: Path = state.state_path(filename)
        self._records: dict[str, dict] = {}
        self._fetched: dict[str, str] = {}
        self._absent: dict[str, str] = {}
        self._retry_seconds = max(0.0, float(absent_retry_days) * 86400.0)
        self._refresh_seconds = (
            None
            if refresh_after_days is None
            else max(0.0, float(refresh_after_days) * 86400.0)
        )
        self._loaded = False
        #: Set whenever the cache is modified, so a collector only rewrites the
        #: file when something actually changed.
        self.dirty = False

    # -- persistence -------------------------------------------------------

    def load(self) -> None:
        self._loaded = True

        try:
            raw = read_json(self._path)
        except (OSError, ValueError) as error:
            # An unreadable cache costs a re-fetch, which is recoverable.
            # Refusing to run because a state file is corrupt is not.
            log_event(
                LOGGER,
                logging.WARNING,
                "record cache unreadable; starting from empty",
                path=str(self._path),
                reason=str(error),
            )
            return

        if not isinstance(raw, dict):
            return

        records = raw.get("records")

        if isinstance(records, dict):
            self._records = {
                key.strip().upper(): value
                for key, value in records.items()
                if isinstance(key, str)
                and isinstance(value, dict)
                and isinstance(value.get("cve_id"), str)
                and value["cve_id"]
            }

        for field_name, target in (("fetched", self._fetched), ("absent", self._absent)):
            entries = raw.get(field_name)

            if isinstance(entries, dict):
                target.update(
                    {
                        key.strip().upper(): value
                        for key, value in entries.items()
                        if isinstance(key, str) and isinstance(value, str)
                    }
                )

    def save(self) -> None:
        write_json_atomic(
            self._path,
            {
                "schema": CACHE_SCHEMA,
                "note": (
                    "Records accumulated across runs, keyed by identifier. Emitted "
                    "in full on every run so that the publication snapshot stays "
                    "complete; 'fetched' dates each record for refresh scheduling "
                    "and 'absent' lists identifiers the upstream has no record for."
                ),
                "updated_at": utc_now_iso(),
                "record_count": len(self._records),
                "absent_count": len(self._absent),
                "records": {key: self._records[key] for key in sorted(self._records)},
                "fetched": {key: self._fetched[key] for key in sorted(self._fetched)},
                "absent": {key: self._absent[key] for key in sorted(self._absent)},
            },
        )

        self.dirty = False

    # -- contents ----------------------------------------------------------

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def absent_count(self) -> int:
        return len(self._absent)

    def has(self, identifier: str) -> bool:
        return (identifier or "").strip().upper() in self._records

    def payloads(self) -> list[dict]:
        """Every cached payload, ordered by identifier for deterministic output."""

        return [self._records[key] for key in sorted(self._records)]

    # -- mutation ----------------------------------------------------------

    def add(self, identifier: str, payload: dict, *, fetched_at: str) -> None:
        key = (identifier or "").strip().upper()

        if not key or not isinstance(payload, dict):
            return

        self._records[key] = payload
        self._fetched[key] = fetched_at
        self._absent.pop(key, None)
        self.dirty = True

    def mark_absent(self, identifier: str, *, at: str) -> None:
        key = (identifier or "").strip().upper()

        if not key:
            return

        self._absent[key] = at
        self.dirty = True

    # -- scheduling --------------------------------------------------------

    def _is_due(self, recorded_at: str, now: str, window_seconds: float) -> bool:
        age = _age_seconds(recorded_at, now)

        if age is None:
            # An unreadable timestamp must not strand an identifier forever.
            return True

        return age >= window_seconds

    def _refreshable(self, identifiers: list[str], now: str) -> list[str]:
        """Cached identifiers whose record is old enough to be asked about again."""

        if self._refresh_seconds is None:
            return []

        due = [
            identifier
            for identifier in identifiers
            if identifier in self._records
            and self._is_due(
                self._fetched.get(identifier, ""), now, self._refresh_seconds
            )
        ]

        # Oldest first, so refreshes cycle rather than repeatedly refreshing the
        # same handful of identifiers.
        return sorted(due, key=lambda identifier: (self._fetched.get(identifier, ""), identifier))

    def pending(self, identifiers: object, *, limit: int, now: str) -> list[str]:
        """The identifiers to fetch now, at most ``limit`` of them.

        **Newest first among the never-seen.** A newly published CVE is what a
        reader acts on today, so a new KEV entry is enriched on the next run rather
        than after the whole catalogue has been swept. The sweep still reaches
        every candidate, just from the recent end down, and it is deterministic.

        Order of business: never-seen identifiers, then records due for refresh,
        then missed identifiers whose cooling-off period has passed. A refresh can
        therefore never crowd out a first look.
        """

        candidates = sorted(
            {
                str(identifier).strip().upper()
                for identifier in (identifiers or ())
                if str(identifier).strip()
            }
        )

        unseen = sorted(
            (
                identifier
                for identifier in candidates
                if identifier not in self._records
                and identifier not in self._absent
            ),
            reverse=True,
        )

        refresh = self._refreshable(candidates, now)

        retryable = sorted(
            (
                identifier
                for identifier in candidates
                if identifier not in self._records
                and identifier in self._absent
                and self._is_due(self._absent[identifier], now, self._retry_seconds)
            ),
            key=lambda identifier: (self._absent[identifier], identifier),
        )

        batch = unseen + refresh + retryable

        if limit is None or limit <= 0:
            return batch

        return batch[: int(limit)]

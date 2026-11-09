"""When ThreatPulse first observed each CVE.

Every other date in the pipeline belongs to a source: ``published_at``,
``updated_at``, a CISA ``date_added``, a CIRCL sighting. Each of them is missing
from most records, and none of them says what an operator actually wants to know
tonight: *is this new to us?*

This registry answers that, and it is the one date the pipeline owns outright, so
its coverage is total. It records the first run in which a CVE appeared in any
collected observation and never moves afterwards — a value that survives restarts
because it lives in ``state/``, not in the publication.

It is published as its own factor (``first_seen``), never merged into ``recency``.
The two mean different things: a CVE published five years ago and collected today
is *old* by ``recency`` and *new* by ``first_seen``, and conflating them would
turn "we just found this" into a claim about the vulnerability's age.

A missing or unreadable registry is treated as empty rather than as an error: the
worst outcome is that first-seen dates restart, and refusing to run because a state
file is unreadable would be worse.
"""

from __future__ import annotations

from pathlib import Path

from lib.atomic import read_json, write_json_atomic
from state.store import StateStore

FILENAME = "cve_first_seen.json"

SCHEMA = 2

TIMESTAMP_FORMAT_LENGTH = 10


class CveFirstSeen:
    """First-observation dates, keyed by CVE identifier."""

    def __init__(self, state: StateStore, filename: str = FILENAME) -> None:
        self._path: Path = state.state_path(filename)
        self._seen: dict[str, str] = {}
        self._loaded = False
        #: Set whenever the registry changes, so a run only rewrites the file when
        #: something actually happened.
        self.dirty = False

    # -- persistence -------------------------------------------------------

    def load(self) -> None:
        if self._loaded:
            return

        self._loaded = True

        raw = read_json(self._path, default=None)

        if not isinstance(raw, dict):
            return

        seen = raw.get("seen")

        if not isinstance(seen, dict):
            return

        self._seen = {
            key.strip().upper(): value
            for key, value in seen.items()
            if isinstance(key, str) and key.strip() and isinstance(value, str)
        }

    def save(self) -> None:
        write_json_atomic(
            self._path,
            {
                "schema": SCHEMA,
                "note": (
                    "The first run in which each CVE appeared in a collected "
                    "observation. Written once per identifier and never moved. "
                    "Published as the 'first_seen' scoring factor; not a claim "
                    "about when the vulnerability was first exploited."
                ),
                "count": len(self._seen),
                "seen": {key: self._seen[key] for key in sorted(self._seen)},
            },
        )

        self.dirty = False

    # -- contents ----------------------------------------------------------

    @property
    def size(self) -> int:
        return len(self._seen)

    def date_for(self, cve_id: str) -> str | None:
        """``YYYY-MM-DD`` of the first run that saw this CVE, or ``None``."""

        value = self._seen.get((cve_id or "").strip().upper())

        if not isinstance(value, str) or len(value) < TIMESTAMP_FORMAT_LENGTH:
            return None

        return value[:TIMESTAMP_FORMAT_LENGTH]

    def snapshot(self) -> dict[str, str]:
        """A copy of the registry, for passing into scoring."""

        return dict(self._seen)

    # -- mutation ----------------------------------------------------------

    def observe(self, cve_ids, *, now: str) -> int:
        """Records identifiers not seen before. Returns how many were new."""

        added = 0

        for identifier in cve_ids or ():
            key = (identifier or "").strip().upper()

            if not key or key in self._seen:
                continue

            self._seen[key] = now
            added += 1

        if added:
            self.dirty = True

        return added

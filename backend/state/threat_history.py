"""Change tracking between publications.

A publication is a full snapshot, replaced wholesale each run. That makes it easy
to say what the product thinks *now* and impossible to say what changed, which is
usually the question an operator actually has: what is new since yesterday, what
got worse, what stopped being reported.

This module keeps a small per-threat record across runs — when it was first
published, how many times it has materially changed, and which fields changed in
the last publication — and reconciles each run against it.

**It tracks a handful of named fields, not the whole record.** A hash of the entire
threat would flag every republication as a change, because retrieval timestamps,
publication references and enrichment blocks all move on every run. What is worth
recording is what a reader would notice: severity, score, confidence, exploitation
status, which sources back it, and how much it carries.

Nothing here invents history. A threat seen for the first time is revision 1, and a
run over an empty registry reports everything as new rather than pretending to a
past it never observed.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from lib.atomic import read_json, write_json_atomic
from state.store import StateStore

FILENAME = "threat_history.json"

SCHEMA = 2

#: Fields whose change is recorded. Chosen because a reader would act differently
#: on them; adding a field here changes what "changed" means, so it is a deliberate
#: act rather than an implementation detail.
TRACKED_FIELDS = (
    "severity",
    "priority_score",
    "confidence_level",
    "exploitation_status",
    "source_keys",
    "vulnerability_count",
)

#: How long an entry is kept after it was last published. A threat that stops being
#: reported is worth remembering as "disappeared" for a while, not forever.
RETENTION_DAYS = 90

#: Timestamps are sliced to 19 characters before parsing, so the format carries no
#: trailing ``Z``. Getting this wrong fails silently: ``_age_days`` returns ``None``
#: for an unreadable value and the pruner keeps what it cannot date, so retention
#: would never fire and nothing would say so.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"


def _age_days(then: str, now: str) -> int | None:
    """Whole days between two timestamps, or ``None`` when unreadable."""

    try:
        start = datetime.strptime(str(then)[:19], TIMESTAMP_FORMAT)
        end = datetime.strptime(str(now)[:19], TIMESTAMP_FORMAT)
    except (TypeError, ValueError):
        return None

    return (end - start).days


def _comparable(value: Any) -> Any:
    """A value that compares by content rather than by identity."""

    if isinstance(value, (list, tuple, set)):
        return sorted(str(item) for item in value)

    if isinstance(value, float):
        return round(value, 2)

    return value


def fingerprint(threat) -> dict[str, Any]:
    """The tracked fields of one threat, in a comparable form."""

    document = threat.to_publication_dict()

    values: dict[str, Any] = {
        field: _comparable(document.get(field)) for field in TRACKED_FIELDS
    }

    values["vulnerability_count"] = len(document.get("vulnerabilities") or [])

    return values


class ThreatHistory:
    """Per-threat publication history, keyed by the threat's identity."""

    def __init__(self, state: StateStore, filename: str = FILENAME) -> None:
        self._path: Path = state.state_path(filename)
        self._entries: dict[str, dict[str, Any]] = {}
        self._loaded = False
        self.dirty = False

    # -- persistence -------------------------------------------------------

    def load(self) -> None:
        if self._loaded:
            return

        self._loaded = True

        # An unreadable registry is treated as empty rather than as an error: the
        # worst outcome is that history restarts, and refusing to run because a
        # state file is corrupt would be worse.
        try:
            raw = read_json(self._path, default=None)
        except (OSError, ValueError):
            return

        if not isinstance(raw, dict):
            return

        entries = raw.get("entries")

        if not isinstance(entries, dict):
            return

        self._entries = {
            str(key): value
            for key, value in entries.items()
            if isinstance(key, str) and isinstance(value, dict)
        }

    def save(self) -> None:
        write_json_atomic(
            self._path,
            {
                "schema": SCHEMA,
                "note": (
                    "Per-threat publication history: when each threat was first "
                    "published, how many times it has materially changed, and the "
                    "fields that changed. Keyed by the threat's identity, not its "
                    "uuid, so a threat keeps its history if its identifier moves."
                ),
                "count": len(self._entries),
                "tracked_fields": list(TRACKED_FIELDS),
                "entries": {
                    key: self._entries[key] for key in sorted(self._entries)
                },
            },
        )

        self.dirty = False

    @property
    def size(self) -> int:
        return len(self._entries)

    # -- reconciliation ----------------------------------------------------

    def reconcile(self, threats, *, now: str) -> dict[str, Any]:
        """Compares a published set against the stored history.

        Attaches ``metadata["temporal"]`` to every threat and returns the run-level
        delta. Entries absent from this publication are counted as disappeared and
        kept for ``RETENTION_DAYS``, so a later run can still recognise them as
        returning rather than as new.
        """

        present: set[str] = set()

        created = 0
        changed = 0
        unchanged = 0

        for threat in threats:
            key = threat.identity_key()
            present.add(key)

            current = fingerprint(threat)
            entry = self._entries.get(key)

            if entry is None:
                self._entries[key] = {
                    "first_published_at": now,
                    "last_published_at": now,
                    "last_changed_at": now,
                    "revision": 1,
                    "fingerprint": current,
                }

                created += 1
                self.dirty = True

                threat.metadata["temporal"] = {
                    "first_published_at": now,
                    "revision": 1,
                }

                continue

            previous = entry.get("fingerprint") or {}

            moved = [
                field
                for field in TRACKED_FIELDS
                if _comparable(previous.get(field)) != current.get(field)
            ]

            entry["last_published_at"] = now
            entry["fingerprint"] = current

            revision = int(entry.get("revision") or 1)

            temporal: dict[str, Any] = {
                "first_published_at": str(entry.get("first_published_at") or now),
                "revision": revision,
            }

            if moved:
                revision += 1
                entry["revision"] = revision
                entry["last_changed_at"] = now

                temporal["revision"] = revision
                temporal["changed_since_previous"] = moved

                changed += 1
                self.dirty = True
            else:
                unchanged += 1

            threat.metadata["temporal"] = temporal

        disappeared = sum(1 for key in self._entries if key not in present)
        pruned = self._prune(now)

        return {
            "new": created,
            "changed": changed,
            "unchanged": unchanged,
            "disappeared": disappeared,
            "pruned": pruned,
            "registry_size": len(self._entries),
        }

    def _prune(self, now: str) -> int:
        """Drops entries that have not been published for ``RETENTION_DAYS``.

        An entry with an unreadable timestamp is kept: discarding a threat's
        history because of a parsing failure would be worse than keeping a stale
        row.
        """

        keep: dict[str, dict[str, Any]] = {}
        dropped = 0

        for key, entry in self._entries.items():
            age = _age_days(str(entry.get("last_published_at") or ""), now)

            if age is not None and age > RETENTION_DAYS:
                dropped += 1
                continue

            keep[key] = entry

        if dropped:
            self._entries = keep
            self.dirty = True

        return dropped


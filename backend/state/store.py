"""Local state store.

Everything the pipeline needs to remember between runs, all written atomically:

* ``last_known_good_<source>.json`` — the most recent validated observation set
  per source, so a source outage degrades rather than destroys intelligence.
* ``identity_aliases.json`` — published threat UUIDs keyed by external id.
* ``run.lock`` — prevents overlapping scheduled runs.
* ``previous_publication.json`` — summary of the last accepted publication, used
  by the quality gate to detect a suspicious drop in volume.
* ``data/latest_publication.json`` — the exact snapshot that was published.
* ``data/run_report.json`` — machine-readable report of the last run.
"""

from __future__ import annotations

import os
import socket
from datetime import datetime, timezone
from pathlib import Path

from lib.atomic import read_json, write_json_atomic
from models.intelligence import Entity, Observation

LOCK_STALE_SECONDS = 3600


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None

    return parsed.replace(tzinfo=timezone.utc)


class StateStore:
    def __init__(self, state_directory: Path, data_directory: Path) -> None:
        self.state_directory = state_directory
        self.data_directory = data_directory
        self.state_directory.mkdir(parents=True, exist_ok=True)
        self.data_directory.mkdir(parents=True, exist_ok=True)

    # -- paths -------------------------------------------------------------

    def state_path(self, name: str) -> Path:
        return self.state_directory / name

    def data_path(self, name: str) -> Path:
        return self.data_directory / name

    # -- last known good ---------------------------------------------------

    def save_last_known_good(
        self,
        source_key: str,
        observations: list[Observation],
        *,
        retrieved_at: str,
        metrics: dict,
    ) -> None:
        write_json_atomic(
            self.state_path(f"last_known_good_{source_key}.json"),
            {
                "source_key": source_key,
                "retrieved_at": retrieved_at,
                "observation_count": len(observations),
                "metrics": metrics,
                "observations": [
                    observation.to_dict() for observation in observations
                ],
            },
        )

    def load_last_known_good(self, source_key: str):
        raw = read_json(self.state_path(f"last_known_good_{source_key}.json"))

        if not isinstance(raw, dict):
            return None

        observations: list[Observation] = []

        for entry in raw.get("observations") or []:
            if not isinstance(entry, dict):
                continue

            entities = [
                Entity(**entity)
                for entity in entry.get("entities") or []
                if isinstance(entity, dict)
                and {"kind", "value", "normalized"} <= set(entity)
            ]

            try:
                observations.append(
                    Observation(
                        source_key=str(entry.get("source_key", source_key)),
                        external_id=str(entry.get("external_id", "")),
                        observed_at=str(entry.get("observed_at", "")),
                        retrieved_at=str(entry.get("retrieved_at", "")),
                        source_record_id=str(entry.get("source_record_id", "")),
                        payload=entry.get("payload") or {},
                        entities=entities,
                    )
                )
            except (TypeError, ValueError):
                continue

        if not observations:
            return None

        return {
            "retrieved_at": raw.get("retrieved_at"),
            "metrics": raw.get("metrics") or {},
            "observations": observations,
        }

    # -- overlap prevention ------------------------------------------------

    def acquire_run_lock(
        self, *, run_id: str, stale_after_seconds: int = LOCK_STALE_SECONDS
    ) -> bool:
        """Creates ``run.lock``; returns False when another run holds it."""

        lock_path = self.state_path("run.lock")
        now = datetime.now(timezone.utc)

        existing = read_json(lock_path)

        if isinstance(existing, dict):
            started_at = _parse_timestamp(existing.get("started_at"))

            if started_at is not None:
                age = (now - started_at).total_seconds()

                if age < stale_after_seconds:
                    return False

        write_json_atomic(
            lock_path,
            {
                "run_id": run_id,
                "pid": os.getpid(),
                "host": socket.gethostname(),
                "started_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )

        return True

    def release_run_lock(self) -> None:
        self.state_path("run.lock").unlink(missing_ok=True)

    # -- publication bookkeeping -------------------------------------------

    def save_previous_publication(self, summary: dict) -> None:
        write_json_atomic(self.state_path("previous_publication.json"), summary)

    def load_previous_publication(self):
        raw = read_json(self.state_path("previous_publication.json"))

        return raw if isinstance(raw, dict) else None

    def save_publication_snapshot(self, payload: dict) -> Path:
        path = self.data_path("latest_publication.json")
        write_json_atomic(path, payload)

        return path

    def save_run_report(self, report: dict) -> Path:
        path = self.data_path("run_report.json")
        write_json_atomic(path, report)

        return path

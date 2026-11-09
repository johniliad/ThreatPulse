"""Collector contract and source-failure semantics.

A collector's only job is to retrieve a source and return validated
observations, or a classified failure. It never scores, correlates or decides
what gets published.

Failure semantics (a source failure must never destroy valid intelligence):

* ``ok``            — fresh observations collected.
* ``degraded``      — retrieval failed transiently, but a previous successful
                      snapshot exists (``state/last_known_good_<key>.json``);
                      the previous observations are reused and clearly marked.
* ``failed``        — retrieval failed and there is no usable snapshot. A
                      ``required`` source failing this way aborts the run; an
                      optional source is skipped and reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from models.intelligence import Observation, Source


@dataclass
class SourceResult:
    source: Source
    status: str
    observations: list[Observation] = field(default_factory=list)
    metrics: dict[str, object] = field(default_factory=dict)
    failure_reason: str | None = None
    failure_transient: bool = False
    used_last_known_good: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def usable(self) -> bool:
        return self.status in ("ok", "degraded")

    def summary(self) -> dict:
        return {
            "source_key": self.source.key,
            "status": self.status,
            "observations": len(self.observations),
            "used_last_known_good": self.used_last_known_good,
            "failure_reason": self.failure_reason,
            "metrics": self.metrics,
        }


class Collector(Protocol):
    """Structural type implemented by every collector."""

    source: Source

    def collect(self, retrieved_at: str) -> SourceResult:  # pragma: no cover
        ...

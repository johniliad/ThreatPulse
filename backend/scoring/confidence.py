"""Confidence assessment, kept deliberately separate from priority.

Priority answers "how urgent is this?"; confidence answers "how strong is the
evidence?". Mixing them would let a well-evidenced low-urgency item look more
certain than it is, and vice versa.

The mapping is inherited from the pre-existing implementation
(``models/publication.py: confidence_from_record``) so that published confidence
values do not change:

* KEV-listed **and** exploited in the wild → 100 / high
* KEV-listed only                        → 95  / high
* otherwise                              → 60  / medium

Confidence is never raised by anything the evidence does not support: an
unlisted, unconfirmed record cannot claim "high".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

LEVEL_THRESHOLDS = ((85.0, CONFIDENCE_HIGH), (60.0, CONFIDENCE_MEDIUM))


@dataclass(frozen=True)
class Confidence:
    score: float
    level: str

    def to_dict(self) -> dict:
        return {"score": self.score, "level": self.level}


def level_for_score(score: float) -> str:
    """Maps a 0–100 confidence score onto a level."""

    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level

    return CONFIDENCE_LOW


def assess(record: dict[str, Any]) -> Confidence:
    """Assesses confidence from the evidence present in a normalized record.

    ``record`` uses the normalized field names produced by
    ``normalization.cisa`` (``kev_listed``, ``exploited_in_wild``).
    """

    kev_listed = record.get("kev_listed") is True
    exploited = record.get("exploited_in_wild") is True

    if kev_listed and exploited:
        return Confidence(score=100.0, level=CONFIDENCE_HIGH)

    if kev_listed:
        return Confidence(score=95.0, level=CONFIDENCE_HIGH)

    if exploited:
        return Confidence(score=80.0, level=CONFIDENCE_MEDIUM)

    return Confidence(score=60.0, level=CONFIDENCE_MEDIUM)


def assess_group(records: list[dict[str, Any]]) -> Confidence:
    """Confidence for a group of records describing the same vulnerability.

    Same ladder as :func:`assess`, applied to the strongest signal any source in
    the group states rather than to one source's payload.

    Corroboration deliberately does **not** raise confidence. Several feeds
    repeating one advisory is still one claim; only KEV listing or reported
    exploitation moves a record above medium, and a group with neither can never
    reach "high".
    """

    kev_listed = any(record.get("kev_listed") is True for record in records)
    exploited = any(record.get("exploited_in_wild") is True for record in records)

    if kev_listed and exploited:
        return Confidence(score=100.0, level=CONFIDENCE_HIGH)

    if kev_listed:
        return Confidence(score=95.0, level=CONFIDENCE_HIGH)

    if exploited:
        return Confidence(score=80.0, level=CONFIDENCE_MEDIUM)

    return Confidence(score=60.0, level=CONFIDENCE_MEDIUM)

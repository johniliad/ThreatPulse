"""Ransomware.live victim-observation normalisation.

**PRIVACY RULE — enforced here and asserted by tests:**

    Victim organisation names are never stored, published or logged. Only the
    aggregate facts needed for regional relevance are kept: the ransomware
    group, the victim's country, the sector, and the claimed attack date.

ThreatPulse is a public dashboard. Naming a victim would republish personal and
commercially sensitive data taken from a criminal leak site, and would also
re-identify an organisation that has not consented to it. So a victim record is
reduced to an aggregate observation, and identical observations are collapsed
with a count.

That collapsing is not just a privacy measure — it is also what the intelligence
needs. "Three manufacturing victims claimed by the same group in one week" is a
threat signal; three named organisations are a liability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from lib.ids import content_digest
from models.intelligence import Entity, Observation
from normalization.cisa import NormalizationError, sanitize_text

COUNTRY_PATTERN = re.compile(r"^[A-Z]{2}$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}")

MAX_GROUP_LENGTH = 100
MAX_SECTOR_LENGTH = 100

#: Field names seen for the sector across ransomware.live record versions.
SECTOR_FIELDS = ("sector", "activity", "industry")

#: The field holding the victim organisation name. Read only to detect presence;
#: its value is never retained.
VICTIM_NAME_FIELDS = ("victim", "post_title", "company", "name")


def _first_present(record: dict, fields: tuple[str, ...]) -> Any:
    for field in fields:
        value = record.get(field)

        if value not in (None, ""):
            return value

    return None


def normalize_country(value: Any) -> str | None:
    """ISO 3166-1 alpha-2, uppercase. Anything else is discarded."""

    text = sanitize_text(value, max_length=8)

    if not text:
        return None

    candidate = text.strip().upper()

    return candidate if COUNTRY_PATTERN.match(candidate) else None


def normalize_attack_date(value: Any) -> str | None:
    """Reduces an attack timestamp to a ``YYYY-MM-DD`` date."""

    text = sanitize_text(value, max_length=40)

    if not text:
        return None

    match = DATE_PATTERN.match(text)

    if not match:
        return None

    year, month, day = (int(part) for part in match.group(0).split("-"))

    if not (2000 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31):
        return None

    return match.group(0)


@dataclass(frozen=True)
class VictimObservation:
    """One aggregate observation. Deliberately carries no victim identity."""

    group: str
    country: str
    sector: str | None
    attack_date: str | None
    victim_count: int

    def identity(self) -> str:
        """Stable, non-identifying identity for this aggregate."""

        return content_digest(
            {
                "group": self.group.lower(),
                "country": self.country,
                "sector": (self.sector or "").lower(),
                "date": self.attack_date or "",
            }
        )[:32]

    def to_payload(self, *, source_key: str) -> dict:
        return {
            "group": self.group,
            "country": self.country,
            "sector": self.sector,
            "attack_date": self.attack_date,
            "victim_count": self.victim_count,
            "aggregate": True,
            "victim_identity_withheld": True,
            "source": source_key,
        }

    def entities(self) -> list[Entity]:
        entities = [
            Entity(kind="country", value=self.country, normalized=self.country),
            Entity(kind="actor", value=self.group, normalized=self.group.lower()),
        ]

        if self.sector:
            entities.append(
                Entity(
                    kind="sector",
                    value=self.sector,
                    normalized=self.sector.lower(),
                )
            )

        return entities


def parse_victims(payload: Any) -> tuple[list[VictimObservation], list[str]]:
    """Validates a ransomware.live victim response.

    Returns ``(observations, rejections)``, each observation carrying a count of
    one. A structurally invalid response raises :class:`NormalizationError`;
    individual unusable records are rejected with a reason.

    The victim name is read only to confirm a record is a victim claim. Its value
    is never placed in the returned objects.
    """

    if isinstance(payload, dict):
        rows = payload.get("data")
    else:
        rows = payload

    if not isinstance(rows, list):
        raise NormalizationError(
            "ransomware.live response is neither an array nor an object with "
            "'data'"
        )

    observations: list[VictimObservation] = []
    rejections: list[str] = []

    for index, row in enumerate(rows):
        where = f"victims[{index}]"

        if not isinstance(row, dict):
            rejections.append(f"{where}: not an object")
            continue

        if _first_present(row, VICTIM_NAME_FIELDS) is None:
            rejections.append(f"{where}: no victim claim present")
            continue

        group = sanitize_text(_first_present(row, ("group", "group_name")), max_length=MAX_GROUP_LENGTH)

        if not group:
            rejections.append(f"{where}: missing ransomware group")
            continue

        country = normalize_country(_first_present(row, ("country", "country_code")))

        if country is None:
            rejections.append(f"{where}: missing or invalid country code")
            continue

        sector = sanitize_text(
            _first_present(row, SECTOR_FIELDS), max_length=MAX_SECTOR_LENGTH
        )

        observations.append(
            VictimObservation(
                group=group,
                country=country,
                sector=sector,
                attack_date=normalize_attack_date(
                    _first_present(row, ("attackdate", "discovered", "date"))
                ),
                victim_count=1,
            )
        )

    return observations, rejections


def aggregate_victims(
    observations: list[VictimObservation],
) -> list[VictimObservation]:
    """Collapses identical observations into counted aggregates.

    Two victims claimed by the same group, in the same country and sector on the
    same date become one observation with ``victim_count = 2``. The count is the
    intelligence; the identities are not kept.
    """

    merged: dict[tuple[str, str, str, str], VictimObservation] = {}

    for observation in observations:
        key = (
            observation.group.lower(),
            observation.country,
            (observation.sector or "").lower(),
            observation.attack_date or "",
        )

        existing = merged.get(key)

        if existing is None:
            merged[key] = observation
            continue

        merged[key] = VictimObservation(
            group=existing.group,
            country=existing.country,
            sector=existing.sector,
            attack_date=existing.attack_date,
            victim_count=existing.victim_count + observation.victim_count,
        )

    return [merged[key] for key in sorted(merged)]


def build_observation(
    observation: VictimObservation, *, source_key: str, retrieved_at: str
) -> Observation:
    """Turns an aggregate into a provenance-carrying observation."""

    return Observation(
        source_key=source_key,
        external_id=f"{source_key}:{observation.identity()}",
        observed_at=observation.attack_date or retrieved_at,
        retrieved_at=retrieved_at,
        source_record_id=observation.identity(),
        payload=observation.to_payload(source_key=source_key),
        entities=observation.entities(),
    )


"""ENISA EUVD (European Union Vulnerability Database) normalisation.

The EU-authoritative vulnerability record. Two of its endpoints are usable and
verified: ``/api/lastvulnerabilities`` and ``/api/exploitedvulnerabilities``. The
latter carries an ``exploitedSince`` date — independent, EU-level confirmation
that a vulnerability is being exploited in the wild, which is exactly the kind of
evidence a KEV threat should carry.

Three properties of the real payload need handling, all verified against the live
API rather than taken from documentation:

* **The CVE identifier is not a field.** It lives inside ``aliases`` as a
  newline-separated string, mixed with other identifiers such as GHSA ids:
  ``"CVE-2026-105455\\nGHSA-8whf-jvmp-ghv3\\n"``.
* **``epss`` units are inconsistent within a single response.** Real values seen
  in one payload: ``0``, ``0.38``, ``0.91`` *and* ``26.57``. Values above 1 are
  percentages and are scaled, or the evidence would be wrong by a factor of 100.
* **Timestamps are not ISO**: ``"Oct 30, 2026, 3:34:49 PM"``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from lib.ids import CVE_PATTERN
from models.intelligence import Entity, Observation
from normalization.cisa import NormalizationError, sanitize_text

MAX_DESCRIPTION_LENGTH = 4000
MAX_VECTOR_LENGTH = 200
MAX_ALIAS_LENGTH = 200
MAX_VENDORS = 20
MAX_REFERENCES = 20

#: ``CVE`` identifiers as they appear inside the ``aliases`` string.
CVE_IN_ALIASES = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

#: The EUVD timestamp format, e.g. ``Oct 30, 2026, 3:34:49 PM``.
EUVD_TIMESTAMP_FORMATS = (
    "%b %d, %Y, %I:%M:%S %p",
    "%b %d, %Y, %I:%M %p",
    "%Y-%m-%dT%H:%M:%S",
)

_WHITESPACE = re.compile(r"\s+")


def normalize_euvd_timestamp(value: Any) -> str | None:
    """An EUVD timestamp reduced to ``YYYY-MM-DDTHH:MM:SSZ``."""

    text = sanitize_text(value, max_length=40)

    if not text:
        return None

    # Single-digit days arrive space-padded, which strptime does not accept.
    collapsed = _WHITESPACE.sub(" ", text).strip()

    for fmt in EUVD_TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(collapsed, fmt)
        except ValueError:
            continue

        return parsed.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return None


def normalize_euvd_epss(value: Any) -> float | None:
    """EUVD's EPSS value as a probability in ``[0, 1]``.

    The field mixes units: a single response contains both ``0.38`` and
    ``26.57``. Anything above 1 is a percentage and is scaled down. The result is
    clamped, so a malformed value cannot produce out-of-range evidence.
    """

    if value is None or isinstance(value, bool):
        return None

    try:
        number = float(value)
    except (TypeError, ValueError):
        return None

    if number != number:  # NaN
        return None

    if number > 1:
        number = number / 100.0

    if number < 0:
        return None

    return min(1.0, number)


def extract_cve_ids(aliases: Any) -> list[str]:
    """Every CVE identifier inside the newline-separated ``aliases`` string."""

    text = sanitize_text(aliases, max_length=MAX_ALIAS_LENGTH * 20)

    if not text:
        return []

    found: set[str] = set()

    for match in CVE_IN_ALIASES.finditer(text):
        candidate = match.group(0).upper()

        if CVE_PATTERN.match(candidate):
            found.add(candidate)

    return sorted(found)


def _split_lines(value: Any, *, limit: int, max_length: int) -> list[str]:
    """Splits EUVD's newline-separated reference and alias strings."""

    text = sanitize_text(value, max_length=max_length * (limit + 1))

    if not text:
        return []

    entries: list[str] = []

    for line in text.splitlines():
        cleaned = sanitize_text(line, max_length=max_length)

        if cleaned and cleaned not in entries:
            entries.append(cleaned)

        if len(entries) >= limit:
            break

    return entries


@dataclass(frozen=True)
class EuvdRecord:
    """One validated EUVD record."""

    euvd_id: str
    cve_ids: list[str] = field(default_factory=list)
    enisa_uuid: str | None = None
    description: str | None = None
    base_score: float | None = None
    base_score_version: str | None = None
    base_score_vector: str | None = None
    epss: float | None = None
    exploited: bool = False
    exploited_since: str | None = None
    published_at: str | None = None
    updated_at: str | None = None
    assigner: str | None = None
    vendors: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_payload(self, *, source_key: str) -> dict:
        return {
            "euvd_id": self.euvd_id,
            "cve_ids": list(self.cve_ids),
            "description": self.description,
            "cvss_score": self.base_score,
            "cvss_version": self.base_score_version,
            "cvss_vector": self.base_score_vector,
            "epss": self.epss,
            "enisa_exploited": self.exploited,
            "exploited_since": self.exploited_since,
            "published_at": self.published_at,
            "updated_at": self.updated_at,
            "assigner": self.assigner,
            "vendors": list(self.vendors),
            "references": list(self.references),
            "source": source_key,
        }

    def entities(self) -> list[Entity]:
        return [
            Entity(kind="cve", value=cve, normalized=cve) for cve in self.cve_ids
        ]


def _vendor_names(payload: dict) -> list[str]:
    names: list[str] = []

    for entry in payload.get("enisaIdVendor") or []:
        if not isinstance(entry, dict):
            continue

        vendor = entry.get("vendor")

        name = sanitize_text(
            vendor.get("name") if isinstance(vendor, dict) else vendor,
            max_length=MAX_ALIAS_LENGTH,
        )

        if name and name not in names:
            names.append(name)

        if len(names) >= MAX_VENDORS:
            break

    return names


def parse_euvd_record(payload: Any, *, exploited: bool = False) -> EuvdRecord:
    """Validates one EUVD record.

    ``exploited`` reflects which endpoint the record came from; an
    ``exploitedSince`` date also marks a record as exploited, whichever endpoint
    returned it.
    """

    if not isinstance(payload, dict):
        raise NormalizationError("EUVD record is not an object")

    euvd_id = sanitize_text(payload.get("id"), max_length=64)

    if not euvd_id:
        raise NormalizationError("EUVD record has no id")

    try:
        base_score: float | None = float(payload.get("baseScore"))
    except (TypeError, ValueError):
        base_score = None

    exploited_since = normalize_euvd_timestamp(payload.get("exploitedSince"))

    return EuvdRecord(
        euvd_id=euvd_id,
        cve_ids=extract_cve_ids(payload.get("aliases")),
        enisa_uuid=sanitize_text(payload.get("enisaUuid"), max_length=64),
        description=sanitize_text(
            payload.get("description"), max_length=MAX_DESCRIPTION_LENGTH
        ),
        base_score=base_score,
        base_score_version=sanitize_text(
            payload.get("baseScoreVersion"), max_length=16
        ),
        base_score_vector=sanitize_text(
            payload.get("baseScoreVector"), max_length=MAX_VECTOR_LENGTH
        ),
        epss=normalize_euvd_epss(payload.get("epss")),
        exploited=exploited or exploited_since is not None,
        exploited_since=exploited_since,
        published_at=normalize_euvd_timestamp(payload.get("datePublished")),
        updated_at=normalize_euvd_timestamp(payload.get("dateUpdated")),
        assigner=sanitize_text(payload.get("assigner"), max_length=100),
        vendors=_vendor_names(payload),
        references=_split_lines(
            payload.get("references"), limit=MAX_REFERENCES, max_length=500
        ),
    )


def parse_euvd_payload(
    payload: Any, *, exploited: bool = False
) -> tuple[list[EuvdRecord], list[str]]:
    """Validates an EUVD response.

    Returns ``(records, rejections)``. A response that is not an array raises
    :class:`NormalizationError`; an individual unusable record is rejected with a
    reason instead, so one bad record cannot discard a whole response.
    """

    if not isinstance(payload, list):
        raise NormalizationError("EUVD response is not an array")

    records: list[EuvdRecord] = []
    rejections: list[str] = []

    for index, row in enumerate(payload):
        try:
            records.append(parse_euvd_record(row, exploited=exploited))
        except NormalizationError as error:
            rejections.append(f"records[{index}]: {error}")

    return records, rejections


def build_observation(
    record: EuvdRecord, *, source_key: str, retrieved_at: str
) -> Observation:
    """Turns an EUVD record into a provenance-carrying observation."""

    return Observation(
        source_key=source_key,
        external_id=record.euvd_id,
        observed_at=(
            record.exploited_since
            or record.updated_at
            or record.published_at
            or retrieved_at
        ),
        retrieved_at=retrieved_at,
        source_record_id=record.euvd_id,
        payload=record.to_payload(source_key=source_key),
        entities=record.entities(),
    )


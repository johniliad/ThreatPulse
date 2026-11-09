"""CISA KEV normalization.

Feed content is untrusted: every field is validated, bounded and sanitised
before it can reach the intelligence model. A record that cannot be trusted is
rejected with a reason rather than silently coerced.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from lib.ids import CVE_PATTERN
from models.intelligence import Entity

CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
WHITESPACE = re.compile(r"\s+")
CWE_PATTERN = re.compile(r"^CWE-\d{1,5}$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

#: ISO-like timestamps, with or without a zone and with or without sub-seconds.
ISO_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|z|[+-]\d{2}:?\d{2})?$"
)

#: Zones equivalent to UTC. Anything else is refused rather than shifted by a guess.
UTC_ZONES = frozenset({"Z", "z", "+00:00", "+0000", "-00:00", "-0000"})

#: ATT&CK technique identifiers as they appear *inside prose* — ``T1566`` or the
#: sub-technique form ``T1566.001``. The word boundaries matter: without them a
#: longer token such as ``AT1566`` would match. A pattern anchored to a whole
#: string is a different job and lives in ``normalization/attack.py``.
TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

MAX_TITLE_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 4000
MAX_ACTION_LENGTH = 4000
MAX_NOTES_LENGTH = 4000
MAX_NAME_LENGTH = 200


class NormalizationError(ValueError):
    """Raised when a source record cannot be normalised safely."""


class RecordUnavailable(NormalizationError):
    """The upstream holds no usable record for this identifier.

    A **permanent** answer, distinct from a malformed record or a transport
    failure: the identifier exists, the upstream simply has nothing for it, or has
    explicitly withdrawn it. A collector records it as a miss and stops asking
    until the cooling-off period expires, instead of retrying it every run.

    It subclasses :class:`NormalizationError` so a caller that only handles the
    general case still behaves safely.
    """


def sanitize_text(value: Any, *, max_length: int) -> str | None:
    """Strips control characters, collapses whitespace and bounds the length."""

    if value is None:
        return None

    if not isinstance(value, str):
        value = str(value)

    cleaned = WHITESPACE.sub(" ", CONTROL_CHARACTERS.sub(" ", value)).strip()

    if cleaned == "":
        return None

    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 1].rstrip() + "\u2026"

    return cleaned


def normalize_date(value: Any) -> str | None:
    """Returns a validated ``YYYY-MM-DD`` string, or None."""

    text = sanitize_text(value, max_length=32)

    if not text or not DATE_PATTERN.match(text):
        return None

    year, month, day = (int(part) for part in text.split("-"))

    if not (2000 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31):
        return None

    return text


def normalize_cwes(value: Any) -> list[str]:
    """Keeps only well-formed, deduplicated CWE identifiers."""

    if not isinstance(value, list):
        return []

    seen: list[str] = []

    for entry in value:
        text = sanitize_text(entry, max_length=32)

        if text and CWE_PATTERN.match(text) and text not in seen:
            seen.append(text)

    return sorted(seen)


def normalize_iso_timestamp(value: Any) -> str | None:
    """An ISO-like timestamp reduced to ``YYYY-MM-DDTHH:MM:SSZ``.

    Sources in the wild mix ``2024-05-08T00:00:00`` (no zone at all) with
    ``2024-08-01T23:44:09.661Z``. A missing zone is read as UTC, matching the CVE
    Program's own convention. A non-UTC offset is **not** silently reinterpreted:
    these fields are optional, so they are dropped instead of being shifted by a
    guess.
    """

    text = sanitize_text(value, max_length=40)

    if not text:
        return None

    match = ISO_PATTERN.match(text)

    if not match:
        return None

    date_part, time_part, zone = match.groups()

    if zone is not None and zone not in UTC_ZONES:
        return None

    return f"{date_part}T{time_part}Z"


def extract_techniques(*texts: str | None) -> list[str]:
    """Every ATT&CK technique identifier mentioned, deduplicated and sorted.

    Shared by every advisory path, so a CISA CSAF advisory and a national CERT feed
    item are read the same way. An identifier found here is a *reference* the source
    made; it is never treated as evidence that the technique was used.
    """

    found: set[str] = set()

    for text in texts:
        if not isinstance(text, str):
            continue

        for match in TECHNIQUE_PATTERN.finditer(text):
            found.add(match.group(0).upper())

    return sorted(found)


def normalize_ransomware_use(value: Any) -> str:
    """Normalises the KEV ``knownRansomwareCampaignUse`` field."""

    text = (sanitize_text(value, max_length=32) or "").strip().lower()

    return "Known" if text == "known" else "Unknown"


def normalize_forensic_triage(value: Any) -> bool:
    """KEV ``forensicTriage`` is ``Yes``/``No``."""

    text = (sanitize_text(value, max_length=8) or "").strip().lower()

    return text == "yes"


@dataclass
class KevRecord:
    """A validated CISA KEV record."""

    cve_id: str
    vendor: str | None
    product: str | None
    title: str | None
    description: str | None
    required_action: str | None
    date_added: str | None
    due_date: str | None
    ransomware_use: str
    forensic_triage: bool
    notes: str | None
    cwes: list[str] = field(default_factory=list)

    def to_payload(self) -> dict:
        """The normalized payload stored with the observation.

        Field names are inherited from the pre-existing implementation
        (``vulnerability_name``, ``source``, ``kev_listed``,
        ``exploited_in_wild``) so that the scoring model and any existing tooling
        keep working unchanged.
        """

        return {
            "cve_id": self.cve_id,
            "vendor": self.vendor,
            "product": self.product,
            "vulnerability_name": self.title,
            "date_added": self.date_added,
            "description": self.description,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "known_ransomware_campaign_use": self.ransomware_use,
            "forensic_triage": "Yes" if self.forensic_triage else "No",
            "notes": self.notes,
            "cwes": self.cwes,
            "source": "cisa_kev",
            "exploited_in_wild": True,
            "kev_listed": True,
        }


def parse_kev_record(payload: Any) -> KevRecord:
    """Validates and normalises one KEV record.

    Raises :class:`NormalizationError` when the record cannot be trusted — for
    example a missing or malformed CVE identifier, which is the only field the
    pipeline cannot work without.
    """

    if not isinstance(payload, dict):
        raise NormalizationError("record is not an object")

    raw_cve = payload.get("cveID")

    if not isinstance(raw_cve, str):
        raise NormalizationError("record has no cveID")

    cve_id = raw_cve.strip().upper()

    if not CVE_PATTERN.match(cve_id):
        raise NormalizationError(f"invalid CVE identifier: {raw_cve!r}")

    date_added = normalize_date(payload.get("dateAdded"))
    due_date = normalize_date(payload.get("dueDate"))

    if date_added is None:
        raise NormalizationError(f"{cve_id}: missing or invalid dateAdded")

    return KevRecord(
        cve_id=cve_id,
        vendor=sanitize_text(payload.get("vendorProject"), max_length=MAX_NAME_LENGTH),
        product=sanitize_text(payload.get("product"), max_length=MAX_NAME_LENGTH),
        title=sanitize_text(
            payload.get("vulnerabilityName"), max_length=MAX_TITLE_LENGTH
        ),
        description=sanitize_text(
            payload.get("shortDescription"), max_length=MAX_DESCRIPTION_LENGTH
        ),
        required_action=sanitize_text(
            payload.get("requiredAction"), max_length=MAX_ACTION_LENGTH
        ),
        date_added=date_added,
        due_date=due_date,
        ransomware_use=normalize_ransomware_use(
            payload.get("knownRansomwareCampaignUse")
        ),
        forensic_triage=normalize_forensic_triage(payload.get("forensicTriage")),
        notes=sanitize_text(payload.get("notes"), max_length=MAX_NOTES_LENGTH),
        cwes=normalize_cwes(payload.get("cwes")),
    )


def build_entities(record: KevRecord) -> list[Entity]:
    """Entities a KEV record is about, for correlation."""

    entities = [Entity(kind="cve", value=record.cve_id, normalized=record.cve_id)]

    if record.vendor and record.product:
        entities.append(
            Entity(
                kind="vendor_product",
                value=f"{record.vendor} {record.product}",
                normalized=f"{record.vendor}|{record.product}".lower(),
            )
        )

    return entities

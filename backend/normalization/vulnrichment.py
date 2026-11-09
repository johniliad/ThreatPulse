"""CISA Vulnrichment normalisation.

Vulnrichment is CISA's Authorized Data Publisher (ADP) enrichment of public CVE
records: three SSVC decision points for every CVE it analyses, plus a CWE and a
CVSS assessment of its own wherever CISA had enough evidence to assert one.

**This source is enrichment, never exploitation evidence.** The published payload
therefore carries no ``kev_listed``, ``exploited_in_wild``, ``date_added`` or
``due_date`` field. Those four are exactly what the correlation engine and the
priority model read to decide that something is exploited and how urgent it is,
and CISA's SSVC assessment is not a ThreatPulse observation of exploitation. Their
absence is what makes this source incapable of moving an existing threat's score.
``FORBIDDEN_PAYLOAD_KEYS`` states the rule; ``tests/test_collectors_vulnrichment``
enforces it, and ``correlation.engine`` only ever lets this source *fill a gap*.

Four properties of the real records drive this implementation. All were taken from
the live repository rather than from documentation:

* **The record URL is derived, not discoverable.** There is no bulk or aggregate
  file. The repository is laid out as
  ``<year>/<block>xxx/CVE-<year>-<number>.json`` where ``block`` is the CVE number
  divided by 1000: ``CVE-2024-0043`` → ``2024/0xxx/``, ``CVE-2024-3477`` →
  ``2024/3xxx/``, ``CVE-2024-25522`` → ``2024/25xxx/``, ``CVE-2026-109619`` →
  ``2026/109xxx/``. A wrong block 404s for every CVE at once, so the mapping is
  asserted against those four examples.
* **The ADP container is one of several.** ``containers.adp`` also carries a
  "CVE Program Container"; only the entry whose ``providerMetadata.shortName`` is
  ``CISA-ADP`` holds the enrichment.
* **``metrics`` is a heterogeneous list.** Each element is either
  ``{"cvssV3_1": {...}}`` or ``{"other": {"type": "ssvc"|"kev", "content": {...}}}``.
  SSVC options are single-key objects and one of the keys contains a space:
  ``{"Technical Impact": "total"}``.
* **A CNA container is not a source of affected products.** CNAs routinely publish
  ``"vendor": "n/a"``, which must not be mistaken for a vendor name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from lib.ids import CVE_PATTERN
from models.intelligence import Entity, Observation
from normalization.cisa import (
    NormalizationError,
    RecordUnavailable,
    normalize_cwes,
    normalize_date,
    normalize_iso_timestamp,
    sanitize_text,
)

MAX_DESCRIPTION_LENGTH = 4000
MAX_TITLE_LENGTH = 500
MAX_NAME_LENGTH = 200
MAX_VECTOR_LENGTH = 200
MAX_REFERENCE_LENGTH = 500

#: The ``shortName`` that identifies the CISA enrichment container.
CISA_ADP_SHORT_NAME = "CISA-ADP"

#: Payload keys this normaliser must never emit. See the module docstring.
FORBIDDEN_PAYLOAD_KEYS = (
    "kev_listed",
    "exploited_in_wild",
    "date_added",
    "due_date",
)

#: SSVC decision points, with the values the CISA Coordinator tree produces.
#: Values outside these sets are dropped rather than guessed at.
SSVC_OPTION_KEYS = {
    "Exploitation": ("exploitation", frozenset({"none", "poc", "active"})),
    "Automatable": ("automatable", frozenset({"no", "yes"})),
    "Technical Impact": ("technical_impact", frozenset({"partial", "total"})),
}

#: CVSS metrics in descending order of preference, with their fallback version.
CVSS_METRIC_KEYS = (
    ("cvssV4_0", "4.0"),
    ("cvssV3_1", "3.1"),
    ("cvssV3_0", "3.0"),
    ("cvssV2_0", "2.0"),
)

_CVE_PARTS = re.compile(r"^CVE-(\d{4})-(\d{4,})$")

#: Placeholders that are not names.
_NOT_A_NAME = frozenset({"n/a", "na", "none", "unknown", "unspecified"})


class VulnrichmentRejected(RecordUnavailable):
    """The record exists but carries no enrichment worth publishing.

    A CVE that CISA has not analysed, or one whose CVE record was withdrawn, is a
    permanent outcome rather than a transient failure: the collector records it as
    a miss instead of retrying it on every run.
    """


def record_path(cve_id: str) -> str:
    """Repository path of a CVE record, e.g. ``2024/25xxx/CVE-2024-25522.json``.

    ``block`` is the CVE number divided by 1000 with ``xxx`` appended, which is the
    CVE Program's own directory convention. Verified against the live repository for
    ``CVE-2024-0043`` (``0xxx``), ``CVE-2024-3477`` (``3xxx``),
    ``CVE-2024-25522`` (``25xxx``) and the six-digit ``2026`` blocks.
    """

    candidate = (cve_id or "").strip().upper()
    match = _CVE_PARTS.match(candidate)

    if not match:
        raise NormalizationError(f"invalid CVE identifier: {cve_id!r}")

    year, number = match.group(1), int(match.group(2))

    return f"{year}/{number // 1000}xxx/{candidate}.json"


def record_url(base_url: str, cve_id: str) -> str:
    """Full URL of a CVE record below a repository base URL."""

    return f"{(base_url or '').rstrip('/')}/{record_path(cve_id)}"


def _as_base_score(value: Any) -> float | None:
    """A CVSS base score, or None when the value is not a plausible one."""

    if value is None or isinstance(value, bool):
        return None

    try:
        number = float(value)
    except (TypeError, ValueError):
        return None

    if number != number or not 0.0 <= number <= 10.0:
        return None

    return round(number, 1)


def _named(value: Any) -> str | None:
    """A vendor or product name, rejecting the placeholders CNAs publish."""

    text = sanitize_text(value, max_length=MAX_NAME_LENGTH)

    if not text or text.strip().lower() in _NOT_A_NAME:
        return None

    return text


def find_adp_container(payload: Any) -> dict | None:
    """The CISA ADP container of a CVE record, or None."""

    if not isinstance(payload, dict):
        return None

    containers = payload.get("containers")

    if not isinstance(containers, dict):
        return None

    entries = containers.get("adp")

    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue

        metadata = entry.get("providerMetadata")

        if not isinstance(metadata, dict):
            continue

        short_name = metadata.get("shortName")

        if (
            isinstance(short_name, str)
            and short_name.strip().upper() == CISA_ADP_SHORT_NAME
        ):
            return entry

    return None


def _metric_blocks(container: dict) -> list[dict]:
    metrics = container.get("metrics")

    return [entry for entry in metrics or [] if isinstance(entry, dict)]


def _other_blocks(container: dict, kind: str) -> list[dict]:
    """Every ``other`` metric of one ``type`` (``ssvc`` or ``kev``)."""

    blocks: list[dict] = []

    for entry in _metric_blocks(container):
        other = entry.get("other")

        if not isinstance(other, dict):
            continue

        if str(other.get("type", "")).strip().lower() != kind:
            continue

        content = other.get("content")

        if isinstance(content, dict):
            blocks.append(content)

    return blocks


@dataclass(frozen=True)
class SsvcAssessment:
    """CISA's SSVC decision points for one CVE.

    A decision point is ``None`` when CISA's tree did not produce it or produced a
    value this version does not recognise. An unrecognised value is dropped rather
    than stored as a guess.
    """

    exploitation: str | None = None
    automatable: str | None = None
    technical_impact: str | None = None
    version: str | None = None
    role: str | None = None
    timestamp: str | None = None

    @property
    def decision_points(self) -> dict[str, str]:
        return {
            key: value
            for key, value in (
                ("exploitation", self.exploitation),
                ("automatable", self.automatable),
                ("technical_impact", self.technical_impact),
            )
            if value
        }

    def to_dict(self) -> dict:
        return {
            "exploitation": self.exploitation,
            "automatable": self.automatable,
            "technical_impact": self.technical_impact,
            "version": self.version,
            "role": self.role,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class CvssAssessment:
    """A CVSS base assessment CISA asserted for a CVE."""

    base_score: float
    version: str | None = None
    base_severity: str | None = None
    vector: str | None = None

    def to_dict(self) -> dict:
        return {
            "base_score": self.base_score,
            "version": self.version,
            "base_severity": self.base_severity,
            "vector": self.vector,
        }


def extract_ssvc(container: dict) -> SsvcAssessment | None:
    """The SSVC assessment in an ADP container, or None."""

    for content in _other_blocks(container, "ssvc"):
        values: dict[str, str | None] = {
            "exploitation": None,
            "automatable": None,
            "technical_impact": None,
        }

        options = content.get("options")

        for option in options if isinstance(options, list) else []:
            if not isinstance(option, dict):
                continue

            for key, raw in option.items():
                mapping = SSVC_OPTION_KEYS.get(str(key).strip())

                if mapping is None:
                    continue

                field_name, allowed = mapping
                token = str(raw).strip().lower()

                if token in allowed:
                    values[field_name] = token

        if not any(values.values()):
            continue

        return SsvcAssessment(
            exploitation=values["exploitation"],
            automatable=values["automatable"],
            technical_impact=values["technical_impact"],
            version=sanitize_text(content.get("version"), max_length=16),
            role=sanitize_text(content.get("role"), max_length=100),
            timestamp=normalize_iso_timestamp(content.get("timestamp")),
        )

    return None


def extract_cvss(container: dict) -> CvssAssessment | None:
    """The most modern CVSS assessment in an ADP container, or None.

    CVSS v4 is preferred over v3.1, v3.1 over v3.0 and v3.0 over v2.0, so a record
    carrying more than one metric yields the newest rather than the first listed.
    """

    for key, fallback_version in CVSS_METRIC_KEYS:
        for entry in _metric_blocks(container):
            block = entry.get(key)

            if not isinstance(block, dict):
                continue

            score = _as_base_score(block.get("baseScore"))

            if score is None:
                continue

            return CvssAssessment(
                base_score=score,
                version=sanitize_text(block.get("version"), max_length=16)
                or fallback_version,
                base_severity=sanitize_text(
                    block.get("baseSeverity"), max_length=16
                ),
                vector=sanitize_text(
                    block.get("vectorString"), max_length=MAX_VECTOR_LENGTH
                ),
            )

    return None


def extract_cwes(container: dict) -> list[str]:
    """CWE identifiers from ``problemTypes[].descriptions[].cweId``.

    Only entries carrying a ``cweId`` are read. A CNA that has no CWE publishes
    ``{"type": "text", "description": "n/a"}``, which must not become a weakness.
    """

    identifiers: list[str] = []
    problems = container.get("problemTypes")

    for problem in problems if isinstance(problems, list) else []:
        if not isinstance(problem, dict):
            continue

        descriptions = problem.get("descriptions")

        for description in descriptions if isinstance(descriptions, list) else []:
            if not isinstance(description, dict):
                continue

            cwe = sanitize_text(description.get("cweId"), max_length=32)

            if cwe:
                identifiers.append(cwe)

    return normalize_cwes(identifiers)


def extract_affected(container: dict) -> tuple[str | None, str | None]:
    """The first usable ``(vendor, product)`` pair in a container."""

    affected = container.get("affected")

    for entry in affected if isinstance(affected, list) else []:
        if not isinstance(entry, dict):
            continue

        vendor = _named(entry.get("vendor"))
        product = _named(entry.get("product"))

        if vendor and product:
            return vendor, product

    return None, None


def extract_description(container: dict) -> str | None:
    """The English description, falling back to the first one present."""

    descriptions = container.get("descriptions")
    first: str | None = None

    for entry in descriptions if isinstance(descriptions, list) else []:
        if not isinstance(entry, dict):
            continue

        value = sanitize_text(
            entry.get("value"), max_length=MAX_DESCRIPTION_LENGTH
        )

        if not value:
            continue

        language = str(entry.get("lang", "")).strip().lower()

        if language.startswith("en"):
            return value

        if first is None:
            first = value

    return first


def extract_kev_metric(container: dict) -> tuple[str | None, str | None]:
    """``(date_added, reference)`` from the KEV metric CISA adds to known CVEs.

    That metric is CISA's own confirmation that the CVE is on the KEV catalogue.
    It is stored as ``kev_date_added`` — deliberately *not* ``date_added``, which
    the priority model reads as a KEV record's own field.
    """

    for content in _other_blocks(container, "kev"):
        date_added = normalize_date(content.get("dateAdded"))
        reference = sanitize_text(
            content.get("reference"), max_length=MAX_REFERENCE_LENGTH
        )

        if reference and not reference.startswith("https://"):
            reference = None

        if date_added or reference:
            return date_added, reference

    return None, None


def build_entities(
    *, cve_id: str, vendor: str | None = None, product: str | None = None
) -> list[Entity]:
    """Entities a Vulnrichment record is about, for correlation.

    The CVE is the primary key, so the enrichment joins the threat the KEV
    catalogue already created rather than forming one of its own.
    """

    entities = [Entity(kind="cve", value=cve_id, normalized=cve_id)]

    if vendor and product:
        entities.append(
            Entity(
                kind="vendor_product",
                value=f"{vendor} {product}",
                normalized=f"{vendor}|{product}".lower(),
            )
        )

    return entities


@dataclass(frozen=True)
class VulnrichmentRecord:
    """A validated CISA Vulnrichment record."""

    cve_id: str
    state: str | None = None
    title: str | None = None
    description: str | None = None
    vendor: str | None = None
    product: str | None = None
    cwes: list[str] = field(default_factory=list)
    cvss: CvssAssessment | None = None
    ssvc: SsvcAssessment | None = None
    kev_date_added: str | None = None
    kev_reference: str | None = None
    adp_updated_at: str | None = None
    published_at: str | None = None
    updated_at: str | None = None
    data_version: str | None = None

    def is_useful(self) -> bool:
        """Whether this record adds anything worth publishing.

        CISA's minimum for an analysed CVE is the SSVC triple, but a record may
        also carry only a CWE or only a CVSS assessment. A record with none of
        them would be a payload that enriches nothing.
        """

        return bool(
            self.ssvc is not None
            or self.cvss is not None
            or self.cwes
            or self.kev_date_added
        )

    def to_payload(self, *, source_key: str) -> dict:
        """The normalized payload stored with the observation.

        ``FORBIDDEN_PAYLOAD_KEYS`` are asserted absent rather than merely omitted:
        a future edit that reintroduces one would otherwise let this enrichment
        source assert exploitation and move a threat's score.
        """

        payload = {
            "cve_id": self.cve_id,
            "vendor": self.vendor,
            "product": self.product,
            "description": self.description,
            "cwes": list(self.cwes),
            "ssvc": self.ssvc.to_dict() if self.ssvc else None,
            "cvss": self.cvss.to_dict() if self.cvss else None,
            "kev_date_added": self.kev_date_added,
            "kev_reference": self.kev_reference,
            "adp_updated_at": self.adp_updated_at,
            "published_at": self.published_at,
            "updated_at": self.updated_at,
            "record_state": self.state,
            "data_version": self.data_version,
            "source": source_key,
            "enrichment": True,
            # The source's own block, published under metadata.enrichment keyed by
            # source, so CISA's assessment stays self-describing.
            "enrichment_summary": {
                "ssvc": self.ssvc.to_dict() if self.ssvc else None,
                "cvss": self.cvss.to_dict() if self.cvss else None,
                "cwes": list(self.cwes),
                "kev_date_added": self.kev_date_added,
                "adp_updated_at": self.adp_updated_at,
            },
        }

        forbidden = sorted(key for key in FORBIDDEN_PAYLOAD_KEYS if key in payload)

        if forbidden:
            raise NormalizationError(
                "Vulnrichment payload must not carry exploitation evidence: "
                + ", ".join(forbidden)
            )

        return payload

    def entities(self) -> list[Entity]:
        """Entities this record is about, for correlation."""

        return build_entities(
            cve_id=self.cve_id, vendor=self.vendor, product=self.product
        )


def build_observation(
    payload: dict, *, source_key: str, retrieved_at: str
) -> Observation:
    """Turns a normalized payload into a provenance-carrying observation.

    Takes the payload rather than the record so that an observation re-emitted
    from the state cache is byte-identical to one built from a fresh fetch.
    """

    cve_id = str(payload.get("cve_id", "")).strip().upper()

    if not cve_id:
        raise NormalizationError("payload has no cve_id")

    entities = build_entities(
        cve_id=cve_id,
        vendor=payload.get("vendor") if isinstance(payload.get("vendor"), str) else None,
        product=payload.get("product")
        if isinstance(payload.get("product"), str)
        else None,
    )

    observed_at = (
        payload.get("adp_updated_at")
        or payload.get("updated_at")
        or payload.get("published_at")
        or retrieved_at
    )

    return Observation(
        source_key=source_key,
        external_id=cve_id,
        observed_at=str(observed_at),
        retrieved_at=retrieved_at,
        source_record_id=cve_id,
        payload=payload,
        entities=entities,
    )


def _provider_updated_at(container: dict) -> str | None:
    metadata = container.get("providerMetadata")

    if not isinstance(metadata, dict):
        return None

    return metadata.get("dateUpdated")


def parse_vulnrichment_record(payload: Any) -> VulnrichmentRecord:
    """Validates one CVE record and extracts CISA's enrichment.

    Raises :class:`NormalizationError` when the record cannot be trusted, and
    :class:`VulnrichmentRejected` when it carries no enrichment at all — a CVE CISA
    has not analysed, or one whose record was withdrawn. The two outcomes are
    deliberately different: the first is a defect worth retrying, the second is a
    permanent answer worth remembering so the collector stops asking.
    """

    if not isinstance(payload, dict):
        raise NormalizationError("CVE record is not an object")

    metadata = payload.get("cveMetadata")

    if not isinstance(metadata, dict):
        raise NormalizationError("CVE record has no cveMetadata")

    raw_cve = metadata.get("cveId")

    if not isinstance(raw_cve, str):
        raise NormalizationError("CVE record has no cveMetadata.cveId")

    cve_id = raw_cve.strip().upper()

    if not CVE_PATTERN.match(cve_id):
        raise NormalizationError(f"invalid CVE identifier: {raw_cve!r}")

    data_type = payload.get("dataType")

    if isinstance(data_type, str) and data_type.strip().upper() != "CVE_RECORD":
        raise NormalizationError(f"{cve_id}: unexpected dataType {data_type!r}")

    state = sanitize_text(metadata.get("state"), max_length=32)

    if (state or "").upper() == "REJECTED":
        raise VulnrichmentRejected(f"{cve_id}: the CVE record was rejected")

    adp = find_adp_container(payload)

    if adp is None:
        raise VulnrichmentRejected(f"{cve_id}: no CISA-ADP container")

    containers = payload.get("containers")
    cna = containers.get("cna") if isinstance(containers, dict) else None
    cna = cna if isinstance(cna, dict) else {}

    vendor, product = extract_affected(adp)

    if not vendor:
        vendor, product = extract_affected(cna)

    kev_date_added, kev_reference = extract_kev_metric(adp)

    record = VulnrichmentRecord(
        cve_id=cve_id,
        state=state,
        title=sanitize_text(cna.get("title"), max_length=MAX_TITLE_LENGTH),
        description=extract_description(cna),
        vendor=vendor,
        product=product,
        cwes=extract_cwes(adp),
        cvss=extract_cvss(adp),
        ssvc=extract_ssvc(adp),
        kev_date_added=kev_date_added,
        kev_reference=kev_reference,
        adp_updated_at=normalize_iso_timestamp(_provider_updated_at(adp)),
        published_at=normalize_iso_timestamp(metadata.get("datePublished")),
        updated_at=normalize_iso_timestamp(metadata.get("dateUpdated")),
        data_version=sanitize_text(payload.get("dataVersion"), max_length=16),
    )

    if not record.is_useful():
        raise VulnrichmentRejected(
            f"{cve_id}: the CISA-ADP container carries no SSVC, CVSS, CWE or KEV data"
        )

    return record

"""The source and attribution register.

Every ingested source must appear in ``data/attribution.json``. The register
answers four questions per source: **who** produced it, **under what licence**,
**at what TLP**, and **how it must be attributed** when ThreatPulse republishes
derived intelligence.

Two rules make this enforceable rather than decorative:

* **No ingestion without attribution.** A source enabled in
  ``config/settings.json`` but missing from the register fails the run. This
  mirrors the TLP rule: absence of a record is not permission.
* **The register is the source of truth for TLP.** Collectors read their
  ``tlp_default`` from here, so no feed can be ingested at a more permissive
  level than the register allows.

Sources declared in configuration but deliberately **not** ingested (for example
NVD, covered indirectly through CIRCL Vulnerability-Lookup and EUVD) are recorded
with ``pipeline_enabled: false`` and published on the "Sources & attribution"
page, so the product is explicit about what it does and does not use.

A record may also carry a **correction**. Two abuse.ch claims in this register were
verified against the live services on 31 Oct 2026 and found to be wrong: ThreatFox
was described as a "CVE-to-IOC bridge" (its records carry no CVE field), and Feodo
Tracker was described as requiring an Auth-Key (its public downloads are keyless).
Those records have since been removed altogether — the abuse.ch sources were
retired on 2 Nov 2026 — but the mechanism is kept: a correction is recorded in
``notes`` rather than silently rewritten, because the register is also the record
of what ThreatPulse believed and why it changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .atomic import read_json
from .tlp import is_ingestible, normalize_marking

REGISTER_FILENAME = "attribution.json"


class AttributionError(RuntimeError):
    """Raised when the register is missing, malformed or incomplete."""


@dataclass(frozen=True)
class AttributionRecord:
    """One source's provenance and usage terms."""

    source_key: str
    name: str
    provider: str
    homepage: str
    licence: str
    licence_url: str | None
    terms_url: str | None
    tlp_default: str
    pipeline_enabled: bool
    attribution_text: str
    tier: int | None = None
    notes: str | None = None

    @property
    def ingestible(self) -> bool:
        """Whether this source's TLP default permits ingestion."""

        return self.pipeline_enabled and is_ingestible(self.tlp_default)

    def to_public_dict(self) -> dict:
        """The shape served publicly, for the attribution page."""

        return {
            "source_key": self.source_key,
            "name": self.name,
            "provider": self.provider,
            "homepage": self.homepage,
            "licence": self.licence,
            "licence_url": self.licence_url,
            "terms_url": self.terms_url,
            "tlp_default": self.tlp_default,
            "ingested": self.pipeline_enabled,
            "attribution_text": self.attribution_text,
            "tier": self.tier,
            "notes": self.notes,
        }


def _require_text(entry: dict, key: str, where: str) -> str:
    value = entry.get(key)

    if not isinstance(value, str) or not value.strip():
        raise AttributionError(f"{where}: missing required field '{key}'")

    return value.strip()


def _optional_text(entry: dict, key: str) -> str | None:
    value = entry.get(key)

    return value.strip() if isinstance(value, str) and value.strip() else None


def _parse_record(entry: Any, index: int) -> AttributionRecord:
    where = f"attribution[{index}]"

    if not isinstance(entry, dict):
        raise AttributionError(f"{where}: not an object")

    source_key = _require_text(entry, "source_key", where)
    where = f"attribution[{source_key}]"

    tlp_default = _require_text(entry, "tlp_default", where).upper()

    if normalize_marking(tlp_default) is None:
        raise AttributionError(
            f"{where}: tlp_default {tlp_default!r} is not a recognised TLP level"
        )

    pipeline_enabled = entry.get("pipeline_enabled", True)

    if not isinstance(pipeline_enabled, bool):
        raise AttributionError(f"{where}: pipeline_enabled must be a boolean")

    tier = entry.get("tier")

    if tier is not None and not isinstance(tier, int):
        raise AttributionError(f"{where}: tier must be an integer when present")

    return AttributionRecord(
        source_key=source_key,
        name=_require_text(entry, "name", where),
        provider=_require_text(entry, "provider", where),
        homepage=_require_text(entry, "homepage", where),
        licence=_require_text(entry, "licence", where),
        licence_url=_optional_text(entry, "licence_url"),
        terms_url=_optional_text(entry, "terms_url"),
        tlp_default=tlp_default,
        pipeline_enabled=pipeline_enabled,
        attribution_text=_require_text(entry, "attribution_text", where),
        tier=tier,
        notes=_optional_text(entry, "notes"),
    )


class AttributionRegister:
    """Loaded, validated attribution register."""

    def __init__(self, records: dict[str, AttributionRecord]) -> None:
        self._records = records

    @property
    def size(self) -> int:
        return len(self._records)

    def get(self, source_key: str) -> AttributionRecord | None:
        return self._records.get(source_key)

    def require(self, source_key: str) -> AttributionRecord:
        """Returns a record or raises — no ingestion without attribution."""

        record = self._records.get(source_key)

        if record is None:
            raise AttributionError(
                f"source '{source_key}' has no attribution record; "
                f"add it to data/{REGISTER_FILENAME} before enabling it"
            )

        return record

    def all_records(self) -> list[AttributionRecord]:
        return [self._records[key] for key in sorted(self._records)]

    def ingested_records(self) -> list[AttributionRecord]:
        return [record for record in self.all_records() if record.pipeline_enabled]

    def tlp_default_for(self, source_key: str) -> str:
        return self.require(source_key).tlp_default

    def to_public_dict(self) -> dict:
        """Attribution payload for the publication and the public page."""

        return {
            "policy": (
                "Every ingested source is attributed. Attribution is provenance, "
                "not endorsement."
            ),
            "sources": [record.to_public_dict() for record in self.all_records()],
        }


def load_register(path: Path | str | None = None) -> AttributionRegister:
    """Loads and validates the register. Fails loudly when malformed."""

    if path is None:
        from .config import BACKEND_ROOT

        path = BACKEND_ROOT / "data" / REGISTER_FILENAME

    path = Path(path)

    raw = read_json(path)

    if raw is None:
        raise AttributionError(f"attribution register not found: {path}")

    if not isinstance(raw, dict):
        raise AttributionError(f"{path}: root must be an object")

    entries = raw.get("sources")

    if not isinstance(entries, list) or not entries:
        raise AttributionError(f"{path}: 'sources' must be a non-empty array")

    records: dict[str, AttributionRecord] = {}

    for index, entry in enumerate(entries):
        record = _parse_record(entry, index)

        if record.source_key in records:
            raise AttributionError(
                f"{path}: duplicate source_key {record.source_key!r}"
            )

        records[record.source_key] = record

    return AttributionRegister(records)


def assert_enabled_sources_attributed(
    register: AttributionRegister, enabled_source_keys: list[str]
) -> None:
    """Fails when any enabled source lacks a usable attribution record."""

    problems: list[str] = []

    for source_key in enabled_source_keys:
        record = register.get(source_key)

        if record is None:
            problems.append(
                f"'{source_key}' is enabled but has no attribution record"
            )
            continue

        if not record.pipeline_enabled:
            problems.append(
                f"'{source_key}' is enabled in settings but the register marks "
                "it as not ingested"
            )
            continue

        if not record.ingestible:
            problems.append(
                f"'{source_key}' declares tlp_default {record.tlp_default}, "
                "which is not ingestible into a public product"
            )

    if problems:
        raise AttributionError(
            "attribution/TLP register is inconsistent with settings:\n  - "
            + "\n  - ".join(problems)
        )



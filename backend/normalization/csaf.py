"""CSAF 2.0 advisory normalisation.

CISA publishes its IT and OT advisories as CSAF 2.0 documents in the
``cisagov/CSAF`` repository, alongside the standard discovery files
(``changes.csv``, ``index.txt``). This module turns one CSAF document into a
provenance-carrying observation.

CSAF is a better fit than an RSS feed for two reasons:

* the document carries its **own handling marking** in
  ``document.distribution.tlp.label``, so the TLP gate enforces the marking the
  publisher actually set instead of a default we assume on its behalf;
* vulnerabilities are **structured**, so CVE identifiers, CVSS scores, affected
  vendors and products, and remediations are read directly rather than being
  guessed from prose.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from lib.ids import CVE_PATTERN
from models.intelligence import Entity, Observation
from normalization.cisa import (
    NormalizationError,
    extract_techniques,
    sanitize_text,
)

#: A single advisory larger than this is refused rather than parsed.
MAX_ADVISORY_BYTES = 4 * 1024 * 1024

MAX_TITLE_LENGTH = 500
MAX_SUMMARY_LENGTH = 4000
MAX_NAME_LENGTH = 200
MAX_REMEDIATION_LENGTH = 1000
MAX_REMEDIATIONS = 10
MAX_CVES = 50

#: Technique identifiers kept per advisory. CISA publishes a handful at most; the
#: bound exists so a malformed document cannot inflate the payload.
MAX_TECHNIQUES = 50

#: A CSAF changes.csv row is a relative advisory path plus a timestamp.
CHANGES_COLUMNS = 2

_TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d",
)

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "none", "unknown")


def normalize_csaf_timestamp(value: Any) -> str | None:
    """CSAF timestamps reduced to ``YYYY-MM-DDTHH:MM:SSZ``."""

    text = sanitize_text(value, max_length=40)

    if not text:
        return None

    for fmt in _TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return None


def _dig(mapping: Any, *keys: str) -> Any:
    """Safe nested lookup; returns None rather than raising."""

    current = mapping

    for key in keys:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

    return current


@dataclass(frozen=True)
class CsafAdvisory:
    """One validated CSAF 2.0 advisory."""

    tracking_id: str
    title: str | None
    tlp_label: str | None
    cve_ids: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    vendor: str | None = None
    product: str | None = None
    summary: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    published_at: str | None = None
    updated_at: str | None = None
    remediations: list[str] = field(default_factory=list)
    document_url: str | None = None

    def to_payload(self, *, source_key: str) -> dict:
        return {
            "tracking_id": self.tracking_id,
            "title": self.title,
            "summary": self.summary,
            "vendor": self.vendor,
            "product": self.product,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "published_at": self.published_at,
            "updated_at": self.updated_at,
            "cve_ids": list(self.cve_ids),
            "technique_ids": list(self.technique_ids),
            "remediations": list(self.remediations),
            "document_url": self.document_url,
            "tlp_label": self.tlp_label,
            "advisory": True,
            "source": source_key,
        }

    def entities(self) -> list[Entity]:
        entities = [
            Entity(kind="cve", value=cve, normalized=cve) for cve in self.cve_ids
        ]

        # A technique the advisory cites is a reference, not proof that it was
        # used. It is carried as an entity so the ATT&CK enricher can name it.
        entities += [
            Entity(kind="technique", value=technique, normalized=technique)
            for technique in self.technique_ids
        ]

        return entities


def _extract_cves(payload: dict) -> list[str]:
    found: set[str] = set()

    for vulnerability in payload.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            continue

        candidate = sanitize_text(vulnerability.get("cve"), max_length=32)

        if candidate:
            upper = candidate.upper()

            if CVE_PATTERN.match(upper):
                found.add(upper)

        if len(found) >= MAX_CVES:
            break

    return sorted(found)


def _advisory_texts(payload: dict) -> list[str]:
    """The prose fields a CSAF advisory keeps an ATT&CK reference in.

    Read explicitly rather than by walking the whole document: an advisory's
    product tree carries CPE strings and product names, and a technique pattern
    applied to those would be guessing at what a token means.
    """

    texts: list[str] = []

    document = payload.get("document")

    if isinstance(document, dict):
        title = document.get("title")

        if isinstance(title, str):
            texts.append(title)

        for note in document.get("notes") or []:
            if isinstance(note, dict) and isinstance(note.get("text"), str):
                texts.append(note["text"])

    for vulnerability in payload.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            continue

        for note in vulnerability.get("notes") or []:
            if isinstance(note, dict) and isinstance(note.get("text"), str):
                texts.append(note["text"])

        for threat in vulnerability.get("threats") or []:
            if isinstance(threat, dict) and isinstance(threat.get("details"), str):
                texts.append(threat["details"])

        for remediation in vulnerability.get("remediations") or []:
            if isinstance(remediation, dict) and isinstance(
                remediation.get("details"), str
            ):
                texts.append(remediation["details"])

    return texts


def _extract_techniques(payload: dict) -> list[str]:
    """ATT&CK technique identifiers the advisory itself cites."""

    return extract_techniques(*_advisory_texts(payload))[:MAX_TECHNIQUES]


def _extract_severity_and_score(payload: dict) -> tuple[str | None, float | None]:
    """Highest CVSS base score, and the most severe reported band."""

    best_score: float | None = None
    best_severity: str | None = None

    for vulnerability in payload.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            continue

        for score in vulnerability.get("scores") or []:
            if not isinstance(score, dict):
                continue

            for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
                block = score.get(key)

                if not isinstance(block, dict):
                    continue

                try:
                    value = float(block.get("baseScore"))
                except (TypeError, ValueError):
                    value = None

                if value is not None and (best_score is None or value > best_score):
                    best_score = value

                severity = sanitize_text(block.get("baseSeverity"), max_length=16)

                if severity:
                    lowered = severity.lower()

                    if lowered in _SEVERITY_ORDER and (
                        best_severity is None
                        or _SEVERITY_ORDER.index(lowered)
                        < _SEVERITY_ORDER.index(best_severity)
                    ):
                        best_severity = lowered

    return best_severity, best_score


def _extract_summary(document: dict) -> str | None:
    for note in document.get("notes") or []:
        if isinstance(note, dict) and note.get("category") == "summary":
            text = sanitize_text(note.get("text"), max_length=MAX_SUMMARY_LENGTH)

            if text:
                return text

    return None


def _extract_vendor_product(payload: dict) -> tuple[str | None, str | None]:
    vendor: str | None = None
    product: str | None = None

    tree = payload.get("product_tree")

    if not isinstance(tree, dict):
        return None, None

    for branch in tree.get("branches") or []:
        if isinstance(branch, dict) and branch.get("category") == "vendor":
            vendor = sanitize_text(branch.get("name"), max_length=MAX_NAME_LENGTH)

            if vendor:
                break

    for entry in tree.get("full_product_names") or []:
        if isinstance(entry, dict):
            product = sanitize_text(
                _dig(entry, "product", "name"), max_length=MAX_NAME_LENGTH
            )

            if product:
                break

    return vendor, product


def _extract_remediations(payload: dict) -> list[str]:
    found: list[str] = []

    for vulnerability in payload.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            continue

        for remediation in vulnerability.get("remediations") or []:
            if not isinstance(remediation, dict):
                continue

            details = sanitize_text(
                remediation.get("details"), max_length=MAX_REMEDIATION_LENGTH
            )

            if details and details not in found:
                found.append(details)

            if len(found) >= MAX_REMEDIATIONS:
                return found

    return found


def parse_csaf_advisory(
    payload: Any, *, document_url: str | None = None
) -> CsafAdvisory:
    """Validates one CSAF 2.x document.

    Raises :class:`NormalizationError` when the document is not a CSAF 2.x
    advisory — in that case the source cannot be trusted at all.
    """

    if not isinstance(payload, dict):
        raise NormalizationError("CSAF document is not an object")

    document = payload.get("document")

    if not isinstance(document, dict):
        raise NormalizationError("CSAF document has no 'document' object")

    version = sanitize_text(document.get("csaf_version"), max_length=16)

    if not version or not version.startswith("2"):
        raise NormalizationError(f"not a CSAF 2.x document (version={version!r})")

    tracking_id = sanitize_text(_dig(document, "tracking", "id"), max_length=100)

    if not tracking_id:
        raise NormalizationError("CSAF document has no tracking id")

    severity, cvss_score = _extract_severity_and_score(payload)
    vendor, product = _extract_vendor_product(payload)

    return CsafAdvisory(
        tracking_id=tracking_id,
        title=sanitize_text(document.get("title"), max_length=MAX_TITLE_LENGTH),
        tlp_label=sanitize_text(
            _dig(document, "distribution", "tlp", "label"), max_length=16
        ),
        cve_ids=_extract_cves(payload),
        technique_ids=_extract_techniques(payload),
        vendor=vendor,
        product=product,
        summary=_extract_summary(document),
        severity=severity,
        cvss_score=cvss_score,
        published_at=normalize_csaf_timestamp(
            _dig(document, "tracking", "initial_release_date")
        ),
        updated_at=normalize_csaf_timestamp(
            _dig(document, "tracking", "current_release_date")
        ),
        remediations=_extract_remediations(payload),
        document_url=document_url,
    )


def parse_changes_csv(body: bytes, *, limit: int = 50) -> list[tuple[str, str]]:
    """Parses a CSAF ``changes.csv`` into ``(relative path, timestamp)`` pairs.

    Rows come back newest first. The file is written newest-first already, but it
    is sorted explicitly so the result never depends on that. A path that is
    absolute, escapes its directory or is not JSON is skipped rather than fetched.
    """

    if not isinstance(body, (bytes, bytearray)):
        raise NormalizationError("changes.csv body is not bytes")

    if len(body) > MAX_ADVISORY_BYTES * 4:
        raise NormalizationError("changes.csv is implausibly large")

    text = body.decode("utf-8-sig", errors="replace")

    rows: list[tuple[str, str]] = []

    for row in csv.reader(io.StringIO(text)):
        if len(row) != CHANGES_COLUMNS:
            continue

        path = row[0].strip().strip('"')
        timestamp = row[1].strip().strip('"')

        if not path or path.startswith("/") or ".." in path:
            continue

        if not path.endswith(".json"):
            continue

        rows.append((path, timestamp))

    rows.sort(key=lambda item: item[1], reverse=True)

    return rows[:limit] if limit > 0 else rows


def build_observation(
    advisory: CsafAdvisory, *, source_key: str, retrieved_at: str
) -> Observation:
    """Turns a CSAF advisory into a provenance-carrying observation."""

    return Observation(
        source_key=source_key,
        external_id=advisory.tracking_id,
        observed_at=advisory.updated_at or advisory.published_at or retrieved_at,
        retrieved_at=retrieved_at,
        source_record_id=advisory.tracking_id,
        payload=advisory.to_payload(source_key=source_key),
        entities=advisory.entities(),
    )



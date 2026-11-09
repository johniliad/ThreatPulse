"""OSV (Open Source Vulnerabilities) normalisation.

OSV answers per identifier at ``https://api.osv.dev/v1/vulns/<id>``. Verified live:
a CVE id works as the identifier when OSV holds a record for it — ``CVE-2021-44228``
returns a full record — and a CVE OSV does not hold answers HTTP 404. So this
source is dependent, and a miss is a normal outcome rather than a fault.

Three properties of the real payload matter:

* **A record can be 115 KB.** The log4j record carries thousands of CPE ranges
  under ``database_specific.unresolved_ranges``. None of that is published: this
  normaliser reads a bounded set of fields and drops the rest, so a large response
  becomes a payload of a few kilobytes.
* **The identifier may not be the CVE.** When OSV holds a record for a CVE, its
  ``id`` *is* the CVE; but a GHSA-sourced record reached through a CVE carries the
  GHSA id and the CVE in ``aliases``. The CVE is taken from ``id`` when that is a
  CVE, and otherwise from ``aliases``.
* **``severity[].score`` is a CVSS *vector*, not a number.** ThreatPulse does not
  derive a base score from a vector — that would be inventing a number — so OSV
  contributes affected packages, ecosystems and fixed versions, and never the
  shared CVSS field.

What it adds that nothing else does: KEV and Red Hat describe **products**, while
OSV describes **open-source packages and the versions that fix them**.
"""

from __future__ import annotations

from typing import Any

from lib.ids import CVE_PATTERN
from models.intelligence import Entity, Observation
from normalization.cisa import (
    NormalizationError,
    RecordUnavailable,
    normalize_iso_timestamp,
    sanitize_text,
)

MAX_PACKAGES = 20
MAX_FIXED_VERSIONS = 20
MAX_REFERENCES = 20
MAX_SEVERITIES = 5
MAX_ALIASES = 20
MAX_TEXT_LENGTH = 4000
MAX_NAME_LENGTH = 200

#: Range types whose ``fixed`` events hold a *version*. ``GIT`` ranges hold a
#: commit hash instead, which is not a version.
VERSION_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})


def record_url(base_url: str, cve_id: str) -> str:
    """URL of the per-identifier record below an OSV API base URL."""

    return f"{(base_url or '').rstrip('/')}/vulns/{cve_id.strip().upper()}"


def _cve_from(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    candidate = value.strip().upper()

    return candidate if CVE_PATTERN.match(candidate) else None


def find_cve_id(payload: dict) -> str | None:
    """The CVE a record is about: its ``id`` when that is a CVE, else an alias."""

    direct = _cve_from(payload.get("id"))

    if direct:
        return direct

    aliases = payload.get("aliases")

    for alias in aliases if isinstance(aliases, list) else []:
        candidate = _cve_from(alias)

        if candidate:
            return candidate

    return None


def _string_list(value: Any, *, limit: int, max_length: int) -> list[str]:
    entries: list[str] = []

    for entry in value if isinstance(value, list) else []:
        text = sanitize_text(entry, max_length=max_length)

        if text and text not in entries:
            entries.append(text)

        if len(entries) >= limit:
            break

    return entries


def parse_affected(value: Any) -> tuple[list[dict], list[str]]:
    """``(packages, fixed_versions)`` from the ``affected`` list.

    Only ``ECOSYSTEM`` and ``SEMVER`` ranges contribute fixed *versions*. A ``GIT``
    range records a commit hash in its ``fixed`` event — real data, but not a
    version, and putting it in a field named ``fixed_versions`` would mislead.
    """

    packages: list[dict] = []
    fixed: list[str] = []

    for entry in value if isinstance(value, list) else []:
        if not isinstance(entry, dict):
            continue

        package = entry.get("package")
        package = package if isinstance(package, dict) else {}

        ecosystem = sanitize_text(package.get("ecosystem"), max_length=64)
        name = sanitize_text(package.get("name"), max_length=MAX_NAME_LENGTH)

        if name and len(packages) < MAX_PACKAGES:
            record = {
                "ecosystem": ecosystem,
                "name": name,
                "purl": sanitize_text(package.get("purl"), max_length=500),
            }

            if record not in packages:
                packages.append(record)

        for range_entry in entry.get("ranges") or []:
            if not isinstance(range_entry, dict):
                continue

            range_type = str(range_entry.get("type") or "").strip().upper()

            if range_type not in VERSION_RANGE_TYPES:
                continue

            for event in range_entry.get("events") or []:
                if not isinstance(event, dict):
                    continue

                version = sanitize_text(event.get("fixed"), max_length=64)

                if version and version not in fixed and len(fixed) < MAX_FIXED_VERSIONS:
                    fixed.append(version)

    return packages, sorted(fixed)


def parse_severities(value: Any) -> list[dict]:
    """``severity`` entries, which carry CVSS *vectors* rather than scores."""

    entries: list[dict] = []

    for entry in value if isinstance(value, list) else []:
        if not isinstance(entry, dict):
            continue

        score = sanitize_text(entry.get("score"), max_length=200)
        kind = sanitize_text(entry.get("type"), max_length=32)

        if score or kind:
            entries.append({"type": kind, "score": score})

        if len(entries) >= MAX_SEVERITIES:
            break

    return entries


def parse_references(value: Any) -> list[dict]:
    entries: list[dict] = []

    for entry in value if isinstance(value, list) else []:
        if not isinstance(entry, dict):
            continue

        url = sanitize_text(entry.get("url"), max_length=500)

        if not url or not url.startswith("https://"):
            continue

        reference = {"type": sanitize_text(entry.get("type"), max_length=32), "url": url}

        if reference not in entries:
            entries.append(reference)

        if len(entries) >= MAX_REFERENCES:
            break

    return entries


def parse_osv_record(payload: Any) -> dict:
    """Validates an OSV record and normalises it.

    Raises :class:`RecordUnavailable` when the record holds nothing worth
    publishing, and :class:`NormalizationError` when it cannot be trusted.
    """

    if not isinstance(payload, dict):
        raise NormalizationError("OSV record is not an object")

    cve_id = find_cve_id(payload)

    if cve_id is None:
        raise NormalizationError("OSV record names no CVE")

    osv_id = sanitize_text(payload.get("id"), max_length=64)
    packages, fixed_versions = parse_affected(payload.get("affected"))
    severities = parse_severities(payload.get("severity"))
    references = parse_references(payload.get("references"))
    aliases = _string_list(payload.get("aliases"), limit=MAX_ALIASES, max_length=64)

    ecosystems = sorted(
        {package["ecosystem"] for package in packages if package.get("ecosystem")}
    )

    if not packages and not severities:
        raise RecordUnavailable(f"{cve_id}: OSV record names no affected package")

    summary = {
        "osv_id": osv_id,
        "aliases": aliases,
        "ecosystems": ecosystems,
        "packages": packages,
        "fixed_versions": fixed_versions,
        "severity": severities,
        "modified_at": normalize_iso_timestamp(payload.get("modified")),
    }

    return {
        "cve_id": cve_id,
        "osv_id": osv_id,
        "aliases": aliases,
        "published_at": normalize_iso_timestamp(payload.get("published")),
        "modified_at": summary["modified_at"],
        "summary": sanitize_text(payload.get("summary"), max_length=MAX_TEXT_LENGTH),
        "details": sanitize_text(payload.get("details"), max_length=MAX_TEXT_LENGTH),
        "severity": severities,
        "ecosystems": ecosystems,
        "packages": packages,
        "fixed_versions": fixed_versions,
        "references": references,
        "osv_url": f"https://osv.dev/vulnerability/{osv_id or cve_id}",
        "source": "osv_dev",
        "enrichment": True,
        "enrichment_summary": summary,
    }


def build_observation(
    payload: dict, *, source_key: str, retrieved_at: str
) -> Observation:
    """Turns a payload into a provenance-carrying observation."""

    cve_id = str(payload.get("cve_id", "")).strip().upper()

    if not CVE_PATTERN.match(cve_id):
        raise NormalizationError(f"invalid CVE identifier: {cve_id!r}")

    return Observation(
        source_key=source_key,
        external_id=cve_id,
        observed_at=(
            payload.get("modified_at")
            or payload.get("published_at")
            or retrieved_at
        ),
        retrieved_at=retrieved_at,
        source_record_id=str(payload.get("osv_id") or cve_id),
        payload=payload,
        entities=[Entity(kind="cve", value=cve_id, normalized=cve_id)],
    )

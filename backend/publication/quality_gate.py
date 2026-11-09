"""Fail-closed quality gate.

Nothing reaches the network or replaces the previous snapshot unless it passes
every check here. The gate validates the **serialised** document — the exact
bytes that will be sent — so a problem cannot hide behind object construction.
"""

from __future__ import annotations

import json
import re
from typing import Any

from lib.ids import CVE_PATTERN, THREAT_UUID_PATTERN
from publication.chunking import ChunkingError, chunk_publication
from publication.builder import (
    ALLOWED_CONFIDENCE_LEVELS,
    ALLOWED_EXPLOITATION_STATUSES,
    ALLOWED_SEVERITIES,
    MAX_TITLE_LENGTH,
    PUBLICATION_UUID_PATTERN,
    SCHEMA_VERSION,
    SECRET_MARKERS,
    SECRET_PATTERNS,
)

ISO_UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

#: Handling markings that must never appear in a public publication.
#: Defence in depth: the ingest-side gate should already have rejected this
#: material, but a marking can also arrive inside a summary, a title or a
#: recommended action, so the serialised document is scanned as well.
RESTRICTIVE_TLP_PATTERN = re.compile(
    r"TLP\s*[:\-]\s*(GREEN|AMBER\+STRICT|AMBER\-STRICT|AMBER|RED)\b",
    re.IGNORECASE,
)


class QualityGateError(RuntimeError):
    """Raised when a publication must not be published."""


def _check_threat(threat: Any, index: int, problems: list[str]) -> None:
    where = f"threats[{index}]"

    if not isinstance(threat, dict):
        problems.append(f"{where}: not an object")
        return

    uuid_value = threat.get("threat_uuid")

    if not isinstance(uuid_value, str) or not THREAT_UUID_PATTERN.match(uuid_value):
        problems.append(f"{where}.threat_uuid: invalid ({uuid_value!r})")

    external_id = threat.get("external_id")
    threat_type = threat.get("threat_type")

    if not isinstance(threat_type, str) or not threat_type:
        problems.append(f"{where}.threat_type: missing")

    if not isinstance(external_id, str) or not CVE_PATTERN.match(
        external_id.upper()
    ):
        problems.append(f"{where}.external_id: not a CVE identifier ({external_id!r})")

    title = threat.get("title")

    if not isinstance(title, str) or not title.strip():
        problems.append(f"{where}.title: empty")
    elif len(title) > MAX_TITLE_LENGTH:
        problems.append(f"{where}.title: exceeds {MAX_TITLE_LENGTH} characters")

    severity = threat.get("severity")

    if severity not in ALLOWED_SEVERITIES:
        problems.append(f"{where}.severity: not allowed ({severity!r})")

    for field in ("priority_score", "confidence_score"):
        value = threat.get(field)

        if not isinstance(value, (int, float)) or isinstance(value, bool):
            problems.append(f"{where}.{field}: not numeric ({value!r})")
        elif not 0 <= float(value) <= 100:
            problems.append(f"{where}.{field}: out of range ({value!r})")

    if threat.get("confidence_level") not in ALLOWED_CONFIDENCE_LEVELS:
        problems.append(
            f"{where}.confidence_level: not allowed "
            f"({threat.get('confidence_level')!r})"
        )

    if threat.get("exploitation_status") not in ALLOWED_EXPLOITATION_STATUSES:
        problems.append(
            f"{where}.exploitation_status: not allowed "
            f"({threat.get('exploitation_status')!r})"
        )

    for field in ("first_seen", "last_seen"):
        value = threat.get(field)

        if value is not None and (
            not isinstance(value, str) or not ISO_UTC_PATTERN.match(value)
        ):
            problems.append(f"{where}.{field}: not an ISO-8601 UTC timestamp")

    source_keys = threat.get("source_keys")

    if not isinstance(source_keys, list) or not source_keys:
        problems.append(f"{where}.source_keys: empty (provenance is required)")

    for position, vulnerability in enumerate(threat.get("vulnerabilities") or []):
        cve_id = (vulnerability or {}).get("cve_id")

        if not isinstance(cve_id, str) or not CVE_PATTERN.match(cve_id.upper()):
            problems.append(
                f"{where}.vulnerabilities[{position}].cve_id: invalid ({cve_id!r})"
            )


def validate_publication(publication: dict) -> list[str]:
    """Returns every structural problem found (empty list means valid)."""

    problems: list[str] = []

    if not isinstance(publication, dict):
        return ["publication: not an object"]

    if publication.get("schema_version") != SCHEMA_VERSION:
        problems.append(
            f"schema_version: expected {SCHEMA_VERSION}, got "
            f"{publication.get('schema_version')!r}"
        )

    publication_uuid = publication.get("publication_uuid")

    if not isinstance(
        publication_uuid, str
    ) or not PUBLICATION_UUID_PATTERN.match(publication_uuid):
        problems.append(f"publication_uuid: invalid ({publication_uuid!r})")

    generated_at = publication.get("generated_at")

    if not isinstance(generated_at, str) or not ISO_UTC_PATTERN.match(generated_at):
        problems.append(
            f"generated_at: not an ISO-8601 UTC timestamp ({generated_at!r})"
        )

    sources = publication.get("sources")

    if not isinstance(sources, list) or not sources:
        problems.append("sources: must be a non-empty array")

    declared_source_keys = {
        source.get("source_key")
        for source in (sources or [])
        if isinstance(source, dict)
    }

    threats = publication.get("threats")

    if not isinstance(threats, list) or not threats:
        problems.append("threats: must be a non-empty array")
        threats = []

    seen_uuids: set[str] = set()

    for index, threat in enumerate(threats):
        _check_threat(threat, index, problems)

        if not isinstance(threat, dict):
            continue

        uuid_value = threat.get("threat_uuid")

        if isinstance(uuid_value, str):
            if uuid_value in seen_uuids:
                problems.append(f"threats[{index}]: duplicate threat_uuid")
            seen_uuids.add(uuid_value)

        for source_key in threat.get("source_keys") or []:
            if source_key not in declared_source_keys:
                problems.append(
                    f"threats[{index}].source_keys: '{source_key}' is not declared "
                    "in sources"
                )

    summary = publication.get("summary")

    if not isinstance(summary, dict):
        problems.append("summary: missing or not an object")
    else:
        if summary.get("threat_count") != len(threats):
            problems.append(
                "summary.threat_count does not match the number of threats "
                f"({summary.get('threat_count')!r} != {len(threats)})"
            )

        vulnerability_total = sum(
            len(threat.get("vulnerabilities") or []) for threat in threats
        )

        if summary.get("vulnerability_count") != vulnerability_total:
            problems.append(
                "summary.vulnerability_count does not match the threats"
            )

    serialized = json.dumps(publication, ensure_ascii=False).lower()

    for marker in SECRET_MARKERS:
        if marker in serialized:
            problems.append(
                f"publication contains a secret-like marker: {marker!r}"
            )

    for label, pattern in SECRET_PATTERNS:
        match = pattern.search(serialized)

        if match is not None:
            problems.append(
                f"publication contains a credential-shaped value ({label}) "
                f"near: {_redacted_context(serialized, match)}"
            )

    return problems


def _redacted_context(serialized: str, match) -> str:
    """A short excerpt around a match, with the matched value redacted.

    Enough to identify which record is responsible without echoing the value
    itself into the log or the console.
    """

    start = max(0, match.start() - 40)
    end = min(len(serialized), match.end() + 40)

    return serialized[start:end].replace(match.group(0), "[redacted]")


def validate_tlp_markings(publication: dict) -> list[str]:
    """Refuses to publish anything carrying a restrictive handling marking.

    This runs on the **serialised** document, so a marking hidden in a summary,
    a title, an action or a payload is still caught.
    """

    problems: list[str] = []

    try:
        serialized = json.dumps(publication, ensure_ascii=False)
    except (TypeError, ValueError) as error:
        return [f"publication is not serialisable for TLP scanning: {error}"]

    for match in sorted(
        {found.group(0) for found in RESTRICTIVE_TLP_PATTERN.finditer(serialized)}
    ):
        problems.append(
            f"publication contains a restrictive handling marking: {match!r}"
        )

    return problems


def validate_source_permission(publication: dict, register) -> list[str]:
    """Every source behind a threat must be registered and ingestible.

    Fails closed: an unregistered source, or one whose register entry is not
    permitted for ingestion, blocks the publication rather than being published
    without attribution.
    """

    problems: list[str] = []

    for index, threat in enumerate(publication.get("threats") or []):
        if not isinstance(threat, dict):
            continue

        for source_key in threat.get("source_keys") or []:
            record = register.get(source_key)

            if record is None:
                problems.append(
                    f"threats[{index}].source_keys: '{source_key}' has no "
                    "attribution record"
                )
                continue

            if not record.ingestible:
                problems.append(
                    f"threats[{index}].source_keys: '{source_key}' is not "
                    "permitted for publication "
                    f"(tlp_default {record.tlp_default})"
                )

    return problems


def validate_chunk_sizes(publication: dict, max_bytes: int) -> list[str]:
    """Refuses a publication that cannot be split into acceptable requests.

    ``publish.php`` receives each request as a single POST body, so every **chunk**
    must fit the server's ``post_max_size`` — not the publication as a whole. When a
    request is too large, PHP discards the body and the API reports an empty
    request, a confusing failure that is far better caught here.

    Two things can make a publication unsendable, and they need different fixes:

    * a **single threat** larger than the limit, which no amount of chunking can
      solve — the threat itself has to be bounded;
    * an **envelope** larger than the limit, which means the summary or the source
      list has to shrink.

    ``max_bytes`` of ``0`` disables the check, matching the other guards.
    """

    if max_bytes <= 0:
        return []

    try:
        plan = chunk_publication(publication, max_bytes=max_bytes)
    except ChunkingError as error:
        return [str(error)]
    except (TypeError, ValueError) as error:
        return [f"publication is not serialisable for sizing: {error}"]

    problems: list[str] = []

    for index, size in enumerate(plan.sizes()):
        if size > max_bytes:
            problems.append(
                f"chunk {index} is {size} bytes, above the configured limit of "
                f"{max_bytes} bytes"
            )

    return problems


def validate_volume(
    summary: dict,
    *,
    previous_summary: dict | None,
    minimum_threats: int,
    maximum_drop_ratio: float,
) -> list[str]:
    """Volume guards against publishing a suspiciously small snapshot."""

    problems: list[str] = []

    threat_count = summary.get("threat_count", 0)

    if threat_count < minimum_threats:
        problems.append(
            f"threat_count {threat_count} is below the configured minimum "
            f"{minimum_threats}"
        )

    if previous_summary:
        previous_count = previous_summary.get("threat_count")

        if isinstance(previous_count, int) and previous_count > 0:
            drop = 1 - (threat_count / previous_count)

            if drop > maximum_drop_ratio:
                problems.append(
                    f"threat_count dropped {drop:.0%} (from {previous_count} to "
                    f"{threat_count}), exceeding the configured limit of "
                    f"{maximum_drop_ratio:.0%}"
                )

    return problems


def assert_publishable(
    publication: dict,
    *,
    previous_summary: dict | None = None,
    minimum_threats: int = 1,
    maximum_drop_ratio: float = 0.25,
    register=None,
    max_payload_bytes: int = 0,
) -> None:
    """Raises :class:`QualityGateError` when anything is wrong.

    ``register`` is the attribution register. When supplied, every source behind
    every threat must be registered and permitted for ingestion. The TLP marking
    scan always runs, because it needs no external state.
    """

    problems = validate_publication(publication)

    summary = publication.get("summary") if isinstance(publication, dict) else None

    if isinstance(summary, dict):
        problems += validate_volume(
            summary,
            previous_summary=previous_summary,
            minimum_threats=minimum_threats,
            maximum_drop_ratio=maximum_drop_ratio,
        )

    if isinstance(publication, dict):
        problems += validate_tlp_markings(publication)
        problems += validate_chunk_sizes(publication, max_payload_bytes)

        if register is not None:
            problems += validate_source_permission(publication, register)

    if problems:
        raise QualityGateError(
            "publication failed the quality gate:\n  - " + "\n  - ".join(problems)
        )


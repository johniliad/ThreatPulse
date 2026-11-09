"""Red Hat Security Data normalisation.

Red Hat publishes a per-CVE record at
``https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json`` — the
dependent, per-CVE shape, which is what this pipeline wants: it answers about the
CVEs ThreatPulse already tracks rather than streaming Red Hat's whole catalogue.

Five properties of the live payload need handling, all verified against the real
API rather than taken from documentation:

* **``references`` is a list of newline-joined strings**, not a list of URLs. A real
  record holds a single element containing many URLs separated by ``\\n``, so it has
  to be split before use or the whole block becomes one unusable reference.
* **``cvss3`` is a nested object with a status**: ``{cvss3_base_score,
  cvss3_scoring_vector, status}``. The score arrives as a *string* (``"7.8"``), and
  ``status`` separates an assessed score from a provisional one.
* **``cwe`` is a comma-separated string** on some records rather than a list.
* **``affected_release`` is the errata list** — one entry per fixed product naming
  the advisory (``RHSA-2021:5137``). This is the most operationally useful thing
  Red Hat publishes: not "a fix exists" but "this advisory fixes it for this
  product, on this date".
* **``package_state`` records what Red Hat decided** — ``Not affected``,
  ``Affected``, ``Will not fix``, ``Fix deferred``. "Not affected" is intelligence
  too, and is why the fix states are counted rather than dropped.

The CVSS this source supplies is a **vendor** assessment, expressed in the context
of Red Hat's own products. It is offered to the correlation engine only as a
fallback, behind CISA's, and the published metadata names whichever source supplied
the number.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from lib.ids import CVE_PATTERN
from models.intelligence import Entity, Observation
from normalization.cisa import (
    NormalizationError,
    RecordUnavailable,
    normalize_cwes,
    normalize_iso_timestamp,
    sanitize_text,
)

MAX_ADVISORIES = 20
MAX_PACKAGE_STATES = 20
MAX_REFERENCES = 20
MAX_TEXT_LENGTH = 4000
MAX_NAME_LENGTH = 200

#: Red Hat's severity vocabulary, lower-cased for consistency.
SEVERITIES = frozenset({"critical", "important", "moderate", "low"})

#: ``cvss3.status`` values that mean the score is an assessed one.
CVSS_STATUSES = frozenset({"verified", "unverified", "reviewed"})


def record_url(base_url: str, cve_id: str) -> str:
    """URL of the per-CVE record below a Security Data base URL."""

    return f"{(base_url or '').rstrip('/')}/cve/{cve_id.strip().upper()}.json"


def split_references(value: Any) -> list[str]:
    """Reference URLs, splitting the newline-joined strings Red Hat publishes.

    The live record holds ``["https://a\\nhttps://b\\nhttps://c"]`` — one element,
    many URLs — so a naive ``list`` would yield a single unusable entry.
    """

    urls: list[str] = []

    for entry in value if isinstance(value, list) else []:
        text = entry if isinstance(entry, str) else ""

        for part in text.split("\n"):
            url = sanitize_text(part, max_length=500)

            if url and url.startswith("https://") and url not in urls:
                urls.append(url)

            if len(urls) >= MAX_REFERENCES:
                return urls

    return urls


def parse_cwes(value: Any) -> list[str]:
    """``cwe`` arrives as ``"CWE-20"`` or ``"CWE-20,CWE-502"``."""

    if isinstance(value, list):
        candidates = [str(entry) for entry in value]
    elif isinstance(value, str):
        candidates = value.split(",")
    else:
        return []

    return normalize_cwes(candidates)


def parse_cvss(block: Any, *, version: str) -> dict | None:
    """A ``cvss3``/``cvss`` block reduced to the engine's shared shape."""

    if not isinstance(block, dict):
        return None

    raw_score = block.get(f"cvss{version}_base_score", block.get("base_score"))

    if raw_score is None or isinstance(raw_score, bool):
        return None

    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        return None

    if not 0.0 <= score <= 10.0:
        return None

    vector = sanitize_text(
        block.get(f"cvss{version}_scoring_vector", block.get("vector")),
        max_length=200,
    )

    status = sanitize_text(block.get("status"), max_length=32)

    return {
        "base_score": round(score, 1),
        "vector": vector,
        "version": version,
        "status": status.lower() if status else None,
    }


def _advisories(value: Any) -> list[dict]:
    entries: list[dict] = []

    for entry in value if isinstance(value, list) else []:
        if not isinstance(entry, dict):
            continue

        advisory = sanitize_text(entry.get("advisory"), max_length=64)

        if not advisory:
            continue

        entries.append(
            {
                "advisory": advisory,
                "product_name": sanitize_text(
                    entry.get("product_name"), max_length=MAX_NAME_LENGTH
                ),
                "package": sanitize_text(entry.get("package"), max_length=MAX_NAME_LENGTH),
                "release_date": normalize_iso_timestamp(entry.get("release_date")),
                "impact": sanitize_text(entry.get("impact"), max_length=32),
            }
        )

        if len(entries) >= MAX_ADVISORIES:
            break

    return entries


def _package_states(value: Any) -> tuple[list[dict], dict[str, int]]:
    entries: list[dict] = []
    counts: dict[str, int] = {}

    for entry in value if isinstance(value, list) else []:
        if not isinstance(entry, dict):
            continue

        state = sanitize_text(entry.get("fix_state"), max_length=64)

        if state:
            counts[state] = counts.get(state, 0) + 1

        if len(entries) < MAX_PACKAGE_STATES:
            entries.append(
                {
                    "product_name": sanitize_text(
                        entry.get("product_name"), max_length=MAX_NAME_LENGTH
                    ),
                    "package_name": sanitize_text(
                        entry.get("package_name"), max_length=MAX_NAME_LENGTH
                    ),
                    "fix_state": state,
                }
            )

    return entries, dict(sorted(counts.items()))


def parse_redhat_record(payload: Any) -> dict:
    """Validates a Security Data record and normalises it.

    Raises :class:`RecordUnavailable` when the record carries nothing worth
    publishing, and :class:`NormalizationError` when it cannot be trusted.
    """

    if not isinstance(payload, dict):
        raise NormalizationError("Red Hat record is not an object")

    raw_cve = payload.get("name") or payload.get("CVE")

    if not isinstance(raw_cve, str):
        raise NormalizationError("Red Hat record has no CVE name")

    cve_id = raw_cve.strip().upper()

    if not CVE_PATTERN.match(cve_id):
        raise NormalizationError(f"invalid CVE identifier: {raw_cve!r}")

    cvss3 = parse_cvss(payload.get("cvss3"), version="3")
    cvss2 = parse_cvss(payload.get("cvss"), version="2")
    advisories = _advisories(payload.get("affected_release"))
    package_states, state_counts = _package_states(payload.get("package_state"))

    severity = sanitize_text(payload.get("threat_severity"), max_length=32)
    severity = severity.lower() if severity else None

    if severity is not None and severity not in SEVERITIES:
        severity = None

    bugzilla = payload.get("bugzilla")
    bugzilla = bugzilla if isinstance(bugzilla, dict) else {}

    details = sanitize_text(payload.get("details"), max_length=MAX_TEXT_LENGTH)

    # A record with no assessment, no errata and no prose says nothing at all.
    if cvss3 is None and cvss2 is None and not advisories and not details:
        raise RecordUnavailable(f"{cve_id}: no Red Hat assessment or errata")

    summary = {
        "threat_severity": severity,
        "public_date": normalize_iso_timestamp(payload.get("public_date")),
        "cvss3": cvss3,
        "cvss2": cvss2,
        "cwe": parse_cwes(payload.get("cwe")),
        "bugzilla_id": sanitize_text(bugzilla.get("id"), max_length=32),
        "advisory_count": len(payload.get("affected_release") or [])
        if isinstance(payload.get("affected_release"), list)
        else 0,
        "advisories": advisories,
        "package_state_counts": state_counts,
        "upstream_fix": sanitize_text(payload.get("upstream_fix"), max_length=500),
    }

    return {
        "cve_id": cve_id,
        "vendor": "Red Hat",
        "product": None,
        "threat_severity": severity,
        "public_date": summary["public_date"],
        # The engine's shared shape: a vendor score, offered only as a fallback.
        "cvss": cvss3 or cvss2,
        "cwe": summary["cwe"],
        "details": details,
        "statement": sanitize_text(payload.get("statement"), max_length=MAX_TEXT_LENGTH),
        "mitigation": sanitize_text(
            payload.get("mitigation"), max_length=MAX_TEXT_LENGTH
        ),
        "upstream_fix": summary["upstream_fix"],
        "bugzilla_id": summary["bugzilla_id"],
        "bugzilla_description": sanitize_text(
            bugzilla.get("description"), max_length=MAX_TEXT_LENGTH
        ),
        "advisory_count": summary["advisory_count"],
        "advisories": advisories,
        "package_state_counts": state_counts,
        "package_states": package_states,
        "references": split_references(payload.get("references")),
        "redhat_url": f"https://access.redhat.com/security/cve/{cve_id}",
        "source": "redhat_security",
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
        observed_at=payload.get("public_date") or retrieved_at,
        retrieved_at=retrieved_at,
        source_record_id=cve_id,
        payload=payload,
        entities=[Entity(kind="cve", value=cve_id, normalized=cve_id)],
    )

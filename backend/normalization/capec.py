"""CAPEC normalisation — the CWE-to-technique route.

CAPEC is a knowledge base, not a feed. It is fetched for one reason: it is the only
published bridge from a **weakness** to an **attack pattern**, and the ATT&CK bundle
supplies the second hop from an attack pattern to a technique.

The chain, and how far it actually reaches
------------------------------------------

``CWE -> CAPEC -> ATT&CK technique``

Measured against the live data rather than assumed:

* the catalogue holds **615 patterns**, of which **450 carry a CWE** — **1,214 links**
  across **336 distinct CWEs**;
* the ATT&CK bundle references **32 CAPEC patterns**, covering **36 techniques**;
* so **31 of the 336 CWEs** reach an ATT&CK technique, and 36 techniques are
  reachable in total;
* against the pipeline's own output, **316 of 1,773 threats carry a CWE**, and **71 of
  them** carry one of the 31 reachable CWEs.

Seventy-one is the number that justifies the fetch. The reach is narrow — 31 CWEs of
336 — and the index says so rather than implying the chain is broad.

A correction worth recording
----------------------------

An earlier note in this repository claimed CAPEC's XML contains "no ATT&CK identifiers
at all, which was checked and found to be true". That was **wrong**. CAPEC's XML
carries **272 taxonomy mappings to ATT&CK** — but they name only the taxonomy, with no
``Entry_ID``, so they identify no technique. The substantive conclusion survived the
correction; the wording did not, and the wording is what a reader would have trusted.

So the identifier-level link is still ATT&CK's own reverse reference, and it is the
only one. This module reads it from the ATT&CK index rather than re-deriving it.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from normalization.cisa import NormalizationError, sanitize_text

INDEX_SCHEMA = 1

#: Where the built index lives, beside the ATT&CK and galaxy indexes.
INDEX_FILENAME = "capec_index.json"

#: The CAPEC 3 XML namespace.
NAMESPACE = "{http://capec.mitre.org/capec-3}"

MAX_DESCRIPTION_LENGTH = 400
MAX_NAME_LENGTH = 200
MAX_CWES_PER_PATTERN = 80
MAX_PATTERNS = 1200

#: Values CAPEC uses for the two ordinal fields, kept only if recognised.
LIKELIHOODS = frozenset({"low", "medium", "high", "very high", "unknown"})
SEVERITIES = frozenset(
    {"low", "medium", "high", "very high", "critical", "unknown"}
)


def _text(pattern: ET.Element, tag: str) -> str | None:
    node = pattern.find(f"./{NAMESPACE}{tag}")

    if node is None:
        return None

    return sanitize_text("".join(node.itertext()), max_length=MAX_DESCRIPTION_LENGTH)


def _cwes(pattern: ET.Element) -> list[str]:
    """The CWE identifiers a pattern is related to."""

    cwes: list[str] = []

    for node in pattern.findall(
        f"./{NAMESPACE}Related_Weaknesses/{NAMESPACE}Related_Weakness"
    ):
        raw = sanitize_text(node.attrib.get("CWE_ID"), max_length=32)

        if not raw:
            continue

        cwe = f"CWE-{raw}"

        if cwe not in cwes:
            cwes.append(cwe)

        if len(cwes) >= MAX_CWES_PER_PATTERN:
            break

    return cwes


def _ordinal(value: str | None, allowed: frozenset[str]) -> str | None:
    text = (value or "").strip().lower()

    return text if text in allowed else None


def parse_catalog(payload: Any) -> list[dict]:
    """Every attack pattern in a CAPEC catalogue document."""

    if isinstance(payload, (bytes, bytearray)):
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as error:
            raise NormalizationError(f"CAPEC XML did not parse: {error}") from error
    elif isinstance(payload, ET.Element):
        root = payload
    else:
        raise NormalizationError("CAPEC payload is not XML bytes")

    patterns = root.findall(f".//{NAMESPACE}Attack_Pattern")

    if not patterns:
        raise NormalizationError(
            "CAPEC document contains no Attack_Pattern elements. The catalogue is "
            "XML in the capec-3 namespace; no patterns means the wrong document."
        )

    parsed: list[dict] = []

    for pattern in patterns[:MAX_PATTERNS]:
        raw_id = sanitize_text(pattern.attrib.get("ID"), max_length=16)

        if not raw_id or not raw_id.isdigit():
            continue

        name = sanitize_text(pattern.attrib.get("Name"), max_length=MAX_NAME_LENGTH)

        parsed.append(
            {
                "id": f"CAPEC-{raw_id}",
                "name": name,
                "abstraction": sanitize_text(
                    pattern.attrib.get("Abstraction"), max_length=32
                ),
                "status": sanitize_text(pattern.attrib.get("Status"), max_length=32),
                "likelihood": _ordinal(_text(pattern, "Likelihood_Of_Attack"), LIKELIHOODS),
                "severity": _ordinal(_text(pattern, "Typical_Severity"), SEVERITIES),
                "description": _text(pattern, "Description"),
                "cwes": _cwes(pattern),
                "url": f"https://capec.mitre.org/data/definitions/{raw_id}.html",
            }
        )

    return parsed


def build_index(
    payload: Any,
    *,
    attack_index: dict | None = None,
    source_url: str | None = None,
    generated_at: str | None = None,
) -> dict:
    """Builds the CWE-to-technique index from a CAPEC catalogue.

    The ATT&CK cross-reference is resolved **here**, at build time, so the published
    index already carries the techniques each pattern reaches and the enrichment stage
    does not need both indexes open to answer one question.
    """

    patterns = parse_catalog(payload)

    # Which CAPEC patterns ATT&CK itself references. This is the only
    # identifier-level link between the two catalogues, and it is read from ATT&CK
    # rather than from CAPEC because CAPEC's own ATT&CK taxonomy mappings name no
    # technique.
    capec_to_techniques: dict[str, list[str]] = {}

    for identifier, entry in ((attack_index or {}).get("techniques") or {}).items():
        if not isinstance(entry, dict):
            continue

        for capec in entry.get("capec") or []:
            bucket = capec_to_techniques.setdefault(str(capec).upper(), [])

            if identifier not in bucket:
                bucket.append(identifier)

    by_cwe: dict[str, list[str]] = {}
    entries: dict[str, dict] = {}

    reachable_techniques: set[str] = set()

    for pattern in patterns:
        techniques = sorted(capec_to_techniques.get(pattern["id"], []))

        entries[pattern["id"]] = {**pattern, "techniques": techniques}

        for cwe in pattern["cwes"]:
            by_cwe.setdefault(cwe, []).append(pattern["id"])

        reachable_techniques.update(techniques)

    for cwe in by_cwe:
        by_cwe[cwe] = sorted(by_cwe[cwe])

    # Only the CWEs that actually reach a technique are worth carrying as a route.
    reachable_cwes = sorted(
        cwe
        for cwe, capecs in by_cwe.items()
        if any(entries[capec]["techniques"] for capec in capecs)
    )

    return {
        "schema_version": INDEX_SCHEMA,
        "source_url": source_url,
        "generated_at": generated_at,
        "counts": {
            "patterns": len(entries),
            "patterns_with_cwes": sum(1 for e in entries.values() if e["cwes"]),
            "patterns_with_techniques": sum(
                1 for e in entries.values() if e["techniques"]
            ),
            "cwe_links": sum(len(e["cwes"]) for e in entries.values()),
            "distinct_cwes": len(by_cwe),
            "reachable_cwes": len(reachable_cwes),
            "reachable_techniques": len(reachable_techniques),
        },
        "entries": {key: entries[key] for key in sorted(entries)},
        "by_cwe": {key: by_cwe[key] for key in sorted(by_cwe)},
        "reachable_cwes": reachable_cwes,
    }


def load_index(path) -> dict | None:
    """Reads a previously built CAPEC index, or None when it is absent.

    A missing index is not an error: it means CAPEC has not been fetched yet, and
    enrichment simply runs without the weakness route.
    """

    from lib.atomic import read_json

    try:
        payload = read_json(path)
    except (OSError, ValueError):
        return None

    if not isinstance(payload, dict) or not isinstance(payload.get("by_cwe"), dict):
        return None

    return payload


def techniques_for_cwes(index: dict, cwes: Any) -> tuple[list[str], list[dict]]:
    """The techniques reachable from a set of CWE identifiers.

    Returns the technique identifiers and the CAPEC patterns that carried them, so the
    published block can name the route rather than presenting a technique as though it
    followed from the CVE directly.
    """

    if not isinstance(index, dict):
        return [], []

    entries = index.get("entries") or {}
    by_cwe = index.get("by_cwe") or {}

    techniques: list[str] = []
    routes: list[dict] = []

    for cwe in sorted({str(value).strip().upper() for value in cwes or () if value}):
        for capec in by_cwe.get(cwe) or []:
            entry = entries.get(capec) or {}
            found = entry.get("techniques") or []

            if not found:
                continue

            routes.append(
                {
                    "cwe": cwe,
                    "capec_id": capec,
                    "capec_name": entry.get("name"),
                    "capec_url": entry.get("url"),
                    "techniques": list(found),
                }
            )

            for technique in found:
                if technique not in techniques:
                    techniques.append(technique)

    return techniques, routes

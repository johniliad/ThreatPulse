"""MITRE ATT&CK normalisation — a knowledge base, not an observation feed.

ATT&CK is the vocabulary behind technique identifiers: given ``T1566`` it supplies
the name (Phishing), the tactic (Initial Access) and a reference URL. It is
**context, never proof of activity** — the development plan is explicit about that,
and the enrichment stage enforces it, since an enricher may not change a threat's
exploitation status, confidence or score.

Four properties of the live bundle decide this implementation. All were measured
against enterprise-attack 20.0 (52,771,014 bytes, 26,690 objects, 31 Oct 2026)
rather than taken from documentation:

* **ATT&CK does not map CVEs.** Exactly **18 of 26,690** objects carry a CVE
  external reference. It therefore cannot enrich a KEV CVE by identifier, and the
  only value it adds is resolving technique references that other sources make.
* **The bundle is 52.7 MB**, above the HTTP client's default ceiling, so a limit
  has to be passed explicitly or the response is refused.
* **The graph is mostly edges.** 21,819 objects are ``relationship`` edges. Only
  867 techniques, 15 tactics, 845 software and 193 groups carry knowledge, and the
  index keeps those and drops the rest.
* **Tactic names are not stable.** In version 20.0, ``TA0005`` is "Stealth" rather
  than the older "Defense Evasion", and ``TA0112`` "Defense Impairment" is new.
  Tactic labels are therefore read from the bundle, never hard-coded.

Deprecated and revoked objects are **kept and flagged** rather than dropped: an
advisory written two years ago may reference a technique that has since been
retired, and resolving it to a name is more useful than a silent miss.
"""

from __future__ import annotations

import re
from typing import Any

from lib.atomic import read_json
from normalization.cisa import NormalizationError, sanitize_text

INDEX_SCHEMA = "1.0"

#: Where the compact knowledge base lives, relative to the backend's data
#: directory. The collector writes it and the enrichment stage reads it, so the
#: name is defined once, beside the format it describes.
INDEX_FILENAME = "attack_index.json"

#: The ``source_name`` ATT&CK uses for its own identifiers.
MITRE_SOURCE = "mitre-attack"

#: ``T1566`` and the sub-technique form ``T1566.001``.
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

#: ``TA0001`` tactics, ``S0001`` software, ``G0001`` groups.
TACTIC_PATTERN = re.compile(r"^TA\d{4}$")
SOFTWARE_PATTERN = re.compile(r"^S\d{4}$")
GROUP_PATTERN = re.compile(r"^G\d{4}$")

#: Bounds on what reaches the index. The full descriptions run to several
#: kilobytes each; a short lead is enough for a tooltip or a UI line.
MAX_DESCRIPTION_LENGTH = 400
MAX_NAME_LENGTH = 200
MAX_ALIASES = 12
MAX_PLATFORMS = 12
MAX_URL_LENGTH = 300
#: Techniques carried per software or group entry.
#:
#: The bundle holds 18,975 ``uses`` relationships across roughly 1,000 software and
#: group objects — an average of about 19 each, but the most prolific use over 200.
#: A cap of 40 truncated exactly the 25 most interesting entries (Cobalt Strike,
#: QakBot, Emotet), which is the opposite of what a bound should do. The index is
#: 1.2 MB with the cap at 250 and no entry truncated, so the bound exists only to
#: stop a pathological bundle, and the count of entries that reach it is reported
#: so a real truncation is visible rather than silent.
MAX_TECHNIQUES_PER_OBJECT = 250


def _attack_references(obj: dict) -> list[dict]:
    return [
        reference
        for reference in obj.get("external_references") or []
        if isinstance(reference, dict)
        and str(reference.get("source_name", "")).strip().lower() == MITRE_SOURCE
    ]


def attack_ids(obj: dict) -> list[str]:
    """Every ATT&CK identifier on an object, uppercased and deduplicated."""

    identifiers: list[str] = []

    for reference in _attack_references(obj):
        value = sanitize_text(reference.get("external_id"), max_length=32)

        if value and value.upper() not in identifiers:
            identifiers.append(value.upper())

    return identifiers


def attack_url(obj: dict) -> str | None:
    """The attack.mitre.org URL for an object, when it publishes one."""

    for reference in _attack_references(obj):
        url = sanitize_text(reference.get("url"), max_length=MAX_URL_LENGTH)

        if url and url.startswith("https://"):
            return url

    return None


#: ``source_name`` ATT&CK uses for CAPEC references.
CAPEC_SOURCE = "capec"

#: ``CAPEC-13`` and the like.
CAPEC_PATTERN = re.compile(r"^CAPEC-\d+$")


def capec_ids(obj: dict) -> list[str]:
    """CAPEC identifiers an ATT&CK object references.

    Verified against the live bundle rather than assumed: **36 of 867 techniques**
    carry a ``source_name: "capec"`` reference. This is the *only* published link
    between CAPEC and ATT&CK — CAPEC's own XML contains no ATT&CK identifiers at
    all, which was checked and found to be true — so it is the second hop of the
    only free structural route from a CWE to a technique.

    The reach is narrow and is reported as narrow: 4% of techniques. It is
    recorded because it is sound, not because it is broad.
    """

    identifiers: list[str] = []

    for reference in obj.get("external_references") or []:
        if not isinstance(reference, dict):
            continue

        if str(reference.get("source_name", "")).strip().lower() != CAPEC_SOURCE:
            continue

        value = sanitize_text(reference.get("external_id"), max_length=32)

        if value and CAPEC_PATTERN.match(value.upper()) and value.upper() not in identifiers:
            identifiers.append(value.upper())

    return identifiers


def is_retired(obj: dict) -> bool:
    """Whether ATT&CK has revoked or deprecated an object."""

    return obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True


def tactics_of(obj: dict) -> list[str]:
    """The tactic short names a technique sits under, e.g. ``initial-access``."""

    phases: list[str] = []

    for phase in obj.get("kill_chain_phases") or []:
        if not isinstance(phase, dict):
            continue

        if str(phase.get("kill_chain_name", "")).strip().lower() != MITRE_SOURCE:
            continue

        name = sanitize_text(phase.get("phase_name"), max_length=64)

        if name and name.lower() not in phases:
            phases.append(name.lower())

    return sorted(phases)


def _names_of(obj: dict) -> list[str]:
    """An object's own name plus its aliases, lowercased and bounded."""

    names: list[str] = []

    primary = sanitize_text(obj.get("name"), max_length=MAX_NAME_LENGTH)

    if primary:
        names.append(primary.lower())

    for alias in obj.get("aliases") or []:
        text = sanitize_text(alias, max_length=MAX_NAME_LENGTH)

        if text and text.lower() not in names:
            names.append(text.lower())

        if len(names) >= MAX_ALIASES:
            break

    return names


def _platforms_of(obj: dict) -> list[str]:
    """The platforms ATT&CK lists for an object, bounded and sorted."""

    platforms: list[str] = []

    for platform in obj.get("x_mitre_platforms") or []:
        text = sanitize_text(platform, max_length=64)

        if text and text not in platforms:
            platforms.append(text)

        if len(platforms) >= MAX_PLATFORMS:
            break

    return sorted(platforms)


def build_index(
    bundle: Any,
    *,
    version: str | None = None,
    source_url: str | None = None,
    generated_at: str | None = None,
) -> dict:
    """Reduces a STIX 2.1 bundle to the index ThreatPulse needs.

    A bundle that yields no techniques raises :class:`NormalizationError`: the
    format has changed, and silently producing an empty knowledge base would look
    like a successful run.
    """

    if not isinstance(bundle, dict):
        raise NormalizationError("ATT&CK bundle is not an object")

    objects = bundle.get("objects")

    if not isinstance(objects, list) or not objects:
        raise NormalizationError("ATT&CK bundle has no objects")

    techniques: dict[str, dict] = {}
    tactics: dict[str, dict] = {}
    software: dict[str, dict] = {}
    groups: dict[str, dict] = {}
    bundle_version = None
    bundle_name = None

    # A first pass maps STIX object ids to the identifiers this index publishes, so
    # the relationship pass after the main loop can translate them.
    stix_map: dict[str, tuple[str, str]] = {}

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        stix_id = obj.get("id")

        if not isinstance(stix_id, str) or not stix_id:
            continue

        kind = obj.get("type")

        for identifier in attack_ids(obj):
            if kind == "attack-pattern" and TECHNIQUE_PATTERN.match(identifier):
                stix_map[stix_id] = ("technique", identifier)
                break

            if kind in ("malware", "tool") and SOFTWARE_PATTERN.match(identifier):
                stix_map[stix_id] = ("software", identifier)
                break

            if kind == "intrusion-set" and GROUP_PATTERN.match(identifier):
                stix_map[stix_id] = ("group", identifier)
                break

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        kind = obj.get("type")

        if kind == "x-mitre-collection":
            # The bundle describes itself, including its ATT&CK version.
            bundle_version = (
                sanitize_text(obj.get("x_mitre_version"), max_length=16)
                or bundle_version
            )
            bundle_name = sanitize_text(obj.get("name"), max_length=200) or bundle_name
            continue

        if kind == "attack-pattern":
            for identifier in attack_ids(obj):
                if not TECHNIQUE_PATTERN.match(identifier):
                    continue

                techniques[identifier] = {
                    "id": identifier,
                    "name": sanitize_text(obj.get("name"), max_length=MAX_NAME_LENGTH),
                    "tactics": tactics_of(obj),
                    "platforms": _platforms_of(obj),
                    "description": sanitize_text(
                        obj.get("description"), max_length=MAX_DESCRIPTION_LENGTH
                    ),
                    "url": attack_url(obj),
                    "retired": is_retired(obj),
                    # The CAPEC patterns ATT&CK itself references, which is the only
                    # published CAPEC-to-ATT&CK link. Carried so the CWE-to-CAPEC-to-
                    # technique route can be closed without re-downloading a 55 MB
                    # bundle to recover a handful of identifiers.
                    "capec": capec_ids(obj),
                }

        elif kind == "x-mitre-tactic":
            short_name = sanitize_text(obj.get("x_mitre_shortname"), max_length=64)

            for identifier in attack_ids(obj):
                if not TACTIC_PATTERN.match(identifier):
                    continue

                tactics[identifier] = {
                    "id": identifier,
                    "short_name": short_name.lower() if short_name else None,
                    "name": sanitize_text(obj.get("name"), max_length=MAX_NAME_LENGTH),
                    "description": sanitize_text(
                        obj.get("description"), max_length=MAX_DESCRIPTION_LENGTH
                    ),
                    "url": attack_url(obj),
                    "retired": is_retired(obj),
                }

        elif kind in ("malware", "tool"):
            for identifier in attack_ids(obj):
                if not SOFTWARE_PATTERN.match(identifier):
                    continue

                software[identifier] = {
                    "id": identifier,
                    "name": sanitize_text(obj.get("name"), max_length=MAX_NAME_LENGTH),
                    "kind": kind,
                    "names": _names_of(obj),
                    "platforms": _platforms_of(obj),
                    "url": attack_url(obj),
                    "retired": is_retired(obj),
                }

        elif kind == "intrusion-set":
            for identifier in attack_ids(obj):
                if not GROUP_PATTERN.match(identifier):
                    continue

                groups[identifier] = {
                    "id": identifier,
                    "name": sanitize_text(obj.get("name"), max_length=MAX_NAME_LENGTH),
                    "names": _names_of(obj),
                    "url": attack_url(obj),
                    "retired": is_retired(obj),
                }

    if not techniques:
        raise NormalizationError("ATT&CK bundle contains no techniques")

    # What ATT&CK actually knows about what software and groups *do*: a ``uses``
    # relationship from a malware, tool or intrusion-set to an attack-pattern.
    #
    # Without this a family can be named but its techniques cannot, and naming the
    # family is only worth doing because the techniques follow from it. This is the
    # link that carries a malware family from a threat all the way to the
    # techniques that family uses — the route ATT&CK cannot offer through a CVE.
    uses: dict[str, list[str]] = {}

    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "relationship":
            continue

        if str(obj.get("relationship_type") or "").strip().lower() != "uses":
            continue

        source = stix_map.get(str(obj.get("source_ref") or ""))
        target = stix_map.get(str(obj.get("target_ref") or ""))

        if not source or not target:
            continue

        if source[0] not in ("software", "group") or target[0] != "technique":
            continue

        bucket = uses.setdefault(source[1], [])

        if target[1] not in bucket and len(bucket) < MAX_TECHNIQUES_PER_OBJECT:
            bucket.append(target[1])

    for collection in (software, groups):
        for identifier, entry in collection.items():
            entry["techniques"] = sorted(uses.get(identifier, []))

    # Reported, not hidden: an entry that reaches the cap has been truncated, and a
    # reader of the run report should know that rather than assume the list is
    # complete.
    at_cap = sum(
        1
        for collection in (software, groups)
        for entry in collection.values()
        if len(entry.get("techniques") or []) >= MAX_TECHNIQUES_PER_OBJECT
    )

    return {
        "schema_version": INDEX_SCHEMA,
        "collection": bundle_name or "Enterprise ATT&CK",
        "version": version or bundle_version,
        "source_url": source_url,
        "generated_at": generated_at,
        "counts": {
            "techniques": len(techniques),
            "tactics": len(tactics),
            "software": len(software),
            "groups": len(groups),
            "objects_read": len(objects),
            "techniques_with_capec": sum(
                1 for entry in techniques.values() if entry.get("capec")
            ),
            "objects_at_technique_cap": at_cap,
        },
        "tactics": {key: tactics[key] for key in sorted(tactics)},
        "techniques": {key: techniques[key] for key in sorted(techniques)},
        "software": {key: software[key] for key in sorted(software)},
        "groups": {key: groups[key] for key in sorted(groups)},
    }


def load_index(path) -> dict | None:
    """Reads a previously built index, or None when it is absent or unusable.

    A missing index is not an error: it means the knowledge base has not been
    fetched yet, and enrichment is simply skipped.
    """

    try:
        raw = read_json(path)
    except (OSError, ValueError):
        return None

    if not isinstance(raw, dict) or not isinstance(raw.get("techniques"), dict):
        return None

    return raw


def tactic_names(index: dict, short_names: Any) -> list[dict]:
    """Tactic ``{id, name}`` for a technique's short names, in ATT&CK id order.

    A short name the bundle does not label is reported as-is rather than given an
    invented display name.
    """

    by_short = {
        entry.get("short_name"): entry
        for entry in (index.get("tactics") or {}).values()
        if isinstance(entry, dict) and entry.get("short_name")
    }

    resolved: list[dict] = []

    for short_name in short_names or []:
        entry = by_short.get(str(short_name).lower())

        if entry is None:
            resolved.append({"id": None, "name": str(short_name)})
            continue

        resolved.append({"id": entry.get("id"), "name": entry.get("name")})

    return sorted(resolved, key=lambda item: (item.get("id") or "zzz", str(item["name"])))


def resolve_techniques(index: dict, identifiers: Any) -> list[dict]:
    """Names, tactics and URLs for a list of technique identifiers.

    An identifier the bundle does not hold comes back with ``known: False``, so a
    consumer can tell "no such technique" from "we failed to look it up". Nothing
    is dropped silently.
    """

    techniques = index.get("techniques") or {}
    resolved: list[dict] = []

    candidates = {
        value.strip().upper()
        for value in identifiers or ()
        if isinstance(value, str) and value.strip()
    }

    for identifier in sorted(candidates):
        entry = techniques.get(identifier)

        if not isinstance(entry, dict):
            resolved.append({"id": identifier, "known": False})
            continue

        resolved.append(
            {
                "id": identifier,
                "known": True,
                "name": entry.get("name"),
                "tactics": tactic_names(index, entry.get("tactics")),
                "platforms": entry.get("platforms") or [],
                "url": entry.get("url"),
                "retired": bool(entry.get("retired")),
            }
        )

    return resolved


def match_actors(index: dict, names: Any) -> list[dict]:
    """ATT&CK software and groups whose name or alias matches a supplied name.

    Matching is **exact and case-insensitive** against a published name or alias.
    It is a name match, not an identification: the matched name travels with the
    result so the claim stays auditable, and a name matching two objects returns
    both rather than guessing which was meant.
    """

    lookup: dict[str, list[tuple[str, str]]] = {}

    for collection, kind in (
        (index.get("groups") or {}, "group"),
        (index.get("software") or {}, "software"),
    ):
        for identifier, entry in collection.items():
            if not isinstance(entry, dict):
                continue

            for candidate in entry.get("names") or []:
                text = str(candidate).strip().lower()

                if text:
                    lookup.setdefault(text, []).append((kind, identifier))

    matches: list[dict] = []

    for name in sorted({str(value).strip().lower() for value in names or ()}):
        if not name:
            continue

        for kind, identifier in sorted(lookup.get(name, [])):
            collection = index.get("groups") if kind == "group" else index.get("software")
            entry = (collection or {}).get(identifier) or {}

            matches.append(
                {
                    "matched_name": name,
                    "kind": kind,
                    "id": identifier,
                    "name": entry.get("name"),
                    "url": entry.get("url"),
                    "retired": bool(entry.get("retired")),
                    # The techniques ATT&CK records this software or group as using.
                    # Carried so a matched family reaches its techniques, which is the
                    # only reason matching a family is worth doing.
                    "techniques": list(entry.get("techniques") or []),
                }
            )

    return matches

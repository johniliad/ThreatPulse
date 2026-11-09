"""MISP Galaxy normalisation — an alias bridge to ATT&CK identifiers.

MISP Galaxy is a set of "cluster" vocabularies. It is not a feed: it carries no
observations, so it is a **knowledge base**, like the ATT&CK index, and the collector
that fetches it publishes nothing.

What it is for
--------------

A malware family named on a threat reaches its ATT&CK techniques
only if the name matches something ATT&CK lists. ATT&CK's own alias list is good but
not complete, and MISP Galaxy supplies the rest: 121 aliases across the three
enterprise-attack clusters that ATT&CK's bundle does not carry — ``havex`` for S0093,
``black energy`` for S0089, ``schtasks.exe`` for S0111, ``cobalt gypsy`` for G0059.

Measured, and deliberately narrow
---------------------------------

Which galaxy files are worth fetching was decided by measurement, not by the file
list:

* ``mitre-enterprise-attack-malware`` (188 values), ``-tool`` (45) and
  ``-intrusion-set`` (69) all carry ``meta.external_id`` — an ATT&CK identifier — and
  every one of those identifiers is already in the ATT&CK index. They therefore add
  **aliases, never new identifiers**: +121 names.
* ``ransomware`` (2,179 values) and ``threat-actor`` (1,114 values) carry **zero**
  ``external_id`` values. They cannot bridge to ATT&CK at all, so they are not
  fetched however large and appealing they look. Their 3.4 MB would buy nothing here.

The ATT&CK index is not modified in place: :func:`extend_attack_index` returns a copy
with the galaxy names folded into each entry's ``names``, so ATT&CK's own vocabulary
stays intact and the added aliases are visible as additions.
"""

from __future__ import annotations

from typing import Any

from lib.atomic import read_json
from normalization.attack import (
    GROUP_PATTERN,
    SOFTWARE_PATTERN,
    TECHNIQUE_PATTERN,
)
from normalization.cisa import NormalizationError, sanitize_text

INDEX_SCHEMA = 1

#: Where the built alias index lives, beside the ATT&CK index.
INDEX_FILENAME = "misp_galaxy_index.json"

MAX_SYNONYMS = 25
MAX_NAME_LENGTH = 200

#: The galaxy files worth fetching: the only ones carrying ATT&CK identifiers.
GALAXY_FILES = (
    "mitre-enterprise-attack-malware.json",
    "mitre-enterprise-attack-tool.json",
    "mitre-enterprise-attack-intrusion-set.json",
)

#: Identifier kinds the ATT&CK index uses, so a galaxy entry can be routed.
PATTERNS = (
    ("technique", TECHNIQUE_PATTERN),
    ("software", SOFTWARE_PATTERN),
    ("group", GROUP_PATTERN),
)


def identifier_kind(identifier: str) -> str | None:
    """Which ATT&CK collection an identifier belongs to, or None."""

    text = str(identifier or "").strip().upper()

    for kind, pattern in PATTERNS:
        if pattern.match(text):
            return kind

    return None


def parse_galaxy(payload: Any) -> list[dict]:
    """The bridgeable entries of one galaxy file.

    A value without a well-formed ``meta.external_id`` is dropped rather than kept
    as a bare name: a name with no ATT&CK identifier behind it cannot resolve to
    anything the index holds, so keeping it would inflate the counts without
    widening the match.
    """

    if not isinstance(payload, dict):
        return []

    galaxy = sanitize_text(payload.get("name"), max_length=MAX_NAME_LENGTH)
    galaxy_type = sanitize_text(payload.get("type"), max_length=MAX_NAME_LENGTH)

    entries: list[dict] = []

    for value in payload.get("values") or []:
        if not isinstance(value, dict):
            continue

        meta = value.get("meta")
        meta = meta if isinstance(meta, dict) else {}

        identifier = sanitize_text(meta.get("external_id"), max_length=32)

        if not identifier:
            continue

        identifier = identifier.upper()
        kind = identifier_kind(identifier)

        if kind is None:
            continue

        name = sanitize_text(value.get("value"), max_length=MAX_NAME_LENGTH)

        synonyms: list[str] = []

        for synonym in meta.get("synonyms") or []:
            text = sanitize_text(synonym, max_length=MAX_NAME_LENGTH)

            # A synonym equal to the name is not an alias, and a synonym that is
            # itself an identifier is not a name a feed would use.
            if (
                text
                and text.lower() != (name or "").lower()
                and identifier_kind(text) is None
                and text not in synonyms
                and len(synonyms) < MAX_SYNONYMS
            ):
                synonyms.append(text)

        entries.append(
            {
                "identifier": identifier,
                "kind": kind,
                "name": name,
                "synonyms": synonyms,
                "galaxy": galaxy,
                "galaxy_type": galaxy_type,
                "uuid": sanitize_text(value.get("uuid"), max_length=64),
            }
        )

    return entries


def build_index(
    payloads: Any,
    *,
    source_url: str | None = None,
    generated_at: str | None = None,
) -> dict:
    """Builds the alias index from the fetched galaxy files."""

    files: list[dict] = []
    entries: dict[str, dict] = {}

    for payload in payloads or ():
        if not isinstance(payload, dict):
            continue

        galaxy_entries = parse_galaxy(payload)

        if not galaxy_entries:
            continue

        files.append(
            {
                "name": sanitize_text(payload.get("name"), max_length=MAX_NAME_LENGTH),
                "type": sanitize_text(payload.get("type"), max_length=MAX_NAME_LENGTH),
                "version": sanitize_text(payload.get("version"), max_length=32),
                "entries": len(galaxy_entries),
            }
        )

        for entry in galaxy_entries:
            # A later file never overwrites an earlier one: the first entry for an
            # identifier is kept, so the index is deterministic whatever order the
            # files are fetched in.
            entries.setdefault(entry["identifier"], entry)

    if not entries:
        raise NormalizationError("MISP Galaxy files yielded no bridgeable entries")

    return {
        "schema_version": INDEX_SCHEMA,
        "source_url": source_url,
        "generated_at": generated_at,
        "files": sorted(files, key=lambda item: item.get("type") or ""),
        "counts": {
            "entries": len(entries),
            "synonyms": sum(len(entry["synonyms"]) for entry in entries.values()),
            "with_synonyms": sum(
                1 for entry in entries.values() if entry["synonyms"]
            ),
            "software": sum(
                1 for entry in entries.values() if entry["kind"] == "software"
            ),
            "groups": sum(1 for entry in entries.values() if entry["kind"] == "group"),
        },
        "entries": {key: entries[key] for key in sorted(entries)},
    }


def load_index(path) -> dict | None:
    """Reads a previously built alias index, or None when it is absent.

    A missing index is not an error: it means the galaxy has not been fetched yet,
    and enrichment simply runs on ATT&CK's own vocabulary.
    """

    try:
        payload = read_json(path)
    except (OSError, ValueError):
        return None

    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), dict):
        return None

    return payload


def extend_attack_index(index: dict, galaxy: dict | None) -> dict:
    """The ATT&CK index with the galaxy's aliases folded into each entry.

    The ATT&CK index itself is left untouched — this returns a copy — so ATT&CK's own
    vocabulary stays exactly what ATT&CK published, and the aliases this adds are
    visible as additions rather than blended into it.

    Names are added to the entry's ``names`` list, which is what ``match_actors``
    indexes, so an alias resolves through the same path as an ATT&CK name and carries
    the same audit trail: the matched name is published beside the identifier.
    """

    entries = (galaxy or {}).get("entries") or {}

    if not entries:
        return index

    extended = dict(index)

    added = 0
    collections_touched = 0

    for collection_name, kind in (("software", "software"), ("groups", "group")):
        collection = index.get(collection_name)

        if not isinstance(collection, dict):
            continue

        copied: dict[str, dict] = {}
        touched = False

        for identifier, entry in collection.items():
            if not isinstance(entry, dict):
                copied[identifier] = entry
                continue

            galaxy_entry = entries.get(identifier)

            if not galaxy_entry or galaxy_entry.get("kind") != kind:
                copied[identifier] = entry
                continue

            existing = list(entry.get("names") or [])
            lowered = {str(name).strip().lower() for name in existing}

            extra = [
                synonym
                for synonym in galaxy_entry.get("synonyms") or []
                if synonym.lower() not in lowered
            ]

            if not extra:
                copied[identifier] = entry
                continue

            copied[identifier] = {
                **entry,
                "names": [*existing, *extra],
                "galaxy_aliases": extra,
            }
            added += len(extra)
            touched = True

        extended[collection_name] = copied

        if touched:
            collections_touched += 1

    if added:
        extended["galaxy_aliases_added"] = added
        extended["galaxy_collections_extended"] = collections_touched

    return extended

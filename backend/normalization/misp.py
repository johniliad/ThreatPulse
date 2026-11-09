"""CIRCL MISP OSINT feed normalisation.

This is the source that makes ATT&CK enrichment reach a **vulnerability**. Every
other route is blocked: ATT&CK does not map CVEs (18 of its 26,690 objects carry
one), and the advisory feeds the pipeline ingests do not cite technique
identifiers. The MISP OSINT feed does — its events carry
``misp-galaxy:mitre-attack-pattern="Hooking - T1179"`` tags, which give both the
technique name and its identifier.

Measured on the live feed rather than assumed:

* the manifest holds **1,681 events** and **125** carry a technique tag;
* **318 distinct technique identifiers** appear across them;
* **77 events are marked TLP:GREEN or TLP:AMBER** and must be rejected — the feed
  is not uniformly clear, so the marking is read **per event**, never assumed from
  the source;
* the tag format is ``"<Name> - T####"``, so both the name and the identifier are
  available without a second lookup.

Two properties shape the implementation:

* **The manifest carries the tags but not the attributes.** Techniques can be read
  from one request; a CVE needs each event's own file, so the fetch is bounded per
  run and remembered in a cache.
* **Only events that reference a CVE can join a threat.** An event tagged with
  techniques and carrying only phone numbers or hashes cannot be correlated to
  anything, so it is counted rather than forced into a group. That is why the
  normaliser emits one observation per **CVE**, not one per event.
"""

from __future__ import annotations

import re
from typing import Any

from lib.ids import CVE_PATTERN
from lib.tlp import normalize_marking
from models.intelligence import Entity, Observation
from normalization.cisa import (
    NormalizationError,
    normalize_iso_timestamp,
    sanitize_text,
)

#: ``misp-galaxy:mitre-attack-pattern="Hooking - T1179"``. The name and the
#: identifier arrive together, which is why no second lookup is needed.
TECHNIQUE_TAG = re.compile(
    r'misp-galaxy:mitre-attack-pattern\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)

#: ``T1179`` and the sub-technique form ``T1059.001``.
TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

#: Any CVE identifier inside an attribute value.
CVE_IN_VALUE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

#: The MISP attribute type that carries a CVE.
VULNERABILITY_TYPE = "vulnerability"

MAX_TECHNIQUES = 40
MAX_CVES = 20
MAX_TEXT_LENGTH = 400


def techniques_from_tags(tags: Any) -> list[str]:
    """Technique identifiers from an event's ATT&CK galaxy tags.

    The tag carries a human name and the identifier; only the identifier is kept
    here, because the name is resolved against the ATT&CK index rather than trusted
    from a feed tag that may lag the current ATT&CK version.
    """

    found: list[str] = []

    for tag in tags or ():
        name = tag.get("name") if isinstance(tag, dict) else tag

        if not isinstance(name, str):
            continue

        for match in TECHNIQUE_TAG.finditer(name):
            for identifier in TECHNIQUE_ID.findall(match.group(1)):
                if identifier.upper() not in found:
                    found.append(identifier.upper())

                    if len(found) >= MAX_TECHNIQUES:
                        return found

    return found


def tlp_markings(tags: Any) -> list[str]:
    """Every ``tlp:*`` marking on an event, **normalised** for the gate.

    Normalised rather than passed through. The gate compares a marking against the
    source default and refuses anything it does not recognise, so handing it the raw
    ``"tlp:white"`` tag name rejects every event on the feed — which is exactly what
    the first live run did, and it looked identical to a feed with nothing in it.

    An unrecognised TLP-like token becomes ``UNKNOWN`` so the gate refuses it rather
    than treating the event as unmarked and therefore public.
    """

    markings: list[str] = []

    for tag in tags or ():
        name = tag.get("name") if isinstance(tag, dict) else tag

        if not isinstance(name, str) or not name.strip().lower().startswith("tlp:"):
            continue

        normalised = normalize_marking(name)

        markings.append(normalised if normalised else "UNKNOWN")

    return markings


def event_candidates(manifest: Any) -> list[dict]:
    """Every manifest entry, as a flat record, in a deterministic order.

    The manifest is keyed by event UUID, and each entry holds the event's tags but
    **not** its attributes — so techniques are available here while CVEs are not.

    The UUID is **lower-cased**, because the manifest and the event files disagree
    on case: the manifest carries some UUIDs in upper case while the files are named
    in lower case, so an upper-case URL returns HTTP 404 for an event that exists.
    Verified live: ``DF7B7020-…json`` is 404 while ``df7b7020-…json`` is 200 for the
    same event. Left alone, that reads as a feed whose events have all been deleted.
    """

    if not isinstance(manifest, dict):
        raise NormalizationError("MISP manifest is not an object")

    candidates: list[dict] = []
    seen: set[str] = set()

    for uuid, entry in manifest.items():
        if not isinstance(entry, dict) or not isinstance(uuid, str):
            continue

        key = uuid.strip().lower()

        if not key or key in seen:
            continue

        seen.add(key)

        candidates.append(
            {
                "uuid": key,
                "info": sanitize_text(entry.get("info"), max_length=MAX_TEXT_LENGTH),
                "date": normalize_iso_timestamp(entry.get("date")),
                "tags": entry.get("Tag") or [],
                "org": (
                    entry.get("Orgc", {}).get("name")
                    if isinstance(entry.get("Orgc"), dict)
                    else None
                ),
            }
        )

    return sorted(candidates, key=lambda item: item["uuid"])


def parse_event(payload: Any) -> dict:
    """Normalises one MISP event into techniques and CVEs.

    Raises :class:`NormalizationError` when the shape is not an event, so a
    mis-shaped response is reported rather than silently treated as an event with
    nothing in it.
    """

    if not isinstance(payload, dict):
        raise NormalizationError("MISP event is not an object")

    event = payload.get("Event")

    if not isinstance(event, dict):
        raise NormalizationError(
            "MISP event payload has no Event object. The feed serves one event per "
            "file; a response without one means the wrong URL was fetched."
        )

    uuid = sanitize_text(event.get("uuid"), max_length=64)

    if not uuid:
        raise NormalizationError("MISP event has no uuid")

    attributes = [
        attribute
        for attribute in (event.get("Attribute") or [])
        if isinstance(attribute, dict)
    ]

    cves: list[str] = []
    comment_texts: list[str] = []

    for attribute in attributes:
        if attribute.get("deleted") is True:
            continue

        value = sanitize_text(attribute.get("value"), max_length=MAX_TEXT_LENGTH)
        kind = str(attribute.get("type") or "").strip().lower()

        if not value:
            continue

        # A CVE can appear in a dedicated ``vulnerability`` attribute, in a comment
        # or in any free-text attribute, so the value is scanned whatever its type.
        # Missing one because it arrived as a comment rather than a
        # ``vulnerability`` attribute would lose the link this source exists to
        # provide.
        if kind == VULNERABILITY_TYPE or CVE_IN_VALUE.search(value):
            for match in CVE_IN_VALUE.findall(value):
                cve = match.upper()

                if cve not in cves and len(cves) < MAX_CVES:
                    cves.append(cve)

        # Attribute comments are kept for the TLP scan rather than for publication:
        # a marking hidden in a comment is still a marking that would be published.
        comment = sanitize_text(attribute.get("comment"), max_length=MAX_TEXT_LENGTH)

        if comment:
            comment_texts.append(comment)

    return {
        "event_uuid": uuid,
        "info": sanitize_text(event.get("info"), max_length=MAX_TEXT_LENGTH),
        "date": normalize_iso_timestamp(event.get("date")),
        "published": event.get("published") is True,
        "techniques": techniques_from_tags(event.get("Tag")),
        "tlp_markings": tlp_markings(event.get("Tag")),
        "cves": sorted(cves),
        "comment_texts": comment_texts,
        "attribute_count": len(attributes),
        "org": (
            event.get("Orgc", {}).get("name")
            if isinstance(event.get("Orgc"), dict)
            else None
        ),
    }


def scan_texts(event: dict) -> tuple[str, ...]:
    """Free text an event carries, for a TLP scan.

    Markings are not only tags. A live run published ``TLP:AMBER`` and ``TLP:GREEN``
    into the product because two events were tagged clear while their **title or an
    attribute comment** named a restrictive marking. The quality gate caught it and
    refused the whole publication, which is the correct outcome and also the reason
    this exists: the tag is a contributor's claim, and the text is what actually gets
    published, so both are scanned.
    """

    texts: list[str] = [event.get("info") or ""]

    for comment in event.get("comment_texts") or ():
        if isinstance(comment, str):
            texts.append(comment)

    return tuple(texts)


def build_observations(
    event: dict, *, source_key: str, retrieved_at: str
) -> list[Observation]:
    """One observation per CVE the event references.

    One per CVE and not one per event, because correlation groups on the CVE: an
    event that names three CVEs is evidence about all three, and an event that
    names none cannot be correlated to anything at all.

    The technique identifiers ride on ``attack_technique_ids`` in the payload, which
    is the field the correlation engine copies onto the threat and the ATT&CK
    enricher reads.
    """

    observations: list[Observation] = []

    techniques = event.get("techniques") or []

    for cve in event.get("cves") or ():
        cve_id = str(cve).strip().upper()

        if not CVE_PATTERN.match(cve_id):
            continue

        payload = {
            "cve_id": cve_id,
            "title": event.get("info"),
            "event_uuid": event.get("event_uuid"),
            "event_date": event.get("date"),
            "technique_ids": techniques,
            "source": source_key,
            "enrichment": True,
            "enrichment_summary": {
                "technique_ids": techniques,
                "event_uuid": event.get("event_uuid"),
                "event_info": event.get("info"),
            },
        }

        # The technique identifiers are declared as **entities**, because that is the
        # engine's vocabulary: it collects ``kind == "technique"`` entities from every
        # observation in a group and publishes them as ``attack_technique_ids``, which
        # the ATT&CK enricher then resolves. A payload field alone would be carried in
        # the observation and never reach the threat.
        entities = [Entity(kind="cve", value=cve_id, normalized=cve_id)]

        for technique in techniques:
            entities.append(
                Entity(
                    kind="technique",
                    value=technique,
                    normalized=technique,
                )
            )

        observations.append(
            Observation(
                source_key=source_key,
                external_id=cve_id,
                observed_at=event.get("date") or retrieved_at,
                retrieved_at=retrieved_at,
                source_record_id=f"{event.get('event_uuid')}:{cve_id}",
                payload=payload,
                entities=entities,
            )
        )

    return observations

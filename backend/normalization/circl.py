"""CIRCL Vulnerability-Lookup sighting normalisation.

Vulnerability-Lookup is CIRCL's aggregation platform, and its distinctive
contribution is **sightings**: dated reports that someone saw, exploited, patched
or doubted a vulnerability. Its API surface was established by reading the live
OpenAPI document (``/api/swagger.json``, 128 paths) rather than by guessing, and
three findings matter:

* **The filter parameter is ``vuln_id``, not ``vulnerability``.** A request using
  ``?vulnerability=CVE-2021-44228`` is *silently ignored* and answers with the whole
  sighting table — 673,198 records in a single response. Only ``vuln_id`` filters,
  so this module builds that query explicitly.
* **Large pages are broken upstream.** Measured against the live endpoint for a CVE
  with 2,015 sightings: ``per_page=15`` returned 91 KB of valid JSON, while
  ``per_page=20`` and above returned 62–88 MB of **truncated, unparseable** JSON.
  The collector therefore asks for a small page and refuses an oversized body
  instead of trying to parse one.
* **Sightings are counts, not a boolean.** The useful output is how many were
  recorded, of which kinds, by whom, and when the most recent one was.

What a sighting is worth: ``type: "exploited"`` from a source such as
``The Shadowserver (honeypot/exploited-vulnerabilities)`` is an independent report
of exploitation by a party other than CISA. It is published as **counts and dates**
and never as an exploitation flag — the payload carries no ``exploited_in_wild``
field, so this source cannot move a threat's score. Teaching the scoring model to
consume sightings is a deliberate change for a later phase, not a side effect of
collecting them.

Because sightings accumulate, the collector refreshes its records on a short
interval rather than caching them permanently.
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

#: Sighting records inspected per CVE. The live endpoint breaks above 15, so this
#: stays well inside the working range.
MAX_SIGHTINGS_SAMPLED = 10

MAX_SOURCES = 10
MAX_AUTHORS = 10
MAX_TYPE_LENGTH = 48


def lookup_url(
    base_url: str, cve_id: str, *, per_page: int = MAX_SIGHTINGS_SAMPLED
) -> str:
    """The per-CVE sighting query.

    ``vuln_id`` is the only parameter that filters; see the module docstring.
    """

    return (
        f"{(base_url or '').rstrip('/')}/sighting/"
        f"?vuln_id={cve_id.strip().upper()}&per_page={int(per_page)}"
    )


def normalize_sighting_type(value: Any) -> str | None:
    """A sighting type token, lower-cased with spaces folded to underscores.

    The API documents title-case labels ("Published Proof of Concept") while the
    JSON carries tokens such as ``exploited``. Unrecognised tokens are kept rather
    than dropped: they are being *counted*, not asserted, so passing one through
    reports what CIRCL said instead of guessing what it meant.
    """

    text = sanitize_text(value, max_length=MAX_TYPE_LENGTH)

    if not text:
        return None

    return text.strip().lower().replace(" ", "_")


def parse_sightings(payload: Any) -> dict:
    """Validates a sighting response and reduces it to counts and dates.

    Raises :class:`RecordUnavailable` when nothing has been sighted, which is a
    permanent-enough answer to remember, and :class:`NormalizationError` when the
    response cannot be trusted.
    """

    if not isinstance(payload, dict):
        raise NormalizationError("sighting response is not an object")

    metadata = payload.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    total = metadata.get("count")

    if isinstance(total, bool) or not isinstance(total, int):
        raise NormalizationError("sighting response has no count")

    raw_rows = payload.get("data")
    rows = (
        [row for row in raw_rows if isinstance(row, dict)]
        if isinstance(raw_rows, list)
        else []
    )

    if total <= 0 or not rows:
        raise RecordUnavailable("no sightings recorded")

    cve_id = None

    for row in rows:
        candidate = sanitize_text(row.get("vulnerability"), max_length=32)

        if candidate:
            cve_id = candidate.upper()
            break

    if not cve_id or not CVE_PATTERN.match(cve_id):
        raise NormalizationError("sighting response names no CVE")

    types: dict[str, int] = {}
    sources: list[str] = []
    authors: list[str] = []
    timestamps: list[str] = []
    exploited = 0

    for row in rows:
        kind = normalize_sighting_type(row.get("type"))

        if kind:
            types[kind] = types.get(kind, 0) + 1

            if kind == "exploited":
                exploited += 1

        source = sanitize_text(row.get("source"), max_length=300)

        if source and source not in sources and len(sources) < MAX_SOURCES:
            sources.append(source)

        author = row.get("author")

        if isinstance(author, dict):
            login = sanitize_text(author.get("login"), max_length=100)

            if login and login not in authors and len(authors) < MAX_AUTHORS:
                authors.append(login)

        stamp = normalize_iso_timestamp(row.get("creation_timestamp"))

        if stamp:
            timestamps.append(stamp)

    latest = max(timestamps) if timestamps else None
    earliest = min(timestamps) if timestamps else None

    summary = {
        "sighting_count": total,
        "sightings_sampled": len(rows),
        "sighting_types": dict(sorted(types.items())),
        "exploited_sightings_sampled": exploited,
        "latest_sighting_at": latest,
        "sighting_sources": sources,
    }

    return {
        "cve_id": cve_id,
        "sighting_count": total,
        # The breakdown covers only the page that was read; the total above is
        # exact. Both are named so a consumer cannot confuse the two.
        "sightings_sampled": len(rows),
        "sighting_types": summary["sighting_types"],
        "exploited_sightings_sampled": exploited,
        "latest_sighting_at": latest,
        "earliest_sighting_sampled_at": earliest,
        "sighting_sources": sources,
        "sighting_authors": authors,
        "circl_url": f"https://vulnerability.circl.lu/vuln/{cve_id}",
        "source": "circl_vulnerability_lookup",
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
        observed_at=payload.get("latest_sighting_at") or retrieved_at,
        retrieved_at=retrieved_at,
        source_record_id=cve_id,
        payload=payload,
        entities=[Entity(kind="cve", value=cve_id, normalized=cve_id)],
    )

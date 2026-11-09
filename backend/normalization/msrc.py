"""Microsoft Security Update Guide normalisation.

MSRC publishes the same information twice, and the choice between them matters.

* **CVRF** — ``api.msrc.microsoft.com/cvrf/v3.0/cvrf/<release>`` — is the standard
  document, and it is **XML**: 46.7 MB for a single month (October 2026, measured).
  It is also per-release, so covering a year means fetching and parsing twelve
  46 MB XML documents to find the handful of CVEs the pipeline tracks.
* **The Security Update Guide API** — ``/sug/v2.0/en-US/affectedProduct`` — is
  **JSON**, OData and filterable, and answers about **one CVE at a time**. A
  single-CVE lookup returns about 1.5 KB.

This module uses the second, because it matches the shape the pipeline already has
for dependent sources (``collectors/cve_lookup.py``): bounded per run, cacheable,
with a definitive "not covered" answer. Two properties of that API were verified
against the live service rather than assumed:

* ``$filter=cveNumber eq '<CVE>'`` returns the affected-product rows for that CVE,
  and an ``@odata.count`` of 0 is a clean, cacheable miss.
* ``$select`` is **rejected with HTTP 403**, so the payload cannot be trimmed
  server-side. That is tolerable per CVE, but it is why this must never be used to
  pull a whole month at once — that is 33,057 rows.

One CVE commonly returns **several rows**, one per affected product. The record is
therefore aggregated: the highest base score, the most severe rating, the union of
CWEs, and every affected product. Taking the first row would understate a CVE that
is Moderate on one product and Critical on another.
"""

from __future__ import annotations

import re
from urllib.parse import quote, urlencode

from lib.ids import CVE_PATTERN
from models.intelligence import Entity, Observation
from normalization.cisa import (
    NormalizationError,
    RecordUnavailable,
    normalize_cwes,
    normalize_iso_timestamp,
    sanitize_text,
)

MAX_PRODUCTS = 25
MAX_BUILDS = 10
MAX_NAME_LENGTH = 200

#: Microsoft's own severity vocabulary, lower-cased.
SEVERITIES = frozenset({"critical", "important", "moderate", "low"})

#: Ranked so the most severe rating across a CVE's rows can be chosen.
SEVERITY_RANK = {"critical": 4, "important": 3, "moderate": 2, "low": 1}

#: MSRC writes a CWE as ``"CWE-862: Missing Authorization"`` — identifier first,
#: then its title. ``normalize_cwes`` expects the bare identifier and rejects
#: anything else, so passing the titled form straight through drops **every** CWE
#: silently while looking like a source that publishes none.
CWE_IN_TITLE = re.compile(r"\bCWE-\d+\b")


def parse_cwe_list(value: object) -> list[str]:
    """CWE identifiers from MSRC's titled ``cweList`` entries."""

    if not isinstance(value, list):
        return []

    bare: list[str] = []

    for entry in value:
        if not isinstance(entry, str):
            continue

        match = CWE_IN_TITLE.search(entry)

        if match:
            bare.append(match.group(0))

    return normalize_cwes(bare)


def record_url(base_url: str, cve_id: str) -> str:
    """OData lookup URL for one CVE.

    The filter expression is a query **value**, so it is percent-encoded rather
    than pasted in. ``urlencode`` is used with ``quote_via=quote`` so spaces become
    ``%20`` rather than ``+``: OData servers are not obliged to read ``+`` as a
    space in a query string, and a silently mis-parsed filter would look exactly
    like a CVE Microsoft does not cover.
    """

    base = (base_url or "").rstrip("/")
    cve = cve_id.strip().upper()

    query = urlencode({"$filter": f"cveNumber eq '{cve}'"}, quote_via=quote)

    return f"{base}?{query}"


def _base_score(row: dict) -> float | None:
    """``baseScore`` arrives as a string (``"3.1"``), not as a number."""

    value = row.get("baseScore")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)

    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None

    return None


def _builds(rows: list[dict]) -> list[str]:
    """The fixed build numbers, which is what an operator actually needs."""

    builds: list[str] = []

    for row in rows:
        for article in row.get("kbArticles") or []:
            if not isinstance(article, dict):
                continue

            build = sanitize_text(
                article.get("fixedBuildNumber"), max_length=MAX_NAME_LENGTH
            )

            if build and build not in builds:
                builds.append(build)

            if len(builds) >= MAX_BUILDS:
                return builds

    return builds


def parse_msrc_record(payload: object) -> dict:
    """Validates and normalises one MSRC lookup into a single CVE payload."""

    if not isinstance(payload, dict):
        raise NormalizationError("MSRC response is not an object")

    rows = payload.get("value")

    if not isinstance(rows, list):
        raise NormalizationError(
            "MSRC response has no value array. The Security Update Guide API is "
            "OData, so a response without one means the filter was rejected rather "
            "than that the CVE is unknown."
        )

    usable = [row for row in rows if isinstance(row, dict)]

    if not usable:
        # An empty result is a real, cacheable answer: Microsoft does not document
        # this CVE. It is not an error, and it must not be retried on every run.
        raise RecordUnavailable("MSRC does not document this CVE")

    raw_cve = usable[0].get("cveNumber")
    cve_id = str(raw_cve or "").strip().upper()

    if not CVE_PATTERN.match(cve_id):
        raise NormalizationError(f"invalid CVE identifier: {raw_cve!r}")

    products: list[str] = []
    severities: list[str] = []
    statuses: list[str] = []
    cwes: list[str] = []
    releases: list[str] = []
    dates: list[str] = []

    best_score: float | None = None
    best_vector: str | None = None

    for row in usable:
        product = sanitize_text(row.get("product"), max_length=MAX_NAME_LENGTH)

        if product and product not in products and len(products) < MAX_PRODUCTS:
            products.append(product)

        severity = sanitize_text(row.get("severity"), max_length=32)
        severity = severity.lower() if severity else None

        if severity in SEVERITIES and severity not in severities:
            severities.append(severity)

        status = sanitize_text(row.get("productStatus"), max_length=32)

        if status and status not in statuses:
            statuses.append(status)

        for cwe in parse_cwe_list(row.get("cweList")):
            if cwe not in cwes:
                cwes.append(cwe)

        release = sanitize_text(row.get("releaseNumber"), max_length=32)

        if release and release not in releases:
            releases.append(release)

        date = normalize_iso_timestamp(row.get("releaseDate"))

        if date and date not in dates:
            dates.append(date)

        score = _base_score(row)

        # The vector travels with its own score, so a published CVSS is never
        # assembled from two different rows.
        if score is not None and (best_score is None or score > best_score):
            best_score = score
            best_vector = sanitize_text(row.get("vectorString"), max_length=200)

    if best_score is None and not severities and not products:
        raise RecordUnavailable(f"{cve_id}: no Microsoft assessment")

    severity = (
        max(severities, key=lambda item: SEVERITY_RANK[item]) if severities else None
    )

    details = None

    if products:
        listed = ", ".join(products[:5]) + (", and others" if len(products) > 5 else "")

        details = (
            f"Microsoft documents {cve_id} as affecting "
            f"{len(products)} product(s) ({listed})."
        )

    builds = _builds(usable)

    summary = {
        "severity": severity,
        "base_score": best_score,
        "release_numbers": sorted(releases),
        "product_statuses": sorted(statuses),
        "affected_product_count": len(products),
        "cwe": cwes,
        "fixed_builds": builds,
        "customer_action_required": any(
            row.get("customerActionRequired") is True for row in usable
        ),
    }

    return {
        "cve_id": cve_id,
        "vendor": "Microsoft",
        "product": products[0] if products else None,
        "threat_severity": severity,
        "public_date": max(dates) if dates else None,
        # The engine's shared shape: a first-party vendor assessment.
        "cvss": (
            {"base_score": best_score, "vector": best_vector, "version": "3.1"}
            if best_score is not None
            else None
        ),
        "cwe": cwes,
        "details": details,
        "affected_products": products,
        "product_statuses": sorted(statuses),
        "release_numbers": sorted(releases),
        "fixed_builds": builds,
        "customer_action_required": summary["customer_action_required"],
        "msrc_url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
        "source": "msrc",
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

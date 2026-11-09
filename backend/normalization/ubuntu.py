"""Ubuntu Security Notices normalisation.

Canonical publishes notices as JSON, and the **list** already carries what is needed:
``https://ubuntu.com/security/notices.json`` returns notices whose entries include the
CVEs they address, so one bounded request yields a CVE-to-advisory mapping without
fetching each notice in turn.

What was checked before building
--------------------------------

* ``https://ubuntu.com/security/CVE-2021-44228.json`` returns **404** for a CVE that
  certainly exists, so Ubuntu offers no per-CVE lookup and cannot use the dependent
  lookup pattern that Red Hat and MSRC use.
* The notices **list** carries ``cves`` and ``cves_ids`` per entry, so the detail
  endpoint is not needed either.

One request, then. The observation is keyed on the CVE, because correlation groups on
the CVE: a notice that addresses three CVEs is evidence about all three, and a notice
that addresses none cannot be correlated at all.

The package lists are deliberately reduced to a count. They are large, they name
Ubuntu releases rather than anything a reader acts on, and the notice URL carries the
detail for anyone who needs it.
"""

from __future__ import annotations

from typing import Any

from lib.ids import CVE_PATTERN
from models.intelligence import Entity, Observation
from normalization.cisa import (
    NormalizationError,
    normalize_iso_timestamp,
    sanitize_text,
)

MAX_TEXT_LENGTH = 4000
MAX_RELEASES = 30
MAX_CVES_PER_NOTICE = 40
MAX_NOTICES = 500


def parse_notices(payload: Any) -> list[dict]:
    """The notices in a ``notices.json`` payload."""

    if isinstance(payload, list):
        notices = payload
    elif isinstance(payload, dict):
        if "notices" not in payload:
            raise NormalizationError(
                "Ubuntu payload has no notices key. The feed serves "
                '{"notices": [...]}; its absence means the wrong document, which is a '
                "different fact from a list that happens to be empty."
            )

        notices = payload.get("notices") or []
    else:
        raise NormalizationError(
            "Ubuntu notices payload is neither an object nor a list"
        )

    if not isinstance(notices, list):
        raise NormalizationError("Ubuntu notices payload has no notices array")

    parsed: list[dict] = []

    for notice in notices[:MAX_NOTICES]:
        if not isinstance(notice, dict):
            continue

        notice_id = sanitize_text(notice.get("id"), max_length=64)

        if not notice_id:
            continue

        cves: list[str] = []

        # ``cves`` is the structured list; ``cves_ids`` is the flat one. Either can be
        # present, and a notice is only useful if one of them names a CVE.
        for entry in notice.get("cves") or []:
            value = entry.get("id") if isinstance(entry, dict) else entry
            text = str(value or "").strip().upper()

            if CVE_PATTERN.match(text) and text not in cves and len(cves) < MAX_CVES_PER_NOTICE:
                cves.append(text)

        for value in notice.get("cves_ids") or []:
            text = str(value or "").strip().upper()

            if CVE_PATTERN.match(text) and text not in cves and len(cves) < MAX_CVES_PER_NOTICE:
                cves.append(text)

        releases = []

        for release in (notice.get("release_packages") or {}).keys():
            text = sanitize_text(release, max_length=64)

            if text and len(releases) < MAX_RELEASES:
                releases.append(text)

        parsed.append(
            {
                "notice_id": notice_id,
                "title": sanitize_text(notice.get("title"), max_length=MAX_TEXT_LENGTH),
                "summary": sanitize_text(
                    notice.get("summary"), max_length=MAX_TEXT_LENGTH
                ),
                "published": normalize_iso_timestamp(notice.get("published")),
                "notice_type": sanitize_text(notice.get("type"), max_length=32),
                "hidden": notice.get("is_hidden") is True,
                "cves": sorted(cves),
                "releases": sorted(releases),
                "package_count": sum(
                    len(packages or [])
                    for packages in (notice.get("release_packages") or {}).values()
                    if isinstance(packages, list)
                ),
                "url": f"https://ubuntu.com/security/notices/{notice_id}",
            }
        )

    return parsed


def build_observations(
    notices: list[dict], *, source_key: str, retrieved_at: str
) -> list[Observation]:
    """One observation per (notice, CVE)."""

    observations: list[Observation] = []

    for notice in notices:
        if notice.get("hidden"):
            # A withdrawn notice is not evidence about anything.
            continue

        for cve in notice.get("cves") or ():
            cve_id = str(cve).strip().upper()

            if not CVE_PATTERN.match(cve_id):
                continue

            payload = {
                "cve_id": cve_id,
                "notice_id": notice.get("notice_id"),
                "title": notice.get("title"),
                "summary": notice.get("summary"),
                "notice_type": notice.get("notice_type"),
                "releases": notice.get("releases") or [],
                "package_count": notice.get("package_count") or 0,
                "ubuntu_url": notice.get("url"),
                "source": source_key,
                "enrichment": True,
                "enrichment_summary": {
                    "notice_id": notice.get("notice_id"),
                    "notice_title": notice.get("title"),
                    "releases": notice.get("releases") or [],
                    "package_count": notice.get("package_count") or 0,
                },
            }

            observations.append(
                Observation(
                    source_key=source_key,
                    external_id=cve_id,
                    observed_at=notice.get("published") or retrieved_at,
                    retrieved_at=retrieved_at,
                    source_record_id=f"{notice.get('notice_id')}:{cve_id}",
                    payload=payload,
                    entities=[Entity(kind="cve", value=cve_id, normalized=cve_id)],
                )
            )

    return observations

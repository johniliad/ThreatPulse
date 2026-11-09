"""Publication builder and fail-closed quality gate.

Builds the schema 1.0 document that ``publish.php`` accepts, then validates it
before anything is written or sent. The gate fails **closed**: an invalid
publication is never written to disk as a candidate and never transmitted.

Two independent defences against replacing good published data with a broken
snapshot:

* structural validation (schema, identifiers, ranges, required fields, absence
  of secrets);
* volume validation against the previous publication (a suspicious drop in
  threat count blocks the publish until it is explicitly overridden).
"""

from __future__ import annotations

import re
from typing import Any

from lib.ids import THREAT_UUID_PATTERN, new_publication_id
from models.intelligence import Publication, Source, Threat

SCHEMA_VERSION = "1.0"

PUBLICATION_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
ALLOWED_CONFIDENCE_LEVELS = {"high", "medium", "low"}
ALLOWED_EXPLOITATION_STATUSES = {"confirmed", "suspected", "unknown", "not_exploited"}

SECRET_MARKERS = (
    "publisher_token",
    "threatpulse_publisher_token",
)

#: Credential-shaped patterns, as ``(label, pattern)`` pairs.
#:
#: A bare protocol word is not a secret. Advisories legitimately discuss
#: "bearer tokens" and "Authorization headers", so matching those words blocked
#: a perfectly clean publication on the first successful run. These patterns
#: require an actual credential-looking value to follow, which is what a leaked
#: token would look like, while leaving prose alone.
SECRET_PATTERNS = (
    (
        "bearer credential",
        re.compile(r"bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    ),
    (
        "authorization header value",
        re.compile(
            r"authorization\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{16,}",
            re.IGNORECASE,
        ),
    ),
)

MAX_TITLE_LENGTH = 1000


class QualityGateError(RuntimeError):
    """Raised when a publication must not be published."""


def build_publication(
    threats: list[Threat],
    sources: list[Source],
    *,
    generated_at: str,
    title: str = "ThreatPulse Cyber Threat Intelligence",
    description: str = (
        "Prioritised cyber threat intelligence aggregated from multiple "
        "independent sources. The attribution register lists every source, its "
        "licence and its current contribution."
    ),
    max_summary_items: int = 10,
    changes: dict[str, Any] | None = None,
) -> Publication:
    """Builds the publication document from intelligence objects.

    The title and description are deliberately about the product rather than about
    one feed. They said "CISA KEV Intelligence" long after the published set became
    a multi-source aggregate, and the summary is served to every API client, so a
    single-source claim there is a false statement rather than a stale comment.
    """

    vulnerability_count = sum(len(threat.vulnerabilities) for threat in threats)

    severity_counts = {severity: 0 for severity in sorted(ALLOWED_SEVERITIES)}

    for threat in threats:
        if threat.severity in severity_counts:
            severity_counts[threat.severity] += 1

    top_threats = [
        {
            "threat_uuid": threat.threat_uuid,
            "external_id": threat.external_id,
            "priority_score": round(threat.priority_score, 2),
            "severity": threat.severity,
        }
        for threat in threats[:max_summary_items]
    ]

    summary: dict[str, Any] = {
        "title": title,
        "description": description,
        "threat_count": len(threats),
        "vulnerability_count": vulnerability_count,
        "critical_count": severity_counts["critical"],
        "high_count": severity_counts["high"],
        "medium_count": severity_counts["medium"],
        "low_count": severity_counts["low"],
        "informational_count": severity_counts["informational"],
        "source_keys": sorted({source.key for source in sources}),
        "top_threats": top_threats,
    }

    # Present only when the caller tracked change; a publication built without it
    # is byte-identical to one built before this stage existed.
    if changes is not None:
        summary["changes"] = changes

    return Publication(
        publication_uuid=new_publication_id(),
        schema_version=SCHEMA_VERSION,
        generated_at=generated_at,
        summary=summary,
        sources=sources,
        threats=threats,
    )


# __PUBLICATION_PART_TWO__

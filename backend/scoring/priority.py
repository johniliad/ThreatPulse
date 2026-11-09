#!/usr/bin/env python3

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import Any


WEIGHTS = {
    "exploitation": 0.30,
    "recency": 0.20,
    "urgency": 0.20,
    "ransomware": 0.15,
    "impact": 0.10,
    "forensic": 0.05,
}


def clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    return max(minimum, min(maximum, value))


def parse_date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


class UnscoreableRecord(ValueError):
    """Raised when a record is not shaped for this priority model.

    The model is derived from the CISA KEV catalogue and reads fields only that
    catalogue provides. Handing it an advisory, an EPSS score or a ransomware
    aggregate would otherwise produce a score assembled from defaults — a number
    that looks authoritative and is not. So it refuses instead.
    """


#: Fields the model reads directly. A record without them is not a KEV record.
REQUIRED_RECORD_FIELDS = ("date_added", "due_date")


def missing_required_fields(record: Any) -> list[str]:
    """Required fields absent from a candidate record."""

    if not isinstance(record, dict):
        return list(REQUIRED_RECORD_FIELDS)

    return [
        field
        for field in REQUIRED_RECORD_FIELDS
        if not isinstance(record.get(field), str) or not record.get(field)
    ]


def can_score(record: Any) -> bool:
    """True when this record is shaped for the CISA-derived model."""

    return not missing_required_fields(record)


def assert_scoreable(record: Any) -> None:
    """Raises :class:`UnscoreableRecord` for a record the model cannot score."""

    missing = missing_required_fields(record)

    if missing:
        raise UnscoreableRecord(
            "record is not a CISA KEV record: missing " + ", ".join(missing)
        )


def _required_field(record: Any, field: str) -> str:
    value = record.get(field) if isinstance(record, dict) else None

    if not isinstance(value, str) or not value:
        raise UnscoreableRecord(
            f"record is not a CISA KEV record: missing {field}"
        )

    return value


def exploitation_score(record: dict[str, Any]) -> float:
    if (
        record.get("kev_listed") is True
        and record.get("exploited_in_wild") is True
    ):
        return 100.0

    if record.get("kev_listed") is True:
        return 90.0

    if record.get("exploited_in_wild") is True:
        return 85.0

    return 0.0


def recency_score(
    record: dict[str, Any],
    reference_date: date | None = None,
) -> float:
    added = parse_date(_required_field(record, "date_added"))

    if reference_date is None:
        reference_date = datetime.now(timezone.utc).date()

    age_days = max(0, (reference_date - added).days)

    if age_days <= 7:
        return 100.0

    if age_days <= 14:
        return 90.0

    if age_days <= 30:
        return 80.0

    if age_days <= 60:
        return 65.0

    if age_days <= 90:
        return 50.0

    if age_days <= 180:
        return 35.0

    return 20.0


def urgency_score(
    record: dict[str, Any],
    reference_date: date | None = None,
) -> float:
    due_date = parse_date(_required_field(record, "due_date"))

    if reference_date is None:
        reference_date = datetime.now(timezone.utc).date()

    days_remaining = (due_date - reference_date).days

    if days_remaining <= 0:
        return 100.0

    if days_remaining <= 3:
        return 100.0

    if days_remaining <= 7:
        return 90.0

    if days_remaining <= 14:
        return 75.0

    if days_remaining <= 30:
        return 55.0

    if days_remaining <= 60:
        return 35.0

    return 20.0


def ransomware_score(record: dict[str, Any]) -> float:
    value = str(
        record.get("known_ransomware_campaign_use", "")
    ).strip().lower()

    if value == "yes":
        return 100.0

    if value == "unknown":
        return 50.0

    if value == "no":
        return 0.0

    return 50.0


def impact_score(record: dict[str, Any]) -> float:
    text = " ".join(
        [
            str(record.get("vulnerability_name", "")),
            str(record.get("description", "")),
        ]
    ).lower()

    # Highest-impact condition:
    # unauthenticated / remote arbitrary code execution.
    if (
        re.search(r"unauthenticated", text)
        and (
            "arbitrary code execution" in text
            or "remote code execution" in text
            or "execute arbitrary code" in text
        )
    ):
        return 100.0

    if (
        "remote code execution" in text
        or "arbitrary code execution" in text
        or "execute arbitrary code" in text
    ):
        return 95.0

    if (
        "authentication bypass" in text
        or "auth bypass" in text
        or "privilege escalation" in text
        or "elevated privileges" in text
    ):
        return 85.0

    if (
        "information disclosure" in text
        or "sensitive information" in text
        or "data exposure" in text
        or "data exfiltration" in text
    ):
        return 75.0

    if (
        "denial of service" in text
        or "denial-of-service" in text
    ):
        return 60.0

    return 50.0


def forensic_score(record: dict[str, Any]) -> float:
    value = str(
        record.get("forensic_triage", "")
    ).strip().lower()

    if value == "yes":
        return 100.0

    if value == "no":
        return 0.0

    return 50.0


def priority_band(score: float) -> str:
    """Maps a score onto its band.

    The boundaries were derived for the v0.1 model's distribution and were not
    recalibrated when the models were unified. Under ``threatpulse_priority_v0.3``
    the same KEV-listed evidence scores materially higher — a record carrying
    exploitation, EPSS, CVSS and corroboration reaches the high 80s — so the old
    85/70 split labelled 23% of a 3,772-record publication "critical", which is not
    a prioritisation anyone can act on.

    ``critical`` moved 85 → 90 and ``high`` 70 → 75. ``medium`` stays at 50 because
    it is the exploitation floor: a record assessed as exploited is floored at 50
    and must not be labelled below medium.

    **Confirmed against a real publication on 2 November 2026** — 3,558 threats,
    model ``threatpulse_priority_v0.3``, scores spanning 7.74 to 97.0:

    ==========  ======      ==========  ======
    percentile  score       percentile  score
    ==========  ======      ==========  ======
    p50          60.47       p85          87.78
    p60          70.92       p90          88.60
    p70          78.98       p95          89.10
    p75          84.77       p97          90.05
    p80          86.53       p99          91.73
    ==========  ======      ==========  ======

    What that settled, and why nothing moved:

    * ``critical`` at 90 is the **97th percentile** — 126 records, 3.5% — which is
      the "top few per cent" the 85 → 90 move was made to produce. The old split put
      23% there; this one is a list a person can work through.
    * ``high`` at 75 is roughly the 66th percentile and labels 31% of the catalogue
      (3.5% critical + 27.5% high). That breadth is deliberate: it is a standing
      work queue, not a page, and raising the bar would not improve those records —
      only make them rarer.
    * **Do not fine-tune these against the curve.** Between 85 and 90 the
      distribution is a plateau: p85 is 87.78 and p90 is 88.60, so five per cent of
      the catalogue sits inside eight tenths of a point. A boundary placed anywhere
      in that range moves hundreds of records on rounding rather than on evidence.

    The published ``severity`` **is** this band — ``correlation/engine.py`` sets
    ``severity = priority_band(score)`` — so a boundary moved here also relabels the
    ``severity`` the API filters on, the badge on every record, and the
    critical/high/medium counts in the publication summary. Change it here and in
    ``frontend/src/lib/priority.ts`` together.
    """

    if score >= 90:
        return "critical"

    if score >= 75:
        return "high"

    if score >= 50:
        return "medium"

    if score >= 25:
        return "low"

    return "informational"


def score_record(
    record: dict[str, Any],
    reference_date: date | None = None,
) -> dict[str, Any]:

    factors = {
        "exploitation": exploitation_score(record),
        "recency": recency_score(record, reference_date),
        "urgency": urgency_score(record, reference_date),
        "ransomware": ransomware_score(record),
        "impact": impact_score(record),
        "forensic": forensic_score(record),
    }

    score = sum(
        factors[name] * WEIGHTS[name]
        for name in WEIGHTS
    )

    score = round(clamp(score), 2)

    added = parse_date(record["date_added"])

    if reference_date is None:
        reference_date = datetime.now(timezone.utc).date()

    age_days = max(0, (reference_date - added).days)

    due_date = parse_date(record["due_date"])
    days_to_due = (due_date - reference_date).days

    reasoning: list[str] = []

    if factors["exploitation"] >= 90:
        reasoning.append(
            "Listed in the CISA Known Exploited Vulnerabilities catalog."
        )

    if age_days <= 7:
        reasoning.append(
            f"Added to CISA KEV within the last {age_days} day(s)."
        )

    if days_to_due <= 0:
        reasoning.append(
            "CISA remediation deadline has been reached or passed."
        )
    elif days_to_due <= 7:
        reasoning.append(
            f"CISA remediation deadline is {days_to_due} day(s) away."
        )

    if factors["ransomware"] >= 90:
        reasoning.append(
            "CISA identifies known ransomware campaign use."
        )
    elif factors["ransomware"] == 50:
        reasoning.append(
            "Ransomware campaign use is currently unknown."
        )

    if factors["impact"] >= 95:
        reasoning.append(
            "Description indicates potential arbitrary code execution."
        )

    if factors["forensic"] >= 90:
        reasoning.append(
            "CISA indicates that forensic triage is required."
        )

    return {
        "priority_score": score,
        "priority_band": priority_band(score),
        "score_factors": factors,
        "score_weights": WEIGHTS.copy(),
        "reasoning": reasoning,
        "scoring_model": "threatpulse_priority_v0.1",
        "reference_date": reference_date.isoformat(),
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python3 scoring/priority.py <normalized-record.json>"
        )
        raise SystemExit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as file:
        record = json.load(file)

    result = score_record(record)

    print(json.dumps(result, indent=2))

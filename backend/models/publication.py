#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any


SCHEMA_VERSION = "1.0"


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def deterministic_uuid(namespace: str, value: str) -> str:
    digest = hashlib.sha256(
        f"{namespace}:{value}".encode("utf-8")
    ).hexdigest()

    return str(uuid.UUID(digest[:32]))


def confidence_from_record(
    record: dict[str, Any],
) -> tuple[float, str]:

    if (
        record.get("kev_listed") is True
        and record.get("exploited_in_wild") is True
    ):
        return 100.0, "high"

    if record.get("kev_listed") is True:
        return 95.0, "high"

    return 60.0, "medium"


def severity_from_band(priority_band: str) -> str:

    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "informational",
    }

    return mapping.get(priority_band, "medium")


def iso_midnight(date_string: str) -> str:
    return f"{date_string}T00:00:00Z"


def build_threat(
    record: dict[str, Any],
    score: dict[str, Any],
    collected_at: str,
) -> dict[str, Any]:

    cve_id = record["cve_id"]

    threat_uuid = deterministic_uuid(
        "threatpulse:cisa_kev",
        cve_id,
    )

    confidence_score, confidence_level = (
        confidence_from_record(record)
    )

    metadata = {
        "source_attribution": {
            "source_key": "cisa_kev",
            "source_name": (
                "CISA Known Exploited Vulnerabilities Catalog"
            ),
            "source_record_id": cve_id,
            "retrieved_at": collected_at,
        },
        "scoring_model": score["scoring_model"],
        "score_factors": score["score_factors"],
        "score_weights": score["score_weights"],
        "reasoning": score["reasoning"],
        "vendor": record.get("vendor"),
        "product": record.get("product"),
        "due_date": record.get("due_date"),
        "known_ransomware_campaign_use": record.get(
            "known_ransomware_campaign_use"
        ),
        "forensic_triage": record.get("forensic_triage"),
        "cwes": record.get("cwes", []),
        "cisa_notes": record.get("notes"),
    }

    return {
        "threat_uuid": threat_uuid,
        "external_id": cve_id,
        "title": record["vulnerability_name"],
        "threat_type": "vulnerability",
        "severity": severity_from_band(
            score["priority_band"]
        ),
        "priority_score": score["priority_score"],
        "confidence_score": confidence_score,
        "confidence_level": confidence_level,
        "exploitation_status": "confirmed",
        "first_seen": iso_midnight(
            record["date_added"]
        ),
        "last_seen": collected_at,
        "summary": record["description"],
        "recommended_action": record["required_action"],
        "source_keys": ["cisa_kev"],
        "metadata": metadata,
        "vulnerabilities": [
            {
                "cve_id": cve_id,
                "description": record["description"],
                "cvss_score": None,
                "cvss_vector": None,
                "severity": severity_from_band(
                    score["priority_band"]
                ),
                "kev_listed": True,
                "exploited_in_wild": True,
                "published_at": None,
                "modified_at": None,
                "vendor": record.get("vendor"),
                "product": record.get("product"),
            }
        ],
    }


def build_publication(
    records: list[dict[str, Any]],
    scores: list[dict[str, Any]],
    collected_at: str,
) -> dict[str, Any]:

    if len(records) != len(scores):
        raise ValueError(
            "Records and scores must contain the same "
            "number of items"
        )

    threats = []

    for record, score in zip(records, scores):
        threats.append(
            build_threat(
                record,
                score,
                collected_at,
            )
        )

    vulnerability_count = sum(
        len(threat["vulnerabilities"])
        for threat in threats
    )

    publication_uuid = str(uuid.uuid4())

    return {
        "schema_version": SCHEMA_VERSION,
        "publication_uuid": publication_uuid,
        "generated_at": collected_at,
        "summary": {
            "title": "ThreatPulse CISA KEV Intelligence",
            "description": (
                "ThreatPulse intelligence derived from the "
                "CISA Known Exploited Vulnerabilities Catalog."
            ),
            "threat_count": len(threats),
            "vulnerability_count": vulnerability_count,
        },
        "sources": [
            {
                "source_key": "cisa_kev",
                "name": (
                    "CISA Known Exploited "
                    "Vulnerabilities Catalog"
                ),
                "source_type": "advisory",
                "url": (
                    "https://www.cisa.gov/"
                    "known-exploited-vulnerabilities-catalog"
                ),
                "provider": "CISA",
                "reliability": "high",
            }
        ],
        "threats": threats,
    }


def write_publication(
    publication: dict[str, Any],
    path: str,
) -> None:

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            publication,
            file,
            indent=2,
            ensure_ascii=False,
        )

        file.write("\n")

"""Enrichment stage (interface + policy).

Enrichment adds context to intelligence objects **without changing their
identity** and **without weakening stronger exploitation evidence**.

The rule that matters most, from the development plan (Phase 4):

    NVD must not override stronger exploitation evidence such as CISA KEV.

Concretely: enrichment may fill in CVSS, CWE, affected products, descriptions,
references and dates; it may never downgrade ``exploitation_status``,
``confidence_score`` or the exploitation factor of the priority score. Those are
derived from the source that actually observed exploitation.

No enricher ships enabled by default. Adding one is a matter of implementing the
protocol and enabling it in ``config/settings.json``; the pipeline already calls
this stage, so no orchestrator change is needed. ``AttackEnricher`` (MITRE ATT&CK)
is registered and activates when the ``mitre_attack`` source is enabled.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass
from typing import Protocol

from lib.logging_setup import get_logger, log_event
from models.intelligence import Threat
from enrichment.attack import AttackEnricher

LOGGER = get_logger("enrichment")

PROTECTED_FIELDS = (
    "exploitation_status",
    "confidence_score",
    "confidence_level",
    "priority_score",
    "severity",
)


class Enricher(Protocol):
    """Adds context to a threat without changing its identity."""

    key: str

    def enabled(self, settings) -> bool:  # pragma: no cover - protocol
        ...

    def enrich(self, threats: list[Threat], settings) -> list[Threat]:  # pragma: no cover
        ...


@dataclass
class NvdEnricher:
    """Placeholder for the Phase 4 NVD enricher.

    Deliberately not implemented: the plan says not to implement every future
    collector in one pass, and an unverified enrichment is worse than none.
    """

    key = "nvd"

    def enabled(self, settings) -> bool:
        try:
            return settings.source("nvd").enabled
        except Exception:  # pragma: no cover - configuration guard
            return False

    def enrich(self, threats: list[Threat], settings) -> list[Threat]:
        log_event(
            LOGGER,
            logging.WARNING,
            "nvd enricher requested but not implemented; skipping",
            threats=len(threats),
        )
        return threats


REGISTERED_ENRICHERS: tuple[Enricher, ...] = (NvdEnricher(), AttackEnricher())


def run_enrichers(threats: list[Threat], *, settings) -> tuple[list[Threat], list[dict]]:
    """Runs every enabled enricher and reports what each did."""

    notes: list[dict] = []
    current = threats

    for enricher in REGISTERED_ENRICHERS:
        if not enricher.enabled(settings):
            notes.append({"enricher": enricher.key, "status": "disabled"})
            continue

        # A deep copy, not a reference. ``to_publication_dict`` hands back the live
        # ``metadata`` dict, so a shallow snapshot would share it with the threat
        # and any change made inside metadata would compare equal — leaving the
        # policy check and the change counter blind to it.
        before = {
            threat.threat_uuid: copy.deepcopy(threat.to_publication_dict())
            for threat in current
        }

        enriched = enricher.enrich(current, settings)

        changed = 0
        violations: list[str] = []

        for threat in enriched:
            original = before.get(threat.threat_uuid)

            if original is None:
                violations.append(f"unknown threat_uuid introduced: {threat.threat_uuid}")
                continue

            updated = threat.to_publication_dict()

            if updated != original:
                changed += 1

            for field in PROTECTED_FIELDS:
                if updated.get(field) != original.get(field):
                    violations.append(
                        f"{threat.threat_uuid}: protected field '{field}' changed"
                    )

        notes.append(
            {
                "enricher": enricher.key,
                "status": "ran",
                "changed": changed,
                "policy_violations": violations,
            }
        )

        current = enriched

    return current, notes

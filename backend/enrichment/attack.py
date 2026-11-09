"""MITRE ATT&CK enrichment — names and tactics for technique references.

The knowledge base is built by ``collectors/mitre_attack.py``; this stage spends it.
For every threat whose evidence references a technique identifier, or names an actor
that ATT&CK lists, a compact block is attached to the threat's metadata.

**ATT&CK is context, never proof of activity.** The development plan is explicit
about that, and the enrichment harness enforces it: ``PROTECTED_FIELDS`` stops this
stage from changing a threat's exploitation status, confidence or priority score,
and any attempt would be reported as a policy violation instead of published.

Two honest limits, both measured rather than assumed:

* Technique references come only from sources that **cite technique identifiers**.
  With the sources enabled today that is the CISA CSAF advisories and the CERT
  feeds, and coverage is thin. A source that speaks ATT&CK natively — a MISP feed
  carrying ``misp-galaxy:mitre-attack-pattern`` tags — is what changes this.
* Actor matching is a **name match** against ATT&CK software and group names and
  aliases, not an identification. The matched name is published beside the ATT&CK
  entry so the claim can be audited, and a name matching two objects yields both.

The route that works is the one through a malware family. ATT&CK does not map CVEs,
so a vulnerability cannot reach a technique; a family can. When a threat carries a
family name, ATT&CK's software vocabulary resolves it — "Cobalt Strike" to S0154,
"QakBot" to S0650 — with the techniques that software uses attached to it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from lib.logging_setup import get_logger, log_event
from models.intelligence import Threat
from normalization.attack import (
    INDEX_FILENAME,
    load_index,
    match_actors,
    resolve_techniques,
)
from normalization.capec import (
    INDEX_FILENAME as CAPEC_INDEX_FILENAME,
    load_index as load_capec_index,
    techniques_for_cwes,
)
from normalization.sigma import (
    INDEX_FILENAME as SIGMA_INDEX_FILENAME,
    detection_summary,
    load_index as load_sigma_index,
)
from normalization.galaxy import (
    INDEX_FILENAME as GALAXY_INDEX_FILENAME,
    extend_attack_index,
    load_index as load_galaxy_index,
)

LOGGER = get_logger("enrichment.attack")

#: Published beside the block so a consumer cannot mistake a name lookup for a
#: statement about an incident.
CONTEXT_NOTE = (
    "MITRE ATT&CK context. A technique or actor named here was referenced by the "
    "evidence, or matches a name ATT&CK lists; it is not evidence that the "
    "technique was used or the actor was involved."
)


def threat_cwes(threat: Threat) -> list[str]:
    """Every CWE the evidence declared for this threat.

    Read from the threat's own metadata and from each enrichment contribution's
    summary, because a weakness can arrive from Microsoft, Red Hat or CISA
    Vulnrichment and whichever supplied it records it under its own summary.
    """

    metadata = threat.metadata if isinstance(threat.metadata, dict) else {}

    found: set[str] = set()

    # The engine publishes ``cwes``; each enrichment summary uses ``cwe``. Both are
    # read, because reading only one of them silently drops every weakness supplied
    # by the other route — which is exactly how the first version of the CAPEC route
    # enriched one threat instead of seventy-one.
    for field in ("cwes", "cwe"):
        for value in metadata.get(field) or ():
            text = str(value).strip().upper()

            if text:
                found.add(text)

    for summary in (metadata.get("enrichment") or {}).values():
        if not isinstance(summary, dict):
            continue

        for value in summary.get("cwe") or ():
            text = str(value).strip().upper()

            if text:
                found.add(text)

    return sorted(found)


def build_context(
    threat: Threat,
    index: dict,
    capec_index: dict | None = None,
    sigma_index: dict | None = None,
) -> dict | None:
    """The ATT&CK block for one threat, or None when there is nothing to add."""

    metadata = threat.metadata if isinstance(threat.metadata, dict) else {}

    technique_ids = metadata.get("attack_technique_ids") or []
    actor_names = list(metadata.get("actor_names") or [])

    # A malware family is a name to resolve, exactly like an actor name.
    #
    # This is where ATT&CK finally reaches published intelligence. ATT&CK does not
    # map CVEs — only 18 of its 26,690 objects carry one — so a threat cannot reach
    # a technique through a vulnerability. It reaches one through its family:
    # "Cobalt Strike" resolves to S0154, "QakBot" to S0650, and software carries the
    # techniques it uses. The matched name is published beside the result, so the
    # claim stays auditable as a name match rather than an identification.
    family = metadata.get("malware_family")

    if isinstance(family, str) and family.strip():
        actor_names.append(family.strip())

    # The early exit is deliberately gone: a threat with no cited technique and no
    # actor name can still reach a technique through a CWE, which is the route that
    # carries the most threats today. The final check decides.
    techniques = resolve_techniques(index, technique_ids) if technique_ids else []
    actors = match_actors(index, actor_names) if actor_names else []

    # A matched family or actor brings the techniques ATT&CK records it as using.
    #
    # They are resolved the same way a cited identifier is, so a reader sees one
    # consistent list with names, tactics and URLs rather than a bare identifier
    # list attached to a software entry. The actor entries keep their own
    # ``techniques`` too, so it stays visible which technique arrived by which
    # route.
    if actors:
        cited = {entry.get("id") for entry in techniques}

        via_actors = sorted(
            {
                technique
                for actor in actors
                for technique in actor.get("techniques") or []
                if technique not in cited
            }
        )

        if via_actors:
            techniques = [*techniques, *resolve_techniques(index, via_actors)]

    # The weakness route: CWE -> CAPEC -> ATT&CK technique.
    #
    # ATT&CK maps no CWE, so this is the only way a weakness reaches a technique, and
    # it is the route that carries the most threats today. The CAPEC pattern that
    # carried each technique is published beside it, because a technique reached
    # through a weakness is a different claim from one the evidence cited directly and
    # a reader has to be able to tell which they are looking at.
    cwes = threat_cwes(threat)
    capec_routes: list[dict] = []

    if cwes and capec_index:
        via_capec, capec_routes = techniques_for_cwes(capec_index, cwes)

        cited = {entry.get("id") for entry in techniques}

        fresh = sorted(technique for technique in via_capec if technique not in cited)

        if fresh:
            techniques = [*techniques, *resolve_techniques(index, fresh)]

    if not techniques and not actors:
        return None

    # Detection coverage, attached to each technique.
    #
    # A technique named beside a threat says what an adversary does; a rule beside that
    # technique says what a defender can do about it, and whether anyone has written
    # one. It is a statement about the technique, never about this threat — the summary
    # carries that caveat itself.
    if sigma_index:
        annotated = []

        for entry in techniques:
            summary = detection_summary(sigma_index, entry.get("id"))

            annotated.append({**entry, "detection": summary} if summary else entry)

        techniques = annotated

    return {
        "note": CONTEXT_NOTE,
        "collection": index.get("collection"),
        "version": index.get("version"),
        "techniques": techniques,
        "actors": actors,
        "cwes": cwes,
        "capec_routes": capec_routes,
    }


@dataclass
class AttackEnricher:
    """Attaches ATT&CK names and tactics to threats that reference them."""

    key = "mitre_attack"

    def enabled(self, settings) -> bool:
        try:
            return settings.source("mitre_attack").enabled
        except Exception:  # pragma: no cover - configuration guard
            return False

    def enrich(self, threats: list[Threat], settings) -> list[Threat]:
        index = load_index(settings.data_directory / INDEX_FILENAME)

        if index is None:
            log_event(
                LOGGER,
                logging.WARNING,
                "no ATT&CK knowledge base on disk; skipping enrichment",
                path=str(settings.data_directory / INDEX_FILENAME),
            )
            return threats

        # The MISP Galaxy alias bridge is folded in here rather than baked into the
        # ATT&CK index, so ATT&CK's own vocabulary stays exactly what ATT&CK
        # published and the added aliases remain visible as additions. A missing
        # galaxy index is not an error: enrichment simply runs on ATT&CK's names.
        galaxy = load_galaxy_index(settings.data_directory / GALAXY_INDEX_FILENAME)
        index = extend_attack_index(index, galaxy)

        # The CAPEC index supplies the weakness route. Absent, enrichment simply runs
        # without it rather than failing.
        capec_index = load_capec_index(settings.data_directory / CAPEC_INDEX_FILENAME)

        # The Sigma index supplies detection coverage per technique. Absent, a
        # technique simply carries none.
        sigma_index = load_sigma_index(settings.data_directory / SIGMA_INDEX_FILENAME)

        enriched = 0
        techniques = 0
        actors = 0
        routes = 0
        detected = 0

        for threat in threats:
            block = build_context(threat, index, capec_index, sigma_index)

            if block is None:
                continue

            threat.metadata["attack"] = block
            enriched += 1
            techniques += len(block["techniques"])
            actors += len(block["actors"])
            routes += len(block.get("capec_routes") or [])
            detected += sum(
                1 for entry in block["techniques"] if entry.get("detection")
            )

        log_event(
            LOGGER,
            logging.INFO,
            "ATT&CK context attached",
            threats=len(threats),
            enriched=enriched,
            technique_references=techniques,
            actor_matches=actors,
            version=index.get("version"),
            galaxy_aliases=index.get("galaxy_aliases_added") or 0,
            capec_routes=routes,
            techniques_with_detection=detected,
        )

        return threats

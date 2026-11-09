"""Correlation: observations → evidence → intelligence objects.

Deterministic and many-to-many, keyed on the primary entity of each
observation. For CISA KEV the key is the CVE identifier, but the engine is not
CVE-specific: it groups by whichever primary entity an observation declares, so
URL/IP/domain/malware/software/actor keys can be added by future collectors
without changing this code.

One CVE does **not** automatically equal one threat. Several observations about
the same entity are merged into one intelligence object with all of their
evidence attached, and an entity observed by one source can later be enriched by
another without changing its identity.

Output ordering is deterministic (priority desc, then external id), so two runs
over the same input produce byte-identical threat arrays apart from timestamps.
"""

from __future__ import annotations

import logging

from lib.ids import IdentityAliasMap, threat_id
from lib.logging_setup import get_logger, log_event
from models.intelligence import Evidence, Threat, Vulnerability
from scoring.confidence import assess_group
from scoring.priority import (
    UnscoreableRecord,
    can_score,
    priority_band,
    score_record,
)
from scoring.universal import (
    SCORING_MODEL as UNIVERSAL_SCORING_MODEL,
    score_group,
)

LOGGER = get_logger("correlation.engine")

#: Namespace for CVE-keyed threat identity.
#:
#: A threat identifier must not depend on which source happened to win the
#: scoring contest. If it did, a CVE first published from non-KEV evidence would
#: get one identifier and a second one when it later entered CISA KEV — two rows
#: in the database for one vulnerability. The values already published for
#: KEV-listed CVEs are ``threatpulse:cisa_kev:<CVE>``, so that is the fixed
#: namespace for every CVE-keyed threat, whoever scores it.
CVE_THREAT_NAMESPACE = "cisa_kev"


PRIMARY_ENTITY_KINDS = ("cve", "url", "ip", "domain", "malware", "software", "actor")

EXPLOITATION_CONFIRMED = "confirmed"
EXPLOITATION_SUSPECTED = "suspected"
EXPLOITATION_UNKNOWN = "unknown"

#: Source ranking for choosing the observation a threat is scored and titled
#: from. Lower is more authoritative. Anything unlisted sorts after these.
SCORING_SOURCE_AUTHORITY = {"cisa_kev": 0}

DEFAULT_SOURCE_AUTHORITY = 100

#: Sources whose observation may supply *enrichment* to a threat that the primary
#: observation already defines: CVSS, CWE, SSVC decision points, vendor assessments.
#: Enrichment may only fill a gap. It never overrides the primary record and never
#: touches a protected field, so listing a source here cannot move a threat's score.
#:
#: Lower is more authoritative, and the order matters for the shared CVSS field:
#: CISA's assessment of a CVE outranks a vendor's, because a vendor score is
#: expressed in the context of that vendor's products.
ENRICHMENT_SOURCE_AUTHORITY = {
    "cisa_vulnrichment": 0,
    # A vendor assessing its own products. Microsoft's Security Update Guide ranks
    # above Red Hat's Security Data because it is the only source that states the
    # affected Microsoft products and the fixed build numbers, but below CISA,
    # because a vendor score is expressed in the context of that vendor's products.
    "msrc": 5,
    "redhat_security": 10,
    "osv_dev": 20,
    "circl_vulnerability_lookup": 30,
    "exploit_availability": 40,
}

DEFAULT_ENRICHMENT_AUTHORITY = 100


def select_primary(observations):
    """Chooses the observation a threat is scored, titled and dated from.

    Only a CISA KEV record carries the ``date_added`` and ``due_date`` fields the
    priority model reads. The first implementation simply took the
    alphabetically-first source key, which meant a CVE present in both KEV and a
    CERT advisory was scored from the advisory and aborted the run.

    Selection is deterministic: scoreable observations only, then source
    authority, then source key, then external id. Returns ``None`` when no
    observation can be scored, so the caller can report the group rather than
    invent a score for it.
    """

    scoreable = [
        observation
        for observation in observations
        if can_score(observation.payload)
    ]

    if not scoreable:
        return None

    return sorted(
        scoreable,
        key=lambda observation: (
            SCORING_SOURCE_AUTHORITY.get(
                observation.source_key, DEFAULT_SOURCE_AUTHORITY
            ),
            observation.source_key,
            observation.external_id,
        ),
    )[0]


def usable_field_count(payload) -> int:
    """How many fields a payload actually carries a value for."""

    if not isinstance(payload, dict):
        return 0

    return sum(
        1
        for value in payload.values()
        if value is not None and value != "" and value != [] and value != {}
    )


def select_universal_primary(observations):
    """The observation a group is titled, dated and described from when no
    observation carries the KEV fields.

    The fullest evidence wins, then source authority, then source key, then external
    id — deterministic, so the same evidence always produces the same record. The
    record's identity does not depend on this choice: the CVE is the group key and is
    passed to the builders explicitly, because an advisory can describe several CVEs
    while naming none of them in a way the pipeline can key on.
    """

    if not observations:
        return None

    return sorted(
        observations,
        key=lambda observation: (
            -usable_field_count(observation.payload),
            SCORING_SOURCE_AUTHORITY.get(
                observation.source_key, DEFAULT_SOURCE_AUTHORITY
            ),
            observation.source_key,
            observation.external_id,
        ),
    )[0]


def carries_enrichment(payload) -> bool:
    """Whether a payload offers enrichment worth attaching to a threat."""

    if not isinstance(payload, dict):
        return False

    for key in ("cvss", "ssvc", "enrichment_summary"):
        value = payload.get(key)

        if isinstance(value, dict) and value:
            return True

    return False


def select_enrichment(observations, primary):
    """Every observation that may enrich a threat, most authoritative first.

    Enrichment is strictly secondary. The primary observation defines the threat's
    identity, title, dates and score; these only ever *fill* fields the primary
    left empty, so a source that appears here cannot change an existing number.

    All of them are returned rather than just one, because the sources contribute
    different things: CISA supplies SSVC decision points and a CVSS, Red Hat
    supplies errata and a product-context severity, OSV supplies affected
    ecosystems, CIRCL supplies sightings. Picking a single winner would make every
    source but the highest-ranked one invisible.

    Ordering is deterministic — source authority, then source key, then external
    id — so the same evidence always produces the same publication.
    """

    candidates = [
        observation
        for observation in observations
        if observation is not primary
        and carries_enrichment(observation.payload)
    ]

    return sorted(
        candidates,
        key=lambda observation: (
            ENRICHMENT_SOURCE_AUTHORITY.get(
                observation.source_key, DEFAULT_ENRICHMENT_AUTHORITY
            ),
            observation.source_key,
            observation.external_id,
        ),
    )


def primary_key(observation):
    """Returns ``(kind, value)`` for the observation's first correlation key."""

    keys = primary_keys(observation)

    return keys[0] if keys else None


def primary_keys(observation):
    """Every correlation key this observation declares, deduplicated.

    Only the **highest-priority entity kind** is used, but *all* values of that
    kind are. An advisory naming five CVEs is evidence about all five of them,
    so it joins five groups.

    This mattered more than it looks: the first implementation returned a single
    key per observation, so an advisory listing several CVEs correlated with
    exactly one of them and silently discarded the rest. The Greek national
    authority's alert naming CVE-2026-109618 *and* CVE-2026-109619 contributed to
    one threat instead of two, and any advisory whose alphabetically-first CVE
    happened not to be in the exploited catalogue contributed to none.
    """

    for kind in PRIMARY_ENTITY_KINDS:
        keys: list[tuple[str, str]] = []
        seen: set[str] = set()

        for entity in observation.entities:
            if entity.kind != kind:
                continue

            value = entity.normalized or entity.value

            if not value or value in seen:
                continue

            seen.add(value)
            keys.append((kind, value))

        if keys:
            return keys

    return []


def group_observations(observations):
    """Groups observations by primary entity, preserving input order.

    An observation with no correlatable entity cannot join a group. That is
    normal — an advisory feed mentioning no CVE produces many such records — so
    they are counted and reported once, rather than logged one line each. A feed
    of a thousand items would otherwise bury the run in warnings.

    An observation joins **every** group for the highest-priority entity kind it
    declares, so an advisory naming several CVEs is attached to all of them
    rather than to whichever one happened to be listed first.
    """

    groups: dict[tuple[str, str], list] = {}
    uncorrelatable: dict[str, int] = {}

    for observation in observations:
        keys = primary_keys(observation)

        if not keys:
            uncorrelatable[observation.source_key] = (
                uncorrelatable.get(observation.source_key, 0) + 1
            )
            continue

        for key in keys:
            groups.setdefault(key, []).append(observation)

    if uncorrelatable:
        log_event(
            LOGGER,
            logging.INFO,
            "observations without a correlatable entity were skipped",
            count=sum(uncorrelatable.values()),
            by_source=dict(sorted(uncorrelatable.items())),
            note=(
                "These declare no CVE, so they cannot join a vulnerability "
                "threat. They remain collected and snapshotted, and are "
                "counted rather than published."
            ),
        )

    return groups


def exploitation_status_for(records) -> str:
    """Strongest exploitation status supported by the evidence."""

    for record in records:
        if (
            record.get("kev_listed") is True
            and record.get("exploited_in_wild") is True
        ):
            return EXPLOITATION_CONFIRMED

    for record in records:
        if record.get("exploited_in_wild") is True:
            return EXPLOITATION_CONFIRMED

    for record in records:
        if record.get("kev_listed") is True:
            return EXPLOITATION_SUSPECTED

    return EXPLOITATION_UNKNOWN


def build_evidence(observation) -> Evidence:
    """One provenance-carrying statement per observation."""

    payload = observation.payload

    statements = [f"{observation.source_key} reported this observation."]

    if payload.get("kev_listed") is True:
        statements.append(
            "Listed in the CISA Known Exploited Vulnerabilities catalog."
        )

    return Evidence(
        source_key=observation.source_key,
        source_record_id=observation.source_record_id,
        observed_at=observation.observed_at,
        relationship="reports",
        statement=" ".join(statements),
        confidence=1.0,
        attributes={
            "retrieved_at": observation.retrieved_at,
            "vendor": payload.get("vendor"),
            "product": payload.get("product"),
        },
    )


def resolve_cvss(record: dict, enrichments):
    """``(base_score, vector, source_key)`` for a published vulnerability.

    The primary record's own values win. An enrichment source may only fill a field
    the primary left empty, and among enrichment sources the first in authority
    order that supplies a base score wins — its vector travels with its score, so a
    published CVSS is never assembled from two different sources.

    The returned source key names whichever source actually supplied the score, so
    the published metadata can state where a CVSS number came from rather than
    implying the KEV catalogue provided it.
    """

    score = record.get("cvss_score")
    vector = record.get("cvss_vector")
    source: str | None = None

    if score is not None and vector is not None:
        return score, vector, None

    for payload in enrichments or ():
        cvss = payload.get("cvss") if isinstance(payload, dict) else None

        if not isinstance(cvss, dict):
            continue

        candidate_score = cvss.get("base_score")

        if not isinstance(candidate_score, (int, float)) or isinstance(
            candidate_score, bool
        ):
            continue

        if score is None:
            score = float(candidate_score)
            source = payload.get("source")

        if vector is None:
            candidate_vector = cvss.get("vector")

            if isinstance(candidate_vector, str) and candidate_vector:
                vector = candidate_vector

        break

    return score, vector, source


def build_vulnerability(
    record: dict,
    severity: str,
    *,
    cve_id: str,
    cvss_score: float | None = None,
    cvss_vector: str | None = None,
) -> Vulnerability:
    """The published vulnerability.

    ``cve_id`` is passed in rather than read from the record: not every source
    payload carries it. CISA CSAF identifies its own records by a tracking number
    and lists the CVEs it covers in ``cve_ids``, so an advisory can be the record a
    group is described from without naming the CVE at all.

    ``severity`` is always the priority band derived from the group's score, never
    the CVSS severity label: the band is what the product's own model decided, and
    it must not drift because a second source described the same CVE.
    """

    return Vulnerability(
        cve_id=cve_id,
        description=record.get("description"),
        cvss_score=(
            cvss_score if cvss_score is not None else record.get("cvss_score")
        ),
        cvss_vector=(
            cvss_vector if cvss_vector is not None else record.get("cvss_vector")
        ),
        severity=severity,
        kev_listed=record.get("kev_listed") is True,
        exploited_in_wild=record.get("exploited_in_wild") is True,
        published_at=record.get("published_at"),
        modified_at=record.get("modified_at"),
        vendor=record.get("vendor"),
        product=record.get("product"),
    )


def legacy_score_for(observations, reference_date) -> dict | None:
    """The v0.1 answer for a KEV-shaped group, published as an audit trail.

    ``threatpulse_priority_v0.1`` raises for anything that is not a KEV record, so
    this returns ``None`` for everything else rather than manufacturing a
    comparison. Only the numbers are kept: the factors, weights and reasoning of the
    legacy model are already documented in :mod:`scoring.priority` and would bloat
    every record that has them.
    """

    for observation in observations:
        if not can_score(observation.payload):
            continue

        try:
            score = score_record(
                observation.payload, reference_date=reference_date
            )
        except (UnscoreableRecord, KeyError, TypeError, ValueError):
            return None

        return {
            "scoring_model": score["scoring_model"],
            "priority_score": score["priority_score"],
            "priority_band": score["priority_band"],
        }

    return None


def build_threat(
    *,
    observations: list,
    cve_id: str,
    reference_date,
    aliases: IdentityAliasMap | None = None,
    source_names: dict[str, str] | None = None,
    first_seen: str | None = None,
) -> Threat:
    """Builds one intelligence object from every observation of an entity.

    ``cve_id`` is the group key. It is passed in rather than read from an
    observation because an observation can declare several CVEs — a national
    advisory naming two — so no single observation reliably names the group's
    subject, and a source's own record identifier is sometimes a tracking number
    (CISA CSAF publishes ``VA-26-216-01``) rather than the CVE.
    """

    ordered = sorted(
        observations, key=lambda item: (item.source_key, item.external_id)
    )

    # The observation the threat is titled, dated and attributed from: the most
    # authoritative one carrying KEV fields where there is one, otherwise the most
    # complete. Scoring no longer depends on this choice — the model reads the whole
    # group.
    primary = select_primary(ordered) or select_universal_primary(ordered)

    if primary is None:
        raise UnscoreableRecord(
            f"{ordered[0].external_id!r}: group carries no observation"
        )

    records = [observation.payload for observation in ordered]

    # Secondary evidence may fill a CVSS gap and contribute SSVC decision points,
    # but the score, severity and exploitation status below are read from the
    # primary observation alone.
    enrichments = select_enrichment(ordered, primary)
    enrichment_payloads = [observation.payload for observation in enrichments]

    score = score_group(
        ordered, reference_date=reference_date, first_seen=first_seen
    )

    severity = priority_band(score["priority_score"])

    confidence = assess_group(records)

    legacy_score = legacy_score_for(ordered, reference_date)

    cvss_score, cvss_vector, cvss_source = resolve_cvss(
        primary.payload, enrichment_payloads
    )

    external_id = cve_id

    published = aliases.get(external_id) if aliases else None

    metadata = {
        "source_attribution": {
            "source_key": primary.source_key,
            "source_name": (source_names or {}).get(
                primary.source_key, primary.source_key
            ),
            "source_record_id": primary.source_record_id,
            "retrieved_at": primary.retrieved_at,
        },
        "scoring_model": score["scoring_model"],
        "score_factors": score["score_factors"],
        "score_weights": score["score_weights"],
        "reasoning": score["reasoning"],
        "vendor": primary.payload.get("vendor"),
        "product": primary.payload.get("product"),
        "due_date": primary.payload.get("due_date"),
        "known_ransomware_campaign_use": primary.payload.get(
            "known_ransomware_campaign_use"
        ),
        "forensic_triage": primary.payload.get("forensic_triage"),
        "cwes": primary.payload.get("cwes", []),
        "cisa_notes": primary.payload.get("notes"),
        "priority_band": score["priority_band"],
        "reference_date": score["reference_date"],
        "observation_count": len(ordered),
        "evidence_source_keys": sorted(
            {observation.source_key for observation in ordered}
        ),
    }

    # The audit trail: what the KEV-derived model said about this record, so the
    # transition can be checked and reversed. Absent for records v0.1 cannot score.
    if legacy_score is not None:
        metadata["legacy_score"] = legacy_score

    # Only present when an enrichment source actually contributed, so a threat
    # without enrichment is published exactly as it was before this stage existed.
    for observation in enrichments:
        ssvc = observation.payload.get("ssvc")

        if isinstance(ssvc, dict) and ssvc:
            metadata["ssvc"] = ssvc
            metadata["ssvc_source"] = observation.source_key
            break

    # Each enrichment source keeps its own block, keyed by source, so a consumer
    # can see what every source said rather than only the one that won a shared
    # field. Provenance is the product's whole point.
    contributions = {
        observation.source_key: observation.payload["enrichment_summary"]
        for observation in enrichments
        if isinstance(observation.payload.get("enrichment_summary"), dict)
        and observation.payload["enrichment_summary"]
    }

    if contributions:
        metadata["enrichment"] = contributions

    if cvss_source:
        metadata["cvss_source"] = cvss_source

    # Technique identifiers and actor names the evidence names. Published so that a
    # consumer — and the ATT&CK enricher — can see what the evidence referenced.
    # These are references, not proof of activity, and they never set exploitation
    # status.
    technique_ids = sorted(
        {
            (entity.normalized or entity.value).upper()
            for observation in ordered
            for entity in observation.entities
            if entity.kind == "technique" and (entity.normalized or entity.value)
        }
    )

    if technique_ids:
        metadata["attack_technique_ids"] = technique_ids

    actor_names = sorted(
        {
            (entity.value or entity.normalized)
            for observation in ordered
            for entity in observation.entities
            if entity.kind == "actor" and (entity.value or entity.normalized)
        }
    )

    if actor_names:
        metadata["actor_names"] = actor_names

    return Threat(
        threat_uuid=published or threat_id(CVE_THREAT_NAMESPACE, external_id),
        external_id=external_id,
        title=primary.payload.get("vulnerability_name")
        or primary.payload.get("title")
        or f"Vulnerability {external_id}",
        threat_type="vulnerability",
        severity=severity,
        priority_score=score["priority_score"],
        confidence_score=confidence.score,
        confidence_level=confidence.level,
        exploitation_status=exploitation_status_for(records),
        first_seen=(
            f"{primary.payload['date_added']}T00:00:00Z"
            if primary.payload.get("date_added")
            else primary.payload.get("published_at")
        ),
        last_seen=primary.retrieved_at,
        summary=primary.payload.get("description"),
        recommended_action=primary.payload.get("required_action"),
        metadata=metadata,
        source_keys=sorted({observation.source_key for observation in ordered}),
        vulnerabilities=[
            build_vulnerability(
                primary.payload,
                severity,
                cve_id=cve_id,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
            )
        ],
        evidence=[build_evidence(observation) for observation in ordered],
    )



def correlate(
    observations,
    *,
    reference_date,
    aliases: IdentityAliasMap | None = None,
    source_names: dict[str, str] | None = None,
    first_seen: dict[str, str] | None = None,
    stats: dict | None = None,
) -> list[Threat]:
    """Turns observations into a deterministically ordered threat list.

    Every published object comes out of a CVE group and is scored by a single model
    (``threatpulse_priority_v0.3``) from whatever evidence the group holds. The
    KEV-derived model (``threatpulse_priority_v0.1``) still runs for KEV-shaped
    records and its answer is published beside the new one as
    ``metadata.legacy_score``, so the transition can be audited record by record. A
    group the model will not score is counted and reported rather than scored from
    defaults: publishing an invented number is worse than publishing nothing.

    ``first_seen`` maps CVE identifiers to the timestamp of the first run that
    observed them. It is the only date the pipeline owns rather than borrows, so it
    is the only recency signal with total coverage.

    Groups keyed on something else entirely (an actor, say) are still counted and
    reported, and still never scored from defaults.

    When ``stats`` is supplied it is filled with the counts, so a run report can
    show how much collected evidence is waiting to be correlated.
    """

    observation_list = list(observations)
    groups = group_observations(observation_list)

    threats: list[Threat] = []
    non_cve_groups = 0
    unscoreable_groups = 0

    for key, group in sorted(groups.items()):
        kind = key[0]

        if kind != "cve":
            non_cve_groups += 1
            continue

        try:
            threats.append(
                build_threat(
                    observations=group,
                    cve_id=key[1].upper(),
                    reference_date=reference_date,
                    aliases=aliases,
                    source_names=source_names,
                    first_seen=(first_seen or {}).get(key[1].upper()),
                )
            )
        except UnscoreableRecord:
            unscoreable_groups += 1

    threats.sort(
        key=lambda threat: (-threat.priority_score, threat.external_id or "")
    )

    summary = {
        "observations": len(observation_list),
        "groups": len(groups),
        "threats": len(threats),
        "multi_observation_groups": sum(
            1 for group in groups.values() if len(group) > 1
        ),
        "groups_keyed_on_a_non_cve_entity": non_cve_groups,
        "cve_groups_without_scoreable_evidence": unscoreable_groups,
        "threats_scored_by_model": sum(
            1
            for threat in threats
            if threat.metadata.get("scoring_model") == UNIVERSAL_SCORING_MODEL
        ),
        "threats_with_legacy_score": sum(
            1 for threat in threats if threat.metadata.get("legacy_score")
        ),
    }

    log_event(
        LOGGER,
        logging.INFO,
        "correlated observations into threats",
        **summary,
    )

    if stats is not None:
        stats.update(summary)

    return threats


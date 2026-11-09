"""The ThreatPulse priority model (``threatpulse_priority_v0.3``).

One model scores every vulnerability threat. Two did before: a model derived from
the CISA KEV catalogue (``threatpulse_priority_v0.1``) scored KEV-listed CVEs, and
a group without KEV evidence was dropped outright. Measured over one collection
run that dropped 1,776 of 3,542 CVE groups — half the correlated intelligence.

The split had a second cost, larger than the first. The KEV model reads
``date_added`` and ``due_date`` and nothing else about dates, and its ``impact``
factor is a regular expression over the description: it never reads CVSS. So the
1,766 most important records were scored without EPSS, without CVSS and without any
notion of how many sources agreed. This model reads all of them.

**Every factor is optional.** One the evidence does not support contributes nothing
and is not reported, so a thin record scores low rather than being filled in with a
default. ``score_factors`` names exactly what produced the number and
``score_weights`` holds only those weights, so a reader can see how thin the
evidence was instead of trusting the total.

=========================  ======  ==================================================
Factor                     Weight  Read from
=========================  ======  ==================================================
exploitation               0.28   KEV listing, reported exploitation, SSVC, CIRCL
                                  sightings, public exploit catalogues
epss                       0.20   EPSS percentile
impact                     0.18   CVSS base score, else a stated severity label
evidence                   0.10   how many independent sources corroborate
urgency                    0.08   a remediation deadline, else an available fix
ransomware                 0.06   the source's own ransomware determination
recency                    0.05   the newest date a source published
first_seen                 0.03   when ThreatPulse first observed the CVE
forensic                   0.02   the source's forensic-triage determination
=========================  ======  ==================================================

``first_seen`` is kept separate from ``recency`` deliberately. They answer different
questions — "how old is this publication" against "how new is this to us" — and a
CVE published years ago and collected today is old by one and new by the other.

``threatpulse_priority_v0.1`` still runs, for KEV-shaped records only, and its
answer is published beside this one as ``metadata.legacy_score``. That is the audit
trail: the transition can be checked record by record, and reversed, without
recomputing anything.

A group with too little evidence is refused rather than scored: fewer than two
independent sources raises :class:`InsufficientEvidence` — unless one of them is the
KEV catalogue, which is a corroborated determination in its own right.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone

from scoring.priority import (
    UnscoreableRecord,
    clamp,
    impact_score as described_impact_score,
    parse_date,
    priority_band,
)

SCORING_MODEL = "threatpulse_priority_v0.3"

#: The model this one replaces. Computed for KEV-shaped records so the transition
#: can be audited; never used for the published priority.
LEGACY_MODEL = "threatpulse_priority_v0.1"

#: Weights sum to 1.0 across every factor, and the score is their weighted sum over
#: the factors that are *present*. Missing evidence therefore lowers the score,
#: which is the right answer for priority, and a thin record cannot reach the top of
#: the scale by accident.
WEIGHTS = {
    "exploitation": 0.28,
    "epss": 0.20,
    "impact": 0.18,
    "evidence": 0.10,
    "urgency": 0.08,
    "ransomware": 0.06,
    "recency": 0.05,
    "first_seen": 0.03,
    "forensic": 0.02,
}


#: Corroboration floor. One source describing a CVE is a report; two independent
#: sources describing it is evidence.
MIN_INDEPENDENT_SOURCES = 2

#: At least one of these must be present, or the group is not scored at all. They
#: are the only factors that speak to urgency rather than merely to existence.
REQUIRED_ANY_OF = ("exploitation", "epss", "impact")

#: ``ssvc.exploitation`` as published by CISA Vulnrichment. These are the source's
#: own words, mapped to a priority contribution — not our inference from them.
SSVC_EXPLOITATION = {
    "active": 100.0,
    "poc": 70.0,
    "proof-of-concept": 70.0,
    "none": 0.0,
}

#: ``severity`` labels, when no numeric CVSS survived normalisation.
SEVERITY_SCORES = {
    "critical": 90.0,
    "high": 75.0,
    "medium": 55.0,
    "low": 30.0,
    "informational": 10.0,
}

#: Evidence-density ladder: independent sources to a 0–100 contribution.
DENSITY_SCORES = {1: 20.0, 2: 45.0, 3: 65.0, 4: 80.0, 5: 90.0}
DENSITY_MAX_SOURCES = 6

#: ``known_ransomware_campaign_use`` and ``forensic_triage`` as the KEV catalogue
#: states them. "Unknown" is a stated value, not a missing one, so it sits in the
#: middle rather than at zero — the same convention as the v0.1 model.
RANSOMWARE_SCORES = {"yes": 100.0, "no": 0.0, "unknown": 50.0}
FORENSIC_SCORES = {"yes": 100.0, "no": 0.0, "unknown": 50.0}

#: Days remaining before a remediation deadline, to a 0–100 contribution. Mirrors
#: ``scoring.priority.urgency_score`` so both models read a deadline the same way.
DEADLINE_LADDER = ((0, 100.0), (3, 90.0), (7, 75.0), (14, 60.0), (30, 40.0))
DEADLINE_FLOOR = 25.0

#: What a stated, published fix is worth when no deadline exists. Well below an
#: expired deadline: a remedy existing is not the same as someone being required to
#: apply it by a date.
AVAILABLE_FIX_SCORE = 55.0

#: An exploitation factor at or above this is a determination that the vulnerability
#: is being exploited, so the record is never published below ``EXPLOITATION_FLOOR``.
#: Without this, a KEV-listed CVE carrying nothing else — no EPSS, no CVSS, no
#: deadline — scored below an unremarkable record that happened to have a CVSS,
#: which is the wrong ordering for someone deciding what to act on tonight.
EXPLOITATION_FLOOR_TRIGGER = 90.0
EXPLOITATION_FLOOR = 50.0


class InsufficientEvidence(UnscoreableRecord):
    """The group holds too little evidence to be scored honestly.

    Subclasses :class:`~scoring.priority.UnscoreableRecord` so the correlation
    engine's existing handling — count the group and report it, never invent a
    score — applies unchanged.
    """


@dataclass(frozen=True)
class Factor:
    """One scored factor, with the evidence that produced it."""

    name: str
    value: float
    because: str


def number(value: object) -> float | None:
    """A finite float from a payload value, or ``None``.

    ``bool`` is excluded deliberately: ``True`` is not the number one, and letting
    it through would turn a flag into a measurement.
    """

    if isinstance(value, bool) or value is None:
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None

    return None


def independent_sources(observations) -> list[str]:
    """Distinct source keys in a group, sorted, so the count is deterministic."""

    return sorted(
        {
            observation.source_key
            for observation in observations
            if observation.source_key
        }
    )


def exploitation_factor(observations) -> Factor | None:
    """The strongest exploitation signal the evidence states, or ``None``.

    Every branch reads what a source published. ``ssvc.exploitation: none`` is a
    real assessment — "checked, not exploited" — so it contributes zero rather
    than being treated as absent.
    """

    best: Factor | None = None

    for observation in observations:
        payload = observation.payload or {}
        candidates: list[tuple[float, str]] = []

        if payload.get("kev_listed") is True:
            candidates.append(
                (100.0, "Listed in the CISA KEV catalogue.")
            )

        if payload.get("exploited_in_wild") is True:
            candidates.append(
                (100.0, "The source reports exploitation in the wild.")
            )

        ssvc = payload.get("ssvc")

        if isinstance(ssvc, dict):
            label = str(ssvc.get("exploitation") or "").strip().lower()

            if label in SSVC_EXPLOITATION:
                candidates.append(
                    (
                        SSVC_EXPLOITATION[label],
                        f"CISA Vulnrichment assesses exploitation as '{label}'.",
                    )
                )

        exploited = number(payload.get("exploited_sightings_sampled"))

        if exploited is not None and exploited > 0:
            candidates.append(
                (
                    95.0,
                    f"{int(exploited)} CIRCL sighting(s) assessed as exploitation.",
                )
            )
        else:
            sightings = number(payload.get("sighting_count"))

            if sightings is not None and sightings > 0:
                candidates.append(
                    (
                        40.0,
                        f"{int(sightings)} CIRCL sighting(s) recorded, none "
                        "assessed as exploitation.",
                    )
                )

        if observation.source_key == "exploit_availability":
            candidates.append(
                (70.0, "A public exploit is catalogued for this CVE.")
            )

        for value, because in candidates:
            if best is None or value > best.value:
                best = Factor("exploitation", value, because)

    return best


def epss_factor(observations) -> Factor | None:
    """EPSS percentile, as a 0–100 contribution.

    The percentile is used rather than the raw probability: EPSS probabilities are
    heavily skewed (most CVEs sit below 0.01), so on its own the probability would
    flatten every record to roughly the same number.
    """

    best: Factor | None = None

    for observation in observations:
        payload = observation.payload or {}
        percentile = number(payload.get("percentile"))

        if percentile is None or not 0.0 <= percentile <= 1.0:
            continue

        probability = number(payload.get("epss"))
        value = clamp(percentile * 100.0)

        because = f"EPSS percentile {percentile:.2f}"

        if probability is not None:
            because += f" (probability {probability:.5f})"

        because += "."

        if best is None or value > best.value:
            best = Factor("epss", value, because)

    return best


def described_impact(payload) -> float | None:
    """Impact read from the wording of the description, as the v0.1 model did.

    Only used when neither a CVSS nor a severity label exists, so nothing it infers
    can override a stated score. ``impact_score`` returns its 50-point floor when
    nothing in the text matches — that is how it says it found no evidence — so 50 is
    reported as absent rather than as a measurement.
    """

    parts = [payload.get("vulnerability_name"), payload.get("description")]
    text = " ".join(str(part) for part in parts if part).strip()

    if not text:
        return None

    value = described_impact_score(payload)

    return None if value == 50.0 else value


def impact_factor(observations) -> Factor | None:
    """Impact from CVSS, else a severity label, else the description's wording."""

    best: Factor | None = None

    for observation in observations:
        payload = observation.payload or {}
        cvss = number(payload.get("cvss_score"))

        if cvss is not None and 0.0 <= cvss <= 10.0:
            candidate = Factor(
                "impact", clamp(cvss * 10.0), f"CVSS base score {cvss:g}."
            )
        else:
            severity = str(payload.get("severity") or "").strip().lower()

            if severity in SEVERITY_SCORES:
                candidate = Factor(
                    "impact",
                    SEVERITY_SCORES[severity],
                    f"Severity reported as '{severity}'.",
                )
            else:
                described = described_impact(payload)

                if described is None:
                    continue

                candidate = Factor(
                    "impact",
                    clamp(described),
                    "The description names a technical consequence.",
                )

        if best is None or candidate.value > best.value:
            best = candidate

    return best


def evidence_factor(observations) -> Factor | None:
    """How many independent sources corroborate the vulnerability."""

    sources = independent_sources(observations)

    if not sources:
        return None

    value = DENSITY_SCORES.get(len(sources), 100.0)

    return Factor(
        "evidence",
        value,
        f"{len(sources)} independent source(s) corroborate this: "
        f"{', '.join(sources)}.",
    )


def states_a_fix(payload) -> bool:
    """Whether a payload states that a remedy exists.

    Read from what the source itself publishes — CSAF remediations, Ubuntu releases,
    MSRC build numbers, Red Hat errata. Nothing is inferred from silence.
    """

    if not isinstance(payload, dict):
        return False

    for key in ("remediations", "releases", "release_numbers", "advisories"):
        value = payload.get(key)

        if isinstance(value, (list, tuple, set)) and value:
            return True

    return False


def urgency_factor(observations, reference_date: date) -> Factor | None:
    """Deadline pressure: a remediation deadline, or failing that an available fix.

    A ``due_date`` is the strongest form — someone with authority has set a clock.
    Without one, a published fix is the next best proxy: the vendor has confirmed the
    vulnerability is real and shipped the remedy, so what remains is the reader's
    own patching. That is the source's statement, not an inference.
    """

    best: Factor | None = None

    for observation in observations:
        payload = observation.payload or {}
        due = day_of(payload.get("due_date"))

        if due is not None:
            days_remaining = (due - reference_date).days
            value = DEADLINE_FLOOR

            for limit, score in DEADLINE_LADDER:
                if days_remaining <= limit:
                    value = score
                    break

            because = (
                "Remediation deadline has passed."
                if days_remaining <= 0
                else f"Remediation deadline is {days_remaining} day(s) away."
            )

            if best is None or value > best.value:
                best = Factor("urgency", value, because)

            continue

        if states_a_fix(payload) and (
            best is None or AVAILABLE_FIX_SCORE > best.value
        ):
            best = Factor(
                "urgency",
                AVAILABLE_FIX_SCORE,
                "The source publishes a fix for this vulnerability.",
            )

    return best


def ransomware_factor(observations) -> Factor | None:
    """The source's own ransomware determination, when it makes one."""

    best: Factor | None = None

    for observation in observations:
        payload = observation.payload or {}
        stated = str(
            payload.get("known_ransomware_campaign_use") or ""
        ).strip().lower()

        if stated not in RANSOMWARE_SCORES:
            continue

        value = RANSOMWARE_SCORES[stated]

        if best is None or value > best.value:
            best = Factor(
                "ransomware",
                value,
                f"Ransomware campaign use is reported as '{stated}'.",
            )

    return best


def forensic_factor(observations) -> Factor | None:
    """The source's own forensic-triage determination, when it makes one."""

    best: Factor | None = None

    for observation in observations:
        payload = observation.payload or {}
        stated = str(payload.get("forensic_triage") or "").strip().lower()

        if stated not in FORENSIC_SCORES:
            continue

        value = FORENSIC_SCORES[stated]

        if best is None or value > best.value:
            best = Factor(
                "forensic",
                value,
                f"Forensic triage is reported as '{stated}'.",
            )

    return best


def kev_corroborated(observations) -> bool:
    """Whether the CISA KEV catalogue is among the evidence.

    KEV is a corroborated determination by a national authority, so a group that
    contains it does not need a second independent source to be scoreable. Without
    this the 1,766 KEV-only records would fail a two-source rule.
    """

    return any(
        isinstance(observation.payload, dict)
        and observation.payload.get("kev_listed") is True
        for observation in observations
    )


#: Age of the most recent publication date to a 0–100 contribution. Same ladder as
#: the v0.1 recency factor, so the two models agree on what "recent" means.
RECENCY_LADDER = ((7, 100.0), (14, 90.0), (30, 80.0), (60, 65.0), (90, 50.0), (180, 35.0))
RECENCY_FLOOR = 20.0


def day_of(value: object) -> date | None:
    """A ``YYYY-MM-DD`` date from a payload value, or ``None``."""

    if not isinstance(value, str) or len(value.strip()) < 10:
        return None

    try:
        return parse_date(value.strip()[:10])
    except ValueError:
        return None


def recency_factor(observations, reference_date: date) -> Factor | None:
    """How recent the newest publish or update date in the group is.

    ``score_date`` is deliberately excluded: that is the day EPSS scored the CVE,
    which is the same for every record in a run and says nothing about the
    vulnerability's age.
    """

    newest: date | None = None

    for observation in observations:
        payload = observation.payload or {}

        for field in ("published_at", "updated_at", "date_added"):
            moment = day_of(payload.get(field))

            if moment is not None and (newest is None or moment > newest):
                newest = moment

    if newest is None:
        return None

    age_days = max(0, (reference_date - newest).days)
    value = RECENCY_FLOOR

    for limit, score in RECENCY_LADDER:
        if age_days <= limit:
            value = score
            break

    return Factor(
        "recency",
        value,
        f"Most recent source date is {age_days} day(s) old.",
    )


def first_seen_factor(
    first_seen: str | None, reference_date: date
) -> Factor | None:
    """How long ago ThreatPulse first observed this CVE.

    The one date the pipeline owns rather than borrows, so its coverage is total.
    It answers "is this new to us?", which is what an operator acts on — not "how
    old is the publication", which is ``recency``.
    """

    moment = day_of(first_seen)

    if moment is None:
        return None

    age_days = max(0, (reference_date - moment).days)
    value = RECENCY_FLOOR

    for limit, score in RECENCY_LADDER:
        if age_days <= limit:
            value = score
            break

    return Factor(
        "first_seen",
        value,
        f"First observed by ThreatPulse {age_days} day(s) ago.",
    )


def score_group(
    observations,
    *,
    reference_date: date | None = None,
    first_seen: str | None = None,
) -> dict:
    """Scores one CVE group from the evidence it holds.

    Returns the same shape as :func:`scoring.priority.score_record`, so the
    publication does not need to know which model produced a record — except that
    ``scoring_model`` says so, and ``score_weights`` contains only the factors that
    were present.

    Raises :class:`InsufficientEvidence` rather than scoring a group on nothing.
    """

    group = list(observations)
    moment = reference_date or datetime.now(timezone.utc).date()

    factors = [
        factor
        for factor in (
            exploitation_factor(group),
            epss_factor(group),
            impact_factor(group),
            evidence_factor(group),
            urgency_factor(group, moment),
            ransomware_factor(group),
            recency_factor(group, moment),
            first_seen_factor(first_seen, moment),
            forensic_factor(group),
        )
        if factor is not None
    ]

    sources = independent_sources(group)

    if len(sources) < MIN_INDEPENDENT_SOURCES and not kev_corroborated(group):
        raise InsufficientEvidence(
            f"only {len(sources)} independent source(s); "
            f"{MIN_INDEPENDENT_SOURCES} required to corroborate a score"
        )

    if not any(factor.name in REQUIRED_ANY_OF for factor in factors):
        raise InsufficientEvidence(
            "no exploitation, EPSS or impact evidence to score from"
        )

    values = {factor.name: round(factor.value, 2) for factor in factors}
    weights = {name: WEIGHTS[name] for name in values}

    score = round(
        clamp(sum(values[name] * weights[name] for name in values)), 2
    )

    # A record assessed as exploited is never published lower than this, whatever
    # else the evidence is missing. See EXPLOITATION_FLOOR.
    floored = values.get("exploitation", 0.0) >= EXPLOITATION_FLOOR_TRIGGER

    if floored:
        score = round(max(score, EXPLOITATION_FLOOR), 2)

    reasoning = [factor.because for factor in factors]

    reasoning.append(
        f"Priority produced by {SCORING_MODEL}; only the factors present in the "
        "evidence contributed to it."
    )

    if floored and score == EXPLOITATION_FLOOR:
        reasoning.append(
            "Held at the exploitation floor: this vulnerability is assessed as "
            "exploited, so it is not ranked below this band whatever else the "
            "evidence lacks."
        )

    return {
        "priority_score": score,
        "priority_band": priority_band(score),
        "score_factors": values,
        "score_weights": weights,
        "reasoning": reasoning,
        "scoring_model": SCORING_MODEL,
        "reference_date": moment.isoformat(),
    }



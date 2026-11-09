"""Guards around the scoring/correlation boundary.

The first live run failed with ``KeyError: 'date_added'`` because the
CISA-derived priority model was handed records that are not CISA KEV records —
an advisory, an EPSS score and a ransomware aggregate. These tests pin the fix:

* the model refuses a record it cannot honestly score, with a typed error;
* a threat is scored from a *scoreable* observation, never from whichever source
  happens to sort first alphabetically;
* groups that cannot be scored are reported, not invented.
"""

from __future__ import annotations

import sys
import unittest
from datetime import date
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from correlation.engine import correlate, select_primary  # noqa: E402
from models.intelligence import Entity, Observation  # noqa: E402
from scoring.priority import (  # noqa: E402
    UnscoreableRecord,
    can_score,
    score_record,
)

CVE = "CVE-2026-109619"
REFERENCE_DATE = date(2026, 10, 30)


def kev_payload(cve: str = CVE) -> dict:
    """A CISA KEV record, carrying every field the model reads."""

    return {
        "cve_id": cve,
        "vendor": "PHP Group",
        "product": "PHP",
        "vulnerability_name": "PHP Stale Internal Request-State Vulnerability",
        "date_added": "2026-10-26",
        "description": "Fixture summary",
        "required_action": "Apply mitigations.",
        "due_date": "2026-11-09",
        "known_ransomware_campaign_use": "Unknown",
        "forensic_triage": "No",
        "notes": None,
        "cwes": [],
        "source": "cisa_kev",
        "exploited_in_wild": True,
        "kev_listed": True,
    }


def epss_payload(cve: str = CVE) -> dict:
    return {
        "cve_id": cve,
        "epss": 0.99,
        "percentile": 1.0,
        "score_date": "2026-10-30",
        "source": "epss_first",
    }


def advisory_payload(cve: str = CVE) -> dict:
    return {
        "title": f"Advisory on {cve}",
        "summary": f"Exploitation of {cve} observed.",
        "link": "https://cert.europa.eu/publications/security-advisories/2026-019/",
        "published_at": "2026-10-28T10:00:00Z",
        "categories": ["Security Advisory"],
        "feed_url": "https://cert.europa.eu/publications/security-advisories-rss",
        "source": "cert_eu_advisories",
    }


def ransomware_payload() -> dict:
    return {
        "group": "lockbit",
        "country": "GR",
        "sector": "manufacturing",
        "attack_date": "2026-10-20",
        "victim_count": 2,
        "aggregate": True,
        "victim_identity_withheld": True,
        "source": "ransomware_live",
    }


def observation(source_key: str, payload: dict, entities: list) -> Observation:
    external_id = payload.get("cve_id") or payload.get("link") or "record"

    return Observation(
        source_key=source_key,
        external_id=external_id,
        observed_at="2026-10-30T00:00:00Z",
        retrieved_at="2026-10-31T00:00:00Z",
        source_record_id=external_id,
        payload=payload,
        entities=entities,
    )


def cve_entities(cve: str = CVE) -> list:
    return [Entity(kind="cve", value=cve, normalized=cve)]


def actor_entities() -> list:
    return [
        Entity(kind="country", value="GR", normalized="GR"),
        Entity(kind="actor", value="lockbit", normalized="lockbit"),
        Entity(kind="sector", value="manufacturing", normalized="manufacturing"),
    ]


class ScoreableRecordTests(unittest.TestCase):
    def test_a_kev_record_is_scoreable(self) -> None:
        self.assertTrue(can_score(kev_payload()))

    def test_non_kev_records_are_not_scoreable(self) -> None:
        for name, payload in (
            ("epss", epss_payload()),
            ("advisory", advisory_payload()),
            ("ransomware", ransomware_payload()),
        ):
            self.assertFalse(can_score(payload), name)

    def test_scoring_a_non_kev_record_raises_a_typed_error(self) -> None:
        with self.assertRaises(UnscoreableRecord):
            score_record(advisory_payload(), reference_date=REFERENCE_DATE)

    def test_the_error_names_the_missing_field(self) -> None:
        with self.assertRaises(UnscoreableRecord) as context:
            score_record(epss_payload(), reference_date=REFERENCE_DATE)

        self.assertIn("date_added", str(context.exception))

    def test_a_missing_container_is_not_scoreable(self) -> None:
        self.assertFalse(can_score(None))
        self.assertFalse(can_score([]))


class PrimarySelectionTests(unittest.TestCase):
    def test_prefers_a_scoreable_observation(self) -> None:
        advisory = observation("cert_eu_advisories", advisory_payload(), cve_entities())
        kev = observation("cisa_kev", kev_payload(), cve_entities())

        # "cert_eu_advisories" sorts before "cisa_kev" — exactly the ordering that
        # aborted the first live run.
        ordered = sorted(
            [advisory, kev], key=lambda item: (item.source_key, item.external_id)
        )

        selected = select_primary(ordered)

        self.assertIsNotNone(selected)
        self.assertEqual(selected.source_key, "cisa_kev")

    def test_returns_none_when_nothing_is_scoreable(self) -> None:
        epss = observation("epss_first", epss_payload(), cve_entities())

        self.assertIsNone(select_primary([epss]))

    def test_kev_outranks_another_scoreable_source(self) -> None:
        other = observation("aaa_other_source", kev_payload(), cve_entities())
        kev = observation("cisa_kev", kev_payload(), cve_entities())

        ordered = sorted(
            [other, kev], key=lambda item: (item.source_key, item.external_id)
        )

        self.assertEqual(select_primary(ordered).source_key, "cisa_kev")


class CorrelationGuardTests(unittest.TestCase):
    def test_a_kev_only_group_publishes_both_scores(self) -> None:
        """The published score is the current model's. The KEV model's answer is
        published beside it, so the change can be audited against what the API
        used to return for the same record."""

        kev = observation("cisa_kev", kev_payload(), cve_entities())

        threats = correlate([kev], reference_date=REFERENCE_DATE)

        self.assertEqual(len(threats), 1)
        self.assertEqual(
            threats[0].metadata["legacy_score"]["priority_score"],
            score_record(kev_payload(), reference_date=REFERENCE_DATE)[
                "priority_score"
            ],
        )
        self.assertEqual(
            threats[0].metadata["scoring_model"], "threatpulse_priority_v0.3"
        )

    def test_kev_plus_advisory_scores_from_kev(self) -> None:
        """The exact regression: an advisory must never become the primary, so the
        KEV record still supplies the exploitation determination."""

        kev = observation("cisa_kev", kev_payload(), cve_entities())
        advisory = observation("cert_eu_advisories", advisory_payload(), cve_entities())

        threats = correlate([advisory, kev], reference_date=REFERENCE_DATE)

        self.assertEqual(len(threats), 1)
        self.assertEqual(
            threats[0].metadata["legacy_score"]["priority_score"],
            score_record(kev_payload(), reference_date=REFERENCE_DATE)[
                "priority_score"
            ],
        )
        self.assertEqual(
            threats[0].metadata["score_factors"]["exploitation"], 100.0
        )
        self.assertEqual(
            threats[0].metadata["source_attribution"]["source_key"], "cisa_kev"
        )
        self.assertIn("cert_eu_advisories", threats[0].source_keys)

    def test_epss_evidence_joins_a_kev_threat(self) -> None:
        kev = observation("cisa_kev", kev_payload(), cve_entities())
        epss = observation("epss_first", epss_payload(), cve_entities())

        threats = correlate([kev, epss], reference_date=REFERENCE_DATE)

        self.assertEqual(len(threats), 1)
        self.assertIn("epss_first", threats[0].source_keys)

    def test_a_cve_group_without_scoreable_evidence_is_reported(self) -> None:
        epss = observation("epss_first", epss_payload(), cve_entities())
        stats: dict = {}

        threats = correlate([epss], reference_date=REFERENCE_DATE, stats=stats)

        self.assertEqual(threats, [])
        self.assertEqual(stats["cve_groups_without_scoreable_evidence"], 1)
        self.assertEqual(stats["threats"], 0)

    def test_an_actor_group_is_not_a_threat(self) -> None:
        """Ransomware aggregates are regional evidence, not KEV-scored threats."""

        victim = observation("ransomware_live", ransomware_payload(), actor_entities())
        stats: dict = {}

        threats = correlate([victim], reference_date=REFERENCE_DATE, stats=stats)

        self.assertEqual(threats, [])
        self.assertEqual(stats["groups_keyed_on_a_non_cve_entity"], 1)

    def test_an_uncorrelatable_observation_is_counted_not_scored(self) -> None:
        bare = observation("ncsa_greece", {"title": "No CVE here"}, [])
        stats: dict = {}

        threats = correlate([bare], reference_date=REFERENCE_DATE, stats=stats)

        self.assertEqual(threats, [])
        self.assertEqual(stats["observations"], 1)

    def test_the_first_run_mix_no_longer_aborts(self) -> None:
        """The shape of the failing run: KEV + EPSS + advisories + ransomware."""

        observations = [
            observation("cisa_kev", kev_payload(), cve_entities()),
            observation("epss_first", epss_payload(), cve_entities()),
            observation("cert_eu_advisories", advisory_payload(), cve_entities()),
            observation(
                "cert_eu_advisories", {"title": "advisory", "link": "https://x/1"}, []
            ),
            observation("ransomware_live", ransomware_payload(), actor_entities()),
        ]
        stats: dict = {}

        threats = correlate(observations, reference_date=REFERENCE_DATE, stats=stats)

        self.assertEqual(len(threats), 1)
        self.assertEqual(stats["threats"], 1)
        self.assertEqual(stats["groups_keyed_on_a_non_cve_entity"], 1)
        self.assertGreaterEqual(stats["multi_observation_groups"], 1)


class MultiEntityCorrelationTests(unittest.TestCase):
    """An advisory naming several CVEs is evidence about all of them.

    The first implementation correlated an observation with a single group, so the
    Greek national authority's alert naming two CVEs contributed to one threat
    instead of two — and any advisory whose first-listed CVE happened to be absent
    from the exploited catalogue contributed to none at all.
    """

    def test_an_observation_joins_every_cve_group_it_declares(self) -> None:
        multi = observation(
            "ncsa_greece",
            {"title": "Critical PHP vulnerabilities", "link": "https://cyber.gov.gr/x"},
            cve_entities("CVE-2026-109618") + cve_entities("CVE-2026-109619"),
        )

        first = observation(
            "cisa_kev",
            kev_payload("CVE-2026-109618"),
            cve_entities("CVE-2026-109618"),
        )
        second = observation(
            "cisa_kev",
            kev_payload("CVE-2026-109619"),
            cve_entities("CVE-2026-109619"),
        )

        threats = correlate([multi, first, second], reference_date=REFERENCE_DATE)

        self.assertEqual(len(threats), 2)

        for threat in threats:
            self.assertIn("ncsa_greece", threat.source_keys)

    def test_an_observation_joins_only_the_highest_priority_kind(self) -> None:
        both = observation(
            "cert_eu_advisories",
            {"title": "advisory", "link": "https://example.invalid/1"},
            actor_entities() + cve_entities(),
        )
        kev = observation("cisa_kev", kev_payload(), cve_entities())

        threats = correlate([both, kev], reference_date=REFERENCE_DATE)

        self.assertEqual(len(threats), 1)
        self.assertIn("cert_eu_advisories", threats[0].source_keys)

    def test_a_duplicated_entity_value_joins_a_group_once(self) -> None:
        duplicated = observation(
            "cert_eu_advisories",
            {"title": "advisory", "link": "https://example.invalid/2"},
            cve_entities() + cve_entities(),
        )
        kev = observation("cisa_kev", kev_payload(), cve_entities())

        threats = correlate([duplicated, kev], reference_date=REFERENCE_DATE)

        self.assertEqual(len(threats), 1)
        self.assertEqual(len(threats[0].evidence), 2)



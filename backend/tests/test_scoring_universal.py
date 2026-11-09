"""The universal priority model: what it scores, and what it refuses to score.

The v0.1 model is KEV-derived and stays exactly as it is — every score already
published for a KEV-listed CVE must not move. These tests cover the second tier:
the groups that carry no KEV fields, which were previously counted and dropped.

Two properties matter more than any single number:

* **nothing is invented.** A factor is either present in the evidence or it is not
  reported at all, and a group without enough evidence is refused rather than
  scored from defaults.
* **identity does not depend on the model.** A CVE must keep one identifier
  whether it is first published from KEV evidence or from four enrichment
  sources, otherwise a later KEV listing would create a second row for the same
  vulnerability.
"""

from __future__ import annotations

import sys
import unittest
from datetime import date
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from correlation.engine import (  # noqa: E402
    CVE_THREAT_NAMESPACE,
    correlate,
)
import lib.ids as ids  # noqa: E402
from models.intelligence import Entity, Observation  # noqa: E402
from scoring import universal  # noqa: E402
from scoring.priority import UnscoreableRecord  # noqa: E402

CVE = "CVE-2016-7951"
REFERENCE_DATE = date(2026, 11, 1)


def observation(
    source_key: str,
    payload: dict,
    cve: str = CVE,
    *,
    external_id: str | None = None,
) -> Observation:
    """One observation about ``cve``, with sane defaults for everything else."""

    record_id = external_id or payload.get("cve_id") or f"{source_key}-record"

    return Observation(
        source_key=source_key,
        external_id=record_id,
        observed_at="2026-10-30T00:00:00Z",
        retrieved_at="2026-10-31T00:00:00Z",
        source_record_id=record_id,
        payload=payload,
        entities=[Entity(kind="cve", value=cve, normalized=cve)],
    )


def epss(percentile: float = 0.84, probability: float = 0.02435) -> dict:
    return {
        "cve_id": CVE,
        "epss": probability,
        "percentile": percentile,
        "score_date": "2026-11-01",
        "source": "epss_first",
    }


def ubuntu() -> dict:
    return {
        "cve_id": CVE,
        "title": "libXtst vulnerabilities",
        "summary": "Several security issues were fixed in libXtst.",
        "notice_id": "USN-8939-1",
        "published_at": "2026-10-20T00:00:00Z",
        "source": "ubuntu_security",
    }


def vulnrichment(exploitation: str = "none", cvss: float = 9.8) -> dict:
    return {
        "cve_id": CVE,
        "ssvc": {"exploitation": exploitation, "automatable": "no"},
        "cvss_score": cvss,
        "vendor": "Keysight",
        "product": "IxChariot",
        "published_at": "2026-10-28T00:00:00Z",
        "source": "cisa_vulnrichment",
    }


def kev() -> dict:
    return {
        "cve_id": CVE,
        "vulnerability_name": "libXtst remote code execution",
        "date_added": "2026-10-26",
        "due_date": "2026-11-09",
        "description": "Fixture summary",
        "known_ransomware_campaign_use": "Unknown",
        "forensic_triage": "No",
        "exploited_in_wild": True,
        "kev_listed": True,
        "source": "cisa_kev",
    }


class UniversalScoringTests(unittest.TestCase):
    """The model itself: which factors it reports, and when it refuses."""

    def _score(self, observations):
        return universal.score_group(
            observations, reference_date=REFERENCE_DATE
        )

    def test_only_the_factors_present_are_reported(self) -> None:
        """EPSS, corroboration and a publish date are all this evidence holds —
        no CVSS and no exploitation signal, so neither is reported."""

        score = self._score(
            [
                observation("epss_first", epss()),
                observation("ubuntu_security", ubuntu()),
            ]
        )

        self.assertEqual(
            set(score["score_factors"]), {"epss", "evidence", "recency"}
        )
        self.assertEqual(
            set(score["score_weights"]), {"epss", "evidence", "recency"}
        )

    def test_absent_factors_contribute_nothing(self) -> None:
        """No CVSS and no exploitation signal, so the score cannot be lifted by
        a factor nobody measured."""

        score = self._score(
            [
                observation("epss_first", epss()),
                observation("ubuntu_security", ubuntu()),
            ]
        )

        self.assertNotIn("impact", score["score_factors"])
        self.assertLess(score["priority_score"], 50.0)

    def test_thin_evidence_does_not_reach_the_top_of_the_scale(self) -> None:
        """A 95th-percentile EPSS on its own is not an urgent vulnerability."""

        score = self._score(
            [
                observation("epss_first", epss(percentile=0.95)),
                observation("ubuntu_security", ubuntu()),
            ]
        )

        self.assertIn(score["priority_band"], {"informational", "low"})

    def test_exploitation_and_impact_lift_the_band(self) -> None:
        score = self._score(
            [
                observation("epss_first", epss(percentile=0.99)),
                observation("ubuntu_security", ubuntu()),
                observation("cisa_vulnrichment", vulnrichment("active", 9.8)),
                observation("cisa_csaf", {"title": "advisory", "cvss_score": 9.8}),
            ]
        )

        self.assertIn(score["priority_band"], {"high", "critical"})
        self.assertEqual(score["score_factors"]["exploitation"], 100.0)

    def test_ssvc_none_is_an_assessment_not_an_absence(self) -> None:
        """'Checked, not exploited' is evidence, and it contributes zero."""

        score = self._score(
            [
                observation("epss_first", epss()),
                observation("cisa_vulnrichment", vulnrichment("none")),
            ]
        )

        self.assertEqual(score["score_factors"]["exploitation"], 0.0)

    def test_one_source_is_refused(self) -> None:
        with self.assertRaises(universal.InsufficientEvidence):
            self._score([observation("epss_first", epss())])

    def test_no_urgency_evidence_is_refused(self) -> None:
        with self.assertRaises(universal.InsufficientEvidence):
            self._score(
                [
                    observation(
                        "cert_eu_advisories",
                        {"title": "advisory", "summary": "text"},
                    ),
                    observation(
                        "national_cert_feeds",
                        {"title": "another", "summary": "more"},
                    ),
                ]
            )

    def test_refusal_is_an_unscoreable_record(self) -> None:
        """The engine catches UnscoreableRecord, so the hierarchy carries the
        behaviour: a refused group is counted, not crashed on."""

        self.assertTrue(
            issubclass(universal.InsufficientEvidence, UnscoreableRecord)
        )

    def test_epss_uses_the_percentile_not_the_probability(self) -> None:
        score = self._score(
            [
                observation(
                    "epss_first", epss(percentile=0.90, probability=0.0004)
                ),
                observation("ubuntu_security", ubuntu()),
            ]
        )

        self.assertAlmostEqual(score["score_factors"]["epss"], 90.0, places=2)

    def test_a_boolean_is_not_a_measurement(self) -> None:
        self.assertIsNone(universal.number(True))
        self.assertIsNone(universal.number(False))

    def test_the_model_name_is_versioned(self) -> None:
        score = self._score(
            [
                observation("epss_first", epss()),
                observation("ubuntu_security", ubuntu()),
            ]
        )

        self.assertEqual(score["scoring_model"], "threatpulse_priority_v0.3")

    def test_reasoning_names_every_factor_and_the_model(self) -> None:
        score = self._score(
            [
                observation("epss_first", epss()),
                observation("ubuntu_security", ubuntu()),
            ]
        )

        joined = " ".join(score["reasoning"])

        self.assertIn("EPSS percentile", joined)
        self.assertIn("independent source", joined)
        self.assertIn("threatpulse_priority_v0.3", joined)


class CorrelationIntegrationTests(unittest.TestCase):
    """What the engine now publishes that it used to drop."""

    def _universal_group(self):
        return [
            observation("epss_first", epss()),
            observation("ubuntu_security", ubuntu()),
        ]

    def test_a_group_without_kev_evidence_is_published(self) -> None:
        stats: dict = {}

        threats = correlate(
            self._universal_group(), reference_date=REFERENCE_DATE, stats=stats
        )

        self.assertEqual(len(threats), 1)
        self.assertEqual(
            threats[0].metadata["scoring_model"], universal.SCORING_MODEL
        )
        self.assertEqual(stats["threats_scored_by_model"], 1)
        self.assertEqual(stats["cve_groups_without_scoreable_evidence"], 0)

    def test_a_kev_group_is_scored_by_the_same_model(self) -> None:
        """One model for every vulnerability, so the numbers are comparable."""

        stats: dict = {}

        threats = correlate(
            [observation("cisa_kev", kev())],
            reference_date=REFERENCE_DATE,
            stats=stats,
        )

        self.assertEqual(len(threats), 1)
        self.assertEqual(
            threats[0].metadata["scoring_model"], universal.SCORING_MODEL
        )
        self.assertEqual(stats["threats_with_legacy_score"], 1)

    def test_a_kev_record_publishes_the_legacy_score_beside_the_new_one(self) -> None:
        """The audit trail: what the KEV model said, so the transition can be
        checked record by record and reversed without recomputing anything."""

        threat = correlate(
            [observation("cisa_kev", kev())], reference_date=REFERENCE_DATE
        )[0]

        legacy = threat.metadata["legacy_score"]

        self.assertEqual(legacy["scoring_model"], universal.LEGACY_MODEL)
        self.assertIsInstance(legacy["priority_score"], float)
        self.assertIn(legacy["priority_band"], {"critical", "high"})

    def test_a_non_kev_record_carries_no_legacy_score(self) -> None:
        """The KEV model cannot score it, so no comparison is invented."""

        threat = correlate(
            self._universal_group(), reference_date=REFERENCE_DATE
        )[0]

        self.assertNotIn("legacy_score", threat.metadata)

    def test_a_kev_only_group_scores_from_one_source(self) -> None:
        """KEV is a corroborated determination in its own right, so the two-source
        corroboration rule must not exclude the 1,766 records that have only it."""

        threats = correlate(
            [observation("cisa_kev", kev())], reference_date=REFERENCE_DATE
        )

        self.assertEqual(len(threats), 1)
        self.assertIn("exploitation", threats[0].metadata["score_factors"])

    def test_identity_does_not_depend_on_the_model_that_scored_it(self) -> None:
        """The property that must never regress. A CVE first published from
        enrichment evidence, then added to KEV, must not change identifier —
        otherwise the database ends up with two threats for one vulnerability."""

        universal_threat = correlate(
            self._universal_group(), reference_date=REFERENCE_DATE
        )[0]

        kev_threat = correlate(
            [observation("cisa_kev", kev())], reference_date=REFERENCE_DATE
        )[0]

        self.assertEqual(universal_threat.threat_uuid, kev_threat.threat_uuid)

    def test_identity_reproduces_every_published_kev_identifier(self) -> None:
        """The namespace is a compatibility constant: changing it would change
        every threat identifier the API has ever published."""

        for cve_id, expected in ids.IDENTITY_VECTORS.items():
            self.assertEqual(
                ids.threat_id(CVE_THREAT_NAMESPACE, cve_id), expected, cve_id
            )

    def test_a_csaf_led_group_publishes_the_cve_not_the_tracking_id(self) -> None:
        """CISA CSAF identifies its own records by tracking id; the threat must
        still be identified by the CVE."""

        csaf = observation(
            "cisa_csaf",
            {
                "cve_id": CVE,
                "tracking_id": "VA-26-216-01",
                "title": "advisory",
                "cvss_score": 9.8,
            },
            external_id="VA-26-216-01",
        )

        threats = correlate(
            [csaf, observation("epss_first", epss())],
            reference_date=REFERENCE_DATE,
        )

        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0].external_id, CVE)

    def test_a_group_led_by_an_advisory_without_a_cve_field_still_publishes(self) -> None:
        """The crash this guards: CISA CSAF lists the CVEs it covers in ``cve_ids``
        and carries no ``cve_id`` at all, so when an advisory became the primary the
        vulnerability builder raised KeyError and the whole run died."""

        csaf = observation(
            "cisa_csaf",
            {
                "advisory": True,
                "cve_ids": [CVE, "CVE-2026-000002"],
                "tracking_id": "VA-26-216-01",
                "title": "IxChariot Endpoint buffer overflow",
                "summary": "Keysight IxChariot Endpoint before 9.5.102 is affected.",
                "vendor": "Keysight",
                "product": "IxChariot",
                "cvss_score": 9.8,
                "severity": "critical",
                "published_at": "2026-10-28T00:00:00Z",
                "updated_at": "2026-10-28T00:00:00Z",
                "remediations": ["Fixed in 9.5.102, released August 11, 2026."],
                "document_url": "https://example.invalid/advisory",
                "tlp_label": "WHITE",
            },
            external_id="VA-26-216-01",
        )

        threats = correlate(
            [csaf, observation("epss_first", epss())],
            reference_date=REFERENCE_DATE,
        )

        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0].vulnerabilities[0].cve_id, CVE)
        self.assertEqual(threats[0].external_id, CVE)

    def test_insufficient_evidence_is_reported_not_published(self) -> None:
        stats: dict = {}

        threats = correlate(
            [observation("epss_first", epss())],
            reference_date=REFERENCE_DATE,
            stats=stats,
        )

        self.assertEqual(threats, [])
        self.assertEqual(stats["cve_groups_without_scoreable_evidence"], 1)
        self.assertEqual(stats["threats_scored_by_model"], 0)

    def test_a_non_kev_record_never_claims_high_confidence(self) -> None:
        threats = correlate(
            [
                observation("epss_first", epss()),
                observation("ubuntu_security", ubuntu()),
                observation("cisa_vulnrichment", vulnrichment("active", 9.8)),
            ],
            reference_date=REFERENCE_DATE,
        )

        self.assertEqual(len(threats), 1)
        self.assertNotEqual(threats[0].confidence_level, "high")
        self.assertLess(threats[0].confidence_score, 85.0)

    def test_the_published_shape_does_not_fork(self) -> None:
        """A universal record must publish the same keys as a KEV one, so the
        API contract stays single-shaped."""

        universal_threat = correlate(
            self._universal_group(), reference_date=REFERENCE_DATE
        )[0]
        kev_threat = correlate(
            [observation("cisa_kev", kev())], reference_date=REFERENCE_DATE
        )[0]

        self.assertEqual(
            set(universal_threat.to_publication_dict()),
            set(kev_threat.to_publication_dict()),
        )


class FirstSeenRegistryTests(unittest.TestCase):
    """D: the one date the pipeline owns rather than borrows."""

    def _store(self):
        import tempfile

        from state.store import StateStore

        root = Path(tempfile.mkdtemp())

        return StateStore(root / "state", root / "data")

    def _registry(self):
        from state.cve_first_seen import CveFirstSeen

        registry = CveFirstSeen(self._store())
        registry.load()

        return registry

    def test_a_cve_is_recorded_once_and_never_moves(self) -> None:
        registry = self._registry()

        self.assertEqual(
            registry.observe(["CVE-2026-0001"], now="2026-10-01T00:00:00Z"), 1
        )
        self.assertEqual(
            registry.observe(["CVE-2026-0001"], now="2026-11-01T00:00:00Z"), 0
        )
        self.assertEqual(registry.date_for("CVE-2026-0001"), "2026-10-01")

    def test_identifiers_are_case_insensitive(self) -> None:
        registry = self._registry()

        registry.observe(["cve-2026-0001"], now="2026-10-01T00:00:00Z")

        self.assertEqual(registry.date_for("CVE-2026-0001"), "2026-10-01")

    def test_it_survives_a_round_trip(self) -> None:
        from state.cve_first_seen import CveFirstSeen

        state = self._store()

        first = CveFirstSeen(state)
        first.observe(["CVE-2026-0001"], now="2026-10-01T00:00:00Z")
        first.save()

        second = CveFirstSeen(state)
        second.load()

        self.assertEqual(second.date_for("CVE-2026-0001"), "2026-10-01")

    def test_an_empty_registry_is_not_an_error(self) -> None:
        registry = self._registry()

        self.assertEqual(registry.size, 0)
        self.assertIsNone(registry.date_for("CVE-2026-0001"))


class UnifiedFactorTests(unittest.TestCase):
    """B: the factors that only exist once the KEV requirement is lifted."""

    def _score(self, observations, first_seen=None):
        return universal.score_group(
            observations, reference_date=REFERENCE_DATE, first_seen=first_seen
        )

    def test_first_seen_is_its_own_factor(self) -> None:
        score = self._score(
            [
                observation("epss_first", epss()),
                observation("ubuntu_security", ubuntu()),
            ],
            first_seen="2026-10-31T00:00:00Z",
        )

        self.assertIn("first_seen", score["score_factors"])
        self.assertEqual(score["score_factors"]["first_seen"], 100.0)

    def test_first_seen_and_recency_are_different_signals(self) -> None:
        """A publication from 2019 collected today is old by one and new by the
        other, and conflating them would turn 'we just found this' into a claim
        about the vulnerability's age."""

        old = dict(ubuntu())
        old["published_at"] = "2019-01-01T00:00:00Z"

        score = self._score(
            [
                observation("epss_first", epss()),
                observation("ubuntu_security", old),
            ],
            first_seen="2026-10-31T00:00:00Z",
        )

        self.assertEqual(score["score_factors"]["first_seen"], 100.0)
        self.assertLess(score["score_factors"]["recency"], 50.0)

    def test_a_remediation_deadline_is_urgency(self) -> None:
        score = self._score(
            [
                observation("cisa_kev", kev()),
                observation("epss_first", epss()),
            ]
        )

        # kev() carries a deadline eight days out: the 14-day rung.
        self.assertEqual(score["score_factors"]["urgency"], 60.0)

    def test_an_available_fix_is_urgency_without_a_deadline(self) -> None:
        """The vendor confirming a vulnerability and shipping the remedy is the
        source's own statement, and the best urgency proxy available off-KEV."""

        payload = dict(ubuntu())
        payload["releases"] = ["jammy", "noble"]

        score = self._score(
            [
                observation("epss_first", epss()),
                observation("ubuntu_security", payload),
            ]
        )

        self.assertEqual(
            score["score_factors"]["urgency"], universal.AVAILABLE_FIX_SCORE
        )

    def test_ransomware_and_forensic_come_from_the_source(self) -> None:
        score = self._score(
            [
                observation("cisa_kev", kev()),
                observation("epss_first", epss()),
            ]
        )

        # kev() states ransomware "Unknown" and forensic triage "No".
        self.assertEqual(score["score_factors"]["ransomware"], 50.0)
        self.assertEqual(score["score_factors"]["forensic"], 0.0)

    def test_a_factor_nobody_stated_is_not_invented(self) -> None:
        score = self._score(
            [
                observation("epss_first", epss()),
                observation("ubuntu_security", ubuntu()),
            ]
        )

        self.assertNotIn("ransomware", score["score_factors"])
        self.assertNotIn("forensic", score["score_factors"])
        self.assertNotIn("urgency", score["score_factors"])
        self.assertNotIn("first_seen", score["score_factors"])


if __name__ == "__main__":
    unittest.main()




"""CIRCL MISP OSINT normalisation.

This source exists for one reason: it is the only feed the pipeline ingests that
cites ATT&CK technique identifiers, and without it the ATT&CK enrichment has nothing
to resolve against a vulnerability. These tests pin the tag format, the per-event TLP
handling and the entity that carries a technique to the correlation engine — all
three of which produced a bug that only a live run exposed.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from normalization import misp  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402


def tag(name: str) -> dict:
    return {"name": name}


def event(
    *,
    uuid: str = "8cc5335e-915b-4e16-837d-49143e6987b4",
    info: str = "Exploitation of a public-facing appliance",
    attributes: list[dict] | None = None,
    tags: list[dict] | None = None,
) -> dict:
    return {
        "Event": {
            "uuid": uuid,
            "info": info,
            "date": "2026-10-13",
            "published": True,
            "Tag": (
                tags
                if tags is not None
                else [
                    tag(
                        'misp-galaxy:mitre-attack-pattern="Exploit Public-Facing '
                        'Application - T1190"'
                    )
                ]
            ),
            "Attribute": attributes if attributes is not None else [],
        }
    }


class TechniqueTagTests(unittest.TestCase):
    def test_the_identifier_is_read_from_the_galaxy_tag(self) -> None:
        self.assertEqual(
            misp.techniques_from_tags(
                [tag('misp-galaxy:mitre-attack-pattern="Hooking - T1179"')]
            ),
            ["T1179"],
        )

    def test_a_sub_technique_identifier_survives(self) -> None:
        self.assertEqual(
            misp.techniques_from_tags(
                [
                    tag(
                        'misp-galaxy:mitre-attack-pattern="Command and Scripting '
                        'Interpreter - T1059.001"'
                    )
                ]
            ),
            ["T1059.001"],
        )

    def test_a_non_attack_tag_is_ignored(self) -> None:
        self.assertEqual(misp.techniques_from_tags([tag("tlp:white")]), [])

    def test_a_bare_string_tag_is_tolerated(self) -> None:
        """Tags arrive as objects from the feed, and a caller may hold them as plain
        strings. The galaxy form is what the feed uses, so that is what is asserted —
        a bare ``T1190`` is *not* read, because the feed does not emit that and
        accepting it would be permissiveness nothing has measured."""

        self.assertEqual(
            misp.techniques_from_tags(
                ['misp-galaxy:mitre-attack-pattern="Hooking - T1179"']
            ),
            ["T1179"],
        )

    def test_a_bare_identifier_is_not_read(self) -> None:
        self.assertEqual(misp.techniques_from_tags(["T1190"]), [])


class TlpMarkingTests(unittest.TestCase):
    def test_a_marking_is_normalised_for_the_gate(self) -> None:
        """The gate compares a marking against the source default. Handing it the raw
        ``tlp:white`` tag name rejected **every** event on the feed, which looked
        exactly like a feed with nothing in it."""

        self.assertEqual(misp.tlp_markings([tag("tlp:white")]), ["CLEAR"])

    def test_a_restrictive_marking_survives_normalisation(self) -> None:
        self.assertEqual(misp.tlp_markings([tag("tlp:green")]), ["GREEN"])

    def test_an_unrecognised_marking_becomes_the_sentinel(self) -> None:
        """So the gate refuses it rather than treating the event as unmarked."""

        self.assertEqual(misp.tlp_markings([tag("tlp:chartreuse")]), ["UNKNOWN"])

    def test_an_event_with_no_marking_returns_nothing(self) -> None:
        self.assertEqual(misp.tlp_markings([tag("misp-galaxy:tool")]), [])


class CandidateTests(unittest.TestCase):
    def test_the_manifest_key_is_lower_cased(self) -> None:
        """The manifest and the event files disagree on case, and the feed serves 404
        for the upper-case spelling — which reads as an event that was withdrawn."""

        candidates = misp.event_candidates(
            {"8CC5335E-915B-4E16-837D-49143E6987B4": {"info": "x"}}
        )

        self.assertEqual(candidates[0]["uuid"], "8cc5335e-915b-4e16-837d-49143e6987b4")

    def test_two_spellings_of_one_event_are_collapsed(self) -> None:
        candidates = misp.event_candidates(
            {
                "8CC5335E-915B-4E16-837D-49143E6987B4": {"info": "x"},
                "8cc5335e-915b-4e16-837d-49143e6987b4": {"info": "x"},
            }
        )

        self.assertEqual(len(candidates), 1)

    def test_the_order_is_deterministic(self) -> None:
        candidates = misp.event_candidates({"b": {"info": "b"}, "a": {"info": "a"}})

        self.assertEqual([item["uuid"] for item in candidates], ["a", "b"])

    def test_a_non_object_manifest_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            misp.event_candidates(["not", "a", "manifest"])


class ParseEventTests(unittest.TestCase):
    def test_a_vulnerability_attribute_yields_its_cve(self) -> None:
        parsed = misp.parse_event(
            event(attributes=[{"type": "vulnerability", "value": "CVE-2024-47575"}])
        )

        self.assertEqual(parsed["cves"], ["CVE-2024-47575"])

    def test_a_cve_in_free_text_is_still_found(self) -> None:
        """Missing one because it arrived as a comment rather than a vulnerability
        attribute would lose the link this source exists to provide."""

        parsed = misp.parse_event(
            event(attributes=[{"type": "comment", "value": "see CVE-2024-47575"}])
        )

        self.assertEqual(parsed["cves"], ["CVE-2024-47575"])

    def test_a_deleted_attribute_contributes_no_comment_text(self) -> None:
        parsed = misp.parse_event(
            event(
                attributes=[
                    {
                        "type": "ip-dst",
                        "value": "203.0.113.9",
                        "comment": "TLP:AMBER",
                        "deleted": True,
                    }
                ]
            )
        )

        self.assertEqual(parsed["comment_texts"], [])

    def test_a_live_attribute_contributes_its_comment_for_the_tlp_scan(self) -> None:
        """A marking hidden in an attribute comment is still a marking that would
        be published, so the comment text has to reach the TLP scan."""

        parsed = misp.parse_event(
            event(
                attributes=[
                    {"type": "ip-dst", "value": "203.0.113.9", "comment": "TLP:AMBER"}
                ]
            )
        )

        self.assertEqual(parsed["comment_texts"], ["TLP:AMBER"])

    def test_a_payload_without_an_event_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            misp.parse_event({"response": {"Attribute": []}})

    def test_an_event_without_a_uuid_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            misp.parse_event({"Event": {"info": "no uuid"}})


class ObservationTests(unittest.TestCase):
    def test_one_observation_per_cve(self) -> None:
        parsed = misp.parse_event(
            event(
                attributes=[
                    {"type": "vulnerability", "value": "CVE-2024-47575"},
                    {"type": "vulnerability", "value": "CVE-2025-55182"},
                ]
            )
        )

        observations = misp.build_observations(
            parsed, source_key="circl_misp_osint", retrieved_at="2026-11-01T00:00:00Z"
        )

        self.assertEqual(
            sorted(item.external_id for item in observations),
            ["CVE-2024-47575", "CVE-2025-55182"],
        )

    def test_the_technique_is_declared_as_an_entity(self) -> None:
        """The engine collects ``kind == "technique"`` entities, not payload fields.
        A payload field alone reaches the observation and never the threat."""

        parsed = misp.parse_event(
            event(attributes=[{"type": "vulnerability", "value": "CVE-2024-47575"}])
        )

        observation = misp.build_observations(
            parsed, source_key="circl_misp_osint", retrieved_at="2026-11-01T00:00:00Z"
        )[0]

        techniques = [
            entity.value for entity in observation.entities if entity.kind == "technique"
        ]

        self.assertEqual(techniques, ["T1190"])

    def test_an_event_naming_no_cve_produces_nothing(self) -> None:
        """It cannot be correlated to anything, so it is counted rather than forced
        into a group."""

        parsed = misp.parse_event(
            event(attributes=[{"type": "phone-number", "value": "1"}])
        )

        self.assertEqual(
            misp.build_observations(
                parsed,
                source_key="circl_misp_osint",
                retrieved_at="2026-11-01T00:00:00Z",
            ),
            [],
        )

    def test_the_scanned_text_covers_the_title_and_the_comments(self) -> None:
        parsed = misp.parse_event(
            event(
                info="Campaign report",
                attributes=[
                    {
                        "type": "ip-dst",
                        "value": "203.0.113.9",
                        "comment": "handling note",
                    }
                ],
            )
        )

        texts = misp.scan_texts(parsed)

        self.assertIn("Campaign report", texts)
        self.assertIn("handling note", texts)

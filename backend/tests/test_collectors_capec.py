"""CAPEC — the CWE-to-technique route.

The chain is ``CWE -> CAPEC -> ATT&CK technique``, and the second hop is not in
CAPEC: its 272 ATT&CK taxonomy mappings name the taxonomy and no technique, so the
only identifier-level link is ATT&CK's own reverse reference. These tests pin that
the cross-reference is resolved from the ATT&CK index, and that the index reports how
narrow the reach really is rather than implying it is broad.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from normalization import capec as capec_module  # noqa: E402
from normalization.attack import build_index as build_attack_index  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402

NS = "http://capec.mitre.org/capec-3"


def pattern(
    identifier: str,
    name: str,
    *,
    cwes: list[str] | None = None,
    likelihood: str | None = "High",
    severity: str | None = "High",
) -> str:
    weakness = "".join(f'<Related_Weakness CWE_ID="{cwe}"/>' for cwe in cwes or [])

    return f"""
    <Attack_Pattern ID="{identifier}" Name="{name}" Abstraction="Standard" Status="Draft">
      <Description>A description of {name}.</Description>
      <Likelihood_Of_Attack>{likelihood or ""}</Likelihood_Of_Attack>
      <Typical_Severity>{severity or ""}</Typical_Severity>
      <Related_Weaknesses>{weakness}</Related_Weaknesses>
    </Attack_Pattern>
    """


def catalogue(*patterns: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Attack_Pattern_Catalog xmlns="{NS}" Name="CAPEC" Version="3.9">'
        f"<Attack_Patterns>{''.join(patterns)}</Attack_Patterns>"
        "</Attack_Pattern_Catalog>"
    ).encode("utf-8")


def attack_bundle() -> dict:
    """An ATT&CK bundle whose technique references one CAPEC pattern."""

    return {
        "objects": [
            {
                "type": "x-mitre-collection",
                "name": "Enterprise ATT&CK",
                "x_mitre_version": "20.0",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Exploit Public-Facing Application",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1190"},
                    {"source_name": "capec", "external_id": "CAPEC-100"},
                ],
            },
        ]
    }


class ParseCatalogTests(unittest.TestCase):
    def test_a_pattern_is_parsed_with_its_cwes(self) -> None:
        parsed = capec_module.parse_catalog(
            catalogue(pattern("100", "Overflow", cwes=["20", "120"]))
        )

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["id"], "CAPEC-100")
        self.assertEqual(parsed[0]["name"], "Overflow")
        self.assertEqual(parsed[0]["cwes"], ["CWE-20", "CWE-120"])

    def test_the_url_points_at_the_pattern(self) -> None:
        parsed = capec_module.parse_catalog(catalogue(pattern("100", "x")))

        self.assertEqual(
            parsed[0]["url"], "https://capec.mitre.org/data/definitions/100.html"
        )

    def test_a_recognised_ordinal_is_kept_and_an_unknown_one_dropped(self) -> None:
        parsed = capec_module.parse_catalog(
            catalogue(
                pattern("100", "a", likelihood="Very High", severity="Totally Severe")
            )
        )

        self.assertEqual(parsed[0]["likelihood"], "very high")
        self.assertIsNone(parsed[0]["severity"])

    def test_a_pattern_without_cwes_still_parses(self) -> None:
        parsed = capec_module.parse_catalog(catalogue(pattern("100", "x")))

        self.assertEqual(parsed[0]["cwes"], [])

    def test_malformed_xml_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            capec_module.parse_catalog(b"<not-xml")

    def test_a_document_with_no_patterns_is_rejected(self) -> None:
        """No patterns means the wrong document, not an empty catalogue."""

        with self.assertRaises(NormalizationError):
            capec_module.parse_catalog(
                f'<Attack_Pattern_Catalog xmlns="{NS}"/>'.encode("utf-8")
            )

    def test_a_non_xml_payload_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            capec_module.parse_catalog({"not": "xml"})


class BuildIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.attack = build_attack_index(
            attack_bundle(), generated_at="2026-11-01T00:00:00Z"
        )
        self.index = capec_module.build_index(
            catalogue(
                pattern("100", "Overflow", cwes=["20", "120"]),
                pattern("200", "No Technique", cwes=["79"]),
            ),
            attack_index=self.attack,
            generated_at="2026-11-01T00:00:00Z",
        )

    def test_the_technique_hop_is_resolved_from_attck(self) -> None:
        self.assertEqual(self.index["entries"]["CAPEC-100"]["techniques"], ["T1190"])

    def test_a_pattern_attck_does_not_reference_carries_no_technique(self) -> None:
        self.assertEqual(self.index["entries"]["CAPEC-200"]["techniques"], [])

    def test_the_cwe_reverse_index_is_built(self) -> None:
        self.assertEqual(self.index["by_cwe"]["CWE-20"], ["CAPEC-100"])
        self.assertEqual(self.index["by_cwe"]["CWE-120"], ["CAPEC-100"])

    def test_only_the_reachable_cwes_are_listed(self) -> None:
        """The narrow reach is reported, not smoothed over.

        The list is sorted as text, so ``CWE-120`` precedes ``CWE-20``. It is an
        identifier list for lookup, not a ranking, and the order is deterministic.
        """

        self.assertEqual(self.index["reachable_cwes"], ["CWE-120", "CWE-20"])
        self.assertEqual(self.index["counts"]["reachable_cwes"], 2)
        self.assertEqual(self.index["counts"]["distinct_cwes"], 3)
        self.assertEqual(self.index["counts"]["reachable_techniques"], 1)

    def test_a_missing_attck_index_leaves_every_pattern_without_techniques(self) -> None:
        index = capec_module.build_index(
            catalogue(pattern("100", "x", cwes=["20"])), attack_index=None
        )

        self.assertEqual(index["entries"]["CAPEC-100"]["techniques"], [])
        self.assertEqual(index["counts"]["reachable_cwes"], 0)


class TechniquesForCwesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = capec_module.build_index(
            catalogue(pattern("100", "Overflow", cwes=["20"])),
            attack_index=build_attack_index(
                attack_bundle(), generated_at="2026-11-01T00:00:00Z"
            ),
        )

    def test_a_cwe_reaches_its_technique(self) -> None:
        techniques, routes = capec_module.techniques_for_cwes(self.index, ["CWE-20"])

        self.assertEqual(techniques, ["T1190"])
        self.assertEqual(routes[0]["capec_id"], "CAPEC-100")
        self.assertEqual(routes[0]["cwe"], "CWE-20")

    def test_the_route_names_the_pattern_that_carried_it(self) -> None:
        """A technique reached through a weakness is a different claim from one the
        evidence cited, so the route travels with it."""

        _, routes = capec_module.techniques_for_cwes(self.index, ["CWE-20"])

        self.assertEqual(routes[0]["capec_name"], "Overflow")
        self.assertEqual(
            routes[0]["capec_url"], "https://capec.mitre.org/data/definitions/100.html"
        )

    def test_case_is_ignored(self) -> None:
        techniques, _ = capec_module.techniques_for_cwes(self.index, ["cwe-20"])

        self.assertEqual(techniques, ["T1190"])

    def test_a_cwe_with_no_technique_yields_nothing(self) -> None:
        self.assertEqual(
            capec_module.techniques_for_cwes(self.index, ["CWE-9999"]), ([], [])
        )

    def test_a_missing_index_yields_nothing(self) -> None:
        self.assertEqual(capec_module.techniques_for_cwes(None, ["CWE-20"]), ([], []))

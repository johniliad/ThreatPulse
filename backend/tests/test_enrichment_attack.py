"""ATT&CK enrichment: CAPEC references, ``uses`` relationships, and families.

Three things are pinned here, all of which were built because ATT&CK cannot reach a
technique through a CVE:

* the CAPEC identifiers ATT&CK itself references, which are the *only* published
  CAPEC-to-ATT&CK link;
* the ``uses`` relationships that carry what software and groups actually do;
* the route from a malware family on a threat to the techniques that family uses —
  the path that finally puts ATT&CK on published intelligence.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from enrichment import attack as enrichment  # noqa: E402
from models.intelligence import Threat  # noqa: E402
from normalization import attack as normalisation  # noqa: E402
from normalization import capec as capec_module  # noqa: E402


def capec_pattern(identifier: str, name: str, *, cwes: list[str]) -> str:
    weakness = "".join(f'<Related_Weakness CWE_ID="{cwe}"/>' for cwe in cwes)

    return (
        f'<Attack_Pattern ID="{identifier}" Name="{name}" Abstraction="Standard" '
        f'Status="Draft"><Description>{name}.</Description>'
        f"<Related_Weaknesses>{weakness}</Related_Weaknesses></Attack_Pattern>"
    )


def capec_catalogue(*patterns: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Name="CAPEC">'
        f"<Attack_Patterns>{''.join(patterns)}</Attack_Patterns>"
        "</Attack_Pattern_Catalog>"
    ).encode("utf-8")


def cwe_threat(cwe: str | None) -> Threat:
    """A threat with no cited technique and no actor — only a weakness."""

    metadata: dict = {}

    if cwe:
        metadata["cwes"] = [cwe]

    return Threat(
        threat_uuid="99999999-2222-3333-4444-555555555555",
        external_id="CVE-2026-12345",
        title="A weakness",
        threat_type="vulnerability",
        severity="high",
        priority_score=60.0,
        confidence_score=70.0,
        confidence_level="high",
        exploitation_status="unknown",
        first_seen=None,
        last_seen=None,
        summary=None,
        recommended_action=None,
        metadata=metadata,
    )


def bundle() -> dict:
    """A minimal but structurally honest ATT&CK bundle."""

    return {
        "type": "bundle",
        "objects": [
            {
                "type": "x-mitre-collection",
                "name": "Enterprise ATT&CK",
                "x_mitre_version": "20.0",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Command and Scripting Interpreter",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059",
                        "url": "https://attack.mitre.org/techniques/T1059",
                    },
                    {
                        "source_name": "capec",
                        "external_id": "CAPEC-242",
                        "url": "https://capec.mitre.org/data/definitions/242.html",
                    },
                ],
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--1",
                "name": "Execution",
                "x_mitre_shortname": "execution",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "TA0002"}
                ],
            },
            {
                "type": "malware",
                "id": "malware--1",
                "name": "QakBot",
                "aliases": ["QBot", "Pinkslipbot"],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "S0650",
                        "url": "https://attack.mitre.org/software/S0650",
                    }
                ],
            },
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "malware--1",
                "target_ref": "attack-pattern--1",
            },
        ],
    }


def index() -> dict:
    return normalisation.build_index(bundle(), generated_at="2026-11-01T00:00:00Z")


def family_threat(family: str) -> Threat:
    return Threat(
        threat_uuid="11111111-2222-3333-4444-555555555555",
        external_id="CVE-2026-109619",
        title=f"{family} infrastructure",
        threat_type="vulnerability",
        severity="low",
        priority_score=40.0,
        confidence_score=65.0,
        confidence_level="medium",
        exploitation_status="unknown",
        first_seen=None,
        last_seen=None,
        summary=None,
        recommended_action=None,
        metadata={"malware_family": family},
    )


class CapecReferenceTests(unittest.TestCase):
    def test_the_capec_identifiers_are_kept(self) -> None:
        """The only published CAPEC-to-ATT&CK link, and it lives in ATT&CK's own
        bundle rather than in CAPEC's data."""

        built = index()

        self.assertEqual(built["techniques"]["T1059"]["capec"], ["CAPEC-242"])
        self.assertEqual(built["counts"]["techniques_with_capec"], 1)

    def test_a_technique_without_a_capec_reference_reports_none(self) -> None:
        self.assertEqual(normalisation.capec_ids({"external_references": []}), [])

    def test_a_non_capec_reference_is_ignored(self) -> None:
        self.assertEqual(
            normalisation.capec_ids(
                {
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1059"}
                    ]
                }
            ),
            [],
        )


class UsesRelationshipTests(unittest.TestCase):
    def test_software_carries_the_techniques_it_uses(self) -> None:
        """Without this a family can be named but its techniques cannot, and naming
        the family is only worth doing because the techniques follow."""

        self.assertEqual(index()["software"]["S0650"]["techniques"], ["T1059"])

    def test_a_relationship_to_a_non_technique_is_ignored(self) -> None:
        payload = bundle()
        payload["objects"][4]["target_ref"] = "malware--1"

        built = normalisation.build_index(payload, generated_at="2026-11-01T00:00:00Z")

        self.assertEqual(built["software"]["S0650"]["techniques"], [])

    def test_the_truncation_count_is_reported(self) -> None:
        """A bound that bites silently is worse than no bound at all."""

        self.assertEqual(index()["counts"]["objects_at_technique_cap"], 0)


class FamilyToTechniqueTests(unittest.TestCase):
    def test_a_family_matches_attck_software(self) -> None:
        matches = normalisation.match_actors(index(), ["QakBot"])

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["kind"], "software")
        self.assertEqual(matches[0]["id"], "S0650")
        self.assertEqual(matches[0]["techniques"], ["T1059"])

    def test_an_alias_matches_too(self) -> None:
        self.assertEqual(
            normalisation.match_actors(index(), ["QBot"])[0]["id"], "S0650"
        )

    def test_an_unmatched_family_produces_nothing(self) -> None:
        self.assertEqual(normalisation.match_actors(index(), ["NotARealFamily"]), [])

    def test_a_threat_carrying_a_family_reaches_its_techniques(self) -> None:
        """The whole point: a family on a threat resolves to software and then to
        the techniques that software uses."""

        block = enrichment.build_context(family_threat("QakBot"), index())

        self.assertIsNotNone(block)
        self.assertEqual(block["actors"][0]["id"], "S0650")
        self.assertEqual([entry["id"] for entry in block["techniques"]], ["T1059"])
        self.assertEqual(
            block["techniques"][0]["name"], "Command and Scripting Interpreter"
        )

    def test_a_threat_with_an_unmatched_family_is_not_enriched(self) -> None:
        self.assertIsNone(enrichment.build_context(family_threat("NotARealFamily"), index()))


class CapecRouteTests(unittest.TestCase):
    """The weakness route, which reaches a threat with no cited technique at all.

    A threat carrying only a CWE has no technique reference and no actor name, so an
    early return written for the cited-identifier case silently discarded it. The
    first version of this route did exactly that and enriched one threat instead of
    seventy-one; these tests exist because the family tests above could not catch it.
    """

    def setUp(self) -> None:
        self.index = index()
        # The pattern must be the one the ATT&CK fixture references (CAPEC-242), or the
        # second hop resolves to nothing and the test would pass for the wrong reason.
        self.capec = capec_module.build_index(
            capec_catalogue(
                capec_pattern("242", "Subverting Environment Variables", cwes=["20"])
            ),
            attack_index=self.index,
        )

    def test_a_threat_with_only_a_cwe_is_enriched(self) -> None:
        block = enrichment.build_context(
            cwe_threat("CWE-20"), self.index, self.capec
        )

        self.assertIsNotNone(block)
        self.assertEqual(block["cwes"], ["CWE-20"])
        self.assertEqual(len(block["capec_routes"]), 1)

    def test_the_route_names_the_capec_pattern(self) -> None:
        block = enrichment.build_context(
            cwe_threat("CWE-20"), self.index, self.capec
        )

        self.assertEqual(block["capec_routes"][0]["capec_id"], "CAPEC-242")
        self.assertEqual([entry["id"] for entry in block["techniques"]], ["T1059"])

    def test_a_threat_without_a_capec_index_still_uses_the_cited_route(self) -> None:
        self.assertIsNone(
            enrichment.build_context(cwe_threat("CWE-20"), self.index, None)
        )

    def test_a_cwe_the_catalogue_does_not_cover_is_not_enriched(self) -> None:
        self.assertIsNone(
            enrichment.build_context(cwe_threat("CWE-9999"), self.index, self.capec)
        )

    def test_the_cwes_are_read_from_an_enrichment_summary(self) -> None:
        """A weakness can arrive from Microsoft, Red Hat or CISA Vulnrichment, and
        whichever supplied it records it under its own summary."""

        threat = cwe_threat(None)
        threat.metadata["enrichment"] = {"redhat_security": {"cwe": ["CWE-20"]}}

        self.assertEqual(enrichment.threat_cwes(threat), ["CWE-20"])
        self.assertIsNotNone(
            enrichment.build_context(threat, self.index, self.capec)
        )

    def test_the_engines_own_cwes_field_is_read_too(self) -> None:
        """The engine publishes ``cwes``; the summaries use ``cwe``."""

        threat = cwe_threat(None)
        threat.metadata["cwes"] = ["CWE-20"]

        self.assertEqual(enrichment.threat_cwes(threat), ["CWE-20"])

    def test_the_block_says_it_is_context_not_proof(self) -> None:
        block = enrichment.build_context(family_threat("QakBot"), index())

        self.assertIn("not evidence", block["note"])

    def test_the_matched_name_travels_with_the_result(self) -> None:
        """A name match is auditable, or it is not a claim worth publishing."""

        block = enrichment.build_context(family_threat("QakBot"), index())

        self.assertEqual(block["actors"][0]["matched_name"], "qakbot")

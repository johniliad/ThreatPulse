"""MISP Galaxy — the alias bridge.

MISP Galaxy is a knowledge base, not a feed: it carries no observations and publishes
nothing. Its one job is to widen the set of names that resolve to an ATT&CK
identifier, and the tests that matter are therefore about *what it refuses to carry*
— a value with no ATT&CK identifier behind it, or a synonym that is really an
identifier — because those are what would inflate the index without widening the
match.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from normalization import galaxy as galaxy_module  # noqa: E402
from normalization.attack import build_index as build_attack_index  # noqa: E402
from normalization.attack import match_actors  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402


def galaxy_file(values: list[dict], *, name: str = "Enterprise ATT&CK malware") -> dict:
    return {
        "name": name,
        "type": "mitre-enterprise-attack-malware",
        "version": "1",
        "values": values,
    }


def value(name: str, external_id: str | None, synonyms: list[str] | None = None) -> dict:
    meta: dict = {}

    if external_id is not None:
        meta["external_id"] = external_id

    if synonyms is not None:
        meta["synonyms"] = synonyms

    return {"value": name, "meta": meta, "uuid": "00000000-0000-0000-0000-000000000001"}


class IdentifierKindTests(unittest.TestCase):
    def test_identifiers_are_routed_to_their_collection(self) -> None:
        self.assertEqual(galaxy_module.identifier_kind("S0093"), "software")
        self.assertEqual(galaxy_module.identifier_kind("G0007"), "group")
        self.assertEqual(galaxy_module.identifier_kind("T1059"), "technique")

    def test_a_non_identifier_is_not_routed(self) -> None:
        self.assertIsNone(galaxy_module.identifier_kind("havex"))
        self.assertIsNone(galaxy_module.identifier_kind(""))


class ParseGalaxyTests(unittest.TestCase):
    def test_an_entry_with_an_attck_identifier_is_kept(self) -> None:
        entries = galaxy_module.parse_galaxy(
            galaxy_file([value("Havex", "S0093", ["black energy"])])
        )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["identifier"], "S0093")
        self.assertEqual(entries[0]["kind"], "software")
        self.assertEqual(entries[0]["synonyms"], ["black energy"])

    def test_an_entry_without_an_identifier_is_dropped(self) -> None:
        """It cannot resolve to anything the index holds, so keeping it would inflate
        the counts without widening the match."""

        self.assertEqual(galaxy_module.parse_galaxy(galaxy_file([value("x", None)])), [])

    def test_an_entry_whose_identifier_is_not_attck_is_dropped(self) -> None:
        self.assertEqual(
            galaxy_module.parse_galaxy(galaxy_file([value("x", "MISP-1234")])), []
        )

    def test_a_synonym_equal_to_the_name_is_dropped(self) -> None:
        entries = galaxy_module.parse_galaxy(
            galaxy_file([value("Havex", "S0093", ["Havex", "black energy"])])
        )

        self.assertEqual(entries[0]["synonyms"], ["black energy"])

    def test_a_synonym_that_is_itself_an_identifier_is_dropped(self) -> None:
        """A feed names a family; it does not name an ATT&CK identifier as a family."""

        entries = galaxy_module.parse_galaxy(
            galaxy_file([value("Havex", "S0093", ["S0093", "G0007"])])
        )

        self.assertEqual(entries[0]["synonyms"], [])

    def test_synonyms_are_bounded(self) -> None:
        entries = galaxy_module.parse_galaxy(
            galaxy_file([value("Havex", "S0093", [f"alias{i}" for i in range(80)])])
        )

        self.assertEqual(len(entries[0]["synonyms"]), galaxy_module.MAX_SYNONYMS)

    def test_a_non_object_payload_yields_nothing(self) -> None:
        self.assertEqual(galaxy_module.parse_galaxy(["not", "a", "galaxy"]), [])


class BuildIndexTests(unittest.TestCase):
    def test_the_index_reports_what_it_holds(self) -> None:
        index = galaxy_module.build_index(
            [galaxy_file([value("Havex", "S0093", ["black energy"])])]
        )

        self.assertEqual(index["counts"]["entries"], 1)
        self.assertEqual(index["counts"]["synonyms"], 1)
        self.assertEqual(index["counts"]["software"], 1)

    def test_an_identifier_is_never_overwritten_by_a_later_file(self) -> None:
        """So the index is deterministic whatever order the files are fetched in."""

        index = galaxy_module.build_index(
            [
                galaxy_file([value("First", "S0093", ["one"])]),
                galaxy_file([value("Second", "S0093", ["two"])]),
            ]
        )

        self.assertEqual(index["entries"]["S0093"]["name"], "First")
        self.assertEqual(index["entries"]["S0093"]["synonyms"], ["one"])

    def test_files_with_nothing_bridgeable_are_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            galaxy_module.build_index([galaxy_file([value("x", None)])])


def attack_bundle() -> dict:
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
                    {"source_name": "mitre-attack", "external_id": "T1190"}
                ],
            },
            {
                "type": "malware",
                "id": "malware--1",
                "name": "Havex",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S0093"}
                ],
            },
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "malware--1",
                "target_ref": "attack-pattern--1",
            },
        ]
    }


class ExtendAttackIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = build_attack_index(
            attack_bundle(), generated_at="2026-11-01T00:00:00Z"
        )
        self.galaxy = galaxy_module.build_index(
            [galaxy_file([value("Havex", "S0093", ["black energy", "havex-2"])])]
        )

    def test_an_alias_reaches_the_identifier_it_belongs_to(self) -> None:
        extended = galaxy_module.extend_attack_index(self.index, self.galaxy)

        matches = match_actors(extended, ["black energy"])

        self.assertEqual(matches[0]["id"], "S0093")
        self.assertEqual(matches[0]["techniques"], ["T1190"])

    def test_the_original_index_is_not_mutated(self) -> None:
        """ATT&CK's vocabulary stays exactly what ATT&CK published.

        The index stores names lower-cased — ``names`` is the matching vocabulary, and
        the display name lives separately in ``name`` — so that is what is asserted.
        """

        galaxy_module.extend_attack_index(self.index, self.galaxy)

        self.assertEqual(self.index["software"]["S0093"]["names"], ["havex"])
        self.assertEqual(self.index["software"]["S0093"]["name"], "Havex")
        self.assertNotIn("galaxy_aliases", self.index["software"]["S0093"])

    def test_the_added_aliases_are_recorded_separately(self) -> None:
        extended = galaxy_module.extend_attack_index(self.index, self.galaxy)

        self.assertEqual(extended["galaxy_aliases_added"], 2)
        self.assertEqual(
            extended["software"]["S0093"]["galaxy_aliases"],
            ["black energy", "havex-2"],
        )

    def test_a_missing_galaxy_leaves_the_index_alone(self) -> None:
        self.assertIs(galaxy_module.extend_attack_index(self.index, None), self.index)

    def test_an_alias_for_an_identifier_not_in_the_index_is_ignored(self) -> None:
        galaxy = galaxy_module.build_index(
            [galaxy_file([value("Elsewhere", "S9999", ["nowhere"])])]
        )

        extended = galaxy_module.extend_attack_index(self.index, galaxy)

        self.assertNotIn("galaxy_aliases_added", extended)

    def test_the_matched_name_travels_so_the_alias_claim_is_auditable(self) -> None:
        extended = galaxy_module.extend_attack_index(self.index, self.galaxy)

        matches = match_actors(extended, ["Black Energy"])

        self.assertEqual(matches[0]["matched_name"], "black energy")
        self.assertEqual(matches[0]["name"], "Havex")

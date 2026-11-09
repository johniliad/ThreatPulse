"""Phase 7 tests for MITRE ATT&CK.

The fixtures are hand-built STIX objects that mirror the live bundle's shapes,
because the assertions that matter are about *policy* as much as parsing:

* ATT&CK is **context, never proof of activity** — an enricher may not change a
  threat's exploitation status, confidence or score, and the published block says
  so in as many words;
* a technique the bundle does not hold is reported as unknown rather than dropped,
  so "no such technique" is distinguishable from "we failed to look it up";
* a retired technique is still resolvable, because an older advisory may cite one;
* tactic labels are read from the bundle, never hard-coded — ATT&CK renamed
  ``TA0005`` from "Defense Evasion" to "Stealth" in version 20.0;
* actor matching is a name match, not an identification, and a name matching two
  objects returns both rather than picking one.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from collectors.mitre_attack import MitreAttackCollector
from enrichment.attack import CONTEXT_NOTE, AttackEnricher, build_context
from enrichment.base import run_enrichers
from lib.attribution import load_register
from lib.config import SourceConfig
from lib.http import HttpError
from models.intelligence import Threat
from normalization.attack import (
    INDEX_FILENAME,
    build_index,
    load_index,
    match_actors,
    resolve_techniques,
)
from normalization.cisa import NormalizationError
from state.store import StateStore

CVE = "CVE-2026-109619"


def stix_bundle(*objects: dict) -> dict:
    return {"type": "bundle", "id": "bundle--test", "objects": list(objects)}


def collection(version: str = "20.0") -> dict:
    return {
        "type": "x-mitre-collection",
        "id": "x-mitre-collection--test",
        "name": "Enterprise ATT&CK",
        "x_mitre_version": version,
    }


def technique(
    identifier: str = "T1566",
    name: str = "Phishing",
    *,
    phase: str = "initial-access",
    deprecated: bool = False,
    description: str = "Adversaries may send phishing messages.",
) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{identifier}",
        "name": name,
        "description": description,
        "x_mitre_deprecated": deprecated,
        "x_mitre_platforms": ["Windows", "Linux"],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": phase}
        ],
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": identifier,
                "url": f"https://attack.mitre.org/techniques/{identifier}",
            },
            # A non-ATT&CK reference must be ignored.
            {"source_name": "some-other-database", "external_id": "NOT-AN-ATTACK-ID"},
        ],
    }


def tactic(
    identifier: str = "TA0001",
    short_name: str = "initial-access",
    name: str = "Initial Access",
) -> dict:
    return {
        "type": "x-mitre-tactic",
        "id": f"x-mitre-tactic--{identifier}",
        "name": name,
        "x_mitre_shortname": short_name,
        "description": f"{name} describes getting in.",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": identifier,
                "url": f"https://attack.mitre.org/tactics/{identifier}",
            }
        ],
    }


def named_object(kind: str, identifier: str, name: str, aliases=()) -> dict:
    return {
        "type": kind,
        "id": f"{kind}--{identifier}",
        "name": name,
        "aliases": list(aliases),
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": identifier,
                "url": f"https://attack.mitre.org/{identifier}",
            }
        ],
    }


def sample_bundle() -> dict:
    return stix_bundle(
        collection(),
        tactic("TA0001", "initial-access", "Initial Access"),
        tactic("TA0005", "stealth", "Stealth"),
        technique("T1566", "Phishing"),
        technique("T1566.001", "Spearphishing Attachment", phase="initial-access"),
        technique("T1002", "Data Compressed", phase="exfiltration", deprecated=True),
        named_object("intrusion-set", "G1040", "Play", aliases=["Playcrypt"]),
        named_object("malware", "S0611", "Clop"),
    )


def make_store() -> StateStore:
    root = Path(tempfile.mkdtemp())

    return StateStore(root / "state", root / "data")


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload
        self.body = (
            payload if isinstance(payload, bytes) else __import__("json").dumps(payload).encode()
        )

    def json(self) -> object:
        return self._payload


class FakeHttp:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = dict(responses)
        self.calls: list[str] = []

    def get(
        self, url: str, *, timeout_seconds=None, headers=None, max_bytes=None
    ) -> FakeResponse:
        self.calls.append(url)

        if url not in self.responses:
            raise AssertionError(f"unexpected request: {url}")

        outcome = self.responses[url]

        if isinstance(outcome, Exception):
            raise outcome

        return FakeResponse(outcome)


def attack_config(**overrides) -> SourceConfig:
    values = {
        "key": "mitre_attack",
        "name": "MITRE ATT&CK Enterprise",
        "source_type": "knowledge_base",
        "url": "https://attack.mitre.org/",
        "feed_url": (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json"
        ),
        "provider": "MITRE",
        "reliability": "high",
        "enabled": True,
        "required": False,
        "timeout_seconds": 180.0,
        "tier": 1,
        "feeds": (),
    }
    values.update(overrides)

    return SourceConfig(**values)


class IndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = build_index(
            sample_bundle(), version="20.0", source_url="https://example.test/b.json"
        )

    def test_counts(self) -> None:
        self.assertEqual(self.index["counts"]["techniques"], 3)
        self.assertEqual(self.index["counts"]["tactics"], 2)
        self.assertEqual(self.index["counts"]["software"], 1)
        self.assertEqual(self.index["counts"]["groups"], 1)
        self.assertEqual(self.index["version"], "20.0")

    def test_only_attack_references_are_read(self) -> None:
        # The fixture also carries a non-ATT&CK external reference.
        self.assertIn("T1566", self.index["techniques"])
        self.assertNotIn("NOT-AN-ATTACK-ID", self.index["techniques"])

    def test_tactics_come_from_kill_chain_phases(self) -> None:
        self.assertEqual(self.index["techniques"]["T1566"]["tactics"], ["initial-access"])

    def test_sub_techniques_are_kept(self) -> None:
        self.assertIn("T1566.001", self.index["techniques"])
        self.assertEqual(
            self.index["techniques"]["T1566.001"]["name"], "Spearphishing Attachment"
        )

    def test_a_retired_technique_is_kept_and_flagged(self) -> None:
        self.assertTrue(self.index["techniques"]["T1002"]["retired"])
        self.assertFalse(self.index["techniques"]["T1566"]["retired"])

    def test_tactic_short_names_are_lower_cased(self) -> None:
        self.assertEqual(self.index["tactics"]["TA0005"]["short_name"], "stealth")
        self.assertEqual(self.index["tactics"]["TA0005"]["name"], "Stealth")

    def test_a_bundle_without_techniques_is_refused(self) -> None:
        with self.assertRaises(NormalizationError):
            build_index(stix_bundle(collection(), tactic()))

    def test_untrustworthy_bundles_are_refused(self) -> None:
        for bundle in (None, [], {}, {"objects": []}, {"objects": "not-a-list"}):
            with self.assertRaises(NormalizationError):
                build_index(bundle)


class ResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = build_index(sample_bundle(), version="20.0")

    def test_a_known_technique_resolves_to_its_name_and_tactic(self) -> None:
        entry = resolve_techniques(self.index, ["T1566"])[0]

        self.assertTrue(entry["known"])
        self.assertEqual(entry["name"], "Phishing")
        self.assertEqual(entry["tactics"], [{"id": "TA0001", "name": "Initial Access"}])
        self.assertTrue(entry["url"].startswith("https://attack.mitre.org/"))

    def test_an_unknown_technique_is_reported_as_unknown_not_dropped(self) -> None:
        entry = resolve_techniques(self.index, ["T9999"])[0]

        self.assertEqual(entry, {"id": "T9999", "known": False})

    def test_identifiers_are_normalised_and_deduplicated(self) -> None:
        entries = resolve_techniques(self.index, [" t1566 ", "T1566", None, ""])

        self.assertEqual([entry["id"] for entry in entries], ["T1566"])

    def test_a_tactic_the_bundle_does_not_label_is_not_given_an_invented_name(
        self,
    ) -> None:
        index = build_index(stix_bundle(collection(), technique(phase="mystery-phase")))

        entry = resolve_techniques(index, ["T1566"])[0]

        self.assertEqual(entry["tactics"], [{"id": None, "name": "mystery-phase"}])

    def test_tactic_labels_are_read_from_the_bundle(self) -> None:
        # Version 20.0 renamed TA0005. The label must come from the bundle.
        index = build_index(
            stix_bundle(
                collection(),
                tactic("TA0005", "stealth", "Stealth"),
                technique("T1562", "Impair Defenses", phase="stealth"),
            )
        )

        entry = resolve_techniques(index, ["T1562"])[0]

        self.assertEqual(entry["tactics"], [{"id": "TA0005", "name": "Stealth"}])


class ActorMatchingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = build_index(sample_bundle())

    def test_a_name_matches_case_insensitively(self) -> None:
        matches = match_actors(self.index, ["play"])

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["id"], "G1040")
        self.assertEqual(matches[0]["kind"], "group")
        self.assertEqual(matches[0]["matched_name"], "play")

    def test_an_alias_matches(self) -> None:
        matches = match_actors(self.index, ["Playcrypt"])

        self.assertEqual([match["id"] for match in matches], ["G1040"])

    def test_a_name_matching_two_objects_returns_both(self) -> None:
        index = build_index(
            stix_bundle(
                collection(),
                technique("T1566", "Phishing"),
                named_object("intrusion-set", "G1024", "Akira"),
                named_object("malware", "S1129", "Akira"),
            )
        )

        matches = match_actors(index, ["Akira"])

        self.assertEqual(sorted(match["id"] for match in matches), ["G1024", "S1129"])

    def test_no_match_is_an_empty_list(self) -> None:
        self.assertEqual(match_actors(self.index, ["lockbit"]), [])
        self.assertEqual(match_actors(self.index, []), [])
        self.assertEqual(match_actors(self.index, [None, ""]), [])

    def test_matching_is_exact_not_partial(self) -> None:
        # "Play" must not match a hypothetical "Playbook".
        index = build_index(
            stix_bundle(
                collection(),
                technique("T1566", "Phishing"),
                named_object("intrusion-set", "G9999", "Playbook"),
            )
        )

        self.assertEqual(match_actors(index, ["Play"]), [])


def make_threat(metadata: dict) -> Threat:
    return Threat(
        threat_uuid="00000000-0000-0000-0000-000000000001",
        external_id=CVE,
        title=CVE,
        threat_type="vulnerability",
        severity="critical",
        priority_score=92.5,
        confidence_score=100.0,
        confidence_level="high",
        exploitation_status="confirmed",
        first_seen=None,
        last_seen=None,
        summary=None,
        recommended_action=None,
        metadata=dict(metadata),
    )


class StubSettings:
    """Just enough settings for the enrichment stage."""

    def __init__(self, *, enabled: bool = True, data_directory: Path | None = None) -> None:
        self._enabled = enabled
        self.data_directory = data_directory or Path(tempfile.mkdtemp())

    def source(self, key: str):
        return SimpleNamespace(key=key, enabled=self._enabled)


def settings_with_index(index: dict, *, enabled: bool = True) -> StubSettings:
    settings = StubSettings(enabled=enabled)
    (settings.data_directory / INDEX_FILENAME).write_text(
        json.dumps(index), encoding="utf-8"
    )

    return settings


class EnricherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = build_index(sample_bundle(), version="20.0")

    def test_a_threat_without_references_is_untouched(self) -> None:
        threat = make_threat({"source_keys": ["cisa_kev"]})

        self.assertIsNone(build_context(threat, self.index))

    def test_a_technique_reference_is_named(self) -> None:
        threat = make_threat({"attack_technique_ids": ["T1566"]})

        block = build_context(threat, self.index)

        self.assertEqual(block["techniques"][0]["name"], "Phishing")
        self.assertEqual(block["techniques"][0]["tactics"][0]["name"], "Initial Access")
        self.assertEqual(block["version"], "20.0")

    def test_an_unknown_technique_reference_is_kept_as_unknown(self) -> None:
        block = build_context(make_threat({"attack_technique_ids": ["T9999"]}), self.index)

        self.assertEqual(block["techniques"], [{"id": "T9999", "known": False}])

    def test_actor_names_are_matched(self) -> None:
        block = build_context(make_threat({"actor_names": ["Play"]}), self.index)

        self.assertEqual(block["actors"][0]["id"], "G1040")

    def test_the_block_states_that_it_is_context_not_proof(self) -> None:
        block = build_context(make_threat({"attack_technique_ids": ["T1566"]}), self.index)

        self.assertEqual(block["note"], CONTEXT_NOTE)
        self.assertIn("not evidence", block["note"])

    def test_enrichment_does_not_change_a_protected_field(self) -> None:
        threat = make_threat({"attack_technique_ids": ["T1566"]})
        before = threat.to_publication_dict()

        AttackEnricher().enrich([threat], settings_with_index(self.index))

        after = threat.to_publication_dict()

        for field in (
            "exploitation_status",
            "confidence_score",
            "confidence_level",
            "priority_score",
            "severity",
            "threat_uuid",
            "title",
        ):
            self.assertEqual(after[field], before[field], field)

    def test_it_attaches_the_block_through_the_harness_without_a_policy_violation(
        self,
    ) -> None:
        threat = make_threat({"attack_technique_ids": ["T1566", "T9999"]})
        settings = settings_with_index(self.index)

        enriched, notes = run_enrichers([threat], settings=settings)

        attack = next(note for note in notes if note["enricher"] == "mitre_attack")

        self.assertEqual(attack["status"], "ran")
        self.assertEqual(attack["policy_violations"], [])
        self.assertEqual(attack["changed"], 1)
        self.assertEqual(len(enriched[0].metadata["attack"]["techniques"]), 2)

    def test_a_disabled_source_does_not_enrich(self) -> None:
        threat = make_threat({"attack_technique_ids": ["T1566"]})
        settings = settings_with_index(self.index, enabled=False)

        enriched, notes = run_enrichers([threat], settings=settings)

        attack = next(note for note in notes if note["enricher"] == "mitre_attack")

        self.assertEqual(attack["status"], "disabled")
        self.assertNotIn("attack", enriched[0].metadata)

    def test_a_missing_index_is_not_an_error(self) -> None:
        threat = make_threat({"attack_technique_ids": ["T1566"]})

        enriched = AttackEnricher().enrich([threat], StubSettings())

        self.assertNotIn("attack", enriched[0].metadata)

    def test_a_corrupt_index_is_not_an_error(self) -> None:
        settings = StubSettings()
        (settings.data_directory / INDEX_FILENAME).write_text("{not json", encoding="utf-8")

        threat = make_threat({"attack_technique_ids": ["T1566"]})

        self.assertIsNone(load_index(settings.data_directory / INDEX_FILENAME))
        self.assertNotIn("attack", AttackEnricher().enrich([threat], settings)[0].metadata)


INDEX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
)
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-20.0.json"
)


def release_index(*, name: str = "Enterprise ATT&CK", url: str = BUNDLE_URL) -> dict:
    """A release index shaped like the live one: **newest first**.

    The real ``index.json`` lists releases newest-first, which is why the collector
    sorts by ``modified`` rather than trusting position. The fixture mirrors that
    so the ordering bug cannot come back.
    """

    return {
        "collections": [
            {
                "name": name,
                "versions": [
                    {
                        "version": "20.0",
                        "url": url,
                        "modified": "2026-10-13T17:53:10.145Z",
                    },
                    {
                        "version": "19.2",
                        "url": url.replace("20.0", "19.2"),
                        "modified": "2026-08-05T21:33:58.496Z",
                    },
                    {
                        "version": "1.0",
                        "url": url.replace("20.0", "1.0"),
                        "modified": "2018-01-17T12:56:55.080Z",
                    },
                ],
            }
        ]
    }


class CollectorTests(unittest.TestCase):
    def _collector(self, http, *, store=None, config=None):
        return MitreAttackCollector(
            config or attack_config(),
            http,
            store or make_store(),
            register=load_register(),
        )

    def test_the_index_url_is_derived_from_the_bundle_url(self) -> None:
        collector = self._collector(FakeHttp({}))

        self.assertEqual(collector.index_url(), INDEX_URL)

    def test_it_resolves_the_latest_version_and_writes_an_index(self) -> None:
        store = make_store()
        http = FakeHttp({INDEX_URL: release_index(), BUNDLE_URL: sample_bundle()})

        result = self._collector(http, store=store).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        # A knowledge base publishes no observations: nothing in ATT&CK is a
        # statement about an incident.
        self.assertEqual(result.observations, [])
        self.assertEqual(result.metrics["bundle_version"], "20.0")
        self.assertEqual(result.metrics["techniques"], 3)

        written = load_index(store.data_path(INDEX_FILENAME))

        self.assertIsNotNone(written)
        self.assertEqual(written["version"], "20.0")
        self.assertEqual(written["counts"]["groups"], 1)

    def test_the_newest_version_is_chosen_not_the_first_listed(self) -> None:
        http = FakeHttp({INDEX_URL: release_index(), BUNDLE_URL: sample_bundle()})

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["bundle_version"], "20.0")
        self.assertEqual(http.calls[1], BUNDLE_URL)

    def test_the_newest_version_is_chosen_regardless_of_list_order(self) -> None:
        """The live index is newest-first; the ordering must not be relied on.

        Taking the last element of a newest-first list selected ATT&CK 1.0 from
        2018 — a 2,781-object bundle instead of 26,690 — and the first version of
        this test encoded the wrong ordering, so it passed while production was
        wrong.
        """

        index = release_index()
        index["collections"][0]["versions"].reverse()

        http = FakeHttp({INDEX_URL: index, BUNDLE_URL: sample_bundle()})

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["bundle_version"], "20.0")
        self.assertEqual(result.metrics["bundle_url"], BUNDLE_URL)

    def test_the_numeric_version_breaks_a_tie_when_no_timestamp_is_published(
        self,
    ) -> None:
        index = {
            "collections": [
                {
                    "name": "Enterprise ATT&CK",
                    "versions": [
                        {"version": "9.0", "url": BUNDLE_URL.replace("20.0", "9.0")},
                        {"version": "20.0", "url": BUNDLE_URL},
                        {"version": "10.0", "url": BUNDLE_URL.replace("20.0", "10.0")},
                    ],
                }
            ]
        }

        http = FakeHttp({INDEX_URL: index, BUNDLE_URL: sample_bundle()})

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        # "9.0" > "20.0" as strings; as versions, 20.0 is newest.
        self.assertEqual(result.metrics["bundle_version"], "20.0")

    def test_the_collection_is_identified_by_url_not_display_name(self) -> None:
        # A renamed collection must not send the pipeline to Mobile or ICS ATT&CK.
        renamed = release_index(name="Enterprise ATT&CK (renamed)")
        http = FakeHttp({INDEX_URL: renamed, BUNDLE_URL: sample_bundle()})

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.metrics["bundle_url"], BUNDLE_URL)

    def test_a_non_enterprise_collection_falls_back_to_the_configured_url(self) -> None:
        mobile = release_index(
            url="https://example.test/mobile-attack/mobile-attack-20.0.json"
        )
        config = attack_config()
        http = FakeHttp({INDEX_URL: mobile, config.feed_url: sample_bundle()})

        result = self._collector(http, config=config).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.metrics["bundle_url"], config.feed_url)
        # No version could be resolved from the index, so the bundle's own version
        # is reported instead of an invented one.
        self.assertEqual(result.metrics["bundle_version"], "20.0")

    def test_an_unresolvable_index_falls_back_to_the_configured_url(self) -> None:
        config = attack_config()
        http = FakeHttp(
            {
                INDEX_URL: HttpError("HTTP 503", transient=True, status=503),
                config.feed_url: sample_bundle(),
            }
        )

        result = self._collector(http, config=config).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.metrics["bundle_url"], config.feed_url)

    def test_a_failed_fetch_with_an_existing_index_degrades(self) -> None:
        store = make_store()
        good = FakeHttp({INDEX_URL: release_index(), BUNDLE_URL: sample_bundle()})

        self._collector(good, store=store).collect("2026-10-30T00:00:00Z")

        failure = HttpError("HTTP 500", transient=True, status=500)
        failing = FakeHttp(
            {INDEX_URL: failure, attack_config().feed_url: failure}
        )
        result = self._collector(failing, store=store).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "degraded")
        self.assertTrue(result.used_last_known_good)
        self.assertTrue(result.metrics["using_existing_index"])
        self.assertEqual(result.metrics["existing_index_version"], "20.0")

    def test_a_failed_fetch_without_an_index_fails(self) -> None:
        failure = HttpError("HTTP 500", transient=True, status=500)
        failing = FakeHttp({INDEX_URL: failure, attack_config().feed_url: failure})

        result = self._collector(failing).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.usable)

    def test_a_malformed_bundle_does_not_replace_a_good_index(self) -> None:
        store = make_store()
        good = FakeHttp({INDEX_URL: release_index(), BUNDLE_URL: sample_bundle()})

        self._collector(good, store=store).collect("2026-10-30T00:00:00Z")

        broken = FakeHttp(
            {INDEX_URL: release_index(), BUNDLE_URL: {"objects": "not-a-list"}}
        )
        result = self._collector(broken, store=store).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "degraded")
        # The previous knowledge base is still on disk and still usable.
        self.assertEqual(load_index(store.data_path(INDEX_FILENAME))["version"], "20.0")

    def test_it_requires_an_attribution_record(self) -> None:
        from lib.attribution import AttributionError

        with self.assertRaises(AttributionError):
            self._collector(FakeHttp({}), config=attack_config(key="ghost_source"))

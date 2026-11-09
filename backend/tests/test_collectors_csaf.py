"""Phase 4 tests for the CISA CSAF collector.

The assertions that matter most:

* a CSAF document's **own** ``distribution.tlp.label`` drives the TLP gate, so an
  AMBER advisory is refused even though its source tree is public;
* CSAF's TLP 1.0 spelling ``WHITE`` is normalised to ``CLEAR`` — without that,
  every advisory would be wrongly rejected;
* ``changes.csv`` is parsed safely, ignoring paths that escape the tree.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from collectors.cisa_csaf import CisaCsafCollector, item_markings
from lib.attribution import load_register
from lib.config import SourceConfig
from lib.http import HttpError
from normalization.cisa import NormalizationError
from normalization.csaf import (
    build_observation,
    normalize_csaf_timestamp,
    parse_changes_csv,
    parse_csaf_advisory,
)
from state.store import StateStore

CHANGES_URL = "https://example.invalid/OT/white/changes.csv"
BASE_URL = "https://example.invalid/OT/white"

CSAF_ADVISORY = {
    "document": {
        "category": "csaf_security_advisory",
        "csaf_version": "2.0",
        "publisher": {
            "category": "coordinator",
            "name": "CISA",
            "namespace": "https://www.cisa.gov/",
        },
        "title": "Siemens SIMATIC Multiple Vulnerabilities",
        "tracking": {
            "id": "icsa-26-302-01",
            "status": "final",
            "version": "1",
            "initial_release_date": "2026-10-29T06:00:00.000000Z",
            "current_release_date": "2026-10-29T06:00:00.000000Z",
            "revision_history": [],
        },
        "distribution": {"tlp": {"label": "WHITE"}},
        "notes": [
            {
                "category": "summary",
                "text": "Successful exploitation could allow remote code execution.",
            }
        ],
    },
    "product_tree": {
        "branches": [{"category": "vendor", "name": "Siemens"}],
        "full_product_names": [
            {
                "product_id": "1",
                "name": "SIMATIC S7-1500",
                "product": {"name": "SIMATIC S7-1500"},
            }
        ],
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2026-30001",
            "title": "Improper Input Validation",
            "notes": [{"category": "summary", "text": "detail"}],
            "scores": [
                {
                    "cvss_v3": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L",
                    }
                }
            ],
            "remediations": [
                {"category": "mitigation", "details": "Apply the vendor update."}
            ],
        },
        {
            "cve": "CVE-2026-30002",
            "scores": [{"cvss_v3": {"baseScore": 6.5, "baseSeverity": "MEDIUM"}}],
        },
    ],
}

CHANGES_CSV = (
    b'"2026/icsa-26-302-03.json","2026-10-29T06:00:00.000000Z"\r\n'
    b'"2026/icsa-26-302-02.json","2026-10-29T06:00:00.000000Z"\r\n'
    b'"2025/icsa-25-275-02.json","2026-10-29T06:00:00.000000Z"\r\n'
    b'"/etc/passwd.json","2026-10-30T00:00:00.000000Z"\r\n'
    b'"../escaped.json","2026-10-30T00:00:00.000000Z"\r\n'
    b'"2026/notes.txt","2026-10-30T00:00:00.000000Z"\r\n'
    b'"2026/icsa-26-301-01.json","2026-11-01T06:00:00.000000Z"\r\n'
)


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload
        self.body = (
            payload
            if isinstance(payload, (bytes, bytearray))
            else json.dumps(payload).encode("utf-8")
        )

    def json(self) -> object:
        return self._payload


class CsafTechniqueTests(unittest.TestCase):
    """An advisory's own ATT&CK references are carried as technique entities.

    The RSS path always extracted these; the CSAF path did not, so a CISA advisory
    that cited a technique would have been read differently from a national CERT
    feed item citing the same one. Both now share one extractor.
    """

    def _advisory(self, **overrides) -> dict:
        document = json.loads(json.dumps(CSAF_ADVISORY))
        document.update(overrides)

        return document

    def test_a_technique_in_a_note_is_captured(self) -> None:
        advisory = parse_csaf_advisory(
            self._advisory(
                document={
                    **CSAF_ADVISORY["document"],
                    "notes": [
                        {
                            "category": "other",
                            "text": (
                                "The threat actor used T1566.001 and T1190 to gain "
                                "access."
                            ),
                        }
                    ],
                }
            )
        )

        self.assertEqual(advisory.technique_ids, ["T1190", "T1566.001"])

    def test_the_reference_survives_into_the_payload_and_entities(self) -> None:
        advisory = parse_csaf_advisory(
            self._advisory(
                document={
                    **CSAF_ADVISORY["document"],
                    "notes": [{"category": "other", "text": "Observed T1059."}],
                }
            )
        )

        self.assertEqual(advisory.to_payload(source_key="cisa_csaf")["technique_ids"], ["T1059"])

        kinds = {entity.kind for entity in advisory.entities()}

        self.assertEqual(kinds, {"cve", "technique"})

    def test_an_advisory_without_techniques_is_unchanged(self) -> None:
        advisory = parse_csaf_advisory(self._advisory())

        self.assertEqual(advisory.technique_ids, [])
        self.assertEqual(
            [entity.kind for entity in advisory.entities()], ["cve"] * len(advisory.cve_ids)
        )

    def test_a_product_name_is_not_mistaken_for_a_technique(self) -> None:
        # The product tree carries CPE strings and names; a technique pattern must
        # not be applied to them.
        advisory = parse_csaf_advisory(
            self._advisory(
                product_tree={
                    "branches": [{"category": "vendor", "name": "T1000 Industries"}],
                    "full_product_names": [],
                }
            )
        )

        self.assertEqual(advisory.technique_ids, [])


class FakeHttp:
    """Exact URL match first, then longest-prefix, then failure."""

    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = dict(responses)
        self.calls: list[str] = []

    def get(self, url: str, *, timeout_seconds=None, headers=None) -> FakeResponse:
        self.calls.append(url)

        if url in self.responses:
            return self._respond(self.responses[url], url)

        for key in sorted(self.responses, key=len, reverse=True):
            if url.startswith(key):
                return self._respond(self.responses[key], url)

        raise HttpError(f"no fixture for {url}", transient=False)

    def _respond(self, outcome: object, url: str) -> FakeResponse:
        if isinstance(outcome, Exception):
            raise outcome

        return FakeResponse(outcome)


def make_store() -> StateStore:
    root = Path(tempfile.mkdtemp())

    return StateStore(root / "state", root / "data")


def csaf_config(**overrides) -> SourceConfig:
    values = {
        "key": "cisa_csaf",
        "name": "CISA CSAF Advisories",
        "source_type": "advisory",
        "url": "https://github.com/cisagov/CSAF",
        "feed_url": CHANGES_URL,
        "provider": "CISA",
        "reliability": "high",
        "enabled": True,
        "required": False,
        "timeout_seconds": 5.0,
        "tier": 1,
        "feeds": (),
    }
    values.update(overrides)

    return SourceConfig(**values)


class CsafNormalizationTests(unittest.TestCase):
    def test_parses_a_csaf_advisory(self) -> None:
        advisory = parse_csaf_advisory(CSAF_ADVISORY)

        self.assertEqual(advisory.tracking_id, "icsa-26-302-01")
        self.assertEqual(advisory.cve_ids, ["CVE-2026-30001", "CVE-2026-30002"])
        self.assertEqual(advisory.tlp_label, "WHITE")
        self.assertEqual(advisory.severity, "critical")
        self.assertAlmostEqual(advisory.cvss_score, 9.8)
        self.assertEqual(advisory.vendor, "Siemens")
        self.assertEqual(advisory.product, "SIMATIC S7-1500")
        self.assertEqual(advisory.published_at, "2026-10-29T06:00:00Z")
        self.assertEqual(advisory.updated_at, "2026-10-29T06:00:00Z")
        self.assertIn("remote code execution", advisory.summary)
        self.assertEqual(advisory.remediations, ["Apply the vendor update."])

    def test_observation_carries_cve_entities_and_provenance(self) -> None:
        advisory = parse_csaf_advisory(CSAF_ADVISORY)

        observation = build_observation(
            advisory, source_key="cisa_csaf", retrieved_at="2026-10-31T00:00:00Z"
        )

        self.assertEqual(observation.external_id, "icsa-26-302-01")
        self.assertEqual({entity.kind for entity in observation.entities}, {"cve"})
        self.assertEqual(observation.payload["source"], "cisa_csaf")
        self.assertTrue(observation.payload["advisory"])
        self.assertEqual(observation.payload["tlp_label"], "WHITE")

    def test_rejects_a_payload_that_is_not_csaf(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_csaf_advisory({"not": "csaf"})

        with self.assertRaises(NormalizationError):
            parse_csaf_advisory("nope")

    def test_rejects_the_wrong_csaf_version(self) -> None:
        payload = json.loads(json.dumps(CSAF_ADVISORY))
        payload["document"]["csaf_version"] = "1.1"

        with self.assertRaises(NormalizationError):
            parse_csaf_advisory(payload)

    def test_rejects_a_missing_tracking_id(self) -> None:
        payload = json.loads(json.dumps(CSAF_ADVISORY))
        del payload["document"]["tracking"]["id"]

        with self.assertRaises(NormalizationError):
            parse_csaf_advisory(payload)

    def test_an_advisory_without_cves_is_still_valid(self) -> None:
        payload = json.loads(json.dumps(CSAF_ADVISORY))
        payload["vulnerabilities"] = []

        advisory = parse_csaf_advisory(payload)

        self.assertEqual(advisory.cve_ids, [])
        self.assertIsNone(advisory.cvss_score)

    def test_timestamps_are_normalised(self) -> None:
        self.assertEqual(
            normalize_csaf_timestamp("2026-10-29T06:00:00.000000Z"),
            "2026-10-29T06:00:00Z",
        )
        self.assertEqual(
            normalize_csaf_timestamp("2026-10-29T06:00:00Z"), "2026-10-29T06:00:00Z"
        )
        self.assertIsNone(normalize_csaf_timestamp("not a date"))
        self.assertIsNone(normalize_csaf_timestamp(None))


class CsafChangesCsvTests(unittest.TestCase):
    def test_parses_rows_newest_first(self) -> None:
        rows = parse_changes_csv(CHANGES_CSV, limit=0)

        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0][0], "2026/icsa-26-301-01.json")

    def test_skips_unsafe_and_non_json_paths(self) -> None:
        paths = {path for path, _ in parse_changes_csv(CHANGES_CSV, limit=0)}

        self.assertNotIn("/etc/passwd.json", paths)
        self.assertNotIn("../escaped.json", paths)
        self.assertNotIn("2026/notes.txt", paths)

    def test_respects_the_limit(self) -> None:
        self.assertEqual(len(parse_changes_csv(CHANGES_CSV, limit=2)), 2)

    def test_non_bytes_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_changes_csv("csv as str")  # type: ignore[arg-type]

    def test_an_empty_file_yields_no_rows(self) -> None:
        self.assertEqual(parse_changes_csv(b"", limit=10), [])


class CsafTlpLabelTests(unittest.TestCase):
    """CSAF uses TLP 1.0 spellings; the gate speaks TLP 2.0."""

    def test_white_is_normalised_to_clear(self) -> None:
        self.assertEqual(item_markings("WHITE"), ["CLEAR"])

    def test_clear_is_accepted(self) -> None:
        self.assertEqual(item_markings("CLEAR"), ["CLEAR"])

    def test_restrictive_labels_are_preserved_for_the_gate(self) -> None:
        self.assertEqual(item_markings("AMBER"), ["AMBER"])
        self.assertEqual(item_markings("RED"), ["RED"])

    def test_an_unrecognised_label_becomes_unknown(self) -> None:
        self.assertEqual(item_markings("PURPLE"), ["UNKNOWN"])

    def test_an_absent_label_means_no_item_marking(self) -> None:
        self.assertEqual(item_markings(None), [])
        self.assertEqual(item_markings(""), [])


class CisaCsafCollectorTests(unittest.TestCase):
    def _collector(self, http, *, config=None, store=None, max_advisories=40):
        return CisaCsafCollector(
            config or csaf_config(),
            http,
            store or make_store(),
            register=load_register(),
            max_advisories=max_advisories,
        )

    @staticmethod
    def _advisory_url(path: str = "2026/icsa-26-302-01.json") -> str:
        return f"{BASE_URL}/{path}"

    @staticmethod
    def _changes(*paths: str) -> bytes:
        return b"".join(
            f'"{path}","2026-10-29T06:00:00.000000Z"\r\n'.encode("utf-8")
            for path in paths
        )

    def test_collects_advisories_discovered_from_changes_csv(self) -> None:
        http = FakeHttp(
            {
                CHANGES_URL: self._changes("2026/icsa-26-302-01.json"),
                self._advisory_url(): CSAF_ADVISORY,
            }
        )

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.metrics["advisories_seen"], 1)
        self.assertEqual(result.metrics["cves_extracted"], 2)
        self.assertEqual(result.metrics["rejected_tlp"], 0)
        self.assertEqual(result.metrics["feeds_ok"], 1)

    def test_the_advisory_url_is_derived_from_the_changes_url(self) -> None:
        http = FakeHttp(
            {
                CHANGES_URL: self._changes("2026/icsa-26-302-01.json"),
                self._advisory_url(): CSAF_ADVISORY,
            }
        )

        self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertIn(self._advisory_url(), http.calls)

    def test_an_amber_advisory_is_refused_by_the_tlp_gate(self) -> None:
        amber = json.loads(json.dumps(CSAF_ADVISORY))
        amber["document"]["distribution"]["tlp"]["label"] = "AMBER"

        http = FakeHttp(
            {
                CHANGES_URL: self._changes("2026/icsa-26-302-01.json"),
                self._advisory_url(): amber,
            }
        )

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["rejected_tlp"], 1)
        self.assertEqual(len(result.observations), 0)
        self.assertEqual(result.status, "failed")

    def test_an_unrecognised_label_is_refused(self) -> None:
        odd = json.loads(json.dumps(CSAF_ADVISORY))
        odd["document"]["distribution"]["tlp"]["label"] = "PURPLE"

        http = FakeHttp(
            {
                CHANGES_URL: self._changes("2026/icsa-26-302-01.json"),
                self._advisory_url(): odd,
            }
        )

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["rejected_tlp"], 1)
        self.assertEqual(len(result.observations), 0)


class CisaCsafResilienceTests(unittest.TestCase):
    def _collector(self, http, *, store=None):
        return CisaCsafCollector(
            csaf_config(), http, store or make_store(), register=load_register()
        )

    @staticmethod
    def _advisory_url(path: str) -> str:
        return f"{BASE_URL}/{path}"

    @staticmethod
    def _changes(*paths: str) -> bytes:
        return b"".join(
            f'"{path}","2026-10-29T06:00:00.000000Z"\r\n'.encode("utf-8")
            for path in paths
        )

    def test_a_malformed_document_does_not_discard_the_others(self) -> None:
        http = FakeHttp(
            {
                CHANGES_URL: self._changes(
                    "2026/icsa-26-302-01.json", "2026/icsa-26-302-02.json"
                ),
                self._advisory_url("2026/icsa-26-302-01.json"): {"not": "csaf"},
                self._advisory_url("2026/icsa-26-302-02.json"): CSAF_ADVISORY,
            }
        )

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.metrics["rejected_malformed"], 1)

    def test_an_advisory_without_a_cve_is_counted_separately(self) -> None:
        without_cve = json.loads(json.dumps(CSAF_ADVISORY))
        without_cve["vulnerabilities"] = []

        http = FakeHttp(
            {
                CHANGES_URL: self._changes("2026/icsa-26-302-01.json"),
                self._advisory_url("2026/icsa-26-302-01.json"): without_cve,
            }
        )

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["advisories_without_cve"], 1)
        self.assertEqual(result.metrics["cves_extracted"], 0)

    def test_a_changes_file_failure_without_a_snapshot_fails(self) -> None:
        http = FakeHttp(
            {CHANGES_URL: HttpError("HTTP 500", transient=True, status=500)}
        )

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.usable)

    def test_a_changes_file_failure_with_a_snapshot_degrades(self) -> None:
        store = make_store()

        good = FakeHttp(
            {
                CHANGES_URL: self._changes("2026/icsa-26-302-01.json"),
                self._advisory_url("2026/icsa-26-302-01.json"): CSAF_ADVISORY,
            }
        )

        self._collector(good, store=store).collect("2026-10-30T00:00:00Z")

        failing = FakeHttp(
            {CHANGES_URL: HttpError("HTTP 500", transient=True, status=500)}
        )

        result = self._collector(failing, store=store).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "degraded")
        self.assertTrue(result.used_last_known_good)
        self.assertEqual(len(result.observations), 1)

    def test_an_attribution_record_is_required(self) -> None:
        from lib.attribution import AttributionError

        with self.assertRaises(AttributionError):
            CisaCsafCollector(
                csaf_config(key="ghost_source"),
                FakeHttp({}),
                make_store(),
                register=load_register(),
            )




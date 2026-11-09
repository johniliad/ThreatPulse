"""Backend test suite (standard library only).

Coverage required by the requirements: configuration, CISA parsing, malformed
feeds, scoring, confidence, deterministic identity, publication validation,
atomic writes, publisher construction, publisher failures and source-failure
semantics. No production credentials, no live network access.

Run:  cd backend && python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import publisher as publisher_module  # noqa: E402
from collectors.cisa_kev import CisaKevCollector  # noqa: E402
from correlation import engine  # noqa: E402
from lib import atomic, config, ids  # noqa: E402
from lib.http import HttpError  # noqa: E402
from lib.logging_setup import redact  # noqa: E402
from models.intelligence import Entity, Observation, Source  # noqa: E402
from normalization import cisa  # noqa: E402
from publication import builder, quality_gate  # noqa: E402
from scoring import confidence, priority  # noqa: E402
from state.store import StateStore  # noqa: E402


def kev_record(**overrides) -> dict:
    record = {
        "cveID": "CVE-2026-109619",
        "vendorProject": "PHP Group",
        "product": "PHP",
        "vulnerabilityName": "PHP Stale Internal Request-State Vulnerability",
        "dateAdded": "2026-10-26",
        "shortDescription": (
            "PHP contains a stale internal request-state vulnerability that "
            "allows for unauthenticated remote code execution."
        ),
        "requiredAction": "Apply mitigations in accordance with vendor instructions.",
        "dueDate": "2026-10-29",
        "knownRansomwareCampaignUse": "Unknown",
        "forensicTriage": "Yes",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2026-109619",
        "cwes": ["CWE-416"],
    }
    record.update(overrides)

    return record


def feed(records) -> dict:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.10.30",
        "count": len(records),
        "vulnerabilities": records,
    }


def settings_payload() -> dict:
    return {
        "schema_version": "1.0",
        "environment": "test",
        "scoring_model": "threatpulse_priority_v0.1",
        "directories": {
            "state": "state",
            "data": "data",
            "logs": "logs",
            "config": "config",
        },
        "http": {
            "connect_timeout_seconds": 5,
            "read_timeout_seconds": 10,
            "max_attempts": 2,
            "backoff_seconds": 0.1,
            "backoff_multiplier": 2,
            "user_agent": "ThreatPulse-Test/0.1",
        },
        "publisher": {
            "endpoint": "https://example.invalid/api/cti/v1/publish.php",
            "timeout_seconds": 30,
            "max_attempts": 2,
            "backoff_seconds": 0.1,
            "verify_tls": True,
        },
        "publication": {
            "minimum_threats": 1,
            "maximum_drop_ratio": 0.25,
            "max_summary_items": 10,
        },
        "sources": [
            {
                "key": "cisa_kev",
                "name": "CISA Known Exploited Vulnerabilities Catalog",
                "source_type": "advisory",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "feed_url": "https://example.invalid/kev.json",
                "provider": "CISA",
                "reliability": "high",
                "enabled": True,
                "required": True,
                "timeout_seconds": 10,
            }
        ],
    }


class BackendTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.state = StateStore(self.root / "state", self.root / "data")

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def settings(self, mutate=None):
        payload = settings_payload()

        if mutate:
            mutate(payload)

        path = self.root / "settings.json"
        path.write_text(json.dumps(payload), encoding="utf-8")

        return config.load_settings(path, backend_root=self.root)

    def collector(self, payload=None, error=None):
        http = mock.Mock()

        if error is not None:
            http.get.side_effect = error
        else:
            http.get.return_value = mock.Mock(json=lambda: payload)

        return CisaKevCollector(self.settings().source("cisa_kev"), http, self.state)


class ConfigTests(BackendTestCase):
    def test_loads_valid_configuration(self):
        settings = self.settings()

        self.assertEqual(settings.schema_version, "1.0")
        self.assertEqual(settings.source("cisa_kev").provider, "CISA")
        self.assertEqual(len(settings.enabled_sources), 1)

    def test_rejects_invalid_configuration(self):
        cases = [
            lambda payload: payload.update({"schema_version": "9.9"}),
            lambda payload: payload["http"].update({"read_timeout_seconds": 0}),
            lambda payload: payload["publisher"].update(
                {"endpoint": "http://insecure.invalid/publish.php"}
            ),
            lambda payload: payload["sources"][0].update(
                {"feed_url": "http://insecure.invalid/kev.json"}
            ),
            lambda payload: payload["sources"].append(dict(payload["sources"][0])),
            lambda payload: payload.update({"sources": []}),
            lambda payload: payload["publication"].update({"maximum_drop_ratio": 1.5}),
        ]

        for mutate in cases:
            with self.assertRaises(config.ConfigError):
                self.settings(mutate)

    def test_environment_file_and_token(self):
        env_file = self.root / "threatpulse.env"
        env_file.write_text(
            "# comment\nexport THREATPULSE_PUBLISHER_TOKEN='secret-value'\n",
            encoding="utf-8",
        )

        self.assertEqual(config.load_publisher_token(env_file), "secret-value")

        empty = self.root / "empty.env"
        empty.write_text("# nothing\n", encoding="utf-8")

        with self.assertRaises(config.ConfigError):
            config.load_publisher_token(empty)

    def test_missing_configuration_file_is_an_error(self):
        with self.assertRaises(config.ConfigError):
            config.load_settings(self.root / "absent.json", backend_root=self.root)


class NormalizationTests(BackendTestCase):
    def test_parses_a_valid_kev_record(self):
        record = cisa.parse_kev_record(kev_record())

        self.assertEqual(record.cve_id, "CVE-2026-109619")
        self.assertEqual(record.date_added, "2026-10-26")
        self.assertEqual(record.cwes, ["CWE-416"])
        self.assertTrue(record.forensic_triage)

    def test_payload_keeps_legacy_field_names(self):
        payload = cisa.parse_kev_record(kev_record()).to_payload()

        for field in (
            "cve_id",
            "vendor",
            "product",
            "vulnerability_name",
            "date_added",
            "description",
            "required_action",
            "due_date",
            "known_ransomware_campaign_use",
            "forensic_triage",
            "notes",
            "cwes",
            "source",
            "kev_listed",
            "exploited_in_wild",
        ):
            self.assertIn(field, payload)

    def test_rejects_unusable_records(self):
        for payload in (
            "not-an-object",
            {"cveID": "not-a-cve", "dateAdded": "2026-10-26"},
            {"cveID": "CVE-2026-109619"},
        ):
            with self.assertRaises(cisa.NormalizationError):
                cisa.parse_kev_record(payload)

    def test_sanitises_hostile_text(self):
        record = cisa.parse_kev_record(
            kev_record(
                vulnerabilityName="  Bad\x00Title\n\nwith   spacing  ",
                shortDescription="x" * 5000,
            )
        )

        self.assertEqual(record.title, "Bad Title with spacing")
        self.assertLessEqual(len(record.description or ""), cisa.MAX_DESCRIPTION_LENGTH)

    def test_normalizes_flags_and_cwes(self):
        self.assertEqual(cisa.normalize_ransomware_use("Known"), "Known")
        self.assertEqual(cisa.normalize_ransomware_use("nonsense"), "Unknown")
        self.assertTrue(cisa.normalize_forensic_triage("Yes"))
        self.assertFalse(cisa.normalize_forensic_triage("No"))

        record = cisa.parse_kev_record(
            kev_record(cwes=["CWE-416", "not-a-cwe", "CWE-79", "CWE-416"])
        )

        self.assertEqual(record.cwes, ["CWE-416", "CWE-79"])


class CollectorTests(BackendTestCase):
    def test_collects_a_valid_feed(self):
        result = self.collector(
            feed([kev_record(), kev_record(cveID="CVE-2021-3199")])
        ).collect("2026-10-30T10:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 2)
        self.assertTrue(self.state.state_path("last_known_good_cisa_kev.json").exists())

    def test_rejects_a_feed_without_vulnerabilities(self):
        result = self.collector({"title": "changed"}).collect("2026-10-30T10:00:00Z")

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.usable)

    def test_rejects_a_feed_whose_shape_changed(self):
        records = [kev_record(cveID="bad")] + [kev_record()]

        result = self.collector(feed(records)).collect("2026-10-30T10:00:00Z")

        self.assertEqual(result.status, "failed")

    def test_malformed_records_do_not_discard_the_rest(self):
        # One malformed record out of ten is within the documented 20% rejection
        # budget, so the valid records are still published.
        records = [kev_record(cveID=f"CVE-2026-{100000 + index}") for index in range(9)]
        records.insert(3, {"cveID": "broken"})

        result = self.collector(feed(records)).collect("2026-10-30T10:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 9)
        self.assertEqual(result.metrics["rejected"], 1)

    def test_degrades_to_last_known_good(self):
        self.collector(feed([kev_record()])).collect("2026-10-30T09:00:00Z")

        degraded = self.collector(
            error=HttpError("timeout", transient=True, attempts=3)
        ).collect("2026-10-30T10:00:00Z")

        self.assertEqual(degraded.status, "degraded")
        self.assertTrue(degraded.used_last_known_good)
        self.assertTrue(degraded.usable)

    def test_fails_when_unavailable_and_no_snapshot_exists(self):
        result = self.collector(
            error=HttpError("boom", transient=False, status=500)
        ).collect("2026-10-30T10:00:00Z")

        self.assertEqual(result.status, "failed")
        self.assertIn("boom", result.failure_reason or "")


class IdentityTests(BackendTestCase):
    def test_reproduces_published_identifiers(self):
        for cve, expected in ids.IDENTITY_VECTORS.items():
            self.assertEqual(ids.threat_id("cisa_kev", cve), expected, cve)

    def test_is_stable_and_case_insensitive(self):
        self.assertEqual(
            ids.threat_id("cisa_kev", "cve-2026-109619"),
            ids.threat_id("cisa_kev", "CVE-2026-109619"),
        )

    def test_rejects_invalid_cve_identifiers(self):
        with self.assertRaises(ValueError):
            ids.normalize_cve("CVE-26-1")


class ScoringTests(BackendTestCase):
    def test_reproduces_published_priority_scores(self):
        php = cisa.parse_kev_record(kev_record()).to_payload()
        php_score = priority.score_record(php, reference_date=date(2026, 10, 30))

        self.assertEqual(php_score["priority_score"], 92.5)
        self.assertEqual(php_score["priority_band"], "critical")
        self.assertEqual(php_score["score_weights"], priority.WEIGHTS)

        ssrf = cisa.parse_kev_record(
            kev_record(
                cveID="CVE-2026-83548",
                vendorProject="SonicWall",
                product="SMA1000 Appliances",
                vulnerabilityName="SonicWall SMA1000 SSRF Vulnerability",
                shortDescription=(
                    "SonicWall SMA1000 Appliances contains a server-side request "
                    "forgery vulnerability that could allow a remote "
                    "unauthenticated attacker to gain unauthorized access."
                ),
                dateAdded="2026-09-02",
                dueDate="2026-09-05",
                forensicTriage="Yes",
            )
        ).to_payload()

        self.assertEqual(
            priority.score_record(ssrf, reference_date=date(2026, 10, 30))[
                "priority_score"
            ],
            80.5,
        )

    def test_is_deterministic(self):
        payload = cisa.parse_kev_record(kev_record()).to_payload()
        reference = date(2026, 10, 30)

        self.assertEqual(
            priority.score_record(payload, reference_date=reference),
            priority.score_record(payload, reference_date=reference),
        )

    def test_confidence_is_separate_from_priority(self):
        payload = cisa.parse_kev_record(kev_record()).to_payload()
        assessed = confidence.assess(payload)

        self.assertEqual((assessed.score, assessed.level), (100.0, "high"))
        self.assertEqual(
            confidence.assess(
                dict(payload, kev_listed=False, exploited_in_wild=False)
            ).level,
            "medium",
        )


# __TESTS_PART_FOUR__



"""Phase 4a tests for the ENISA EUVD collector.

The payload shapes here are copied from the **live** EUVD API, including the three
properties that would break a collector written from documentation alone: the CVE
id buried in the ``aliases`` string, ``epss`` values in mixed units within one
response, and non-ISO timestamps.
"""

from __future__ import annotations

import unittest

from collectors.enisa_euvd import EuvdCollector, deduplicate, is_exploited_endpoint
from correlation.engine import correlate
from lib.attribution import load_register
from lib.config import SourceConfig
from lib.http import HttpError
from normalization.cisa import NormalizationError
from normalization.euvd import (
    build_observation,
    extract_cve_ids,
    normalize_euvd_epss,
    normalize_euvd_timestamp,
    parse_euvd_payload,
    parse_euvd_record,
)
from state.store import StateStore
from tests.test_collectors_epss_ransomware import make_store
from tests.test_correlation_scoring_guard import (
    REFERENCE_DATE,
    cve_entities,
    kev_payload,
    observation as kev_observation,
)

EXPLOITED_URL = "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities"
LATEST_URL = "https://euvdservices.enisa.europa.eu/api/lastvulnerabilities"

#: Trimmed from the live response, with the real field names and value quirks.
EUVD_EXPLOITED = [
    {
        "id": "EUVD-2026-98214",
        "enisaUuid": "74dd4a29-2a66-3386-b28d-e7a8b9627933",
        "description": "GitLab has remediated an issue in GitLab CE/EE ...",
        "datePublished": "Oct 13, 2026, 1:05:46 AM",
        "dateUpdated": "Oct 30, 2026, 11:18:16 PM",
        "baseScore": 10,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "references": "https://gitlab.com/gitlab-org/gitlab/-/work_items/630686\n",
        "aliases": "CVE-2026-97229\nGHSA-9hj5-r43h-h3xg\n",
        "assigner": "GitLab",
        "epss": 26.57,
        "exploitedSince": "Oct 29, 2026, 12:00:00 AM",
        "enisaIdVendor": [{"id": "ce5a7876", "vendor": {"name": "GitLab"}}],
    },
    {
        "id": "EUVD-2026-112462",
        "enisaUuid": "2ebecd7b-7202-39ee-a1cd-bbbd39e43ad7",
        "description": "A vulnerability in the Remote Access SSL VPN service ...",
        "datePublished": "Oct 28, 2026, 8:05:31 PM",
        "dateUpdated": "Oct 30, 2026, 3:55:57 AM",
        "baseScore": 8.6,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
        "references": "https://sec.cloudapps.cisco.com/security/center/content/x\n",
        "aliases": "GHSA-3whv-82g3-5cwx\nCVE-2026-76418\n",
        "assigner": "cisco",
        "epss": 0.91,
        "exploitedSince": "Oct 29, 2026, 12:00:00 AM",
        "enisaIdVendor": [{"id": "9230b445", "vendor": {"name": "Cisco"}}],
    },
]

EUVD_LATEST = [
    {
        "id": "EUVD-2026-114130",
        "enisaUuid": "b7badf02-5538-359c-ba09-2cf4e520320a",
        "description": "RTIR's ticket creation forms ...",
        "datePublished": "Oct 30, 2026, 3:34:49 PM",
        "dateUpdated": "Oct 30, 2026, 5:18:22 PM",
        "baseScore": 5.3,
        "baseScoreVersion": "4.0",
        "baseScoreVector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N",
        "references": "https://cert.pl/en/posts/2026/10/CVE-2026-105454\n",
        "aliases": "CVE-2026-105455\nGHSA-8whf-jvmp-ghv3\n",
        "assigner": "CERT-PL",
        "epss": 0,
        "enisaIdVendor": [{"id": "0b36986f", "vendor": {"name": "Best Practical Solutions"}}],
    }
]


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def json(self) -> object:
        return self._payload


class FakeHttp:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = dict(responses)
        self.calls: list[str] = []

    def get(self, url: str, *, timeout_seconds=None, headers=None) -> FakeResponse:
        self.calls.append(url)

        outcome = self.responses.get(url)

        if outcome is None:
            raise HttpError(f"no fixture for {url}", transient=False)

        if isinstance(outcome, Exception):
            raise outcome

        return FakeResponse(outcome)


def euvd_config(**overrides) -> SourceConfig:
    values = {
        "key": "enisa_euvd",
        "name": "European Union Vulnerability Database (EUVD)",
        "source_type": "vulnerability_database",
        "url": "https://euvd.enisa.europa.eu/",
        "feed_url": EXPLOITED_URL,
        "provider": "ENISA",
        "reliability": "high",
        "enabled": True,
        "required": False,
        "timeout_seconds": 5.0,
        "tier": 1,
        "feeds": (),
    }
    values.update(overrides)

    return SourceConfig(**values)


class EuvdNormalizationTests(unittest.TestCase):
    def test_extracts_cves_from_the_aliases_string(self) -> None:
        self.assertEqual(extract_cve_ids("CVE-2026-97229\nGHSA-9hj5-r43h-h3xg\n"), ["CVE-2026-97229"])
        self.assertEqual(extract_cve_ids("GHSA-3whv-82g3-5cwx\nCVE-2026-76418\n"), ["CVE-2026-76418"])
        self.assertEqual(extract_cve_ids("GHSA-only\n"), [])
        self.assertEqual(extract_cve_ids(None), [])

    def test_epss_units_are_normalised(self) -> None:
        # 26.57 and 0.38 appear in the same live response.
        self.assertAlmostEqual(normalize_euvd_epss(26.57), 0.2657)
        self.assertAlmostEqual(normalize_euvd_epss(0.38), 0.38)
        self.assertEqual(normalize_euvd_epss(0), 0.0)
        self.assertEqual(normalize_euvd_epss(100), 1.0)
        self.assertIsNone(normalize_euvd_epss("nonsense"))
        self.assertIsNone(normalize_euvd_epss(-1))

    def test_timestamps_are_parsed(self) -> None:
        self.assertEqual(
            normalize_euvd_timestamp("Oct 30, 2026, 3:34:49 PM"), "2026-10-30T15:34:49Z"
        )
        self.assertEqual(
            normalize_euvd_timestamp("Oct 29, 2026, 12:00:00 AM"), "2026-10-29T00:00:00Z"
        )
        self.assertIsNone(normalize_euvd_timestamp("not a date"))
        self.assertIsNone(normalize_euvd_timestamp(None))

    def test_parses_a_record(self) -> None:
        record = parse_euvd_record(EUVD_EXPLOITED[0], exploited=True)

        self.assertEqual(record.euvd_id, "EUVD-2026-98214")
        self.assertEqual(record.cve_ids, ["CVE-2026-97229"])
        self.assertEqual(record.base_score, 10.0)
        self.assertEqual(record.vendors, ["GitLab"])
        self.assertTrue(record.exploited)
        self.assertEqual(record.exploited_since, "2026-10-29T00:00:00Z")
        self.assertEqual(record.published_at, "2026-10-13T01:05:46Z")

    def test_exploited_since_marks_a_record_exploited(self) -> None:
        record = parse_euvd_record(EUVD_EXPLOITED[0], exploited=False)

        self.assertTrue(record.exploited)

    def test_a_record_without_exploited_since_is_not_exploited(self) -> None:
        record = parse_euvd_record(EUVD_LATEST[0])

        self.assertFalse(record.exploited)
        self.assertIsNone(record.exploited_since)

    def test_rejects_a_record_without_an_id(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_euvd_record({"aliases": "CVE-2026-97229"})

    def test_rejects_a_non_object_record(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_euvd_record("nonsense")

    def test_a_bad_record_does_not_discard_the_response(self) -> None:
        records, rejections = parse_euvd_payload(
            [{"aliases": "no id here"}, EUVD_EXPLOITED[0]], exploited=True
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(len(rejections), 1)

    def test_a_non_array_response_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_euvd_payload({"status": "ok"})

    def test_the_observation_is_cve_keyed(self) -> None:
        record = parse_euvd_record(EUVD_EXPLOITED[0], exploited=True)

        observation = build_observation(
            record, source_key="enisa_euvd", retrieved_at="2026-10-31T00:00:00Z"
        )

        self.assertEqual(observation.external_id, "EUVD-2026-98214")
        self.assertEqual({entity.kind for entity in observation.entities}, {"cve"})
        self.assertEqual(observation.payload["enisa_exploited"], True)
        self.assertAlmostEqual(observation.payload["epss"], 0.2657)


class EuvdEnrichmentTests(unittest.TestCase):
    """The point of the source: it must land on a KEV-scored threat."""

    def test_an_euvd_record_enriches_a_kev_threat(self) -> None:
        records, _ = parse_euvd_payload(EUVD_EXPLOITED, exploited=True)

        euvd_observation = build_observation(
            records[0], source_key="enisa_euvd", retrieved_at="2026-10-31T00:00:00Z"
        )

        # CVE-2026-97229 is both an EUVD exploited record and a KEV entry.
        kev = kev_observation(
            "cisa_kev", kev_payload("CVE-2026-97229"), cve_entities("CVE-2026-97229")
        )

        threats = correlate([kev, euvd_observation], reference_date=REFERENCE_DATE)

        self.assertEqual(len(threats), 1)
        self.assertIn("enisa_euvd", threats[0].source_keys)
        self.assertIn("cisa_kev", threats[0].source_keys)
        self.assertEqual(len(threats[0].evidence), 2)

    def test_a_non_kev_euvd_record_does_not_create_a_threat(self) -> None:
        records, _ = parse_euvd_payload(EUVD_LATEST, exploited=False)

        euvd_observation = build_observation(
            records[0], source_key="enisa_euvd", retrieved_at="2026-10-31T00:00:00Z"
        )

        threats = correlate([euvd_observation], reference_date=REFERENCE_DATE)

        self.assertEqual(threats, [])


class EuvdCollectorTests(unittest.TestCase):
    def _collector(self, http, *, config=None, store=None):
        return EuvdCollector(
            config or euvd_config(feeds=(EXPLOITED_URL, LATEST_URL)),
            http,
            store or make_store(),
            register=load_register(),
        )

    def test_collects_from_both_endpoints(self) -> None:
        http = FakeHttp({EXPLOITED_URL: EUVD_EXPLOITED, LATEST_URL: EUVD_LATEST})

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 3)
        self.assertEqual(result.metrics["endpoints_ok"], 2)
        self.assertEqual(result.metrics["records_with_cve"], 3)
        self.assertEqual(result.metrics["exploited_records"], 2)

    def test_records_from_the_exploited_endpoint_are_marked(self) -> None:
        http = FakeHttp({EXPLOITED_URL: EUVD_EXPLOITED})

        result = self._collector(
            http, config=euvd_config(feeds=(EXPLOITED_URL,))
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["exploited_records"], 2)
        self.assertTrue(
            all(observation.payload["enisa_exploited"] for observation in result.observations)
        )

    def test_the_same_record_on_both_endpoints_is_collapsed(self) -> None:
        http = FakeHttp({EXPLOITED_URL: EUVD_EXPLOITED, LATEST_URL: EUVD_EXPLOITED})

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(len(result.observations), 2)
        self.assertEqual(result.metrics["records_seen"], 4)

    def test_deduplicate_prefers_the_exploited_variant(self) -> None:
        plain = parse_euvd_record(dict(EUVD_LATEST[0]))
        exploited = parse_euvd_record(
            {**EUVD_LATEST[0], "exploitedSince": "Oct 29, 2026, 12:00:00 AM"},
            exploited=True,
        )

        for order in ([plain, exploited], [exploited, plain]):
            merged = deduplicate(order)

            self.assertEqual(len(merged), 1)
            self.assertTrue(merged[0].exploited)

    def test_a_partial_endpoint_failure_is_not_total_failure(self) -> None:
        http = FakeHttp(
            {
                EXPLOITED_URL: EUVD_EXPLOITED,
                LATEST_URL: HttpError("HTTP 503", transient=True, status=503),
            }
        )

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.metrics["endpoints_failed"], 1)

    def test_all_endpoints_failing_without_a_snapshot_fails(self) -> None:
        failure = HttpError("HTTP 500", transient=True, status=500)

        http = FakeHttp({EXPLOITED_URL: failure, LATEST_URL: failure})

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.usable)

    def test_all_endpoints_failing_with_a_snapshot_degrades(self) -> None:
        store = make_store()
        config = euvd_config(feeds=(EXPLOITED_URL,))

        good = FakeHttp({EXPLOITED_URL: EUVD_EXPLOITED})
        self._collector(good, config=config, store=store).collect("2026-10-30T00:00:00Z")

        failing = FakeHttp(
            {EXPLOITED_URL: HttpError("HTTP 500", transient=True, status=500)}
        )
        result = self._collector(failing, config=config, store=store).collect(
            "2026-10-31T00:00:00Z"
        )

        self.assertEqual(result.status, "degraded")
        self.assertTrue(result.used_last_known_good)
        self.assertEqual(len(result.observations), 2)

    def test_an_attribution_record_is_required(self) -> None:
        from lib.attribution import AttributionError

        with self.assertRaises(AttributionError):
            EuvdCollector(
                euvd_config(key="ghost_source"),
                FakeHttp({}),
                make_store(),
                register=load_register(),
            )

    def test_endpoint_detection(self) -> None:
        self.assertTrue(is_exploited_endpoint(EXPLOITED_URL))
        self.assertFalse(is_exploited_endpoint(LATEST_URL))
        self.assertFalse(is_exploited_endpoint(""))



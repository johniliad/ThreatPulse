"""Phase 4a tests for the CISA Vulnrichment collector.

The fixture is the **live** record for ``CVE-2024-25522``, reproduced verbatim
apart from its long reference URLs. It carries every structural trap a collector
written from documentation alone would get wrong:

* two ADP containers, only the second of which is CISA's;
* ``metrics`` mixing a ``cvssV3_1`` object with an ``other``/``ssvc`` object;
* SSVC options as single-key objects, one key containing a space
  (``{"Technical Impact": "total"}``);
* a CNA container whose vendor and product are both the literal ``"n/a"``;
* a ``problemTypes`` entry that is ``type: "text"`` with description ``"n/a"``.

The assertions that matter most are not "does it parse" but the rules the product
depends on:

* the record path mapping, because a wrong block 404s for every CVE at once and
  would be recorded silently as "CISA has not enriched any of these";
* **enrichment never moves a score** — the published 77.5 for the guard fixture
  must be identical with and without this source in the group;
* a bounded, incremental fetch: a second run over the same CVEs makes no requests.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from collectors.cisa_vulnrichment import CACHE_FILENAME, CisaVulnrichmentCollector
from correlation.engine import correlate
from lib.attribution import load_register
from lib.config import SourceConfig
from lib.http import HttpError
from normalization.cisa import NormalizationError
from normalization.vulnrichment import (
    FORBIDDEN_PAYLOAD_KEYS,
    VulnrichmentRejected,
    build_observation,
    extract_cvss,
    extract_ssvc,
    find_adp_container,
    normalize_iso_timestamp,
    parse_vulnrichment_record,
    record_path,
    record_url,
)
from state.store import StateStore
from state.record_cache import RecordCache
from tests.test_correlation_scoring_guard import (
    CVE as GUARD_CVE,
    REFERENCE_DATE,
    cve_entities,
    kev_payload,
    observation as kev_observation,
)

BASE_URL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
CVE = "CVE-2024-25522"

#: The score the CISA-derived model gives the guard fixture. Pinned so that this
#: source can never silently change an already-published number.
GUARD_FIXTURE_SCORE = 77.5

#: Verbatim from the live repository, minus the long reference URLs.
REAL_RECORD = {
    "dataType": "CVE_RECORD",
    "containers": {
        "adp": [
            {
                "title": "CVE Program Container",
                "references": [
                    {
                        "url": "https://gist.github.com/Mr-xn/bc8261a5c3e35a72768723acf1da358d",
                        "tags": ["x_transferred"],
                    }
                ],
                "providerMetadata": {
                    "orgId": "af854a3a-2127-422b-91ae-364da2661108",
                    "shortName": "CVE",
                    "dateUpdated": "2024-08-01T23:44:09.661Z",
                },
            },
            {
                "metrics": [
                    {
                        "cvssV3_1": {
                            "scope": "UNCHANGED",
                            "version": "3.1",
                            "baseScore": 9.4,
                            "attackVector": "NETWORK",
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                            "integrityImpact": "HIGH",
                            "userInteraction": "NONE",
                            "attackComplexity": "LOW",
                            "availabilityImpact": "LOW",
                            "privilegesRequired": "NONE",
                            "confidentialityImpact": "HIGH",
                        }
                    },
                    {
                        "other": {
                            "type": "ssvc",
                            "content": {
                                "id": CVE,
                                "role": "CISA Coordinator",
                                "options": [
                                    {"Exploitation": "poc"},
                                    {"Automatable": "yes"},
                                    {"Technical Impact": "total"},
                                ],
                                "version": "2.0.3",
                                "timestamp": "2024-05-24T15:01:21.328734Z",
                            },
                        }
                    },
                ],
                "affected": [
                    {
                        "cpes": ["cpe:2.3:a:ruvar:ruvarOA:-:*:*:*:*:*:*:*"],
                        "vendor": "ruvar",
                        "product": "ruvarOA",
                        "versions": [
                            {"status": "affected", "version": "6.01"},
                            {"status": "affected", "version": "6.02"},
                        ],
                        "defaultStatus": "unknown",
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "type": "CWE",
                                "cweId": "CWE-89",
                                "description": (
                                    "CWE-89 Improper Neutralization of Special "
                                    "Elements used in an SQL Command ('SQL Injection')"
                                ),
                            }
                        ]
                    }
                ],
                "providerMetadata": {
                    "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                    "shortName": "CISA-ADP",
                    "dateUpdated": "2024-05-24T15:01:00.494Z",
                },
                "title": "CISA ADP Vulnrichment",
            },
        ],
        "cna": {
            "affected": [
                {
                    "vendor": "n/a",
                    "product": "n/a",
                    "versions": [{"status": "affected", "version": "n/a"}],
                }
            ],
            "references": [
                {
                    "url": (
                        "https://gist.github.com/Mr-xn/"
                        "bc8261a5c3e35a72768723acf1da358d"
                    )
                }
            ],
            "descriptions": [
                {
                    "lang": "en",
                    "value": (
                        "RuvarOA v6.01 and v12.01 were discovered to contain a SQL "
                        "injection vulnerability via the office_missive_id parameter "
                        "at /WorkFlow/wf_work_form_save.aspx."
                    ),
                }
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {"lang": "en", "type": "text", "description": "n/a"}
                    ]
                }
            ],
            "providerMetadata": {
                "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                "shortName": "mitre",
                "dateUpdated": "2024-05-08T14:50:16.295143",
            },
        },
    },
    "cveMetadata": {
        "cveId": CVE,
        "state": "PUBLISHED",
        "dateUpdated": "2024-08-01T23:44:09.661Z",
        "dateReserved": "2024-02-07T00:00:00",
        "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
        "datePublished": "2024-05-08T00:00:00",
        "assignerShortName": "mitre",
    },
    "dataVersion": "5.1",
}


def record_url_for(cve_id: str) -> str:
    return record_url(BASE_URL, cve_id)


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def json(self) -> object:
        return self._payload


class FakeHttp:
    """Stand-in for HttpClient. An unregistered URL fails the test loudly."""

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


def make_store() -> StateStore:
    root = Path(tempfile.mkdtemp())

    return StateStore(root / "state", root / "data")


def vulnrichment_config(**overrides) -> SourceConfig:
    values = {
        "key": "cisa_vulnrichment",
        "name": "CISA Vulnrichment",
        "source_type": "vulnerability_enrichment",
        "url": "https://github.com/cisagov/vulnrichment",
        "feed_url": BASE_URL,
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


def make_collector(
    http,
    *,
    cve_ids=(),
    store: StateStore | None = None,
    max_fetches: int = 150,
    config: SourceConfig | None = None,
) -> CisaVulnrichmentCollector:
    return CisaVulnrichmentCollector(
        config or vulnrichment_config(),
        http,
        store or make_store(),
        register=load_register(),
        cve_ids=cve_ids,
        max_fetches=max_fetches,
    )


def enrichment_observation(cve: str = GUARD_CVE, *, cvss: float = 9.4):
    """A Vulnrichment observation as the collector would emit it.

    Defaults to the guard fixture's CVE so that it joins that KEV group, which is
    what makes the "enrichment cannot move a score" assertion meaningful.
    """

    payload = {
        "cve_id": cve,
        "vendor": "ruvar",
        "product": "ruvarOA",
        "description": "SQL injection in RuvarOA.",
        "cwes": ["CWE-89"],
        "ssvc": {
            "exploitation": "poc",
            "automatable": "yes",
            "technical_impact": "total",
            "version": "2.0.3",
            "role": "CISA Coordinator",
            "timestamp": "2024-05-24T15:01:21Z",
        },
        "cvss": {
            "base_score": cvss,
            "version": "3.1",
            "base_severity": "CRITICAL",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
        },
        "kev_date_added": None,
        "kev_reference": None,
        "adp_updated_at": "2024-05-24T15:01:00Z",
        "published_at": "2024-05-08T00:00:00Z",
        "updated_at": "2024-08-01T23:44:09Z",
        "record_state": "PUBLISHED",
        "data_version": "5.1",
        "source": "cisa_vulnrichment",
        "enrichment": True,
    }

    return build_observation(
        payload, source_key="cisa_vulnrichment", retrieved_at="2026-10-31T00:00:00Z"
    )


class RecordPathTests(unittest.TestCase):
    """The mapping that must be right, or every fetch 404s at once."""

    def test_the_four_verified_blocks(self) -> None:
        self.assertEqual(
            record_path("CVE-2024-0043"), "2024/0xxx/CVE-2024-0043.json"
        )
        self.assertEqual(
            record_path("CVE-2024-3477"), "2024/3xxx/CVE-2024-3477.json"
        )
        self.assertEqual(
            record_path("CVE-2024-25522"), "2024/25xxx/CVE-2024-25522.json"
        )
        self.assertEqual(
            record_path("CVE-2026-109619"), "2026/109xxx/CVE-2026-109619.json"
        )

    def test_lowercase_input_is_accepted(self) -> None:
        self.assertEqual(
            record_path("cve-2024-25522"), "2024/25xxx/CVE-2024-25522.json"
        )

    def test_an_invalid_identifier_is_refused(self) -> None:
        for value in ("", "CVE-24-25522", "GHSA-1", "CVE-2024-255", None):
            with self.assertRaises(NormalizationError):
                record_path(value)

    def test_the_url_joins_the_base_and_tolerates_a_trailing_slash(self) -> None:
        expected = f"{BASE_URL}/2024/25xxx/CVE-2024-25522.json"

        self.assertEqual(record_url(BASE_URL, CVE), expected)
        self.assertEqual(record_url(BASE_URL + "/", CVE), expected)


class TimestampTests(unittest.TestCase):
    def test_both_live_spellings(self) -> None:
        self.assertEqual(
            normalize_iso_timestamp("2024-05-08T00:00:00"), "2024-05-08T00:00:00Z"
        )
        self.assertEqual(
            normalize_iso_timestamp("2024-08-01T23:44:09.661Z"),
            "2024-08-01T23:44:09Z",
        )

    def test_a_non_utc_offset_is_dropped_rather_than_shifted(self) -> None:
        self.assertIsNone(normalize_iso_timestamp("2024-05-08T00:00:00+02:00"))

    def test_unusable_values(self) -> None:
        self.assertIsNone(normalize_iso_timestamp(None))
        self.assertIsNone(normalize_iso_timestamp("May 8, 2024"))


class ContainerTests(unittest.TestCase):
    def test_the_cisa_container_is_selected_not_the_first_one(self) -> None:
        container = find_adp_container(REAL_RECORD)

        self.assertEqual(container["title"], "CISA ADP Vulnrichment")

    def test_no_adp_container(self) -> None:
        self.assertIsNone(find_adp_container({"containers": {"adp": []}}))
        self.assertIsNone(find_adp_container({"containers": {}}))
        self.assertIsNone(find_adp_container(None))


class RealRecordTests(unittest.TestCase):
    """The live ``CVE-2024-25522`` record, end to end."""

    def setUp(self) -> None:
        self.record = parse_vulnrichment_record(REAL_RECORD)

    def test_identity_and_dates(self) -> None:
        self.assertEqual(self.record.cve_id, CVE)
        self.assertEqual(self.record.state, "PUBLISHED")
        self.assertEqual(self.record.published_at, "2024-05-08T00:00:00Z")
        self.assertEqual(self.record.updated_at, "2024-08-01T23:44:09Z")
        self.assertEqual(self.record.adp_updated_at, "2024-05-24T15:01:00Z")
        self.assertEqual(self.record.data_version, "5.1")

    def test_ssvc_decision_points_including_the_spaced_key(self) -> None:
        self.assertEqual(self.record.ssvc.exploitation, "poc")
        self.assertEqual(self.record.ssvc.automatable, "yes")
        self.assertEqual(self.record.ssvc.technical_impact, "total")
        self.assertEqual(self.record.ssvc.version, "2.0.3")
        self.assertEqual(self.record.ssvc.role, "CISA Coordinator")
        self.assertEqual(
            self.record.ssvc.decision_points,
            {"exploitation": "poc", "automatable": "yes", "technical_impact": "total"},
        )

    def test_cvss(self) -> None:
        self.assertEqual(self.record.cvss.base_score, 9.4)
        self.assertEqual(self.record.cvss.version, "3.1")
        self.assertEqual(self.record.cvss.base_severity, "CRITICAL")
        self.assertTrue(self.record.cvss.vector.startswith("CVSS:3.1/"))

    def test_cwe_comes_from_the_adp_container(self) -> None:
        self.assertEqual(self.record.cwes, ["CWE-89"])

    def test_vendor_and_product_come_from_the_adp_not_the_cna(self) -> None:
        # The CNA container publishes vendor "n/a", which is not a vendor name.
        self.assertEqual(self.record.vendor, "ruvar")
        self.assertEqual(self.record.product, "ruvarOA")

    def test_the_cna_description_is_used(self) -> None:
        self.assertIn("SQL injection", self.record.description)

    def test_this_record_carries_no_kev_metric(self) -> None:
        self.assertIsNone(self.record.kev_date_added)
        self.assertIsNone(self.record.kev_reference)

    def test_the_payload_never_carries_exploitation_evidence(self) -> None:
        payload = self.record.to_payload(source_key="cisa_vulnrichment")

        for key in FORBIDDEN_PAYLOAD_KEYS:
            self.assertNotIn(key, payload, f"{key} must never be published")

    def test_entities_are_cve_keyed(self) -> None:
        entities = self.record.entities()

        self.assertEqual(entities[0].kind, "cve")
        self.assertEqual(entities[0].normalized, CVE)
        self.assertEqual(entities[1].kind, "vendor_product")


def ssvc_metric(
    exploitation: str = "none",
    automatable: str = "no",
    impact: str = "partial",
    version: str = "2.0.3",
) -> dict:
    return {
        "other": {
            "type": "ssvc",
            "content": {
                "options": [
                    {"Exploitation": exploitation},
                    {"Automatable": automatable},
                    {"Technical Impact": impact},
                ],
                "version": version,
            },
        }
    }


def cisa_container(
    *, metrics=None, affected=None, problem_types=None, updated_at=None
) -> dict:
    container = {
        "providerMetadata": {
            "shortName": "CISA-ADP",
            "dateUpdated": updated_at or "2026-01-01T00:00:00Z",
        },
        "metrics": metrics if metrics is not None else [ssvc_metric()],
    }

    if affected is not None:
        container["affected"] = affected

    if problem_types is not None:
        container["problemTypes"] = problem_types

    return container


def cve_record(
    *, adp=None, cna=None, cve_id: str = CVE, state: str = "PUBLISHED", data_type=None
) -> dict:
    record = {
        "containers": {
            "adp": adp if adp is not None else [cisa_container()],
            "cna": cna or {},
        },
        "cveMetadata": {"cveId": cve_id, "state": state},
        "dataVersion": "5.1",
    }

    if data_type is not None:
        record["dataType"] = data_type

    return record


class RejectionTests(unittest.TestCase):
    """Records that exist but carry nothing worth publishing."""

    def test_a_rejected_cve_record_is_not_enrichment(self) -> None:
        with self.assertRaises(VulnrichmentRejected):
            parse_vulnrichment_record(cve_record(state="REJECTED"))

    def test_a_missing_cisa_container_is_not_enrichment(self) -> None:
        with self.assertRaises(VulnrichmentRejected):
            parse_vulnrichment_record(
                cve_record(adp=[{"providerMetadata": {"shortName": "CVE"}}])
            )

    def test_a_container_with_nothing_to_add_is_not_enrichment(self) -> None:
        with self.assertRaises(VulnrichmentRejected):
            parse_vulnrichment_record(cve_record(adp=[cisa_container(metrics=[])]))

    def test_rejection_is_also_a_normalization_error(self) -> None:
        # A caller that only catches NormalizationError must still be safe.
        self.assertTrue(issubclass(VulnrichmentRejected, NormalizationError))

    def test_a_cwe_alone_is_enough_to_publish(self) -> None:
        record = parse_vulnrichment_record(
            cve_record(
                adp=[
                    cisa_container(
                        metrics=[],
                        problem_types=[{"descriptions": [{"cweId": "CWE-79"}]}],
                    )
                ]
            )
        )

        self.assertEqual(record.cwes, ["CWE-79"])

    def test_a_kev_metric_alone_is_enough_to_publish(self) -> None:
        record = parse_vulnrichment_record(
            cve_record(
                adp=[
                    cisa_container(
                        metrics=[
                            {
                                "other": {
                                    "type": "kev",
                                    "content": {
                                        "dateAdded": "2026-01-02",
                                        "reference": "https://www.cisa.gov/kev?q=" + CVE,
                                    },
                                }
                            }
                        ]
                    )
                ]
            )
        )

        self.assertEqual(record.kev_date_added, "2026-01-02")
        self.assertTrue(record.kev_reference.startswith("https://"))

    def test_a_non_https_kev_reference_is_dropped(self) -> None:
        record = parse_vulnrichment_record(
            cve_record(
                adp=[
                    cisa_container(
                        metrics=[
                            {
                                "other": {
                                    "type": "kev",
                                    "content": {
                                        "dateAdded": "2026-01-02",
                                        "reference": "http://insecure.example/kev",
                                    },
                                }
                            }
                        ]
                    )
                ]
            )
        )

        self.assertIsNone(record.kev_reference)
        self.assertEqual(record.kev_date_added, "2026-01-02")


class MalformedRecordTests(unittest.TestCase):
    def test_untrustworthy_payloads_raise(self) -> None:
        for payload in (
            None,
            [],
            {},
            {"cveMetadata": {}},
            {"cveMetadata": {"cveId": "not-a-cve"}},
            cve_record(cve_id="CVE-2026-1"),
        ):
            with self.assertRaises(NormalizationError):
                parse_vulnrichment_record(payload)

    def test_an_unexpected_data_type_is_refused(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_vulnrichment_record(cve_record(data_type="SOMETHING_ELSE"))


class CvssTests(unittest.TestCase):
    def test_v4_is_preferred_over_v3_1(self) -> None:
        cvss = extract_cvss(
            cisa_container(
                metrics=[
                    {"cvssV3_1": {"baseScore": 7.5, "vectorString": "CVSS:3.1/x"}},
                    {"cvssV4_0": {"baseScore": 9.8, "vectorString": "CVSS:4.0/x"}},
                ]
            )
        )

        self.assertEqual(cvss.base_score, 9.8)
        self.assertEqual(cvss.version, "4.0")

    def test_a_missing_version_falls_back_to_the_metric_name(self) -> None:
        cvss = extract_cvss(
            cisa_container(metrics=[{"cvssV3_1": {"baseScore": 5.0}}])
        )

        self.assertEqual(cvss.version, "3.1")

    def test_an_impossible_score_is_ignored(self) -> None:
        self.assertIsNone(
            extract_cvss(cisa_container(metrics=[{"cvssV3_1": {"baseScore": 42}}]))
        )
        self.assertIsNone(
            extract_cvss(cisa_container(metrics=[{"cvssV3_1": {"baseScore": "high"}}]))
        )

    def test_no_metrics_means_no_cvss(self) -> None:
        self.assertIsNone(extract_cvss(cisa_container(metrics=[])))


class SsvcTests(unittest.TestCase):
    def test_an_unrecognised_value_is_dropped_not_guessed(self) -> None:
        ssvc = extract_ssvc(
            cisa_container(
                metrics=[ssvc_metric(exploitation="everywhere", impact="total")]
            )
        )

        self.assertIsNone(ssvc.exploitation)
        self.assertEqual(ssvc.technical_impact, "total")

    def test_values_are_case_insensitive(self) -> None:
        ssvc = extract_ssvc(
            cisa_container(
                metrics=[
                    ssvc_metric(
                        exploitation="ACTIVE", automatable="YES", impact="TOTAL"
                    )
                ]
            )
        )

        self.assertEqual(
            ssvc.decision_points,
            {
                "exploitation": "active",
                "automatable": "yes",
                "technical_impact": "total",
            },
        )

    def test_no_ssvc_metric(self) -> None:
        self.assertIsNone(extract_ssvc(cisa_container(metrics=[])))


class CacheTests(unittest.TestCase):
    """The memory that makes a bounded fetch converge."""

    def setUp(self) -> None:
        self.store = make_store()
        self.cache = RecordCache(self.store, filename=CACHE_FILENAME)
        self.cache.load()

    def test_unseen_cves_come_first_newest_identifier_first(self) -> None:
        pending = self.cache.pending(
            ["CVE-2024-1", "CVE-2024-3", "CVE-2024-2"],
            limit=10,
            now="2026-10-31T00:00:00Z",
        )

        self.assertEqual(pending, ["CVE-2024-3", "CVE-2024-2", "CVE-2024-1"])

    def test_a_newly_published_cve_is_preferred_over_an_older_unseen_one(self) -> None:
        """A new KEV entry must not wait for the whole catalogue to be swept."""

        pending = self.cache.pending(
            ["CVE-2002-0367", "CVE-2026-97229"],
            limit=1,
            now="2026-10-31T00:00:00Z",
        )

        self.assertEqual(pending, ["CVE-2026-97229"])

    def test_the_batch_is_bounded(self) -> None:
        pending = self.cache.pending(
            [f"CVE-2024-{index:04d}" for index in range(100)],
            limit=5,
            now="2026-10-31T00:00:00Z",
        )

        self.assertEqual(len(pending), 5)
        self.assertEqual(pending[0], "CVE-2024-0099")

    def test_a_cached_cve_is_never_pending_again(self) -> None:
        self.cache.add(CVE, {"cve_id": CVE}, fetched_at="2026-10-31T00:00:00Z")

        self.assertEqual(
            self.cache.pending([CVE], limit=10, now="2026-10-31T00:00:00Z"), []
        )

    def test_an_absent_cve_is_not_retried_inside_the_window(self) -> None:
        self.cache.mark_absent(CVE, at="2026-10-31T00:00:00Z")

        self.assertEqual(
            self.cache.pending([CVE], limit=10, now="2026-11-05T00:00:00Z"), []
        )

    def test_an_absent_cve_is_retried_after_the_window(self) -> None:
        self.cache.mark_absent(CVE, at="2026-10-31T00:00:00Z")

        self.assertEqual(
            self.cache.pending([CVE], limit=10, now="2026-12-05T00:00:00Z"), [CVE]
        )

    def test_a_successful_add_clears_the_absent_marker(self) -> None:
        self.cache.mark_absent(CVE, at="2026-10-31T00:00:00Z")
        self.cache.add(CVE, {"cve_id": CVE}, fetched_at="2026-10-31T00:00:00Z")

        self.assertTrue(self.cache.has(CVE))
        self.assertEqual(self.cache.absent_count, 0)

    def test_the_cache_survives_a_round_trip(self) -> None:
        self.cache.add(CVE, {"cve_id": CVE, "cvss": {"base_score": 9.4}},
                       fetched_at="2026-10-31T00:00:00Z")
        self.cache.mark_absent("CVE-2024-9999", at="2026-10-31T00:00:00Z")
        self.cache.save()

        reloaded = RecordCache(self.store, filename=CACHE_FILENAME)
        reloaded.load()

        self.assertTrue(reloaded.has(CVE))
        self.assertEqual(reloaded.record_count, 1)
        self.assertEqual(reloaded.absent_count, 1)
        self.assertEqual(
            reloaded.payloads()[0]["cvss"]["base_score"], 9.4
        )

    def test_a_corrupt_cache_is_treated_as_empty_not_as_an_error(self) -> None:
        self.store.state_path(CACHE_FILENAME).write_text(
            "not json at all", encoding="utf-8"
        )

        broken = RecordCache(self.store, filename=CACHE_FILENAME)
        broken.load()

        self.assertEqual(broken.record_count, 0)
        self.assertEqual(broken.absent_count, 0)
        self.assertEqual(
            broken.pending([CVE], limit=10, now="2026-10-31T00:00:00Z"), [CVE]
        )

    def test_a_well_formed_but_useless_cache_is_tolerated(self) -> None:
        self.store.state_path(CACHE_FILENAME).write_text(
            '{"records": {"CVE-2024-1": "not an object"}, "absent": []}',
            encoding="utf-8",
        )

        tolerant = RecordCache(self.store, filename=CACHE_FILENAME)
        tolerant.load()

        self.assertEqual(tolerant.record_count, 0)
        self.assertEqual(tolerant.absent_count, 0)


class CollectorTests(unittest.TestCase):
    def test_an_empty_cve_list_is_a_no_op(self) -> None:
        http = FakeHttp({})

        result = make_collector(http, cve_ids=[]).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertTrue(result.metrics["skipped"])
        self.assertEqual(result.observations, [])
        self.assertEqual(http.calls, [])

    def test_invalid_cve_ids_are_discarded_before_any_request(self) -> None:
        http = FakeHttp({})

        result = make_collector(
            http, cve_ids=["not-a-cve", "CVE-2024-255"]
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(http.calls, [])
        self.assertTrue(result.metrics["skipped"])

    def test_a_fetched_record_is_cached_and_emitted(self) -> None:
        http = FakeHttp({record_url_for(CVE): REAL_RECORD})

        result = make_collector(http, cve_ids=[CVE]).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.metrics["fetches_ok"], 1)
        self.assertEqual(result.metrics["records_with_cvss"], 1)
        self.assertEqual(result.metrics["records_with_ssvc"], 1)

        payload = result.observations[0].payload

        self.assertEqual(payload["ssvc"]["exploitation"], "poc")
        self.assertEqual(payload["cvss"]["base_score"], 9.4)

        for key in FORBIDDEN_PAYLOAD_KEYS:
            self.assertNotIn(key, payload)

    def test_a_second_run_makes_no_request_and_still_emits(self) -> None:
        """The incremental property: the snapshot stays complete for free."""

        store = make_store()
        first = FakeHttp({record_url_for(CVE): REAL_RECORD})

        make_collector(first, cve_ids=[CVE], store=store).collect(
            "2026-10-31T00:00:00Z"
        )

        second = FakeHttp({})

        result = make_collector(second, cve_ids=[CVE], store=store).collect(
            "2026-11-01T00:00:00Z"
        )

        self.assertEqual(second.calls, [])
        self.assertEqual(result.metrics["fetches_attempted"], 0)
        self.assertEqual(result.metrics["cached_records"], 1)
        self.assertEqual(len(result.observations), 1)

    def test_a_404_is_absent_not_a_failure(self) -> None:
        http = FakeHttp(
            {
                record_url_for(CVE): HttpError(
                    "HTTP 404", transient=False, status=404
                )
            }
        )

        result = make_collector(http, cve_ids=[CVE]).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["absent"], 1)
        self.assertEqual(result.metrics["fetch_failures"], 0)

    def test_an_absent_cve_is_not_requested_again_next_run(self) -> None:
        store = make_store()

        make_collector(
            FakeHttp(
                {
                    record_url_for(CVE): HttpError(
                        "HTTP 404", transient=False, status=404
                    )
                }
            ),
            cve_ids=[CVE],
            store=store,
        ).collect("2026-10-31T00:00:00Z")

        second = FakeHttp({})

        result = make_collector(second, cve_ids=[CVE], store=store).collect(
            "2026-11-01T00:00:00Z"
        )

        self.assertEqual(second.calls, [])
        self.assertEqual(result.metrics["cache_absent"], 1)

    def test_a_transient_failure_is_not_remembered_as_absent(self) -> None:
        store = make_store()
        failure = HttpError("HTTP 500", transient=True, status=500)

        result = make_collector(
            FakeHttp({record_url_for(CVE): failure}), cve_ids=[CVE], store=store
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["absent"], 0)
        self.assertEqual(result.metrics["fetch_failures"], 1)

        cache = RecordCache(store, filename=CACHE_FILENAME)
        cache.load()

        self.assertEqual(cache.absent_count, 0)
        self.assertEqual(
            cache.pending([CVE], limit=5, now="2026-11-01T00:00:00Z"), [CVE]
        )

    def test_all_404s_with_an_empty_cache_fail_loudly(self) -> None:
        """A wrong record path must not be recorded as 'CISA covers none'."""

        cves = [f"CVE-2026-{1000 + index}" for index in range(30)]

        http = FakeHttp(
            {
                record_url_for(cve): HttpError(
                    "HTTP 404", transient=False, status=404
                )
                for cve in cves
            }
        )

        result = make_collector(http, cve_ids=cves).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.usable)
        self.assertEqual(result.metrics["absent"], 30)
        self.assertEqual(result.metrics["absent_ratio"], 1.0)

    def test_a_malformed_record_is_counted_and_retried(self) -> None:
        store = make_store()

        result = make_collector(
            FakeHttp({record_url_for(CVE): {"nonsense": True}}),
            cve_ids=[CVE],
            store=store,
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["rejected_malformed"], 1)
        self.assertEqual(result.metrics["absent"], 0)

        cache = RecordCache(store, filename=CACHE_FILENAME)
        cache.load()

        self.assertEqual(
            cache.pending([CVE], limit=5, now="2026-11-01T00:00:00Z"), [CVE]
        )

    def test_a_record_for_the_wrong_cve_is_refused(self) -> None:
        store = make_store()

        result = make_collector(
            FakeHttp({record_url_for(CVE): cve_record(cve_id="CVE-2026-999999")}),
            cve_ids=[CVE],
            store=store,
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["rejected_malformed"], 1)
        self.assertEqual(result.metrics["absent"], 0)
        self.assertFalse(RecordCache(store, filename=CACHE_FILENAME).has(CVE))

    def test_a_record_marked_restrictively_is_refused_by_the_gate(self) -> None:
        store = make_store()

        record = cve_record(
            cna={
                "descriptions": [
                    {"lang": "en", "value": "Handling: TLP:AMBER do not share."}
                ]
            }
        )

        result = make_collector(
            FakeHttp({record_url_for(CVE): record}), cve_ids=[CVE], store=store
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["rejected_tlp"], 1)

        cache = RecordCache(store, filename=CACHE_FILENAME)
        cache.load()

        self.assertFalse(cache.has(CVE))

    def test_the_batch_size_is_respected(self) -> None:
        cves = [f"CVE-2026-{2000 + index}" for index in range(10)]

        http = FakeHttp(
            {record_url_for(cve): cve_record(cve_id=cve) for cve in cves}
        )

        result = make_collector(http, cve_ids=cves, max_fetches=4).collect(
            "2026-10-31T00:00:00Z"
        )

        self.assertEqual(len(http.calls), 4)
        self.assertEqual(result.metrics["fetches_attempted"], 4)
        self.assertEqual(result.metrics["fetches_ok"], 4)
        self.assertEqual(len(result.observations), 4)

    def test_an_attribution_record_is_required(self) -> None:
        from lib.attribution import AttributionError

        with self.assertRaises(AttributionError):
            CisaVulnrichmentCollector(
                vulnrichment_config(key="ghost_source"),
                FakeHttp({}),
                make_store(),
                register=load_register(),
                cve_ids=[CVE],
            )

    def test_a_total_failure_with_a_snapshot_degrades(self) -> None:
        store = make_store()
        config = vulnrichment_config()

        make_collector(
            FakeHttp({record_url_for(CVE): REAL_RECORD}),
            cve_ids=[CVE],
            store=store,
            config=config,
        ).collect("2026-10-30T00:00:00Z")

        # The cache is lost while the last-known-good snapshot survives (a
        # restored state directory, a manual cleanup): degrade, do not fail.
        store.state_path(CACHE_FILENAME).unlink()

        failure = HttpError("HTTP 500", transient=True, status=500)

        result = make_collector(
            FakeHttp({record_url_for(CVE): failure}),
            cve_ids=[CVE],
            store=store,
            config=config,
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "degraded")
        self.assertTrue(result.used_last_known_good)
        self.assertEqual(len(result.observations), 1)


class CorrelationEnrichmentTests(unittest.TestCase):
    """What enrichment may and may not change.

    Before the models were unified, an enrichment observation could not move a
    published number at all: the v0.1 model read the primary record and nothing
    else. Under ``threatpulse_priority_v0.3`` the whole group *is* the evidence, so
    a Vulnrichment record can move the score — that is the point of reading it. What
    it still may not move is identity, title, dates, confidence, exploitation status
    or the legacy score, and whatever it does move is named in ``score_factors``.
    """

    def _threat(self, observations):
        return correlate(observations, reference_date=REFERENCE_DATE)[0]

    def _kev(self):
        return kev_observation("cisa_kev", kev_payload(), cve_entities())

    def test_the_legacy_score_of_the_guard_fixture_is_still_pinned(self) -> None:
        """The v0.1 answer must not drift; that is what the pin was for."""

        threat = self._threat([self._kev()])

        self.assertEqual(
            threat.metadata["legacy_score"]["priority_score"], GUARD_FIXTURE_SCORE
        )
        self.assertEqual(
            threat.metadata["scoring_model"], "threatpulse_priority_v0.3"
        )

    def test_enrichment_cannot_move_identity_dates_or_confidence(self) -> None:
        before = self._threat([self._kev()])
        after = self._threat([self._kev(), enrichment_observation()])

        self.assertEqual(after.threat_uuid, before.threat_uuid)
        self.assertEqual(after.title, before.title)
        self.assertEqual(after.first_seen, before.first_seen)
        self.assertEqual(after.summary, before.summary)
        self.assertEqual(after.confidence_score, before.confidence_score)
        self.assertEqual(after.confidence_level, before.confidence_level)
        self.assertEqual(after.exploitation_status, before.exploitation_status)
        self.assertEqual(
            after.metadata["legacy_score"], before.metadata["legacy_score"]
        )

    def test_enrichment_may_move_the_score_and_says_why(self) -> None:
        before = self._threat([self._kev()])
        after = self._threat([self._kev(), enrichment_observation()])

        self.assertGreaterEqual(after.priority_score, before.priority_score)

        # A second source is itself evidence, so corroboration rises even when the
        # enrichment carries no CVSS. The reasoning has to name it.
        self.assertGreater(
            after.metadata["score_factors"]["evidence"],
            before.metadata["score_factors"]["evidence"],
        )
        self.assertTrue(
            any(
                "independent source" in line
                for line in after.metadata["reasoning"]
            )
        )

    def test_enrichment_fills_the_cvss_gap_the_kev_record_leaves(self) -> None:
        before = self._threat([self._kev()])
        after = self._threat([self._kev(), enrichment_observation()])

        # The KEV catalogue publishes no CVSS at all, so this is a real gap.
        self.assertIsNone(before.vulnerabilities[0].cvss_score)
        self.assertEqual(after.vulnerabilities[0].cvss_score, 9.4)
        self.assertTrue(after.vulnerabilities[0].cvss_vector.startswith("CVSS:3.1/"))
        self.assertEqual(after.metadata["cvss_source"], "cisa_vulnrichment")

    def test_ssvc_decision_points_are_published(self) -> None:
        after = self._threat([self._kev(), enrichment_observation()])

        self.assertEqual(after.metadata["ssvc"]["exploitation"], "poc")
        self.assertEqual(after.metadata["ssvc"]["technical_impact"], "total")
        self.assertEqual(after.metadata["ssvc_source"], "cisa_vulnrichment")

    def test_a_threat_without_enrichment_gains_no_metadata_keys(self) -> None:
        metadata = self._threat([self._kev()]).metadata

        self.assertNotIn("ssvc", metadata)
        self.assertNotIn("ssvc_source", metadata)
        self.assertNotIn("cvss_source", metadata)

    def test_enrichment_alone_cannot_create_a_threat(self) -> None:
        """This source carries no exploitation evidence, so it cannot invent one."""

        stats: dict = {}

        threats = correlate(
            [enrichment_observation()], reference_date=REFERENCE_DATE, stats=stats
        )

        self.assertEqual(threats, [])
        self.assertEqual(stats["cve_groups_without_scoreable_evidence"], 1)

    def test_the_primary_records_own_cvss_wins(self) -> None:
        payload = {
            **kev_payload(),
            "cvss_score": 5.0,
            "cvss_vector": "CVSS:3.1/AV:L/AC:H/x",
        }

        threat = self._threat(
            [
                kev_observation("cisa_kev", payload, cve_entities()),
                enrichment_observation(cvss=9.4),
            ]
        )

        self.assertEqual(threat.vulnerabilities[0].cvss_score, 5.0)
        self.assertEqual(
            threat.vulnerabilities[0].cvss_vector, "CVSS:3.1/AV:L/AC:H/x"
        )
        self.assertNotIn("cvss_source", threat.metadata)

    def test_the_enrichment_source_is_credited(self) -> None:
        threat = self._threat([self._kev(), enrichment_observation()])

        self.assertIn("cisa_vulnrichment", threat.source_keys)
        self.assertIn(
            "cisa_vulnrichment", {item.source_key for item in threat.evidence}
        )

"""Phase 1 tests for the EPSS and ransomware.live collectors.

The assertions that matter most here are not "does it parse" but the rules the
product depends on:

* EPSS never overrides exploitation evidence, and an empty CVE list is a no-op;
* **victim identities never reach the stored observation** (privacy);
* overlapping feeds must not inflate a regional signal (max, not sum).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from collectors.epss import EpssCollector
from collectors.ransomware_live import RansomwareLiveCollector, merge_feeds
from lib.attribution import load_register
from lib.config import SourceConfig
from lib.http import HttpError
from normalization.cisa import NormalizationError
from normalization.epss import (
    build_epss_observation,
    parse_epss_payload,
)
from normalization.ransomware_live import (
    VictimObservation,
    aggregate_victims,
    build_observation,
    parse_victims,
)
from state.store import StateStore

EPSS_URL = "https://api.first.org/data/v1/epss"
VICTIMS_URL = "https://api.ransomware.live/v2/recentvictims"
GREECE_URL = "https://api.ransomware.live/v2/countryvictims/GR"


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def json(self) -> object:
        return self._payload


class Queue(list):
    """Marks a list as a *queue of outcomes* rather than a response payload.

    Needed because a real ransomware.live response is itself a JSON array, so
    "value is a list" cannot mean "queue" without ambiguity.
    """


class FakeHttp:
    """Stand-in for HttpClient, matching URLs by prefix and supporting queues."""

    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = {key: value for key, value in responses.items()}
        self.calls: list[str] = []

    def get(self, url: str, *, timeout_seconds=None, headers=None) -> FakeResponse:
        self.calls.append(url)

        for key, value in self.responses.items():
            if not url.startswith(key):
                continue

            outcome = value

            if isinstance(value, Queue):
                if not value:
                    raise HttpError(f"no fixture left for {url}", transient=False)

                outcome = value.pop(0)

            if isinstance(outcome, Exception):
                raise outcome

            return FakeResponse(outcome)

        raise HttpError(f"no fixture for {url}", transient=False)


def make_store() -> StateStore:
    root = Path(tempfile.mkdtemp())

    return StateStore(root / "state", root / "data")


def epss_config(**overrides) -> SourceConfig:
    values = {
        "key": "epss_first",
        "name": "Exploit Prediction Scoring System (EPSS)",
        "source_type": "exploitation_probability",
        "url": "https://www.first.org/epss/",
        "feed_url": EPSS_URL,
        "provider": "FIRST",
        "reliability": "high",
        "enabled": True,
        "required": False,
        "timeout_seconds": 5.0,
        "tier": 1,
        "feeds": (),
    }
    values.update(overrides)

    return SourceConfig(**values)


def victims_config(**overrides) -> SourceConfig:
    values = {
        "key": "ransomware_live",
        "name": "Ransomware.live",
        "source_type": "ransomware_observations",
        "url": "https://www.ransomware.live/",
        "feed_url": VICTIMS_URL,
        "provider": "Ransomware.live",
        "reliability": "medium",
        "enabled": True,
        "required": False,
        "timeout_seconds": 5.0,
        "tier": 1,
        "feeds": (),
    }
    values.update(overrides)

    return SourceConfig(**values)


def epss_payload(*rows: dict) -> dict:
    return {"status": "OK", "data": list(rows)}


def victim(*, name: str = "Acme SA", group: str = "lockbit", country: str = "GR", sector: str = "manufacturing", date: str = "2026-10-20") -> dict:
    return {
        "victim": name,
        "group": group,
        "country": country,
        "sector": sector,
        "attackdate": date,
    }


class EpssNormalizationTests(unittest.TestCase):
    def test_parses_a_valid_row(self) -> None:
        records, rejections = parse_epss_payload(
            epss_payload(
                {
                    "cve": "cve-2024-3400",
                    "epss": "0.999990000",
                    "percentile": "1.000000000",
                    "date": "2026-10-30",
                }
            )
        )

        self.assertEqual(rejections, [])
        self.assertEqual(len(records), 1)

        record = records[0]

        self.assertEqual(record.cve_id, "CVE-2024-3400")
        self.assertAlmostEqual(record.epss, 0.99999)
        self.assertAlmostEqual(record.percentile, 1.0)
        self.assertEqual(record.score_date, "2026-10-30")

    def test_rejects_out_of_range_scores(self) -> None:
        records, rejections = parse_epss_payload(
            epss_payload({"cve": "CVE-2024-3400", "epss": "1.5", "percentile": "0.5"})
        )

        self.assertEqual(records, [])
        self.assertIn("invalid epss value", rejections[0])

    def test_rejects_an_invalid_cve(self) -> None:
        records, rejections = parse_epss_payload(
            epss_payload({"cve": "not-a-cve", "epss": "0.5", "percentile": "0.5"})
        )

        self.assertEqual(records, [])
        self.assertIn("invalid CVE identifier", rejections[0])

    def test_rejects_a_non_object_row_without_discarding_the_batch(self) -> None:
        payload = {
            "data": [
                "nonsense",
                {"cve": "CVE-2024-3400", "epss": "0.5", "percentile": "0.5"},
            ]
        }

        records, rejections = parse_epss_payload(payload)

        self.assertEqual(len(records), 1)
        self.assertEqual(len(rejections), 1)

    def test_structurally_invalid_responses_are_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_epss_payload(["not", "an", "object"])

        with self.assertRaises(NormalizationError):
            parse_epss_payload({"status": "OK"})

    def test_observation_carries_provenance(self) -> None:
        records, _ = parse_epss_payload(
            epss_payload({"cve": "CVE-2024-3400", "epss": "0.5", "percentile": "0.9"})
        )

        observation = build_epss_observation(
            records[0], source_key="epss_first", retrieved_at="2026-10-31T00:00:00Z"
        )

        self.assertEqual(observation.external_id, "CVE-2024-3400")
        self.assertEqual(observation.payload["source"], "epss_first")
        self.assertEqual(observation.entities[0].kind, "cve")


class EpssCollectorTests(unittest.TestCase):
    def _collector(self, http, *, cve_ids=(), store=None) -> EpssCollector:
        return EpssCollector(
            epss_config(),
            http,
            store or make_store(),
            register=load_register(),
            cve_ids=cve_ids,
        )

    def test_empty_cve_list_is_a_no_op_not_a_failure(self) -> None:
        store = make_store()
        result = self._collector(FakeHttp({}), store=store).collect(
            "2026-10-31T00:00:00Z"
        )

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.observations, [])
        self.assertTrue(result.metrics["skipped"])
        self.assertTrue(result.usable)
        self.assertFalse(store.state_path("last_known_good_epss_first.json").exists())

    def test_scores_the_supplied_cves(self) -> None:
        http = FakeHttp(
            {
                EPSS_URL: epss_payload(
                    {"cve": "CVE-2024-3400", "epss": "0.99", "percentile": "1.0"},
                    {"cve": "CVE-2023-22894", "epss": "0.10", "percentile": "0.5"},
                )
            }
        )

        result = self._collector(
            http, cve_ids=["CVE-2024-3400", "CVE-2023-22894"]
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 2)
        self.assertEqual(result.metrics["cves_requested"], 2)
        self.assertEqual(result.metrics["cves_missing"], 0)

    def test_batches_respect_the_api_limit(self) -> None:
        cve_ids = [f"CVE-2026-{10000 + index}" for index in range(150)]

        http = FakeHttp(
            {
                EPSS_URL: epss_payload(
                    {"cve": "CVE-2026-10000", "epss": "0.5", "percentile": "0.5"}
                )
            }
        )

        result = self._collector(http, cve_ids=cve_ids).collect("2026-10-31T00:00:00Z")

        self.assertEqual(len(http.calls), 2)
        self.assertEqual(result.metrics["batches_total"], 2)
        self.assertEqual(result.metrics["cves_requested"], 150)
        self.assertEqual(result.metrics["cves_missing"], 149)

    def test_one_failed_batch_does_not_discard_the_others(self) -> None:
        cve_ids = [f"CVE-2026-{10000 + index}" for index in range(150)]

        http = FakeHttp(
            {
                EPSS_URL: Queue(
                    [
                        epss_payload(
                            {"cve": "CVE-2026-10000", "epss": "0.5", "percentile": "0.5"}
                        ),
                        HttpError("HTTP 503", transient=True, status=503),
                    ]
                )
            }
        )

        result = self._collector(http, cve_ids=cve_ids).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.metrics["batches_failed"], 1)

    def test_all_batches_failing_without_a_snapshot_fails(self) -> None:
        http = FakeHttp({EPSS_URL: HttpError("HTTP 500", transient=True, status=500)})

        result = self._collector(http, cve_ids=["CVE-2024-3400"]).collect(
            "2026-10-31T00:00:00Z"
        )

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.usable)

    def test_all_batches_failing_with_a_snapshot_degrades(self) -> None:
        store = make_store()

        good = FakeHttp(
            {
                EPSS_URL: epss_payload(
                    {"cve": "CVE-2024-3400", "epss": "0.9", "percentile": "1.0"}
                )
            }
        )

        self._collector(good, cve_ids=["CVE-2024-3400"], store=store).collect(
            "2026-10-30T00:00:00Z"
        )

        failing = FakeHttp({EPSS_URL: HttpError("HTTP 500", transient=True, status=500)})

        result = self._collector(
            failing, cve_ids=["CVE-2024-3400"], store=store
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "degraded")
        self.assertTrue(result.used_last_known_good)
        self.assertEqual(len(result.observations), 1)


class RansomwarePrivacyTests(unittest.TestCase):
    """The privacy rule is a product commitment, so it is asserted directly."""

    def test_victim_name_is_not_stored_in_the_payload(self) -> None:
        observations, rejections = parse_victims([victim(name="Acme Shipping SA")])

        self.assertEqual(rejections, [])

        serialized = json.dumps(
            observations[0].to_payload(source_key="ransomware_live")
        )

        self.assertNotIn("Acme", serialized)
        self.assertNotIn("Shipping", serialized)

    def test_victim_name_is_not_in_the_observation(self) -> None:
        observations, _ = parse_victims([victim(name="Acme Shipping SA")])

        observation = build_observation(
            observations[0],
            source_key="ransomware_live",
            retrieved_at="2026-10-31T00:00:00Z",
        )

        serialized = json.dumps(observation.to_dict())

        self.assertNotIn("Acme", serialized)
        self.assertNotIn("acme", serialized.lower())

    def test_identity_is_a_digest_not_a_name(self) -> None:
        observations, _ = parse_victims([victim(name="Acme Shipping SA")])
        identity = observations[0].identity()

        self.assertEqual(len(identity), 32)
        self.assertNotIn("acme", identity.lower())

    def test_payload_declares_that_identity_was_withheld(self) -> None:
        observations, _ = parse_victims([victim()])
        payload = observations[0].to_payload(source_key="ransomware_live")

        self.assertTrue(payload["aggregate"])
        self.assertTrue(payload["victim_identity_withheld"])
        self.assertEqual(payload["victim_count"], 1)


class RansomwareNormalizationTests(unittest.TestCase):
    def test_parses_a_valid_claim(self) -> None:
        observations, rejections = parse_victims([victim()])

        self.assertEqual(rejections, [])
        self.assertEqual(len(observations), 1)

        observation = observations[0]

        self.assertEqual(observation.group, "lockbit")
        self.assertEqual(observation.country, "GR")
        self.assertEqual(observation.sector, "manufacturing")
        self.assertEqual(observation.attack_date, "2026-10-20")

    def test_aggregates_identical_claims_with_a_count(self) -> None:
        observations, _ = parse_victims(
            [victim(name="One SA"), victim(name="Two SA"), victim(name="Three SA")]
        )

        aggregates = aggregate_victims(observations)

        self.assertEqual(len(aggregates), 1)
        self.assertEqual(aggregates[0].victim_count, 3)

    def test_different_sectors_are_separate_aggregates(self) -> None:
        observations, _ = parse_victims(
            [victim(sector="manufacturing"), victim(sector="shipping")]
        )

        aggregates = aggregate_victims(observations)

        self.assertEqual(len(aggregates), 2)
        self.assertEqual(
            {entry.sector for entry in aggregates}, {"manufacturing", "shipping"}
        )

    def test_different_groups_and_countries_are_separate(self) -> None:
        observations, _ = parse_victims(
            [victim(group="lockbit"), victim(group="akira"), victim(country="CY")]
        )

        self.assertEqual(len(aggregate_victims(observations)), 3)

    def test_rejects_a_missing_or_invalid_country(self) -> None:
        records = [victim(country=""), victim(country="GRC"), victim(country="12")]

        observations, rejections = parse_victims(records)

        self.assertEqual(observations, [])
        self.assertEqual(len(rejections), 3)

    def test_rejects_a_missing_group(self) -> None:
        record = victim()
        record["group"] = ""

        observations, rejections = parse_victims([record])

        self.assertEqual(observations, [])
        self.assertIn("missing ransomware group", rejections[0])

    def test_rejects_a_record_with_no_victim_claim(self) -> None:
        observations, rejections = parse_victims(
            [{"group": "lockbit", "country": "GR"}]
        )

        self.assertEqual(observations, [])
        self.assertIn("no victim claim present", rejections[0])


class RansomwareNormalizationExtraTests(unittest.TestCase):
    def test_rejects_non_object_rows(self) -> None:
        observations, rejections = parse_victims(["nonsense"])

        self.assertEqual(observations, [])
        self.assertIn("not an object", rejections[0])

    def test_structurally_invalid_payloads_are_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_victims("not a feed")

        with self.assertRaises(NormalizationError):
            parse_victims({"unexpected": True})

    def test_accepts_a_data_wrapper(self) -> None:
        observations, rejections = parse_victims({"data": [victim()]})

        self.assertEqual(len(observations), 1)
        self.assertEqual(rejections, [])

    def test_identity_is_stable_and_country_sensitive(self) -> None:
        first, _ = parse_victims([victim()])
        second, _ = parse_victims([victim(name="A completely different name")])
        third, _ = parse_victims([victim(country="CY")])

        self.assertEqual(first[0].identity(), second[0].identity())
        self.assertNotEqual(first[0].identity(), third[0].identity())

    def test_entities_cover_country_actor_and_sector(self) -> None:
        observations, _ = parse_victims([victim()])
        kinds = {entity.kind for entity in observations[0].entities()}

        self.assertEqual(kinds, {"country", "actor", "sector"})

    def test_sector_is_omitted_when_absent(self) -> None:
        record = victim()
        record.pop("sector")

        observations, _ = parse_victims([record])

        self.assertIsNone(observations[0].sector)
        self.assertEqual(
            {entity.kind for entity in observations[0].entities()},
            {"country", "actor"},
        )

    def test_alternate_sector_field_names_are_accepted(self) -> None:
        record = victim()
        record.pop("sector")
        record["activity"] = "Energy"

        observations, _ = parse_victims([record])

        self.assertEqual(observations[0].sector, "Energy")


class MergeFeedsTests(unittest.TestCase):
    """Overlapping feeds must not inflate a regional signal."""

    def test_counts_are_merged_with_max_not_sum(self) -> None:
        first = [VictimObservation("lockbit", "GR", "shipping", "2026-10-20", 2)]
        second = [VictimObservation("lockbit", "GR", "shipping", "2026-10-20", 3)]

        merged = merge_feeds([first, second])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].victim_count, 3)

    def test_distinct_aggregates_are_all_kept(self) -> None:
        first = [VictimObservation("lockbit", "GR", "shipping", "2026-10-20", 2)]
        second = [VictimObservation("akira", "CY", None, None, 1)]

        merged = merge_feeds([first, second])

        self.assertEqual(len(merged), 2)


class RansomwareLiveCollectorTests(unittest.TestCase):
    def _collector(self, http, *, config=None, store=None) -> RansomwareLiveCollector:
        return RansomwareLiveCollector(
            config or victims_config(),
            http,
            store or make_store(),
            register=load_register(),
        )

    def test_collects_aggregates_and_counts_the_primary_country(self) -> None:
        http = FakeHttp(
            {
                VICTIMS_URL: [
                    victim(name="One SA"),
                    victim(name="Two SA"),
                    victim(name="Three SA", country="CY", sector="banking"),
                ]
            }
        )

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.metrics["victim_claims_seen"], 3)
        self.assertEqual(result.metrics["aggregates"], 2)
        self.assertEqual(result.metrics["countries_observed"], 2)
        self.assertEqual(result.metrics["primary_country_aggregates"], 1)
        self.assertEqual(result.metrics["primary_country_victim_count"], 2)

    def test_overlapping_feeds_do_not_inflate_counts(self) -> None:
        http = FakeHttp(
            {
                VICTIMS_URL: [victim(name="One SA")],
                GREECE_URL: [victim(name="One SA"), victim(name="Two SA")],
            }
        )

        result = self._collector(
            http, config=victims_config(feeds=(VICTIMS_URL, GREECE_URL))
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.metrics["victim_claims_seen"], 3)
        self.assertEqual(result.metrics["aggregates"], 1)
        self.assertEqual(result.metrics["primary_country_victim_count"], 2)

    def test_victim_names_never_reach_the_stored_observation(self) -> None:
        http = FakeHttp({VICTIMS_URL: [victim(name="Acme Shipping SA")]})

        result = self._collector(http).collect("2026-10-31T00:00:00Z")
        serialized = json.dumps(
            [observation.to_dict() for observation in result.observations]
        )

        self.assertNotIn("Acme", serialized)
        self.assertNotIn("acme", serialized.lower())

    def test_partial_failure_is_not_total_failure(self) -> None:
        http = FakeHttp(
            {
                VICTIMS_URL: [victim()],
                GREECE_URL: HttpError("HTTP 503", transient=True, status=503),
            }
        )

        result = self._collector(
            http, config=victims_config(feeds=(VICTIMS_URL, GREECE_URL))
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.metrics["feeds_ok"], 1)
        self.assertEqual(result.metrics["feeds_failed"], 1)
        self.assertTrue(result.metrics["partial"])

    def test_zero_aggregates_without_a_snapshot_fails(self) -> None:
        http = FakeHttp({VICTIMS_URL: []})

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.usable)

    def test_zero_aggregates_with_a_snapshot_degrades(self) -> None:
        store = make_store()

        good = FakeHttp({VICTIMS_URL: [victim()]})
        self._collector(good, store=store).collect("2026-10-30T00:00:00Z")

        empty = FakeHttp({VICTIMS_URL: []})
        result = self._collector(empty, store=store).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "degraded")
        self.assertTrue(result.used_last_known_good)
        self.assertEqual(len(result.observations), 1)

    def test_all_feeds_failing_without_a_snapshot_fails(self) -> None:
        http = FakeHttp(
            {VICTIMS_URL: HttpError("HTTP 500", transient=True, status=500)}
        )

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "failed")

    def test_attribution_record_is_required(self) -> None:
        from lib.attribution import AttributionError

        with self.assertRaises(AttributionError):
            RansomwareLiveCollector(
                victims_config(key="ghost_source"),
                FakeHttp({VICTIMS_URL: [victim()]}),
                make_store(),
                register=load_register(),
            )






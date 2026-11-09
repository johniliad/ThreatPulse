"""Wiring tests: the publication-side TLP gate and the collector registry.

Two classes of mistake these guard against:

* a publication carrying material that should never be public, whether it
  arrived through the ingest gate or hid inside a summary or metadata field;
* a source that is enabled in configuration but has no collector, which would
  otherwise be silently skipped and reported as "no intelligence".
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import run_pipeline  # noqa: E402
from collectors.cisa_kev import CisaKevCollector  # noqa: E402
from collectors.epss import EpssCollector  # noqa: E402
from collectors.ransomware_live import RansomwareLiveCollector  # noqa: E402
from collectors.rss_feed import RssFeedCollector  # noqa: E402
from lib.attribution import load_register  # noqa: E402
from lib.config import load_settings  # noqa: E402
from publication import chunking, quality_gate  # noqa: E402
from state.store import StateStore  # noqa: E402
from tests.test_publication_publisher import minimal_publication  # noqa: E402


class TlpPublicationGateTests(unittest.TestCase):
    def test_a_clean_publication_has_no_marking_problems(self) -> None:
        self.assertEqual(
            quality_gate.validate_tlp_markings(minimal_publication()), []
        )

    def test_a_clear_marking_is_allowed(self) -> None:
        payload = minimal_publication()
        payload["threats"][0]["summary"] = "Handling: TLP:CLEAR."

        self.assertEqual(quality_gate.validate_tlp_markings(payload), [])

    def test_a_restrictive_marking_anywhere_blocks_publication(self) -> None:
        for marking in ("TLP:AMBER", "tlp:amber+strict", "TLP:RED", "TLP:GREEN"):
            payload = minimal_publication()
            payload["threats"][0]["summary"] = f"Handling: {marking}."

            self.assertTrue(
                quality_gate.validate_tlp_markings(payload),
                f"{marking} was not detected",
            )

    def test_a_marking_hidden_in_metadata_is_caught(self) -> None:
        payload = minimal_publication()
        payload["threats"][0]["metadata"] = {"note": "TLP:AMBER do not share"}

        self.assertTrue(quality_gate.validate_tlp_markings(payload))

    def test_assert_publishable_blocks_a_marking(self) -> None:
        payload = minimal_publication()
        payload["threats"][0]["title"] = "TLP:RED advisory"

        with self.assertRaises(quality_gate.QualityGateError):
            quality_gate.assert_publishable(payload)


class SourcePermissionTests(unittest.TestCase):
    def test_a_registered_ingestible_source_is_allowed(self) -> None:
        self.assertEqual(
            quality_gate.validate_source_permission(
                minimal_publication(), load_register()
            ),
            [],
        )

    def test_an_unregistered_source_is_refused(self) -> None:
        payload = minimal_publication()
        payload["threats"][0]["source_keys"] = ["ghost_source"]

        problems = quality_gate.validate_source_permission(payload, load_register())

        self.assertTrue(any("no attribution record" in p for p in problems))

    def test_a_non_ingestible_source_is_refused(self) -> None:
        payload = minimal_publication()
        payload["threats"][0]["source_keys"] = ["nvd"]

        problems = quality_gate.validate_source_permission(payload, load_register())

        self.assertTrue(any("not permitted for publication" in p for p in problems))

    def test_assert_publishable_with_a_register_refuses_an_unattributed_source(
        self,
    ) -> None:
        payload = minimal_publication()
        payload["threats"][0]["source_keys"] = ["nvd"]
        payload["sources"] = [dict(payload["sources"][0], source_key="nvd")]

        with self.assertRaises(quality_gate.QualityGateError):
            quality_gate.assert_publishable(payload, register=load_register())


class CollectorRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.settings = load_settings()
        cls.register = load_register()

        root = Path(tempfile.mkdtemp())
        cls.state = StateStore(root / "state", root / "data")

    def _collector(self, key: str, **kwargs):
        return run_pipeline.build_source_collector(
            self.settings.source(key),
            self.settings,
            self.state,
            self.register,
            **kwargs,
        )

    def test_cisa_kev_uses_its_own_collector(self) -> None:
        self.assertIsInstance(self._collector("cisa_kev"), CisaKevCollector)

    def test_rss_sources_use_the_generic_collector(self) -> None:
        for key in sorted(run_pipeline.RSS_SOURCE_KEYS):
            self.assertIsInstance(self._collector(key), RssFeedCollector, key)

    def test_ransomware_live_uses_its_collector(self) -> None:
        self.assertIsInstance(
            self._collector("ransomware_live"), RansomwareLiveCollector
        )

    def test_epss_receives_the_discovered_cves(self) -> None:
        collector = self._collector("epss_first", cve_ids=["CVE-2026-109619"])

        self.assertIsInstance(collector, EpssCollector)
        self.assertEqual(collector._cve_ids, ["CVE-2026-109619"])

    def test_an_unimplemented_source_returns_none(self) -> None:
        """A source with no collector must be reported, not silently skipped.

        The key is synthetic so this test does not need editing every time a real
        source gains a collector.
        """

        from dataclasses import replace

        unimplemented = replace(
            self.settings.source("cisa_kev"), key="not_implemented_yet"
        )

        self.assertIsNone(
            run_pipeline.build_source_collector(
                unimplemented, self.settings, self.state, self.register
            )
        )

    def test_every_enabled_source_has_an_implemented_collector(self) -> None:
        """An enabled source with no collector would be silently skipped."""

        for source in self.settings.enabled_sources:
            self.assertIsNotNone(
                self._collector(source.key),
                f"{source.key} is enabled but has no collector",
            )

    def test_collection_order_runs_kev_first_and_epss_last(self) -> None:
        keys = ["epss_first", "cert_eu_advisories", "cisa_kev", "ransomware_live"]

        ordered = sorted(
            keys,
            key=lambda key: (
                run_pipeline.COLLECTION_ORDER.get(
                    key, run_pipeline.DEFAULT_COLLECTION_ORDER
                ),
                key,
            ),
        )

        self.assertEqual(ordered[0], "cisa_kev")
        self.assertEqual(ordered[-1], "epss_first")

    def test_national_cert_feeds_covers_many_feeds(self) -> None:
        config = self.settings.source("national_cert_feeds")

        self.assertGreater(len(config.feed_urls), 10)

    def test_the_pipeline_has_an_entry_point(self) -> None:
        """`python3 run_pipeline.py --dry-run` must actually execute."""

        source = (BACKEND_ROOT / "run_pipeline.py").read_text(encoding="utf-8")

        self.assertIn('if __name__ == "__main__":', source)
        self.assertIn("raise SystemExit(main())", source)


class PayloadSizeGuardTests(unittest.TestCase):
    """A publication is split so that every request fits the API's body limit.

    This used to be a single-request guard: a publication larger than the limit was
    refused outright. A live run produced a 10.5 MB publication, which that guard
    refused — correctly, but the fix is to send it in pieces, not to raise the
    ceiling.
    """

    def test_a_small_publication_passes(self) -> None:
        self.assertEqual(
            quality_gate.validate_chunk_sizes(minimal_publication(), 1024 * 1024),
            [],
        )

    def test_a_threat_larger_than_the_limit_is_refused(self) -> None:
        """No amount of chunking fixes a single oversized threat, so the message
        must say so and name the threat rather than the publication."""

        payload = minimal_publication()
        payload["threats"][0]["summary"] = "x" * 5000

        problems = quality_gate.validate_chunk_sizes(payload, 1000)

        self.assertTrue(problems)
        self.assertIn("a single threat does not fit", problems[0])
        self.assertIn("CVE-2026-109619", problems[0])

    def test_a_zero_limit_disables_the_check(self) -> None:
        payload = minimal_publication()
        payload["threats"][0]["summary"] = "x" * 5000

        self.assertEqual(quality_gate.validate_chunk_sizes(payload, 0), [])

    def test_assert_publishable_enforces_the_limit(self) -> None:
        payload = minimal_publication()
        payload["threats"][0]["summary"] = "x" * 5000

        with self.assertRaises(quality_gate.QualityGateError):
            quality_gate.assert_publishable(payload, max_payload_bytes=1000)

    def _many_threats(self, count: int) -> dict:
        payload = minimal_publication()
        payload["threats"] = [
            dict(
                payload["threats"][0],
                external_id=f"CVE-2026-{100000 + index}",
                threat_uuid=f"11111111-2222-3333-4444-{index:012d}",
            )
            for index in range(count)
        ]

        return payload

    def test_a_publication_too_large_for_one_request_is_split(self) -> None:
        payload = self._many_threats(200)
        limit = 8192

        self.assertEqual(quality_gate.validate_chunk_sizes(payload, limit), [])

        plan = chunking.chunk_publication(payload, max_bytes=limit)

        self.assertGreater(plan.count, 1)
        self.assertTrue(all(size <= limit for size in plan.sizes()))

    def test_splitting_preserves_every_threat_in_order(self) -> None:
        payload = self._many_threats(50)

        plan = chunking.chunk_publication(payload, max_bytes=4096)

        rebuilt = [threat for chunk in plan.chunks for threat in chunk["threats"]]

        self.assertEqual(rebuilt, payload["threats"])

    def test_every_chunk_carries_the_publication_envelope(self) -> None:
        """A chunk must be usable on its own, so nothing has to be remembered
        between requests and any chunk can be retried independently."""

        payload = self._many_threats(50)

        plan = chunking.chunk_publication(payload, max_bytes=4096)

        self.assertGreater(plan.count, 1)

        for index, chunk in enumerate(plan.chunks):
            self.assertEqual(chunk["publication_uuid"], payload["publication_uuid"])
            self.assertEqual(chunk["schema_version"], payload["schema_version"])
            self.assertEqual(chunk["summary"], payload["summary"])
            self.assertEqual(chunk["sources"], payload["sources"])
            self.assertEqual(chunk["chunk"], {"index": index, "count": plan.count})

    def test_a_single_request_publication_is_not_chunked(self) -> None:
        plan = chunking.chunk_publication(
            minimal_publication(), max_bytes=1024 * 1024
        )

        self.assertEqual(plan.count, 1)
        self.assertFalse(plan.chunked)

    def test_an_envelope_too_large_to_send_is_refused(self) -> None:
        """Chunking cannot help when the envelope alone does not fit."""

        payload = minimal_publication()
        payload["summary"] = {"description": "x" * 5000}

        problems = quality_gate.validate_chunk_sizes(payload, 1000)

        self.assertTrue(problems)
        self.assertIn("envelope alone", problems[0])

    def test_the_limit_is_configured_and_positive(self) -> None:
        limit = load_settings().publication.max_payload_bytes

        self.assertIsInstance(limit, int)
        self.assertGreater(limit, 0)
        # Deliberately below a common 8 MB post_max_size.
        self.assertLess(limit, 8 * 1024 * 1024)


class SecretScanTests(unittest.TestCase):
    """The credential scan must catch secrets without flagging ordinary prose.

    The first successful run was blocked by the literal marker ``"bearer "``
    appearing in an advisory that discussed bearer tokens. A protocol word is not
    a credential.
    """

    def test_prose_about_bearer_tokens_does_not_block_publication(self) -> None:
        payload = minimal_publication()
        payload["threats"][0]["summary"] = "Attackers reused stolen bearer tokens."

        self.assertEqual(quality_gate.validate_publication(payload), [])

    def test_prose_about_authorization_headers_does_not_block_publication(self) -> None:
        payload = minimal_publication()
        payload["threats"][0]["recommended_action"] = (
            "Review how the Authorization header is handled."
        )

        self.assertEqual(quality_gate.validate_publication(payload), [])

    def test_a_real_bearer_credential_blocks_publication(self) -> None:
        payload = minimal_publication()
        payload["threats"][0]["title"] = (
            "Leak: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        )

        self.assertTrue(quality_gate.validate_publication(payload))

    def test_an_authorization_value_blocks_publication(self) -> None:
        payload = minimal_publication()
        payload["summary"]["n"] = "Authorization: abcdefghijklmnopqrstuvwxyz"

        self.assertTrue(quality_gate.validate_publication(payload))

    def test_the_credential_is_never_echoed_in_the_problem(self) -> None:
        secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

        payload = minimal_publication()
        payload["threats"][0]["title"] = f"Leak: Bearer {secret}"

        problems = quality_gate.validate_publication(payload)
        joined = " ".join(problems)

        self.assertNotIn(secret, joined)
        self.assertIn("[redacted]", joined)

    def test_the_publisher_token_marker_still_blocks(self) -> None:
        payload = minimal_publication()
        payload["summary"]["n"] = "publisher_token=leaked"

        self.assertTrue(quality_gate.validate_publication(payload))


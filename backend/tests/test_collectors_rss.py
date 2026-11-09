"""Phase 1 collector tests: RSS/Atom parsing and the advisory collector.

All HTTP is faked, so these tests need no network and no credentials. The
important assertions are the failure semantics: one bad item must not destroy a
feed, one bad feed must not destroy a source, and a source that yields nothing
must not overwrite good published intelligence.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from collectors.rss_feed import RssFeedCollector
from lib.attribution import AttributionError, load_register
from lib.config import SourceConfig
from lib.http import HttpError
from normalization.cisa import NormalizationError
from normalization.rss import (
    extract_cve_ids,
    extract_techniques,
    parse_feed,
    strip_dangerous_xml,
)
from state.store import StateStore

RSS_FEED = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>CERT-EU Security Advisories</title>
  <item>
    <title>Advisory on CVE-2026-12345 in Example Product</title>
    <link>https://example.invalid/advisory/1</link>
    <description>&lt;p&gt;Exploitation of CVE-2026-12345 using T1059 observed.&lt;/p&gt;</description>
    <pubDate>Tue, 28 Oct 2026 10:00:00 +0000</pubDate>
    <category>Security Advisory</category>
  </item>
  <item>
    <title>Advisory marked for partners</title>
    <link>https://example.invalid/advisory/2</link>
    <description>Handling: TLP:AMBER. Not for public release.</description>
    <pubDate>Wed, 29 Oct 2026 09:00:00 +0000</pubDate>
  </item>
</channel></rss>
"""

ATOM_FEED = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>National CERT</title>
  <entry>
    <title>Vulnerability in Example Software</title>
    <link href="https://example.invalid/atom/1"/>
    <updated>2026-10-29T08:30:00Z</updated>
    <summary>CVE-2026-54321 is being exploited. See T1190.</summary>
  </entry>
</feed>
"""

DOCTYPE_ONLY_FEED = b"""<?xml version="1.0"?>
<!DOCTYPE rss SYSTEM "rss.dtd">
<rss version="2.0"><channel>
  <item><title>Safe item</title><link>https://example.invalid/safe</link></item>
</channel></rss>
"""

ENTITY_BOMB_FEED = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<rss version="2.0"><channel>
  <item><title>&lol2;</title><link>https://example.invalid/bomb</link></item>
</channel></rss>
"""


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body


class FakeHttp:
    """Minimal stand-in for :class:`lib.http.HttpClient`."""

    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[str] = []
        self.headers: list[dict | None] = []

    def get(self, url: str, *, timeout_seconds=None, headers=None) -> FakeResponse:
        self.calls.append(url)
        self.headers.append(headers)

        outcome = self.responses.get(url)

        if outcome is None:
            raise HttpError(f"no fixture for {url}", transient=False)

        if isinstance(outcome, Exception):
            raise outcome

        return FakeResponse(outcome)  # type: ignore[arg-type]


def make_config(**overrides) -> SourceConfig:
    values = {
        "key": "cert_eu_advisories",
        "name": "CERT-EU Security Advisories",
        "source_type": "advisory",
        "url": "https://example.invalid/",
        "feed_url": "https://example.invalid/feed.xml",
        "provider": "CERT-EU",
        "reliability": "high",
        "enabled": True,
        "required": False,
        "timeout_seconds": 5.0,
        "tier": 1,
        "feeds": (),
    }
    values.update(overrides)

    return SourceConfig(**values)


def make_store() -> StateStore:
    root = Path(tempfile.mkdtemp())

    return StateStore(root / "state", root / "data")


class FeedParsingTests(unittest.TestCase):
    def test_parses_rss_items(self) -> None:
        items = parse_feed(RSS_FEED)

        self.assertEqual(len(items), 2)

        first = items[0]

        self.assertEqual(first.title, "Advisory on CVE-2026-12345 in Example Product")
        self.assertEqual(first.link, "https://example.invalid/advisory/1")
        self.assertEqual(first.published_at, "2026-10-28T10:00:00Z")
        self.assertEqual(first.categories, ["Security Advisory"])
        self.assertEqual(first.tlp_markings, set())

    def test_html_is_reduced_to_text(self) -> None:
        first = parse_feed(RSS_FEED)[0]

        self.assertEqual(
            first.summary,
            "Exploitation of CVE-2026-12345 using T1059 observed.",
        )

    def test_restrictive_marking_is_detected_on_the_item(self) -> None:
        second = parse_feed(RSS_FEED)[1]

        self.assertEqual(second.tlp_markings, {"AMBER"})

    def test_parses_atom_entries(self) -> None:
        items = parse_feed(ATOM_FEED)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].link, "https://example.invalid/atom/1")
        self.assertEqual(items[0].published_at, "2026-10-29T08:30:00Z")

    def test_doctype_without_entities_still_parses(self) -> None:
        items = parse_feed(DOCTYPE_ONLY_FEED)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].title, "Safe item")

    def test_strip_dangerous_xml_removes_doctype_and_entities(self) -> None:
        cleaned = strip_dangerous_xml(ENTITY_BOMB_FEED)

        self.assertNotIn(b"<!DOCTYPE", cleaned)
        self.assertNotIn(b"<!ENTITY", cleaned)

    def test_entity_bomb_is_rejected_rather_than_expanded(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_feed(ENTITY_BOMB_FEED)

    def test_malformed_xml_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_feed(b"<rss><channel>")

    def test_oversized_feed_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_feed(b"x" * (8 * 1024 * 1024 + 1))

    def test_non_bytes_input_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_feed("<rss/>")  # type: ignore[arg-type]

    def test_empty_document_yields_no_items(self) -> None:
        self.assertEqual(parse_feed(b"<rss version='2.0'><channel/></rss>"), [])

    def test_extract_cve_ids(self) -> None:
        self.assertEqual(
            extract_cve_ids("cve-2026-12345 and CVE-2026-12345 and CVE-2025-1234"),
            ["CVE-2025-1234", "CVE-2026-12345"],
        )
        self.assertEqual(extract_cve_ids(None, "nothing here"), [])

    def test_short_cve_sequences_are_not_matched(self) -> None:
        # A real CVE identifier has at least four digits in its sequence.
        self.assertEqual(extract_cve_ids("CVE-2025-1 is not a CVE identifier"), [])

    def test_extract_techniques(self) -> None:
        self.assertEqual(extract_techniques("T1059 and T1190.001"), ["T1059", "T1190.001"])
        self.assertEqual(extract_techniques("no techniques"), [])


class RssFeedCollectorTests(unittest.TestCase):
    FEED_URL = "https://example.invalid/feed.xml"

    def _collector(self, http, *, config=None, store=None) -> RssFeedCollector:
        return RssFeedCollector(
            config or make_config(),
            http,
            store or make_store(),
            register=load_register(),
        )

    def test_collects_items_and_gates_restrictive_ones(self) -> None:
        http = FakeHttp({self.FEED_URL: RSS_FEED})
        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.metrics["items_seen"], 2)
        self.assertEqual(result.metrics["rejected_tlp"], 1)
        self.assertEqual(result.metrics["feeds_ok"], 1)
        self.assertEqual(result.metrics["tlp_default"], "CLEAR")

    def test_observation_carries_provenance_and_entities(self) -> None:
        http = FakeHttp({self.FEED_URL: RSS_FEED})
        observation = self._collector(http).collect("2026-10-31T00:00:00Z").observations[0]

        self.assertEqual(observation.source_key, "cert_eu_advisories")
        self.assertEqual(observation.external_id, "https://example.invalid/advisory/1")
        self.assertEqual(observation.observed_at, "2026-10-28T10:00:00Z")
        self.assertEqual(observation.retrieved_at, "2026-10-31T00:00:00Z")
        self.assertEqual(observation.payload["feed_url"], self.FEED_URL)
        self.assertEqual(observation.payload["source"], "cert_eu_advisories")

        entities = {entity.kind: entity for entity in observation.entities}

        self.assertEqual(entities["cve"].normalized, "CVE-2026-12345")
        self.assertEqual(entities["technique"].normalized, "T1059")

    def test_partial_failure_is_not_total_failure(self) -> None:
        good = "https://example.invalid/good.xml"
        bad = "https://example.invalid/bad.xml"

        http = FakeHttp(
            {
                good: RSS_FEED,
                bad: HttpError("HTTP 503", transient=True, status=503),
            }
        )

        result = self._collector(
            http, config=make_config(feeds=(good, bad))
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.metrics["feeds_ok"], 1)
        self.assertEqual(result.metrics["feeds_failed"], 1)
        self.assertTrue(result.metrics["partial"])

    def test_all_feeds_failing_without_a_snapshot_fails(self) -> None:
        http = FakeHttp(
            {self.FEED_URL: HttpError("HTTP 500", transient=True, status=500)}
        )

        result = self._collector(http).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.usable)

    def test_all_feeds_failing_with_a_snapshot_degrades(self) -> None:
        store = make_store()
        good_http = FakeHttp({self.FEED_URL: RSS_FEED})

        first = self._collector(good_http, store=store).collect("2026-10-30T00:00:00Z")

        self.assertEqual(first.status, "ok")

        failing_http = FakeHttp(
            {self.FEED_URL: HttpError("HTTP 500", transient=True, status=500)}
        )

        second = self._collector(failing_http, store=store).collect(
            "2026-10-31T00:00:00Z"
        )

        self.assertEqual(second.status, "degraded")
        self.assertTrue(second.used_last_known_good)
        self.assertEqual(len(second.observations), 1)
        self.assertTrue(second.usable)

    def test_zero_accepted_items_does_not_overwrite_good_data(self) -> None:
        store = make_store()
        good_http = FakeHttp({self.FEED_URL: RSS_FEED})

        self._collector(good_http, store=store).collect("2026-10-30T00:00:00Z")

        only_restricted = b"""<?xml version="1.0"?>
        <rss version="2.0"><channel><item>
          <title>Restricted only</title>
          <link>https://example.invalid/restricted</link>
          <description>Handling: TLP:AMBER.</description>
        </item></channel></rss>
        """

        restricted_http = FakeHttp({self.FEED_URL: only_restricted})

        result = self._collector(restricted_http, store=store).collect(
            "2026-10-31T00:00:00Z"
        )

        self.assertEqual(result.status, "degraded")
        self.assertEqual(result.metrics["items_accepted"], 0)
        self.assertEqual(result.metrics["rejected_tlp"], 1)
        self.assertEqual(len(result.observations), 1)

    def test_duplicate_items_across_feeds_are_collapsed(self) -> None:
        first = "https://example.invalid/one.xml"
        second = "https://example.invalid/two.xml"

        http = FakeHttp({first: RSS_FEED, second: RSS_FEED})

        result = self._collector(
            http, config=make_config(feeds=(first, second))
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.metrics["rejected_duplicate"], 1)

    def test_collector_requires_an_attribution_record(self) -> None:
        http = FakeHttp({self.FEED_URL: RSS_FEED})

        with self.assertRaises(AttributionError):
            RssFeedCollector(
                make_config(key="ghost_source"),
                http,
                make_store(),
                register=load_register(),
            )

    def test_requests_xml_rather_than_json_from_a_feed(self) -> None:
        """A JSON Accept header on an XML feed is answered with HTTP 403 by WAFs."""

        http = FakeHttp({self.FEED_URL: RSS_FEED})

        self._collector(http).collect("2026-10-31T00:00:00Z")

        sent = http.headers[0]

        self.assertIsNotNone(sent)
        self.assertIn("xml", sent["Accept"])
        self.assertNotIn("application/json", sent["Accept"])

    def test_parses_atom_and_records_the_link_as_identity(self) -> None:
        url = "https://example.invalid/atom.xml"
        http = FakeHttp({url: ATOM_FEED})

        result = self._collector(http, config=make_config(feed_url=url)).collect(
            "2026-10-31T00:00:00Z"
        )

        self.assertEqual(result.status, "ok")
        self.assertEqual(
            result.observations[0].external_id, "https://example.invalid/atom/1"
        )



"""Phase 4a tests for the Exploit-DB, Red Hat, OSV and CIRCL sources.

Every fixture here is copied from a **live** response captured on 31 Oct 2026, and
each one carries a trap that a collector written from documentation alone would get
wrong:

* Exploit-DB puts CVE ids in ``codes``, not ``aliases``, mixed with other
  identifier schemes;
* Red Hat joins its reference URLs with newlines inside a *single* list element,
  returns CVSS scores as strings, and publishes a nested ``cvss3`` object;
* OSV answers a CVE query with a record whose ``id`` is a GHSA or PYSEC id and whose
  ``aliases`` hold the CVE, and its ``GIT`` ranges put a commit hash in ``fixed``;
* CIRCL's sighting endpoint ignores a ``vulnerability`` filter but honours
  ``vuln_id``, and returns unparseable multi-megabyte JSON for larger pages.

The rules the product depends on are asserted alongside the parsing: a miss is
remembered rather than retried forever, and no source here can assert exploitation
or move a threat's score.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from collectors.circl_vulnerability_lookup import (
    CirclVulnerabilityLookupCollector,
)
from collectors.exploit_availability import ExploitAvailabilityCollector
from collectors.osv_dev import OsvCollector
from collectors.redhat_security import RedhatSecurityCollector
from lib.attribution import load_register
from lib.config import SourceConfig
from lib.http import HttpError
from normalization.cisa import NormalizationError, RecordUnavailable
from normalization.circl import (
    lookup_url as circl_lookup_url,
    normalize_sighting_type,
    parse_sightings,
)
from normalization.exploitdb import extract_cve_ids, parse_exploits
from normalization.osv import find_cve_id, parse_osv_record, record_url as osv_url
from normalization.redhat import (
    parse_redhat_record,
    record_url as redhat_url,
    split_references,
)
from state.store import StateStore

CVE = "CVE-2021-44228"

#: The real header and three real rows, including one naming only an OSVDB id.
EXPLOIT_CSV = (
    "id,file,description,date_published,author,type,platform,port,date_added,"
    "date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
    '16929,exploits/aix/dos/16929.rb,"AIX Calendar Manager Service Daemon (rpc.cmsd) '
    'Opcode 21 - Buffer Overflow (Metasploit)",2010-11-11,Metasploit,dos,aix,,'
    "2010-11-11,2011-03-06,1,CVE-2009-3699;OSVDB-58726,\"Metasploit Framework (MSF)\","
    ",,,http://aix.software.ibm.com/aix/efixes/security/cmsd_advisory.asc\n"
    '19046,exploits/aix/dos/19046.txt,"AppleShare IP Mail Server 5.0.3 - Buffer '
    'Overflow",1999-10-15,"Chris Wedgwood",dos,aix,,1999-10-15,2014-01-02,1,'
    "CVE-1999-1015;OSVDB-5970,,,,,https://www.securityfocus.com/bid/61/info\n"
    '19049,exploits/aix/dos/19049.txt,"BSDI 4.0 tcpmux / inetd - Crash",1998-04-07,'
    '"Mark Schaefer",dos,aix,,1998-04-07,2014-01-02,1,OSVDB-82889,,,,,'
    "https://www.securityfocus.com/bid/66/info\n"
)

#: Trimmed from the live record for CVE-2021-44228, keeping every trap.
REDHAT_RECORD = {
    "threat_severity": "Critical",
    "public_date": "2021-12-10T02:01:00Z",
    "bugzilla": {
        "description": "log4j-core: Remote code execution in Log4j 2.x",
        "id": "2030932",
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2030932",
    },
    "cvss3": {
        "cvss3_base_score": "10.0",
        "cvss3_scoring_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "status": "verified",
    },
    "cvss": None,
    "cwe": "CWE-20",
    "details": "A flaw was found in the Java logging library Apache Log4j.",
    "statement": "Red Hat has released updated packages that fix this flaw.",
    "mitigation": "None known.",
    "name": "CVE-2021-44228",
    "upstream_fix": None,
    "csaw": {},
    "affected_release": [
        {
            "product_name": "OpenShift Logging 5.0",
            "release_date": "2021-12-14T00:00:00Z",
            "advisory": "RHSA-2021:5137",
            "cpe": "cpe:/a:redhat:logging:5.0::el8",
            "package": "openshift-logging/elasticsearch6-rhel8:v5.0.10-1",
            "impact": "moderate",
        }
    ],
    "package_state": [
        {
            "product_name": "A-MQ Clients 2",
            "fix_state": "Not affected",
            "package_name": "log4j-core",
            "cpe": "cpe:/a:redhat:a_mq_clients:2",
        },
        {
            "product_name": "Red Hat JBoss Fuse",
            "fix_state": "Affected",
            "package_name": "log4j-core",
            "cpe": "cpe:/a:redhat:jboss_fuse:6",
        },
    ],
    # One element, three URLs: the live shape.
    "references": [
        "https://cve.org/CVERecord?id=CVE-2021-44228\n"
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228\n"
        "https://logging.apache.org/log4j/2.x/security.html"
    ],
}

#: The live PYSEC record: the ``id`` is not a CVE, the CVE is in ``aliases``, and a
#: GIT range carries a commit hash in ``fixed``.
OSV_PYSEC_RECORD = {
    "id": "PYSEC-2021-441",
    "details": "TensorFlow is an end-to-end open source platform for machine learning.",
    "aliases": [
        "BIT-tensorflow-2021-29513",
        "CVE-2021-29513",
        "GHSA-452g-f7fp-9jf7",
    ],
    "modified": "2023-12-06T01:01:03.253096Z",
    "published": "2021-05-14T20:15:00Z",
    "references": [
        {
            "type": "FIX",
            "url": "https://github.com/tensorflow/tensorflow/commit/030af767",
        },
        {
            "type": "ADVISORY",
            "url": "https://github.com/tensorflow/tensorflow/security/advisories/GHSA-452g-f7fp-9jf7",
        },
    ],
    "affected": [
        {
            "package": {
                "name": "tensorflow-cpu",
                "ecosystem": "PyPI",
                "purl": "pkg:pypi/tensorflow-cpu",
            },
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/tensorflow/tensorflow",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "030af767d357d1b4088c4a25c72cb3906abac489"},
                    ],
                },
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.2.0rc0"},
                        {"introduced": "2.4.0"},
                        {"fixed": "2.4.3"},
                    ],
                },
            ],
            "versions": ["1.15.0", "2.1.0"],
        }
    ],
    "schema_version": "1.7.3",
}

#: The live GHSA record for log4j: a CVSS *vector* in ``severity``.
OSV_GHSA_RECORD = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "summary": "Remote code injection in Log4j",
    "details": "Log4j versions prior to 2.16.0 are subject to remote code execution.",
    "aliases": ["CVE-2021-44228"],
    "modified": "2025-10-22T19:37:02.616807Z",
    "published": "2021-12-10T00:40:56Z",
    "references": [
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
        {"type": "WEB", "url": "https://github.com/apache/logging-log4j2/pull/608"},
    ],
    "affected": [
        {
            "package": {
                "name": "org.apache.logging.log4j:log4j-core",
                "ecosystem": "Maven",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.0.0"}, {"fixed": "2.16.0"}],
                }
            ],
        }
    ],
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H"}
    ],
}

#: The live sighting response shape.
CIRCL_RESPONSE = {
    "metadata": {"count": 2015, "page": 1, "per_page": 10},
    "data": [
        {
            "uuid": "8fcd9c73-8566-4658-93eb-cccacb8f0acc",
            "creation_timestamp": "2026-10-30T00:00:00+00:00",
            "type": "exploited",
            "source": "The Shadowserver (honeypot/exploited-vulnerabilities) - (2026-10-30)",
            "content": "",
            "vulnerability": "CVE-2021-44228",
            "author": {"login": "automation"},
        },
        {
            "uuid": "0a97a1a5-9c98-41fa-a575-db76f443318f",
            "creation_timestamp": "2026-10-28T12:00:00+00:00",
            "type": "seen",
            "source": "https://bsky.app/profile/exploitdb-bot.bsky.social/post/1",
            "content": "New exploit discussed.",
            "vulnerability": "CVE-2021-44228",
            "author": {"login": "analyst"},
        },
    ],
}


def make_store() -> StateStore:
    root = Path(tempfile.mkdtemp())

    return StateStore(root / "state", root / "data")


class FakeResponse:
    """A response that can be read as JSON or as raw bytes."""

    def __init__(self, payload: object) -> None:
        self._payload = payload

        if isinstance(payload, bytes):
            self.body = payload
        elif isinstance(payload, str):
            self.body = payload.encode("utf-8")
        else:
            self.body = json.dumps(payload).encode("utf-8")

    def json(self) -> object:
        if isinstance(self._payload, (str, bytes)):
            raise ValueError("not a JSON fixture")

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


def source_config(key: str, **overrides) -> SourceConfig:
    values = {
        "key": key,
        "name": key,
        "source_type": "vendor_advisory",
        "url": "https://example.test/",
        "feed_url": "https://example.test/api",
        "provider": "Example",
        "reliability": "high",
        "enabled": True,
        "required": False,
        "timeout_seconds": 5.0,
        "tier": 1,
        "feeds": (),
    }
    values.update(overrides)

    return SourceConfig(**values)


class ExploitDbParsingTests(unittest.TestCase):
    def test_cve_ids_come_from_codes_and_aliases(self) -> None:
        self.assertEqual(
            extract_cve_ids({"codes": "CVE-2009-3699;OSVDB-58726", "aliases": ""}),
            ["CVE-2009-3699"],
        )
        self.assertEqual(
            extract_cve_ids({"codes": "OSVDB-1", "aliases": "CVE-1999-1015"}),
            ["CVE-1999-1015"],
        )
        self.assertEqual(extract_cve_ids({"codes": "", "aliases": ""}), [])

    def test_only_wanted_cves_are_kept(self) -> None:
        by_cve, metrics = parse_exploits(
            EXPLOIT_CSV, wanted={"CVE-2009-3699", "CVE-1999-1015"}
        )

        self.assertEqual(sorted(by_cve), ["CVE-1999-1015", "CVE-2009-3699"])
        self.assertEqual(metrics["csv_rows"], 3)
        self.assertEqual(metrics["csv_rows_with_a_cve"], 2)
        self.assertEqual(metrics["csv_rows_matching_our_cves"], 2)

    def test_a_row_naming_only_an_osvdb_id_is_skipped(self) -> None:
        by_cve, _metrics = parse_exploits(EXPLOIT_CSV, wanted={"OSVDB-82889"})

        self.assertEqual(by_cve, {})

    def test_the_true_count_is_kept_separate_from_the_listed_entries(self) -> None:
        csv_text = EXPLOIT_CSV + EXPLOIT_CSV.splitlines()[1] + "\n"

        by_cve, _metrics = parse_exploits(csv_text, wanted={"CVE-2009-3699"})

        exploits = by_cve["CVE-2009-3699"]

        self.assertEqual(exploits.total, 2)
        self.assertEqual(len(exploits.entries), 2)

    def test_an_entry_is_described(self) -> None:
        by_cve, _metrics = parse_exploits(EXPLOIT_CSV, wanted={"CVE-2009-3699"})

        entry = by_cve["CVE-2009-3699"].entries[0].to_dict()

        self.assertEqual(entry["id"], "16929")
        self.assertEqual(entry["type"], "dos")
        self.assertEqual(entry["platform"], "aix")
        self.assertEqual(entry["published_at"], "2010-11-11")
        self.assertTrue(entry["verified"])

    def test_a_changed_header_is_refused(self) -> None:
        for text in ("", "   ", "id,file\n1,2\n", "file,codes,aliases\nx,y,z\n"):
            with self.assertRaises(NormalizationError):
                parse_exploits(text, wanted={"CVE-2009-3699"})

    def test_the_payload_carries_no_exploitation_claim(self) -> None:
        from normalization.exploitdb import build_payload

        by_cve, _metrics = parse_exploits(EXPLOIT_CSV, wanted={"CVE-2009-3699"})

        payload = build_payload(
            by_cve["CVE-2009-3699"], source_key="exploit_availability"
        )

        self.assertNotIn("exploited_in_wild", payload)
        self.assertNotIn("kev_listed", payload)
        self.assertEqual(payload["exploit_count"], 1)
        self.assertEqual(payload["platforms"], ["aix"])
        self.assertIn("enrichment_summary", payload)


class RedhatParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = parse_redhat_record(REDHAT_RECORD)

    def test_the_url_is_the_per_cve_endpoint(self) -> None:
        self.assertEqual(
            redhat_url("https://access.redhat.com/hydra/rest/securitydata", CVE),
            "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-44228.json",
        )

    def test_reference_urls_are_split_out_of_one_newline_joined_string(self) -> None:
        references = self.payload["references"]

        self.assertEqual(len(references), 3)
        self.assertEqual(references[0], "https://cve.org/CVERecord?id=CVE-2021-44228")
        self.assertTrue(all(url.startswith("https://") for url in references))

    def test_a_non_https_reference_is_dropped(self) -> None:
        self.assertEqual(
            split_references(["http://insecure.test/x\nhttps://ok.test/y"]),
            ["https://ok.test/y"],
        )

    def test_the_cvss_score_is_parsed_from_a_string(self) -> None:
        self.assertEqual(self.payload["cvss"]["base_score"], 10.0)
        self.assertEqual(self.payload["cvss"]["version"], "3")
        self.assertEqual(self.payload["cvss"]["status"], "verified")
        self.assertTrue(self.payload["cvss"]["vector"].startswith("CVSS:3.1/"))

    def test_a_comma_separated_cwe_string_becomes_a_list(self) -> None:
        self.assertEqual(self.payload["cwe"], ["CWE-20"])

    def test_the_errata_list_is_captured(self) -> None:
        self.assertEqual(self.payload["advisory_count"], 1)
        self.assertEqual(self.payload["advisories"][0]["advisory"], "RHSA-2021:5137")
        self.assertEqual(
            self.payload["advisories"][0]["product_name"], "OpenShift Logging 5.0"
        )
        self.assertEqual(
            self.payload["advisories"][0]["release_date"], "2021-12-14T00:00:00Z"
        )

    def test_fix_states_are_counted_not_dropped(self) -> None:
        self.assertEqual(
            self.payload["package_state_counts"], {"Affected": 1, "Not affected": 1}
        )

    def test_the_severity_is_lower_cased(self) -> None:
        self.assertEqual(self.payload["threat_severity"], "critical")

    def test_the_payload_carries_no_exploitation_claim(self) -> None:
        for key in ("kev_listed", "exploited_in_wild", "date_added", "due_date"):
            self.assertNotIn(key, self.payload)

    def test_a_record_with_nothing_to_say_is_unavailable(self) -> None:
        with self.assertRaises(RecordUnavailable):
            parse_redhat_record({"name": CVE})

    def test_a_record_without_a_cve_is_malformed(self) -> None:
        for payload in (None, [], {}, {"name": "not-a-cve"}):
            with self.assertRaises(NormalizationError):
                parse_redhat_record(payload)

    def test_unavailable_is_also_a_normalization_error(self) -> None:
        self.assertTrue(issubclass(RecordUnavailable, NormalizationError))


class OsvParsingTests(unittest.TestCase):
    def test_the_url_is_the_per_identifier_endpoint(self) -> None:
        self.assertEqual(
            osv_url("https://api.osv.dev/v1", CVE),
            "https://api.osv.dev/v1/vulns/CVE-2021-44228",
        )

    def test_the_cve_is_read_from_aliases_when_the_id_is_not_one(self) -> None:
        # The live PYSEC record: id is PYSEC, the CVE is an alias.
        self.assertEqual(find_cve_id(OSV_PYSEC_RECORD), "CVE-2021-29513")
        self.assertEqual(find_cve_id(OSV_GHSA_RECORD), "CVE-2021-44228")
        self.assertIsNone(find_cve_id({"id": "GHSA-x", "aliases": ["GHSA-y"]}))

    def test_a_pysec_record_is_normalised(self) -> None:
        payload = parse_osv_record(OSV_PYSEC_RECORD)

        self.assertEqual(payload["cve_id"], "CVE-2021-29513")
        self.assertEqual(payload["osv_id"], "PYSEC-2021-441")
        self.assertEqual(payload["ecosystems"], ["PyPI"])
        self.assertEqual(payload["packages"][0]["name"], "tensorflow-cpu")
        self.assertEqual(payload["packages"][0]["purl"], "pkg:pypi/tensorflow-cpu")
        self.assertEqual(payload["published_at"], "2021-05-14T20:15:00Z")

    def test_a_git_range_commit_hash_is_not_reported_as_a_fixed_version(self) -> None:
        payload = parse_osv_record(OSV_PYSEC_RECORD)

        self.assertEqual(payload["fixed_versions"], ["2.2.0rc0", "2.4.3"])
        self.assertNotIn(
            "030af767d357d1b4088c4a25c72cb3906abac489", payload["fixed_versions"]
        )

    def test_the_severity_vector_is_kept_as_a_string(self) -> None:
        payload = parse_osv_record(OSV_GHSA_RECORD)

        self.assertEqual(payload["severity"][0]["type"], "CVSS_V3")
        self.assertTrue(payload["severity"][0]["score"].startswith("CVSS:3.1/"))
        # A vector is not a number, so it must not become the shared CVSS field.
        self.assertNotIn("cvss", payload)

    def test_references_are_filtered_to_https(self) -> None:
        payload = parse_osv_record(
            {**OSV_GHSA_RECORD, "references": [{"type": "WEB", "url": "http://x.test"}]}
        )

        self.assertEqual(payload["references"], [])

    def test_a_record_without_packages_or_severity_is_unavailable(self) -> None:
        with self.assertRaises(RecordUnavailable):
            parse_osv_record({"id": CVE, "aliases": []})

    def test_a_record_naming_no_cve_is_malformed(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_osv_record({"id": "GHSA-only", "aliases": []})

    def test_untrustworthy_payloads_raise(self) -> None:
        for payload in (None, [], "x"):
            with self.assertRaises(NormalizationError):
                parse_osv_record(payload)


class CirclParsingTests(unittest.TestCase):
    def test_the_query_uses_vuln_id_because_vulnerability_is_ignored(self) -> None:
        url = circl_lookup_url("https://vulnerability.circl.lu/api", CVE)

        self.assertIn("vuln_id=CVE-2021-44228", url)
        self.assertNotIn("vulnerability=", url)
        # Kept small: the endpoint returns unparseable JSON above per_page=15.
        self.assertIn("per_page=10", url)

    def test_the_live_response_is_reduced_to_counts_and_dates(self) -> None:
        payload = parse_sightings(CIRCL_RESPONSE)

        self.assertEqual(payload["cve_id"], CVE)
        self.assertEqual(payload["sighting_count"], 2015)
        self.assertEqual(payload["sightings_sampled"], 2)
        self.assertEqual(payload["sighting_types"], {"exploited": 1, "seen": 1})
        self.assertEqual(payload["exploited_sightings_sampled"], 1)
        self.assertEqual(payload["latest_sighting_at"], "2026-10-30T00:00:00Z")
        self.assertIn("automation", payload["sighting_authors"])
        self.assertIn("shadowserver", " ".join(payload["sighting_sources"]).lower())

    def test_the_payload_carries_no_exploitation_flag(self) -> None:
        payload = parse_sightings(CIRCL_RESPONSE)

        for key in ("exploited_in_wild", "kev_listed", "date_added", "due_date"):
            self.assertNotIn(key, payload)

    def test_sighting_types_are_normalised(self) -> None:
        self.assertEqual(normalize_sighting_type("Exploited"), "exploited")
        self.assertEqual(
            normalize_sighting_type("Published Proof of Concept"),
            "published_proof_of_concept",
        )
        self.assertIsNone(normalize_sighting_type(None))

    def test_nothing_sighted_is_unavailable(self) -> None:
        with self.assertRaises(RecordUnavailable):
            parse_sightings({"metadata": {"count": 0}, "data": []})

    def test_a_response_without_a_count_is_malformed(self) -> None:
        for payload in (None, [], {}, {"metadata": {}, "data": []}):
            with self.assertRaises(NormalizationError):
                parse_sightings(payload)

    def test_rows_naming_no_cve_are_malformed(self) -> None:
        with self.assertRaises(NormalizationError):
            parse_sightings(
                {"metadata": {"count": 1}, "data": [{"type": "seen"}]}
            )


class LookupContractTests(unittest.TestCase):
    """The shared lookup contract, exercised through the real sources."""

    def _redhat(self, http, *, store=None):
        return RedhatSecurityCollector(
            source_config("redhat_security"),
            http,
            store or make_store(),
            register=load_register(),
            cve_ids=[CVE],
        )

    def test_a_404_is_remembered_as_a_miss_not_retried(self) -> None:
        store = make_store()
        url = redhat_url("https://example.test/api", CVE)
        missing = HttpError("HTTP 404", transient=False, status=404)

        first = self._redhat(FakeHttp({url: missing}), store=store).collect(
            "2026-10-31T00:00:00Z"
        )

        self.assertEqual(first.metrics["absent"], 1)
        self.assertEqual(first.metrics["fetch_failures"], 0)

        second_http = FakeHttp({})
        second = self._redhat(second_http, store=store).collect("2026-11-01T00:00:00Z")

        self.assertEqual(second_http.calls, [])
        self.assertEqual(second.metrics["cache_absent"], 1)

    def test_a_transport_failure_is_retried_not_remembered(self) -> None:
        store = make_store()
        url = redhat_url("https://example.test/api", CVE)
        failure = HttpError("HTTP 500", transient=True, status=500)

        result = self._redhat(FakeHttp({url: failure}), store=store).collect(
            "2026-10-31T00:00:00Z"
        )

        self.assertEqual(result.metrics["absent"], 0)
        self.assertEqual(result.metrics["fetch_failures"], 1)

    def test_a_record_for_the_wrong_cve_is_refused(self) -> None:
        url = redhat_url("https://example.test/api", CVE)

        result = self._redhat(
            FakeHttp({url: {**REDHAT_RECORD, "name": "CVE-2024-99999"}})
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.metrics["rejected_malformed"], 1)

    def test_a_cached_record_is_re_emitted_without_a_request(self) -> None:
        store = make_store()
        url = redhat_url("https://example.test/api", CVE)

        self._redhat(FakeHttp({url: REDHAT_RECORD}), store=store).collect(
            "2026-10-31T00:00:00Z"
        )

        http = FakeHttp({})
        result = self._redhat(http, store=store).collect("2026-11-01T00:00:00Z")

        self.assertEqual(http.calls, [])
        self.assertEqual(len(result.observations), 1)

    def test_a_record_due_for_refresh_is_asked_again(self) -> None:
        store = make_store()
        url = redhat_url("https://example.test/api", CVE)

        self._redhat(FakeHttp({url: REDHAT_RECORD}), store=store).collect(
            "2026-10-31T00:00:00Z"
        )

        # Past the 30-day refresh window: errata may have been added since.
        http = FakeHttp({url: REDHAT_RECORD})

        self._redhat(http, store=store).collect("2026-12-15T00:00:00Z")

        self.assertEqual(len(http.calls), 1)

    def test_the_exploit_catalogue_is_filtered_to_known_cves(self) -> None:
        collector = ExploitAvailabilityCollector(
            source_config("exploit_availability"),
            FakeHttp({"https://example.test/api": EXPLOIT_CSV}),
            make_store(),
            register=load_register(),
            cve_ids=["CVE-2009-3699"],
        )

        result = collector.collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.metrics["cves_with_public_exploits"], 1)
        self.assertEqual(result.metrics["csv_rows"], 3)

    def test_an_empty_cve_list_makes_the_bulk_source_a_no_op(self) -> None:
        http = FakeHttp({})

        result = ExploitAvailabilityCollector(
            source_config("exploit_availability"),
            http,
            make_store(),
            register=load_register(),
            cve_ids=[],
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertTrue(result.metrics["skipped"])
        self.assertEqual(http.calls, [])

    def test_the_circl_collector_asks_for_a_small_page(self) -> None:
        url = circl_lookup_url("https://example.test/api", CVE)
        http = FakeHttp({url: CIRCL_RESPONSE})

        result = CirclVulnerabilityLookupCollector(
            source_config("circl_vulnerability_lookup"),
            http,
            make_store(),
            register=load_register(),
            cve_ids=[CVE],
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "ok")
        self.assertIn("per_page=10", http.calls[0])
        self.assertEqual(result.metrics["sightings_reported"], 2015)

    def test_an_oversized_response_fails_the_source_rather_than_being_parsed(
        self,
    ) -> None:
        url = osv_url("https://example.test/api", CVE)
        too_big = HttpError(
            "returned more than 4194304 bytes", transient=False, status=200
        )

        result = OsvCollector(
            source_config("osv_dev"),
            FakeHttp({url: too_big}),
            make_store(),
            register=load_register(),
            cve_ids=[CVE],
        ).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.metrics["fetch_failures"], 1)
        # Crucially not recorded as a miss: it must be retried.
        self.assertEqual(result.metrics["absent"], 0)

    def test_every_source_requires_an_attribution_record(self) -> None:
        from lib.attribution import AttributionError

        for factory in (
            RedhatSecurityCollector,
            OsvCollector,
            CirclVulnerabilityLookupCollector,
        ):
            with self.assertRaises(AttributionError):
                factory(
                    source_config("ghost_source"),
                    FakeHttp({}),
                    make_store(),
                    register=load_register(),
                    cve_ids=[CVE],
                )


class CircuitBreakerTests(unittest.TestCase):
    """An unreachable source must not spend the whole budget on retries."""

    def _collector(self, http, cves):
        return RedhatSecurityCollector(
            source_config("redhat_security"),
            http,
            make_store(),
            register=load_register(),
            cve_ids=cves,
        )

    def test_an_unreachable_endpoint_abandons_the_batch(self) -> None:
        cves = [f"CVE-2026-{9000 + index}" for index in range(40)]
        failure = HttpError("SSL: CERTIFICATE_VERIFY_FAILED", transient=True)

        http = FakeHttp(
            {redhat_url("https://example.test/api", cve): failure for cve in cves}
        )

        result = self._collector(http, cves).collect("2026-10-31T00:00:00Z")

        self.assertEqual(result.status, "failed")
        self.assertTrue(result.metrics["batch_abandoned"])
        # Five attempts, not forty.
        self.assertEqual(len(http.calls), 5)
        self.assertIn("unreachable", result.failure_reason)

    def test_a_miss_resets_the_failure_counter(self) -> None:
        cves = [f"CVE-2026-{9000 + index}" for index in range(40)]
        failure = HttpError("connection reset", transient=True)
        missing = HttpError("HTTP 404", transient=False, status=404)

        def url_for(cve: str) -> str:
            return redhat_url("https://example.test/api", cve)

        responses: dict[str, object] = {}

        # Descending order: 9039 down to 9000.
        for cve in ("CVE-2026-9039", "CVE-2026-9038", "CVE-2026-9037", "CVE-2026-9036"):
            responses[url_for(cve)] = failure

        # A 404 proves the endpoint is answering, so the count restarts.
        responses[url_for("CVE-2026-9035")] = missing

        for index in range(9034, 9029, -1):
            responses[url_for(f"CVE-2026-{index}")] = failure

        http = FakeHttp(responses)
        result = self._collector(http, cves).collect("2026-10-31T00:00:00Z")

        self.assertTrue(result.metrics["batch_abandoned"])
        self.assertEqual(result.metrics["absent"], 1)
        # 4 failures + 1 miss + 5 more failures before abandoning.
        self.assertEqual(len(http.calls), 10)

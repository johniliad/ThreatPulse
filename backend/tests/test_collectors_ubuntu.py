"""Ubuntu Security Notices normalisation.

One request yields a CVE-to-advisory mapping, because the notices list already carries
the CVEs each notice addresses. The tests that matter are the ones about what is *not*
taken: a notice with no CVE cannot be correlated, a withdrawn notice is not evidence,
and the package lists are reduced to a count rather than published in full.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from normalization import ubuntu as ubuntu_module  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402


def notice(
    *,
    notice_id: str = "USN-8958-1",
    title: str = ".NET vulnerabilities",
    summary: str = "Several security issues were fixed in .NET",
    published: str = "2026-10-29T17:02:55.501527",
    cves: list[str] | None = None,
    cves_ids: list[str] | None = None,
    hidden: bool = False,
    release_packages: dict | None = None,
) -> dict:
    return {
        "id": notice_id,
        "title": title,
        "summary": summary,
        "published": published,
        "type": "USN",
        "is_hidden": hidden,
        "cves": [{"id": cve, "notices_ids": [notice_id]} for cve in cves or []],
        "cves_ids": cves_ids or [],
        "release_packages": release_packages
        if release_packages is not None
        else {"noble": [{"name": "dotnet8"}], "jammy": [{"name": "dotnet6"}]},
    }


class ParseNoticesTests(unittest.TestCase):
    def test_a_notice_is_parsed_with_its_cves(self) -> None:
        parsed = ubuntu_module.parse_notices(
            {"notices": [notice(cves=["CVE-2026-114148", "CVE-2026-114149"])]}
        )

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["notice_id"], "USN-8958-1")
        self.assertEqual(parsed[0]["cves"], ["CVE-2026-114148", "CVE-2026-114149"])

    def test_the_flat_cve_list_is_read_too(self) -> None:
        """Either field can carry them, so reading only one loses notices."""

        parsed = ubuntu_module.parse_notices(
            {"notices": [notice(cves_ids=["CVE-2026-114148"])]}
        )

        self.assertEqual(parsed[0]["cves"], ["CVE-2026-114148"])

    def test_a_malformed_cve_is_not_kept(self) -> None:
        parsed = ubuntu_module.parse_notices(
            {"notices": [notice(cves=["CVE-2026-114148", "not-a-cve"])]}
        )

        self.assertEqual(parsed[0]["cves"], ["CVE-2026-114148"])

    def test_the_releases_are_read_from_the_package_map(self) -> None:
        parsed = ubuntu_module.parse_notices({"notices": [notice()]})

        self.assertEqual(parsed[0]["releases"], ["jammy", "noble"])

    def test_the_package_count_is_reduced_to_a_number(self) -> None:
        """The package lists are large and name releases rather than anything a reader
        acts on, so they are counted and the notice URL carries the detail."""

        parsed = ubuntu_module.parse_notices({"notices": [notice()]})

        self.assertEqual(parsed[0]["package_count"], 2)

    def test_the_url_points_at_the_notice(self) -> None:
        parsed = ubuntu_module.parse_notices({"notices": [notice()]})

        self.assertEqual(
            parsed[0]["url"], "https://ubuntu.com/security/notices/USN-8958-1"
        )

    def test_a_notice_without_an_id_is_dropped(self) -> None:
        parsed = ubuntu_module.parse_notices({"notices": [{"title": "no id"}]})

        self.assertEqual(parsed, [])

    def test_a_bare_list_is_accepted(self) -> None:
        parsed = ubuntu_module.parse_notices([notice()])

        self.assertEqual(len(parsed), 1)

    def test_a_payload_that_is_neither_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            ubuntu_module.parse_notices("not a payload")

    def test_a_payload_without_a_notices_array_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            ubuntu_module.parse_notices({"results": []})


class ObservationTests(unittest.TestCase):
    def test_one_observation_per_cve(self) -> None:
        parsed = ubuntu_module.parse_notices(
            {"notices": [notice(cves=["CVE-2026-114148", "CVE-2026-114149"])]}
        )

        observations = ubuntu_module.build_observations(
            parsed, source_key="ubuntu_security", retrieved_at="2026-11-01T00:00:00Z"
        )

        self.assertEqual(
            sorted(item.external_id for item in observations),
            ["CVE-2026-114148", "CVE-2026-114149"],
        )

    def test_the_observation_declares_the_cve_as_an_entity(self) -> None:
        parsed = ubuntu_module.parse_notices(
            {"notices": [notice(cves=["CVE-2026-114148"])]}
        )

        observation = ubuntu_module.build_observations(
            parsed, source_key="ubuntu_security", retrieved_at="2026-11-01T00:00:00Z"
        )[0]

        self.assertEqual([entity.kind for entity in observation.entities], ["cve"])

    def test_the_notice_identity_travels_with_the_observation(self) -> None:
        parsed = ubuntu_module.parse_notices(
            {"notices": [notice(cves=["CVE-2026-114148"])]}
        )

        observation = ubuntu_module.build_observations(
            parsed, source_key="ubuntu_security", retrieved_at="2026-11-01T00:00:00Z"
        )[0]

        self.assertEqual(observation.payload["notice_id"], "USN-8958-1")
        self.assertEqual(
            observation.payload["ubuntu_url"],
            "https://ubuntu.com/security/notices/USN-8958-1",
        )

    def test_a_notice_naming_no_cve_produces_nothing(self) -> None:
        """It cannot be correlated to anything, so it is not forced into a group."""

        parsed = ubuntu_module.parse_notices({"notices": [notice()]})

        self.assertEqual(
            ubuntu_module.build_observations(
                parsed,
                source_key="ubuntu_security",
                retrieved_at="2026-11-01T00:00:00Z",
            ),
            [],
        )

    def test_a_withdrawn_notice_is_not_evidence(self) -> None:
        parsed = ubuntu_module.parse_notices(
            {"notices": [notice(cves=["CVE-2026-114148"], hidden=True)]}
        )

        self.assertEqual(
            ubuntu_module.build_observations(
                parsed,
                source_key="ubuntu_security",
                retrieved_at="2026-11-01T00:00:00Z",
            ),
            [],
        )

    def test_the_published_date_is_the_observation_time(self) -> None:
        parsed = ubuntu_module.parse_notices(
            {"notices": [notice(cves=["CVE-2026-114148"])]}
        )

        observation = ubuntu_module.build_observations(
            parsed, source_key="ubuntu_security", retrieved_at="2026-11-01T00:00:00Z"
        )[0]

        self.assertEqual(observation.observed_at, "2026-10-29T17:02:55Z")

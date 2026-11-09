"""Microsoft Security Update Guide normalisation.

The MSRC payload is aggregated rather than read row by row, because one CVE
commonly returns several rows — one per affected product — and taking the first
would understate a CVE that is Moderate on one product and Critical on another.
These tests pin that behaviour, and the URL encoding, which is where a mistake
would look exactly like a CVE Microsoft does not cover.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from normalization import msrc  # noqa: E402
from normalization.cisa import NormalizationError, RecordUnavailable  # noqa: E402

BASE = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct"


def row(
    *,
    product: str = "Windows Server 2022",
    severity: str = "Important",
    base_score: str | None = "8.1",
    vector: str = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe: list[str] | None = None,
    status: str = "fixed",
    build: str | None = "10.0.20348.1000",
    action: bool = True,
) -> dict:
    return {
        "cveNumber": "CVE-2026-91732",
        "releaseNumber": "2026-Oct",
        "releaseDate": "2026-10-13T07:00:00-07:00",
        "product": product,
        "severity": severity,
        "baseScore": base_score,
        "vectorString": vector,
        "cweList": cwe if cwe is not None else ["CWE-862: Missing Authorization"],
        "productStatus": status,
        "customerActionRequired": action,
        "kbArticles": (
            [{"fixedBuildNumber": build, "articleName": "Release Notes"}]
            if build
            else []
        ),
    }


def response(*rows: dict) -> dict:
    return {"@odata.count": len(rows), "value": list(rows)}


class MsrcUrlTests(unittest.TestCase):
    def test_the_filter_is_percent_encoded(self) -> None:
        """A raw apostrophe or space would be a malformed query, and a malformed
        query looks exactly like a CVE Microsoft does not cover."""

        url = msrc.record_url(BASE, "cve-2026-91732")

        self.assertEqual(
            url,
            BASE + "?%24filter=cveNumber%20eq%20%27CVE-2026-91732%27",
        )
        self.assertNotIn(" ", url)
        self.assertNotIn("'", url)
        # `+` is not read as a space by every OData server, so it must not appear.
        self.assertNotIn("+", url)

    def test_a_trailing_slash_on_the_base_is_tolerated(self) -> None:
        self.assertEqual(
            msrc.record_url(BASE + "/", "CVE-2026-91732"),
            msrc.record_url(BASE, "CVE-2026-91732"),
        )


class MsrcAggregationTests(unittest.TestCase):
    def test_a_single_row_parses(self) -> None:
        payload = msrc.parse_msrc_record(response(row()))

        self.assertEqual(payload["cve_id"], "CVE-2026-91732")
        self.assertEqual(payload["vendor"], "Microsoft")
        self.assertEqual(payload["threat_severity"], "important")
        self.assertEqual(payload["cvss"]["base_score"], 8.1)
        self.assertEqual(payload["cwe"], ["CWE-862"])

    def test_the_highest_base_score_across_rows_wins(self) -> None:
        """Taking the first row would understate the CVE."""

        payload = msrc.parse_msrc_record(
            response(
                row(product="A", base_score="3.1", severity="Moderate"),
                row(product="B", base_score="9.8", severity="Critical"),
                row(product="C", base_score="5.0", severity="Important"),
            )
        )

        self.assertEqual(payload["cvss"]["base_score"], 9.8)
        self.assertEqual(payload["threat_severity"], "critical")

    def test_the_vector_travels_with_its_own_score(self) -> None:
        """A published CVSS must never be assembled from two different rows."""

        payload = msrc.parse_msrc_record(
            response(
                row(base_score="3.1", vector="CVSS:3.1/LOW"),
                row(base_score="9.8", vector="CVSS:3.1/HIGH"),
            )
        )

        self.assertEqual(payload["cvss"]["base_score"], 9.8)
        self.assertEqual(payload["cvss"]["vector"], "CVSS:3.1/HIGH")

    def test_affected_products_are_unioned_and_deduplicated(self) -> None:
        payload = msrc.parse_msrc_record(
            response(
                row(product="Windows Server 2022"),
                row(product="Windows 11"),
                row(product="Windows Server 2022"),
            )
        )

        self.assertEqual(
            payload["affected_products"], ["Windows Server 2022", "Windows 11"]
        )

    def test_cwes_are_unioned_across_rows(self) -> None:
        payload = msrc.parse_msrc_record(
            response(
                row(cwe=["CWE-862: Missing Authorization"]),
                row(cwe=["CWE-79: Improper Neutralization"]),
            )
        )

        self.assertEqual(sorted(payload["cwe"]), ["CWE-79", "CWE-862"])

    def test_fixed_builds_are_collected(self) -> None:
        """The build number is what an operator actually needs."""

        payload = msrc.parse_msrc_record(
            response(
                row(product="A", build="10.0.20348.1000"),
                row(product="B", build="10.0.22621.1000"),
            )
        )

        self.assertEqual(
            payload["fixed_builds"], ["10.0.20348.1000", "10.0.22621.1000"]
        )

    def test_a_customer_action_flag_is_carried(self) -> None:
        payload = msrc.parse_msrc_record(response(row(action=True)))

        self.assertTrue(payload["customer_action_required"])

    def test_the_payload_is_offered_to_the_engine_as_enrichment(self) -> None:
        payload = msrc.parse_msrc_record(response(row()))

        self.assertTrue(payload["enrichment"])
        self.assertIn("enrichment_summary", payload)


class MsrcValidationTests(unittest.TestCase):
    def test_an_empty_result_is_a_cacheable_miss_not_an_error(self) -> None:
        with self.assertRaises(RecordUnavailable):
            msrc.parse_msrc_record({"@odata.count": 0, "value": []})

    def test_a_response_without_a_value_array_is_an_error(self) -> None:
        """OData returns this when the filter is rejected — a different fact from
        the CVE being unknown, and it must not be cached as a miss."""

        with self.assertRaises(NormalizationError) as context:
            msrc.parse_msrc_record({"error": {"code": "BadRequest"}})

        self.assertIn("value array", str(context.exception))

    def test_a_non_object_response_is_an_error(self) -> None:
        with self.assertRaises(NormalizationError):
            msrc.parse_msrc_record(["not", "an", "object"])

    def test_a_row_without_an_assessment_is_a_miss(self) -> None:
        with self.assertRaises(RecordUnavailable):
            msrc.parse_msrc_record(
                response(
                    {
                        "cveNumber": "CVE-2026-91732",
                        "product": None,
                        "severity": None,
                        "baseScore": None,
                    }
                )
            )

    def test_an_unrecognised_severity_is_not_published(self) -> None:
        payload = msrc.parse_msrc_record(response(row(severity="Unknown")))

        self.assertIsNone(payload["threat_severity"])

    def test_an_unparseable_score_is_ignored_rather_than_guessed(self) -> None:
        payload = msrc.parse_msrc_record(response(row(base_score="not-a-number")))

        self.assertIsNone(payload["cvss"])

    def test_the_observation_declares_the_cve(self) -> None:
        payload = msrc.parse_msrc_record(response(row()))
        observation = msrc.build_observation(
            payload, source_key="msrc", retrieved_at="2026-11-01T00:00:00Z"
        )

        self.assertEqual(observation.external_id, "CVE-2026-91732")
        self.assertEqual([entity.kind for entity in observation.entities], ["cve"])

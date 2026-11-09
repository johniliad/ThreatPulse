"""Source health: the per-run report the API publishes.

Source health answers a different question from the attribution register. The
register says what a source is and on what terms it may be used; health says
whether it actually worked on the run that produced the publication. A reader
looking at a low count needs the second, and before this existed it was only
visible in a log line on the machine that ran the pipeline.

What these tests hold in place:

* the report describes the run that produced the document, not the collectors
  that happened to be registered;
* every status the pipeline can emit is counted, and an unexpected one is still
  reported rather than dropped;
* nothing in ``SourceResult.summary()`` is lost on the way to the public
  document — a failure reason that does not travel is a failure nobody can see.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from collectors.base import SourceResult  # noqa: E402
from models.intelligence import Source  # noqa: E402
from run_pipeline import build_source_health  # noqa: E402

GENERATED_AT = "2026-11-02T01:15:00Z"


def make_source(key: str) -> Source:
    return Source(
        key=key,
        name=f"Fixture {key}",
        source_type="advisory",
        url=f"https://example.test/{key}",
        provider="Fixture",
        reliability="high",
    )


def make_result(
    key: str,
    status: str,
    *,
    observations: int = 0,
    failure_reason: str | None = None,
    used_last_known_good: bool = False,
    metrics: dict | None = None,
) -> SourceResult:
    return SourceResult(
        source=make_source(key),
        status=status,
        observations=[object()] * observations,
        metrics=metrics or {},
        failure_reason=failure_reason,
        used_last_known_good=used_last_known_good,
    )


class SourceHealthShapeTests(unittest.TestCase):
    def test_the_report_is_stamped_with_the_publication_time(self) -> None:
        health = build_source_health([], generated_at=GENERATED_AT)

        self.assertEqual(health["generated_at"], GENERATED_AT)

    def test_one_entry_per_collected_source(self) -> None:
        health = build_source_health(
            [
                make_result("cisa_kev", "ok", observations=3),
                make_result("epss", "ok", observations=1),
            ],
            generated_at=GENERATED_AT,
        )

        self.assertEqual(
            [source["source_key"] for source in health["sources"]],
            ["cisa_kev", "epss"],
        )

    def test_entries_are_ordered_for_stable_output(self) -> None:
        health = build_source_health(
            [
                make_result("zebra", "ok"),
                make_result("alpha", "ok"),
                make_result("midway", "ok"),
            ],
            generated_at=GENERATED_AT,
        )

        self.assertEqual(
            [source["source_key"] for source in health["sources"]],
            ["alpha", "midway", "zebra"],
        )

    def test_a_run_with_no_sources_reports_zeroes_rather_than_nothing(self) -> None:
        health = build_source_health([], generated_at=GENERATED_AT)

        self.assertEqual(health["sources"], [])
        self.assertEqual(
            health["summary"],
            {"ok": 0, "degraded": 0, "failed": 0, "sources": 0},
        )

    def test_the_summary_counts_each_status(self) -> None:
        health = build_source_health(
            [
                make_result("a", "ok"),
                make_result("b", "ok"),
                make_result("c", "degraded", used_last_known_good=True),
                make_result("d", "failed", failure_reason="timed out"),
            ],
            generated_at=GENERATED_AT,
        )

        self.assertEqual(
            health["summary"],
            {"ok": 2, "degraded": 1, "failed": 1, "sources": 4},
        )

    def test_the_summary_counts_are_derived_not_asserted(self) -> None:
        """The counts must follow the entries, never the other way round."""

        health = build_source_health(
            [make_result("a", "ok")],
            generated_at=GENERATED_AT,
        )

        self.assertEqual(health["summary"]["sources"], len(health["sources"]))
        self.assertEqual(health["summary"]["ok"], len(health["sources"]))


class SourceHealthContentTests(unittest.TestCase):
    def test_a_degraded_source_keeps_its_failure_reason(self) -> None:
        health = build_source_health(
            [
                make_result(
                    "epss",
                    "degraded",
                    used_last_known_good=True,
                    failure_reason="HTTP 503 from the EPSS API.",
                )
            ],
            generated_at=GENERATED_AT,
        )

        source = health["sources"][0]

        self.assertEqual(source["status"], "degraded")
        self.assertTrue(source["used_last_known_good"])
        self.assertEqual(
            source["failure_reason"], "HTTP 503 from the EPSS API."
        )

    def test_observation_counts_survive_the_round_trip(self) -> None:
        health = build_source_health(
            [make_result("cisa_kev", "ok", observations=1766)],
            generated_at=GENERATED_AT,
        )

        self.assertEqual(health["sources"][0]["observations"], 1766)

    def test_metrics_travel_with_the_entry(self) -> None:
        health = build_source_health(
            [
                make_result(
                    "redhat_security",
                    "ok",
                    metrics={"cache_hits": 12, "pending": 3},
                )
            ],
            generated_at=GENERATED_AT,
        )

        self.assertEqual(
            health["sources"][0]["metrics"],
            {"cache_hits": 12, "pending": 3},
        )

    def test_an_unexpected_status_is_reported_but_not_counted(self) -> None:
        """A new status must not vanish, and must not corrupt the counts."""

        health = build_source_health(
            [
                make_result("a", "ok"),
                make_result("b", "skipped"),
            ],
            generated_at=GENERATED_AT,
        )

        self.assertEqual(
            [source["status"] for source in health["sources"]],
            ["ok", "skipped"],
        )

        self.assertEqual(
            health["summary"],
            {"ok": 1, "degraded": 0, "failed": 0, "sources": 2},
        )


if __name__ == "__main__":
    unittest.main()


"""Temporal intelligence: what changed between two publications.

A publication is a full snapshot, so on its own it cannot answer the question an
operator actually asks — what is new, what got worse, what stopped being reported.
These tests cover the registry that answers it: what it counts, what it refuses to
call a change, and how it behaves across runs.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from models.intelligence import Threat  # noqa: E402
from publication.builder import build_publication  # noqa: E402
from state.store import StateStore  # noqa: E402
from state.threat_history import ThreatHistory  # noqa: E402

NOW = "2026-11-02T00:00:00Z"
LATER = "2026-11-03T00:00:00Z"
MUCH_LATER = "2027-03-01T00:00:00Z"


def threat(
    cve: str = "CVE-2026-0001",
    *,
    severity: str = "high",
    score: float = 77.0,
    confidence: str = "medium",
    exploitation: str = "confirmed",
    sources: tuple[str, ...] = ("cisa_kev",),
    uuid: str | None = None,
) -> Threat:
    return Threat(
        threat_uuid=uuid or f"uuid-{cve}",
        external_id=cve,
        title=f"Vulnerability {cve}",
        threat_type="vulnerability",
        severity=severity,
        priority_score=score,
        confidence_score=60.0,
        confidence_level=confidence,
        exploitation_status=exploitation,
        first_seen="2026-10-01T00:00:00Z",
        last_seen="2026-10-31T00:00:00Z",
        summary="summary",
        recommended_action=None,
        source_keys=list(sources),
    )


def store() -> StateStore:
    root = Path(tempfile.mkdtemp())

    return StateStore(root / "state", root / "data")


def history(state: StateStore) -> ThreatHistory:
    registry = ThreatHistory(state)
    registry.load()

    return registry


class FirstPublicationTests(unittest.TestCase):
    def test_a_first_publication_marks_everything_new(self) -> None:
        registry = history(store())

        delta = registry.reconcile(
            [threat(), threat("CVE-2026-0002")], now=NOW
        )

        self.assertEqual(delta["new"], 2)
        self.assertEqual(delta["changed"], 0)
        self.assertEqual(delta["disappeared"], 0)
        self.assertEqual(registry.size, 2)

    def test_every_threat_carries_a_temporal_block(self) -> None:
        registry = history(store())
        first = threat()

        registry.reconcile([first], now=NOW)

        self.assertEqual(first.metadata["temporal"]["revision"], 1)
        self.assertEqual(first.metadata["temporal"]["first_published_at"], NOW)


class ChangeDetectionTests(unittest.TestCase):
    def _established(self):
        state = store()
        registry = history(state)
        registry.reconcile([threat()], now=NOW)
        registry.save()

        return state

    def test_an_unchanged_republish_changes_nothing(self) -> None:
        state = self._established()
        again = threat()

        delta = history(state).reconcile([again], now=LATER)

        self.assertEqual(delta["new"], 0)
        self.assertEqual(delta["changed"], 0)
        self.assertEqual(delta["unchanged"], 1)
        self.assertEqual(again.metadata["temporal"]["revision"], 1)
        self.assertNotIn("changed_since_previous", again.metadata["temporal"])

    def test_the_first_publication_date_never_moves(self) -> None:
        state = self._established()
        again = threat()

        history(state).reconcile([again], now=LATER)

        self.assertEqual(again.metadata["temporal"]["first_published_at"], NOW)

    def test_a_moved_score_bumps_the_revision_and_names_the_field(self) -> None:
        state = self._established()
        worse = threat(score=91.0)

        delta = history(state).reconcile([worse], now=LATER)

        self.assertEqual(delta["changed"], 1)
        self.assertEqual(worse.metadata["temporal"]["revision"], 2)
        self.assertEqual(
            worse.metadata["temporal"]["changed_since_previous"],
            ["priority_score"],
        )

    def test_severity_and_corroboration_are_tracked(self) -> None:
        state = self._established()
        escalated = threat(severity="critical", sources=("cisa_kev", "vulnrichment"))

        history(state).reconcile([escalated], now=LATER)

        moved = escalated.metadata["temporal"]["changed_since_previous"]

        self.assertIn("severity", moved)
        self.assertIn("source_keys", moved)

    def test_untracked_fields_do_not_count_as_change(self) -> None:
        """Retrieval timestamps and enrichment blocks move on every run; treating
        them as change would make every republication a change."""

        state = self._established()
        noisy = threat()
        noisy.metadata["retrieved_at"] = LATER
        noisy.metadata["enrichment"] = {"ssvc": {"exploitation": "active"}}

        delta = history(state).reconcile([noisy], now=LATER)

        self.assertEqual(delta["changed"], 0)


class DisappearanceTests(unittest.TestCase):
    def _established(self):
        state = store()
        registry = history(state)
        registry.reconcile([threat(), threat("CVE-2026-0002")], now=NOW)
        registry.save()

        return state

    def test_a_threat_absent_from_the_run_is_counted(self) -> None:
        delta = history(self._established()).reconcile([threat()], now=LATER)

        self.assertEqual(delta["disappeared"], 1)

    def test_a_disappeared_threat_keeps_its_entry(self) -> None:
        registry = history(self._established())

        registry.reconcile([], now=LATER)

        self.assertEqual(registry.size, 2)

    def test_a_returning_threat_is_not_reported_as_new(self) -> None:
        state = self._established()

        gone = history(state)
        gone.reconcile([], now=LATER)
        gone.save()

        delta = history(state).reconcile([threat()], now="2026-11-04T00:00:00Z")

        self.assertEqual(delta["new"], 0)
        self.assertEqual(delta["unchanged"], 1)


class RetentionTests(unittest.TestCase):
    def test_an_entry_older_than_retention_is_pruned(self) -> None:
        state = store()
        registry = history(state)
        registry.reconcile([threat()], now=NOW)
        registry.save()

        later = history(state)
        delta = later.reconcile([], now=MUCH_LATER)

        self.assertEqual(delta["pruned"], 1)
        self.assertEqual(later.size, 0)


class PersistenceTests(unittest.TestCase):
    def test_it_survives_a_round_trip(self) -> None:
        state = store()
        registry = history(state)
        registry.reconcile([threat()], now=NOW)
        registry.save()

        again = threat()
        history(state).reconcile([again], now=LATER)

        self.assertEqual(again.metadata["temporal"]["first_published_at"], NOW)

    def test_an_unreadable_registry_is_not_an_error(self) -> None:
        state = store()
        path = state.state_path("threat_history.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not json at all", encoding="utf-8")

        delta = history(state).reconcile([threat()], now=NOW)

        self.assertEqual(delta["new"], 1)

    def test_history_follows_identity_not_uuid(self) -> None:
        """The uuid is derived from the CVE, but if it ever moves the history must
        follow the threat rather than silently treat it as new."""

        state = store()
        registry = history(state)
        registry.reconcile([threat(uuid="uuid-a")], now=NOW)
        registry.save()

        moved = threat(uuid="uuid-b")
        delta = history(state).reconcile([moved], now=LATER)

        self.assertEqual(delta["new"], 0)
        self.assertEqual(moved.metadata["temporal"]["revision"], 1)


class PublicationSummaryTests(unittest.TestCase):
    def test_the_summary_carries_the_change_counts(self) -> None:
        registry = history(store())
        changes = registry.reconcile([threat()], now=NOW)

        publication = build_publication(
            [threat()], [], generated_at=NOW, changes=changes
        )

        self.assertEqual(publication.summary["changes"]["new"], 1)

    def test_a_publication_without_change_tracking_is_unchanged(self) -> None:
        publication = build_publication([threat()], [], generated_at=NOW)

        self.assertNotIn("changes", publication.summary)

    def test_the_summary_does_not_claim_a_single_source(self) -> None:
        """It was served as "CISA KEV Intelligence", derived from "the CISA Known
        Exploited Vulnerabilities Catalog", long after the published set became a
        multi-source aggregate. The summary goes to every API client."""

        publication = build_publication([threat()], [], generated_at=NOW)

        self.assertNotIn("CISA KEV", publication.summary["title"])
        self.assertNotIn("Known Exploited", publication.summary["description"])


if __name__ == "__main__":
    unittest.main()


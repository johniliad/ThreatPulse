"""Chunked publishing: the publisher sends a publication in pieces.

A publication that fits one request is still sent as one chunk, so the
single-request path is unchanged. These tests cover what is new: that a large
publication is split, that the pieces are sent in order, that a failure stops the
run rather than growing an unfinishable publication, and that an incomplete
publication is reported as a problem rather than as a success.
"""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import publisher  # noqa: E402
from lib.config import load_settings  # noqa: E402
from lib.http import HttpError  # noqa: E402

PUBLICATION_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


class FakeResponse:
    def __init__(self, status: int, payload: dict) -> None:
        self.status = status
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class FakeHttp:
    """Records what was sent and replays canned responses."""

    def __init__(self, responses=None) -> None:
        self.responses = list(responses or [])
        self.sent: list[dict] = []

    def post_json(self, url, payload, *, timeout_seconds=None, headers=None):
        self.sent.append(payload)

        if self.responses:
            response = self.responses.pop(0)

            if isinstance(response, Exception):
                raise response

            return response

        chunk = payload.get("chunk") or {}

        # Faithful to publish.php, which echoes the chunk it was given. A fake
        # that omits it describes an endpoint that ignored the chunk block.
        return FakeResponse(
            201,
            {
                "status": "ok",
                "publication_uuid": PUBLICATION_UUID,
                "chunk_index": chunk.get("index"),
                "chunk_count": chunk.get("count"),
                "complete": True,
            },
        )


def publication(threat_count: int) -> dict:
    threats = [
        {
            "threat_uuid": f"11111111-2222-3333-4444-{index:012d}",
            "external_id": f"CVE-2026-{100000 + index}",
            "title": f"Vulnerability CVE-2026-{100000 + index}",
            "threat_type": "vulnerability",
            "severity": "high",
            "priority_score": 80.0,
            "confidence_score": 95.0,
            "confidence_level": "high",
            "exploitation_status": "confirmed",
            "first_seen": "2026-10-01T00:00:00Z",
            "last_seen": "2026-10-31T00:00:00Z",
            "source_keys": ["cisa_kev"],
            "vulnerabilities": [],
            "summary": "x" * 200,
        }
        for index in range(threat_count)
    ]

    return {
        "publication_uuid": PUBLICATION_UUID,
        "schema_version": "1.0",
        "generated_at": "2026-10-31T00:00:00Z",
        "summary": {"threat_count": threat_count},
        "sources": [{"source_key": "cisa_kev"}],
        "threats": threats,
    }


def settings_with_limit(max_bytes: int):
    settings = load_settings()

    return replace(
        settings,
        publication=replace(settings.publication, max_payload_bytes=max_bytes),
    )


class ChunkedPublishingTests(unittest.TestCase):
    def test_a_small_publication_is_sent_as_one_chunk(self) -> None:
        http = FakeHttp()

        outcome = publisher.publish_publication(
            publication(1),
            settings=settings_with_limit(1024 * 1024),
            token="token",
            http=http,
        )

        self.assertEqual(len(http.sent), 1)
        self.assertEqual(outcome.chunks_sent, 1)
        self.assertEqual(outcome.chunks_total, 1)
        self.assertTrue(outcome.ok)
        self.assertTrue(outcome.complete)

    def test_a_large_publication_is_split_and_sent_in_order(self) -> None:
        http = FakeHttp()

        outcome = publisher.publish_publication(
            publication(200),
            settings=settings_with_limit(8192),
            token="token",
            http=http,
        )

        self.assertGreater(outcome.chunks_total, 1)
        self.assertEqual(outcome.chunks_sent, outcome.chunks_total)

        # The slices reconstruct the original, in order.
        rebuilt = [threat for chunk in http.sent for threat in chunk["threats"]]

        self.assertEqual(
            [threat["external_id"] for threat in rebuilt],
            [f"CVE-2026-{100000 + index}" for index in range(200)],
        )

        for index, chunk in enumerate(http.sent):
            self.assertEqual(chunk["chunk"]["index"], index)
            self.assertEqual(chunk["chunk"]["count"], outcome.chunks_total)

    def test_no_chunk_sent_is_empty(self) -> None:
        http = FakeHttp()

        publisher.publish_publication(
            publication(200),
            settings=settings_with_limit(8192),
            token="token",
            http=http,
        )

        self.assertTrue(all(chunk["threats"] for chunk in http.sent))

    def test_a_failure_stops_the_run_rather_than_growing_a_partial_publication(
        self,
    ) -> None:
        http = FakeHttp(
            responses=[
                FakeResponse(202, {"status": "ok", "chunk_count": 5}),
                HttpError("chunk 1 failed", transient=False, status=500),
            ]
        )

        with self.assertRaises(HttpError) as context:
            publisher.publish_publication(
                publication(200),
                settings=settings_with_limit(8192),
                token="token",
                http=http,
            )

        # Two requests made, and the rest were never attempted: sending them would
        # grow a publication that no later chunk could complete.
        self.assertEqual(len(http.sent), 2)

        # And the error says what the failure left behind, not just that a request
        # failed.
        message = str(context.exception)

        self.assertIn("incomplete on the API", message)
        self.assertIn("upserted rather than duplicated", message)

    def test_a_failure_on_the_first_chunk_is_not_reported_as_partial(self) -> None:
        """Chunk 0 creates the publication, so failing there leaves nothing behind
        and the error should be the original one."""

        http = FakeHttp(
            responses=[HttpError("chunk 0 failed", transient=False, status=500)]
        )

        with self.assertRaises(HttpError) as context:
            publisher.publish_publication(
                publication(200),
                settings=settings_with_limit(8192),
                token="token",
                http=http,
            )

        self.assertNotIn("incomplete on the API", str(context.exception))

    def test_a_duplicate_publication_is_reported_as_already_published(self) -> None:
        http = FakeHttp(
            responses=[HttpError("duplicate", transient=False, status=409)]
        )

        outcome = publisher.publish_publication(
            publication(1),
            settings=settings_with_limit(1024 * 1024),
            token="token",
            http=http,
        )

        self.assertTrue(outcome.duplicate)
        self.assertTrue(outcome.ok)
        self.assertEqual(
            publisher.validate_api_response(outcome, publication(1)), []
        )

    def test_a_dry_run_sends_nothing_and_reports_the_plan(self) -> None:
        http = FakeHttp()

        outcome = publisher.publish_publication(
            publication(200),
            settings=settings_with_limit(8192),
            token="token",
            http=http,
            dry_run=True,
        )

        self.assertEqual(http.sent, [])
        self.assertGreater(outcome.response["chunks"], 1)
        self.assertGreater(outcome.response["total_bytes"], 0)


class ChunkedResponseValidationTests(unittest.TestCase):
    def test_an_incomplete_publication_is_reported(self) -> None:
        outcome = publisher.PublishOutcome(
            status_code=500,
            response={"status": "error"},
            chunks_sent=2,
            chunks_total=5,
        )

        problems = publisher.validate_api_response(outcome, publication(1))

        self.assertTrue(problems)
        self.assertIn("2 of 5", problems[0])

    def test_a_final_chunk_that_did_not_complete_is_reported(self) -> None:
        """Otherwise a bug that dropped the last chunk would look like success."""

        outcome = publisher.PublishOutcome(
            status_code=201,
            response={
                "status": "ok",
                "publication_uuid": PUBLICATION_UUID,
                "complete": False,
            },
            chunks_sent=3,
            chunks_total=3,
        )

        problems = publisher.validate_api_response(outcome, publication(1))

        self.assertTrue(any("complete=true" in problem for problem in problems))

    def test_a_completed_multi_chunk_publication_passes(self) -> None:
        outcome = publisher.PublishOutcome(
            status_code=201,
            response={
                "status": "ok",
                "publication_uuid": PUBLICATION_UUID,
                "complete": True,
            },
            chunks_sent=3,
            chunks_total=3,
        )

        self.assertEqual(
            publisher.validate_api_response(outcome, publication(1)), []
        )

    def test_a_single_request_publication_need_not_report_completeness(self) -> None:
        """An API older than chunking sends no ``complete`` field at all, so the
        check must not demand one from a single-request publication."""

        outcome = publisher.PublishOutcome(
            status_code=201,
            response={"status": "ok", "publication_uuid": PUBLICATION_UUID},
            chunks_sent=1,
            chunks_total=1,
        )

        self.assertEqual(
            publisher.validate_api_response(outcome, publication(1)), []
        )

    def test_a_duplicate_after_the_first_chunk_is_reported_as_incomplete(self) -> None:
        """An API that predates chunking ignores the chunk block and treats each
        chunk as its own publication, so it answers the second chunk with 409 and
        only the first chunk's threats are stored. Reporting success there would be
        silent data loss."""

        outcome = publisher.PublishOutcome(
            status_code=409,
            response={"status": "duplicate"},
            chunks_sent=2,
            chunks_total=5,
            partial_duplicate=True,
        )

        self.assertFalse(outcome.ok)

        problems = publisher.validate_api_response(outcome, publication(1))

        self.assertTrue(problems)
        self.assertIn("predates chunked publishing", problems[0])

    def test_a_duplicate_after_the_first_chunk_stops_the_run(self) -> None:
        http = FakeHttp(
            responses=[
                FakeResponse(202, {"status": "ok", "chunk_count": 5}),
                HttpError("duplicate", transient=False, status=409),
            ]
        )

        outcome = publisher.publish_publication(
            publication(200),
            settings=settings_with_limit(8192),
            token="token",
            http=http,
        )

        # The remaining chunks are not attempted against an API that is treating
        # each one as a separate publication.
        self.assertEqual(len(http.sent), 2)
        self.assertTrue(outcome.partial_duplicate)
        self.assertFalse(outcome.ok)


class RefusedChunkDiagnosticsTests(unittest.TestCase):
    """A 409 must be reported with the reason the API gave.

    publish.php answers three different 409s: a publication_uuid that is already
    stored, a chunk for a publication it considers finalised, and a chunk that
    arrived before chunk 0. They call for different actions, so a paraphrase of
    the status code is not enough to act on. Collapsing them into "already exists
    on the API" is what sent several runs after a stale endpoint while the real
    cause was a status column that could not store 'receiving'.
    """

    def test_the_api_message_is_reported_with_its_meaning(self) -> None:
        outcome = publisher.PublishOutcome(
            status_code=409,
            response={
                "status": "duplicate",
                "message": "Publication is already complete",
                "publication_status": "receiving",
            },
            chunks_sent=2,
            chunks_total=2,
            partial_duplicate=True,
        )

        problems = publisher.validate_api_response(outcome, publication(1))

        self.assertIn("Publication is already complete", problems[0])
        self.assertIn("considered finished", problems[0])
        self.assertNotIn("empty status", problems[0])

    def test_an_empty_publication_status_points_at_the_column(self) -> None:
        """The empty status is the signature of the truncation that broke
        chunked publishing, and it has to survive into the report."""

        outcome = publisher.PublishOutcome(
            status_code=409,
            response={
                "status": "duplicate",
                "message": "Publication is already complete",
                "publication_status": "",
            },
            chunks_sent=2,
            chunks_total=2,
            partial_duplicate=True,
        )

        problems = publisher.validate_api_response(outcome, publication(1))

        self.assertIn("empty status", problems[0])
        self.assertIn("MODIFY status VARCHAR(20)", problems[0])

    def test_a_chunk_the_api_did_not_report_as_a_chunk_stops_the_run(self) -> None:
        """An endpoint that predates chunking accepts the first chunk without
        mentioning it. Detecting that here stops the upload instead of sending
        every remaining megabyte to be refused."""

        http = FakeHttp(
            responses=[FakeResponse(202, {"status": "ok", "publication_id": 9})]
        )

        outcome = publisher.publish_publication(
            publication(200),
            settings=settings_with_limit(8192),
            token="token",
            http=http,
        )

        self.assertEqual(len(http.sent), 1)
        self.assertEqual(http.sent[0]["chunk"]["index"], 0)
        self.assertTrue(outcome.chunk_ignored)
        self.assertFalse(outcome.ok)

    def test_an_ignored_chunk_block_is_reported_as_a_stale_endpoint(self) -> None:
        outcome = publisher.PublishOutcome(
            status_code=202,
            response={"status": "ok", "publication_id": 9},
            chunks_sent=1,
            chunks_total=2,
            chunk_ignored=True,
        )

        problems = publisher.validate_api_response(outcome, publication(200))

        self.assertIn("did not report it as a chunk", problems[0])
        self.assertIn("older than this backend", problems[0])

"""Publisher response classification.

A publication the API **accepted** must never be reported as a failure, even when
the response body cannot be parsed. The HTTP status is authoritative for a
publish: ``publish.php`` sends 201 only after committing. Reporting an accepted
publication as a failure is worse than useless — it invites an operator to "fix"
something that already worked.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import publisher as publisher_module  # noqa: E402
from lib.http import HttpError, HttpResponse  # noqa: E402
from tests.test_publication_publisher import (  # noqa: E402
    PublicationTestCase,
    minimal_publication,
)

ENDPOINT = "https://example.invalid/api/cti/v1/publish.php"

#: Reproduces the real failure: a secrets file emitting a line before its JSON.
STRAY_PREFIX = (
    b"// /home/iliadis/threatpulse-secrets/threatpulse-db-write-config.php\n"
)

ACCEPTED_BODY = (
    STRAY_PREFIX
    + b'{"status":"ok","message":"Publication accepted","publication_id":4,'
    b'"publication_uuid":"166befaf-4cea-45ac-804c-124e851eca80","threat_count":1}'
)

CLEAN_BODY = (
    b'{"status":"ok","publication_id":4,'
    b'"publication_uuid":"166befaf-4cea-45ac-804c-124e851eca80","threat_count":1}'
)


class StubHttp:
    def __init__(self, outcome: object) -> None:
        self._outcome = outcome
        self.calls = 0

    def post_json(self, url, payload, *, timeout_seconds=None, headers=None):
        self.calls += 1

        if isinstance(self._outcome, Exception):
            raise self._outcome

        return self._outcome


def http_response(body: bytes, status: int) -> HttpResponse:
    return HttpResponse(
        status=status, body=body, headers={}, url=ENDPOINT, attempts=1
    )


class PublishResponseTests(PublicationTestCase):
    def _publish(self, outcome: object):
        return publisher_module.publish_publication(
            minimal_publication(),
            settings=self.settings(),
            token="test-token",
            http=StubHttp(outcome),
        )

    def test_a_clean_201_is_verified(self) -> None:
        result = self._publish(http_response(CLEAN_BODY, 201))

        self.assertTrue(result.ok)
        self.assertFalse(result.unverified)
        self.assertEqual(result.status_code, 201)

    def test_a_201_with_a_stray_prefix_is_accepted_but_unverified(self) -> None:
        result = self._publish(http_response(ACCEPTED_BODY, 201))

        self.assertTrue(result.ok)
        self.assertTrue(result.unverified)
        self.assertEqual(result.response["status"], "accepted-unverified")

    def test_an_unverified_outcome_reports_no_problems(self) -> None:
        result = self._publish(http_response(ACCEPTED_BODY, 201))

        self.assertEqual(
            publisher_module.validate_api_response(result, minimal_publication()),
            [],
        )

    def test_an_empty_201_body_is_also_accepted_but_unverified(self) -> None:
        result = self._publish(http_response(b"", 201))

        self.assertTrue(result.ok)
        self.assertTrue(result.unverified)

    def test_a_500_with_an_unparseable_body_still_fails(self) -> None:
        with self.assertRaises(HttpError):
            self._publish(http_response(b"<html>Internal Server Error</html>", 500))

    def test_a_500_with_an_empty_body_still_fails(self) -> None:
        with self.assertRaises(HttpError):
            self._publish(http_response(b"", 500))

    def test_a_409_is_still_treated_as_already_published(self) -> None:
        result = self._publish(
            HttpError("HTTP 409", transient=False, status=409)
        )

        self.assertTrue(result.duplicate)
        self.assertTrue(result.ok)
        self.assertFalse(result.unverified)

    def test_a_dry_run_transmits_nothing(self) -> None:
        http = StubHttp(http_response(CLEAN_BODY, 201))

        result = publisher_module.publish_publication(
            minimal_publication(),
            settings=self.settings(),
            token="test-token",
            http=http,
            dry_run=True,
        )

        self.assertEqual(http.calls, 0)
        self.assertEqual(result.status_code, 0)

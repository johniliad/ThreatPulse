"""HTTP response diagnostics.

A non-JSON response used to report only "was not valid JSON", which hides the
one fact that identifies the cause: whether the body was **empty**. An empty body
means the script never reached its own error handling, so PHP terminated or
something upstream refused the request.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from lib.http import (  # noqa: E402
    HttpError,
    HttpResponse,
    describe_error_body,
)

URL = "https://example.invalid/api/cti/v1/publish.php"


def fake_http_error(body: bytes, status: int = 500) -> Exception:
    """A stand-in for urllib's HTTPError, which is a readable file object."""

    class _Error(Exception):
        def __init__(self, payload: bytes, code: int) -> None:
            super().__init__(f"HTTP Error {code}")
            self.code = code
            self._payload = payload

        def read(self, size: int = -1) -> bytes:
            return self._payload if size < 0 else self._payload[:size]

    return _Error(body, status)


class ErrorBodyTests(unittest.TestCase):
    """An HTTP error's body is the only evidence the caller ever gets.

    Before this, a 5xx from a PHP endpoint was reported as nothing but its status
    code. A PHP fatal error, an uncaught exception and a framework error page all
    arrive as a body that says what went wrong, and all of it was discarded —
    which is what made a production publish failure undiagnosable from the run log.
    """

    def test_the_body_is_quoted(self) -> None:
        described = describe_error_body(
            fake_http_error(b'{"status":"error","error_message":"Unknown column"}')
        )

        self.assertIn("Unknown column", described)

    def test_a_php_fatal_is_quoted(self) -> None:
        described = describe_error_body(
            fake_http_error(
                b"<b>Fatal error</b>: Allowed memory size of 134217728 bytes exhausted"
            )
        )

        self.assertIn("memory size", described)

    def test_an_empty_body_is_stated_rather_than_left_blank(self) -> None:
        self.assertIn("empty body", describe_error_body(fake_http_error(b"")))

    def test_an_unreadable_body_is_reported_by_size(self) -> None:
        described = describe_error_body(fake_http_error(b"\xff\xfe\x00\x01"))

        self.assertTrue(described)

    def test_a_very_long_body_is_bounded(self) -> None:
        described = describe_error_body(fake_http_error(b"x" * 100000))

        self.assertLess(len(described), 1500)

    def test_something_without_a_body_is_tolerated(self) -> None:
        self.assertEqual(describe_error_body(Exception("no body here")), "")

    def test_a_failing_read_is_tolerated(self) -> None:
        class Broken(Exception):
            def read(self, size: int = -1) -> bytes:
                raise OSError("stream closed")

        self.assertEqual(describe_error_body(Broken()), "")



URL = "https://example.invalid/api/cti/v1/publish.php"


def response(body: bytes, status: int = 500) -> HttpResponse:
    return HttpResponse(
        status=status, body=body, headers={}, url=URL, attempts=1
    )


class HttpResponseDiagnosticsTests(unittest.TestCase):
    def test_valid_json_still_parses(self) -> None:
        self.assertEqual(
            response(b'{"status": "ok"}', 200).json(), {"status": "ok"}
        )

    def test_an_empty_body_names_the_server_limits_to_check(self) -> None:
        with self.assertRaises(HttpError) as context:
            response(b"").json()

        message = str(context.exception)

        self.assertIn("empty body", message)
        self.assertIn("HTTP 500", message)
        self.assertIn("post_max_size", message)
        self.assertIn("memory_limit", message)
        self.assertIn("max_execution_time", message)
        self.assertIn("PHP error log", message)

    def test_a_non_json_body_reports_the_status_and_size(self) -> None:
        body = b"<html><body>Fatal error: Allowed memory size exhausted</body></html>"

        with self.assertRaises(HttpError) as context:
            response(body).json()

        message = str(context.exception)

        self.assertIn("HTTP 500", message)
        self.assertIn(f"{len(body)} bytes", message)
        self.assertIn("Fatal error", message)

    def test_a_credential_in_the_body_is_redacted(self) -> None:
        secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

        with self.assertRaises(HttpError) as context:
            response(f"<html>Bearer {secret}</html>".encode()).json()

        message = str(context.exception)

        self.assertNotIn(secret, message)
        self.assertIn("[redacted]", message)

    def test_the_body_snippet_is_bounded(self) -> None:
        with self.assertRaises(HttpError) as context:
            response(b"x" * 5000).json()

        self.assertLess(len(str(context.exception)), 1000)

    def test_the_error_is_permanent_so_it_is_not_retried(self) -> None:
        with self.assertRaises(HttpError) as context:
            response(b"", 500).json()

        self.assertFalse(context.exception.transient)
        self.assertEqual(context.exception.status, 500)

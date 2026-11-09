"""HTTP client guarantees: secret redaction and conditional requests.

Two properties the product depends on and that nothing else asserts:

* **a credential must not reach a log, an exception, a traceback or a
  response.** Pattern matching catches ``Bearer`` tokens and ``key=value``
  forms; a bare path segment matches neither, so literal values are registered
  for redaction instead. That registration outlives the source that motivated
  it, so a future source that puts a credential back into a URL still cannot
  log it.
* **a conditional request must treat 304 as success, not as a failure.** An
  unchanged feed that is retried anyway is a wasted request against someone
  else's service, and that is how free feeds get closed.
"""

from __future__ import annotations

import logging
import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import (  # noqa: E402
    REDACTED,
    clear_registered_secrets,
    redact,
    redact_value,
    register_secret,
    registered_secret_count,
)


class PathEmbeddedSecretTests(unittest.TestCase):
    """A key carried in a URL path must not reach a log, an exception or a response.

    Pattern matching alone cannot catch this shape — a bare path segment is not a
    ``Bearer`` token and has no ``key=value`` form — so the literal value is
    registered instead. URLhaus used to carry its Auth-Key exactly this way and now
    sends it as a request header; the registration is kept as a backstop, so a source
    that puts a credential back into a URL still cannot log it.
    """

    SECRET = "0123456789abcdef0123456789abcdef"
    URL = f"https://feeds.example.invalid/downloads/json_recent/{SECRET}/"

    def setUp(self) -> None:
        clear_registered_secrets()

    def tearDown(self) -> None:
        clear_registered_secrets()

    def _client(self) -> HttpClient:
        return HttpClient(
            user_agent="ThreatPulse-Test/0.1",
            connect_timeout_seconds=1,
            read_timeout_seconds=1,
            max_attempts=1,
            sleep=lambda _: None,
        )

    def test_a_registered_secret_is_removed_from_any_string(self) -> None:
        register_secret(self.SECRET)

        self.assertNotIn(self.SECRET, redact(self.URL))
        self.assertIn(REDACTED, redact(self.URL))

    def test_redaction_reaches_nested_structures(self) -> None:
        register_secret(self.SECRET)

        cleaned = redact_value({"url": self.URL, "nested": [self.URL]})

        self.assertNotIn(self.SECRET, cleaned["url"])
        self.assertNotIn(self.SECRET, cleaned["nested"][0])

    def test_a_short_value_is_not_registered(self) -> None:
        """A three-character "secret" would mangle every message containing it."""

        register_secret("abc")

        self.assertEqual(registered_secret_count(), 0)

    def test_an_http_error_message_does_not_leak_the_key(self) -> None:
        import urllib.error
        from unittest import mock

        register_secret(self.SECRET)

        failure = urllib.error.HTTPError(self.URL, 404, "Not Found", {}, None)

        with mock.patch("urllib.request.urlopen", side_effect=failure):
            with self.assertRaises(HttpError) as context:
                self._client().get(self.URL)

        self.assertNotIn(self.SECRET, str(context.exception))
        self.assertIn(REDACTED, str(context.exception))

    def test_a_transport_error_message_does_not_leak_the_key(self) -> None:
        import urllib.error
        from unittest import mock

        register_secret(self.SECRET)

        with mock.patch(
            "urllib.request.urlopen", side_effect=urllib.error.URLError("boom")
        ):
            with self.assertRaises(HttpError) as context:
                self._client().get(self.URL)

        self.assertNotIn(self.SECRET, str(context.exception))

    def test_a_successful_response_never_carries_the_raw_url(self) -> None:
        from unittest import mock

        register_secret(self.SECRET)

        class FakeResponse:
            status = 200
            headers = {}

            def read(self, amount: int = -1) -> bytes:
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *arguments) -> bool:
                return False

        with mock.patch("urllib.request.urlopen", return_value=FakeResponse()):
            response = self._client().get(self.URL)

        self.assertNotIn(self.SECRET, response.url)
        self.assertIn(REDACTED, response.url)

    def test_a_log_record_does_not_leak_the_key(self) -> None:
        """The URL is logged as structured context, which the original filter never
        inspected: it only redacted ``str`` arguments."""

        from lib.logging_setup import _KeyValueFormatter, _RedactingFilter

        register_secret(self.SECRET)

        record = logging.LogRecord(
            name="threatpulse.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="http request completed",
            args=(),
            exc_info=None,
        )
        record.context = {"url": self.URL}

        _RedactingFilter().filter(record)
        rendered = _KeyValueFormatter().format(record)

        self.assertNotIn(self.SECRET, rendered)
        self.assertIn(REDACTED, rendered)

    def test_a_traceback_does_not_leak_the_key(self) -> None:
        import sys as _sys

        from lib.logging_setup import _KeyValueFormatter

        register_secret(self.SECRET)

        try:
            raise HttpError(f"GET {self.URL} failed", transient=False, status=404)
        except HttpError:
            record = logging.LogRecord(
                name="threatpulse.test",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="failed",
                args=(),
                exc_info=_sys.exc_info(),
            )

        self.assertNotIn(self.SECRET, _KeyValueFormatter().format(record))



class ConditionalRequestTests(unittest.TestCase):
    """A feed that supports ETag/Last-Modified must cost one 304 rather than a
    full download when nothing has changed."""

    URL = "https://feeds.example.invalid/downloads/latest.csv"

    def _client(self, max_attempts: int = 1) -> HttpClient:
        return HttpClient(
            user_agent="ThreatPulse-Test/0.1",
            connect_timeout_seconds=1,
            read_timeout_seconds=1,
            max_attempts=max_attempts,
            sleep=lambda _: None,
        )

    def test_validators_are_sent_as_conditional_headers(self) -> None:
        from unittest import mock

        captured: dict = {}

        class FakeResponse:
            status = 200
            headers = {}

            def read(self, amount: int = -1) -> bytes:
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *arguments) -> bool:
                return False

        def fake_urlopen(request, timeout=None):
            captured["headers"] = {
                key.lower(): value for key, value in request.headers.items()
            }
            return FakeResponse()

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            self._client().get(
                self.URL,
                etag='"981e0-6557159bdc098"',
                last_modified="Tue, 30 Jun 2026 04:53:05 GMT",
            )

        self.assertEqual(
            captured["headers"].get("if-none-match"), '"981e0-6557159bdc098"'
        )
        self.assertEqual(
            captured["headers"].get("if-modified-since"),
            "Tue, 30 Jun 2026 04:53:05 GMT",
        )

    def test_a_304_is_a_success_not_an_error(self) -> None:
        """urllib reports 304 as an HTTPError like any other non-2xx status."""

        import urllib.error
        from unittest import mock

        not_modified = urllib.error.HTTPError(
            self.URL, 304, "Not Modified", {"ETag": '"abc"'}, None
        )

        with mock.patch("urllib.request.urlopen", side_effect=not_modified):
            response = self._client().get(self.URL, etag='"abc"')

        self.assertEqual(response.status, 304)
        self.assertEqual(response.body, b"")

    def test_a_304_is_not_retried(self) -> None:
        import urllib.error
        from unittest import mock

        calls: list = []

        def fake_urlopen(request, timeout=None):
            calls.append(request)
            raise urllib.error.HTTPError(self.URL, 304, "Not Modified", {}, None)

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            self._client(max_attempts=3).get(self.URL, etag='"abc"')

        self.assertEqual(len(calls), 1)


class RefusedRequestBodyTests(unittest.TestCase):
    """A refused request must say why, in the log as well as in the exception.

    publish.php answers 409 with a JSON body naming the reason, and three
    different reasons share that status. The body is readable exactly once, so it
    has to be captured before the warning is logged and reused for the exception.
    Without it the run log said only "status=409 transient=false attempt=1",
    which is what sent several runs after the wrong cause.
    """

    URL = "https://api.example.invalid/api/cti/v1/publish.php"

    BODY = (
        b'{"status":"error","message":"Publication is already complete",'
        b'"publication_uuid":"u","publication_status":""}'
    )

    def test_the_refused_body_reaches_both_the_log_and_the_error(self) -> None:
        import io
        import urllib.error
        from unittest import mock

        from lib.logging_setup import _KeyValueFormatter

        def fake_urlopen(request, timeout=None):
            raise urllib.error.HTTPError(
                self.URL, 409, "Conflict", {}, io.BytesIO(self.BODY)
            )

        client = HttpClient(
            user_agent="ThreatPulse-Test/0.1",
            connect_timeout_seconds=1,
            read_timeout_seconds=1,
            max_attempts=1,
            sleep=lambda _: None,
        )

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertLogs("threatpulse.http", level="WARNING") as captured:
                with self.assertRaises(HttpError) as raised:
                    client.post_json(self.URL, {"a": 1})

        self.assertEqual(len(captured.records), 1)

        # assertLogs formats only the message, so the structured context has to
        # be rendered the way the run log renders it.
        formatted = _KeyValueFormatter().format(captured.records[0])

        self.assertIn("Publication is already complete", formatted)
        self.assertIn("Publication is already complete", str(raised.exception))

"""HTTP client with timeouts, bounded retries and explicit status handling.

Deliberately built on the standard library only: the VM needs no third-party
packages and the behaviour stays fully inspectable.

Failure classification is explicit and shared with the collectors:

* ``transient`` — timeout, connection reset, HTTP 408/425/429, HTTP 5xx.
  Retried with exponential backoff up to ``max_attempts``.
* ``permanent`` — other HTTP 4xx, malformed JSON. Never retried; the caller
  decides whether it can continue.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .logging_setup import get_logger, log_event, redact

LOGGER = get_logger("http")

TRANSIENT_STATUS_CODES = frozenset({408, 425, 429})

#: Default ceiling for a response body. ``response.read()`` with no limit lets a
#: misbehaving endpoint exhaust the VM's memory, and a body this large is not
#: usable JSON in any case. CIRCL's sighting endpoint was observed returning 65 MB
#: of *unparseable* JSON for one request, which is exactly the case this guards.
DEFAULT_MAX_BODY_BYTES = 32 * 1024 * 1024

#: How much of an error response body to read and quote. A PHP fatal error page is
#: small; a framework error page can be tens of kilobytes. Enough to carry the
#: message, bounded so a hostile or broken endpoint cannot flood the log.
MAX_ERROR_BODY_BYTES = 8192
MAX_ERROR_BODY_CHARS = 600


class HttpError(RuntimeError):
    """A failed HTTP interaction, classified as transient or permanent."""

    def __init__(
        self,
        message: str,
        *,
        transient: bool,
        status: int | None = None,
        attempts: int = 1,
    ) -> None:
        super().__init__(message)
        self.transient = transient
        self.status = status
        self.attempts = attempts


def describe_error_body(error: Exception) -> str:
        """The response body of an HTTP error, appended to the message.

        Without this, a 5xx from a PHP endpoint is reported as nothing but its
        status code, and every such failure is undiagnosable from the run log. A
        PHP fatal error, an uncaught exception and a framework error page all
        arrive as a body that says what went wrong; discarding it throws away the
        only evidence the caller is ever going to get.

        Bounded and redacted, because an error page can be large and can echo back
        request material — a publisher token in a URL is exactly the kind of thing
        an error page repeats.
        """

        read = getattr(error, "read", None)

        if not callable(read):
            return ""

        try:
            body = read(MAX_ERROR_BODY_BYTES)
        except Exception:  # pragma: no cover - defensive
            return ""

        if not body:
            return " (empty body)"

        text = body.decode("utf-8", errors="replace").strip()[:MAX_ERROR_BODY_CHARS]

        if not text:
            return f" ({len(body)} bytes of unreadable body)"

        return f". Body: {redact(text)}"

@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str]
    url: str
    attempts: int

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise HttpError(
                self._describe_non_json_response(error),
                transient=False,
                status=self.status,
                attempts=self.attempts,
            ) from error

    def _describe_non_json_response(self, error: Exception) -> str:
        """Explains a non-JSON response well enough to act on.

        "was not valid JSON" on its own is not actionable. An **empty** body in
        particular means the script never reached its own error handling — PHP
        terminated, or something upstream refused the request — so the status
        code and body size are the diagnosis, and the limits to check are named.
        """

        if not self.body:
            return (
                f"{self.url} returned HTTP {self.status} with an empty body: the "
                "API produced no JSON at all. That normally means PHP terminated "
                "before responding. Check the PHP error log, and compare the "
                "request size against post_max_size, memory_limit and "
                "max_execution_time on the server."
            )

        snippet = redact(self.body[:200].decode("utf-8", errors="replace"))

        return (
            f"Response from {self.url} was not valid JSON "
            f"(HTTP {self.status}, {len(self.body)} bytes): {error}. "
            f"Body begins: {snippet!r}"
        )


def is_transient_status(status: int) -> bool:
    return status in TRANSIENT_STATUS_CODES or 500 <= status <= 599


class HttpClient:
    """Small GET/POST client used by collectors and the publisher."""

    def __init__(
        self,
        *,
        user_agent: str,
        connect_timeout_seconds: float,
        read_timeout_seconds: float,
        max_attempts: int = 3,
        backoff_seconds: float = 2.0,
        backoff_multiplier: float = 2.0,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        sleep=time.sleep,
    ) -> None:
        self._user_agent = user_agent
        self._connect_timeout = connect_timeout_seconds
        self._read_timeout = read_timeout_seconds
        self._max_attempts = max(1, int(max_attempts))
        self._backoff_seconds = backoff_seconds
        self._backoff_multiplier = backoff_multiplier
        self._max_body_bytes = max(0, int(max_body_bytes))
        self._sleep = sleep

    def get(
        self,
        url: str,
        *,
        timeout_seconds: float | None = None,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> HttpResponse:
        """GET a URL, optionally conditionally.

        ``etag`` and ``last_modified`` add ``If-None-Match`` and
        ``If-Modified-Since``. When the server answers **HTTP 304** the response is
        returned normally with an empty body rather than raised as an error: "not
        modified" is a successful, useful answer, and it is what makes a large
        unchanged bulk file cost one cheap request instead of a full download.
        """

        merged_headers: dict[str, str] = dict(headers or {})

        if etag:
            merged_headers["If-None-Match"] = etag

        if last_modified:
            merged_headers["If-Modified-Since"] = last_modified

        return self._request(
            "GET",
            url,
            body=None,
            timeout_seconds=timeout_seconds,
            headers=merged_headers or None,
            max_bytes=max_bytes,
        )

    def post_json(
        self,
        url: str,
        payload: Any,
        *,
        timeout_seconds: float | None = None,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
    ) -> HttpResponse:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        merged_headers = {"Content-Type": "application/json; charset=utf-8"}
        merged_headers.update(headers or {})

        return self._request(
            "POST",
            url,
            body=body,
            timeout_seconds=timeout_seconds,
            headers=merged_headers,
            max_bytes=max_bytes,
        )

    # -- internals ---------------------------------------------------------

    def _request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None,
        timeout_seconds: float | None,
        headers: dict[str, str] | None,
        max_bytes: int | None = None,
    ) -> HttpResponse:
        read_timeout = timeout_seconds or self._read_timeout
        limit = self._max_body_bytes if max_bytes is None else max(0, int(max_bytes))
        last_error: Exception | None = None

        # The raw URL never leaves this method. A credential can arrive inside the
        # request *path*, so every log line, every HttpError message and every
        # HttpResponse.url is built from this value instead. Callers already know
        # what they asked for; none of them need the credential back.
        safe_url = redact(url)

        for attempt in range(1, self._max_attempts + 1):
            request = urllib.request.Request(url, data=body, method=method)
            request.add_header("User-Agent", self._user_agent)
            request.add_header("Accept", "application/json")

            for key, value in (headers or {}).items():
                request.add_header(key, value)

            try:
                with urllib.request.urlopen(
                    request, timeout=max(self._connect_timeout, read_timeout)
                ) as response:
                    # Read one byte past the ceiling so an oversized body can be
                    # detected without buffering all of it.
                    payload = (
                        response.read(limit + 1) if limit > 0 else response.read()
                    )

                    if limit > 0 and len(payload) > limit:
                        raise HttpError(
                            f"{method} {safe_url} returned more than {limit} bytes; "
                            "refusing to buffer it. An oversized body is either a "
                            "misbehaving endpoint or a request parameter that was "
                            "silently ignored.",
                            transient=False,
                            status=response.status,
                            attempts=attempt,
                        )

                    log_event(
                        LOGGER,
                        logging.DEBUG,
                        "http request completed",
                        method=method,
                        url=safe_url,
                        status=response.status,
                        bytes=len(payload),
                        attempt=attempt,
                    )

                    return HttpResponse(
                        status=response.status,
                        body=payload,
                        headers=dict(response.headers.items()),
                        url=safe_url,
                        attempts=attempt,
                    )

            except urllib.error.HTTPError as error:
                last_error = error

                # 304 Not Modified is a success, not a failure. urllib reports it
                # as an HTTPError like any other non-2xx status, so it is unwrapped
                # here and returned as an empty 304 response. This is what lets a
                # bulk source that supports conditional requests cost one cheap
                # request when nothing has changed.
                if error.code == 304:
                    log_event(
                        LOGGER,
                        logging.INFO,
                        "http resource not modified",
                        method=method,
                        url=safe_url,
                        status=304,
                        attempt=attempt,
                    )

                    return HttpResponse(
                        status=304,
                        body=b"",
                        headers=dict(error.headers.items()) if error.headers else {},
                        url=safe_url,
                        attempts=attempt,
                    )

                transient = is_transient_status(error.code)

                # The body can only be read once, and it is the only thing that
                # says *why* a request was refused. Read it here, log it, and carry
                # the same text into the exception, so neither the log nor the
                # error reports a status code with no explanation.
                body_detail = describe_error_body(error)

                log_event(
                    LOGGER,
                    logging.WARNING,
                    "http error status",
                    method=method,
                    url=safe_url,
                    status=error.code,
                    transient=transient,
                    attempt=attempt,
                    body=body_detail.strip() or None,
                )

                if not transient or attempt == self._max_attempts:
                    raise HttpError(
                        f"{method} {safe_url} failed with HTTP {error.code}"
                        + body_detail,
                        transient=transient,
                        status=error.code,
                        attempts=attempt,
                    ) from error

            except (urllib.error.URLError, TimeoutError, OSError) as error:
                last_error = error

                log_event(
                    LOGGER,
                    logging.WARNING,
                    "http transport error",
                    method=method,
                    url=safe_url,
                    error=type(error).__name__,
                    attempt=attempt,
                )

                if attempt == self._max_attempts:
                    raise HttpError(
                        f"{method} {safe_url} failed after {attempt} attempts: {error}",
                        transient=True,
                        attempts=attempt,
                    ) from error

            self._sleep(self._delay_for(attempt))

        raise HttpError(  # pragma: no cover - defensive
            f"{method} {safe_url} failed: {last_error}",
            transient=True,
            attempts=self._max_attempts,
        )

    def _delay_for(self, attempt: int) -> float:
        return self._backoff_seconds * (self._backoff_multiplier ** (attempt - 1))


"""Structured operational logging with secret redaction.

Two sinks are configured:

* stderr, for interactive and systemd-journald use;
* an optional rotating file under ``backend/logs/``.

Every message passes through :func:`redact`, so a token can never reach a log
file even if a caller accidentally formats one into a message.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
from pathlib import Path
from typing import Any

REDACTED = "[redacted]"

#: Shortest value worth registering as a secret. Below this, a substring
#: replacement would over-redact ordinary text — a three-character "secret" would
#: mangle every message containing those characters.
MIN_SECRET_LENGTH = 8

# Anything that looks like a credential-bearing value.
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(authorization)\b\s*[:=]\s*\S+"),
    re.compile(
        r"(?i)\b([a-z0-9_.-]*)(token|secret|password|passwd|api[_-]?key|credential)"
        r"\b\s*[:=]\s*[\"']?([^\s\"',}]{4,})"
    ),
)

#: Values the process has been told are secret, redacted wherever they appear.
#:
#: This exists because **pattern matching is not sufficient**. A credential can
#: arrive as a bare path segment like ``/downloads/json_recent/1a2b3c…/`` — a shape
#: none of the patterns above recognise, because it is not a ``Bearer`` token and
#: has no ``key=value`` form. Registering the literal value catches it in a URL, in
#: an exception message, in a ``repr`` and in a structured log field alike.
#:
#: URLhaus carried its Auth-Key exactly that way until it was retired from the
#: pipeline. The registration is kept as a backstop, so a source that puts a
#: credential back into a URL still cannot log it.
_REGISTERED_SECRETS: set[str] = set()


def register_secret(value: str | None) -> None:
    """Registers a literal secret value so :func:`redact` removes it everywhere.

    Idempotent, and ignores values too short to distinguish from ordinary text.
    """

    if isinstance(value, str) and len(value.strip()) >= MIN_SECRET_LENGTH:
        _REGISTERED_SECRETS.add(value.strip())


def clear_registered_secrets() -> None:
    """Forgets every registered secret. For tests, not for production paths."""

    _REGISTERED_SECRETS.clear()


def registered_secret_count() -> int:
    """How many distinct secrets are registered. Never exposes a value."""

    return len(_REGISTERED_SECRETS)


def redact(message: str) -> str:
    """Removes credential-shaped substrings and every registered secret.

    Registered secrets are removed first, and longest first, because an exact
    match is strictly more reliable than a shape: a 40-character key that also
    happens to look like a ``token=`` value must not be left half-replaced.
    """

    if not isinstance(message, str) or not message:
        return message

    cleaned = message

    for secret in sorted(_REGISTERED_SECRETS, key=len, reverse=True):
        if secret in cleaned:
            cleaned = cleaned.replace(secret, REDACTED)

    cleaned = _SECRET_PATTERNS[0].sub(r"\1 " + REDACTED, cleaned)
    cleaned = _SECRET_PATTERNS[1].sub(r"\1: " + REDACTED, cleaned)
    cleaned = _SECRET_PATTERNS[2].sub(r"\1\2=" + REDACTED, cleaned)

    return cleaned


def redact_value(value: Any) -> Any:
    """Applies :func:`redact` through a nested structure.

    Structured log context is a ``dict``, and the original filter only redacted
    ``str`` arguments — so a URL logged as a keyword argument (which lands in
    ``context``, not in ``args``) passed through untouched. That is precisely how a
    path-embedded key would have leaked.
    """

    if isinstance(value, str):
        return redact(value)

    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(item) for item in value)

    return value


class _RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)

        if record.args:
            record.args = redact_value(record.args)

        context = getattr(record, "context", None)

        if context:
            record.context = redact_value(context)

        return True


class _KeyValueFormatter(logging.Formatter):
    """Renders ``key=value`` context next to a compact, greppable prefix."""

    def format(self, record: logging.LogRecord) -> str:
        base = (
            f"{self.formatTime(record, '%Y-%m-%dT%H:%M:%S%z')} "
            f"{record.levelname:<7} {record.name:<28} {record.getMessage()}"
        )

        context: dict[str, Any] = getattr(record, "context", None) or {}

        if context:
            rendered = " ".join(
                f"{key}={json.dumps(value, ensure_ascii=False, default=str)}"
                for key, value in context.items()
            )
            base = f"{base} | {rendered}"

        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"

        # Final catch-all. An exception's own message is rendered here and never
        # passes through the filter, so a URL embedded in an HttpError — which is
        # exactly how a path-embedded key would travel — would otherwise reach the
        # log verbatim.
        return redact(base)


def configure_logging(
    *,
    level: str = "INFO",
    log_directory: Path | None = None,
    log_file: str = "threatpulse.log",
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
    console: bool = True,
) -> logging.Logger:
    """Configures the root logger once and returns the pipeline logger."""

    root = logging.getLogger("threatpulse")
    root.setLevel(level.upper())
    root.handlers.clear()
    root.propagate = False

    formatter = _KeyValueFormatter()
    redaction_filter = _RedactingFilter()

    if console:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.addFilter(redaction_filter)
        root.addHandler(stream_handler)

    if log_directory is not None:
        log_directory.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_directory / log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redaction_filter)
        root.addHandler(file_handler)

    return root


def get_logger(name: str) -> logging.Logger:
    """Returns a child logger under the ``threatpulse`` namespace."""

    return logging.getLogger(f"threatpulse.{name}")


def log_event(
    logger: logging.Logger,
    level: int,
    message: str,
    **context: Any,
) -> None:
    """Logs ``message`` with structured, redacted context."""

    logger.log(level, message, extra={"context": context})

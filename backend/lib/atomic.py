"""Atomic JSON file writes.

Publication and state artifacts must never be observed half-written: a crash
during a write must leave either the previous complete file or the new complete
file, never a truncated one. Every important artifact goes through
``write_json_atomic``.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def write_json_atomic(path: Path, payload: Any, *, indent: int = 2) -> None:
    """Write ``payload`` as JSON to ``path`` via a temporary file + rename.

    The temporary file is created in the destination directory so that
    ``os.replace`` is an atomic operation on the same filesystem.
    """

    path.parent.mkdir(parents=True, exist_ok=True)

    serialized = json.dumps(
        payload,
        indent=indent,
        ensure_ascii=False,
        sort_keys=False,
        default=str,
    )

    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    )

    temporary_path = Path(temporary_name)

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(serialized)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, path)

        # Make the rename durable as well, not just the file contents. Not every
        # platform permits opening a directory for fsync (Windows does not), so a
        # failure here is not an error: the rename itself is still atomic.
        try:
            directory_descriptor = os.open(str(path.parent), os.O_RDONLY)
        except OSError:  # pragma: no cover - platform dependent
            return

        try:
            os.fsync(directory_descriptor)
        except OSError:  # pragma: no cover - platform dependent
            pass
        finally:
            os.close(directory_descriptor)

    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def read_json(path: Path, *, default: Any = None) -> Any:
    """Read JSON from ``path``, returning ``default`` when it is absent."""

    if not path.exists():
        return default

    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_text_atomic(path: Path, text: str) -> None:
    """Write plain text atomically (used for the human-readable run report)."""

    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    )

    temporary_path = Path(temporary_name)

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise

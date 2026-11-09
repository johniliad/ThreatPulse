"""Deterministic identity for intelligence objects.

The threat identity scheme is inherited verbatim from the pre-existing
implementation (``models/publication.py``) and verified against live data:

.. code-block:: python

    digest = hashlib.sha256(f"{namespace}:{value}".encode("utf-8")).hexdigest()
    threat_uuid = str(uuid.UUID(digest[:32]))

with ``namespace = "threatpulse:cisa_kev"`` and ``value = <CVE identifier>``.

Verified vectors (live API, 30 Oct 2026)::

    CVE-2026-109619 -> 394720a7-b42e-cc69-c522-0c68b5d75567
    CVE-2026-109618 -> 3b1bb43f-d68c-5865-5230-923d12c35c18
    CVE-2026-97229  -> 03d6df8f-7cb5-899e-5817-31e2c78af383
    CVE-2021-3199   -> c6bec5ff-37c6-b9c1-ff1c-a16f28333174
    CVE-2023-22894  -> 2d33a473-8e0f-40b2-efc4-2090f22aa51a

These are asserted by ``tests/test_identity.py``, so a change to this module can
never silently republish 1,764 threats under new identifiers.

Publication identifiers are **not** derived this way: the pre-existing
implementation uses ``uuid.uuid4()`` per run, which is correct because a
publication is an event (a snapshot taken at a point in time), not an entity.
``publish.php`` answers HTTP 409 for a repeated ``publication_uuid``, and the
publisher treats that as "already published" rather than as a failure.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path

from .atomic import read_json, write_json_atomic

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
THREAT_UUID_PATTERN = re.compile(r"^[0-9a-fA-F-]{36}$")

# Namespace prefixes. ``threatpulse:cisa_kev`` is fixed by published data and
# must never change; the others follow the same convention for new object types.
NAMESPACE_THREAT = "threatpulse"

# Documented, asserted compatibility vectors.
IDENTITY_VECTORS = {
    "CVE-2026-109619": "394720a7-b42e-cc69-c522-0c68b5d75567",
    "CVE-2026-109618": "3b1bb43f-d68c-5865-5230-923d12c35c18",
    "CVE-2026-97229": "03d6df8f-7cb5-899e-5817-31e2c78af383",
    "CVE-2021-3199": "c6bec5ff-37c6-b9c1-ff1c-a16f28333174",
    "CVE-2023-22894": "2d33a473-8e0f-40b2-efc4-2090f22aa51a",
}


def normalize_cve(value: str) -> str:
    """Uppercases and validates a CVE identifier."""

    candidate = (value or "").strip().upper()

    if not CVE_PATTERN.match(candidate):
        raise ValueError(f"Invalid CVE identifier: {value!r}")

    return candidate


def derived_uuid(namespace: str, value: str) -> str:
    """Stable UUID derived from ``namespace:value`` (legacy-compatible)."""

    digest = hashlib.sha256(f"{namespace}:{value}".encode("utf-8")).hexdigest()

    return str(uuid.UUID(digest[:32]))


def threat_id(source_key: str, external_id: str) -> str:
    """Threat identity for a source/external-identifier pair.

    ``threat_id("cisa_kev", "CVE-2026-109619")`` reproduces the identifier
    already published by the API for that CVE.
    """

    return derived_uuid(
        f"{NAMESPACE_THREAT}:{source_key}", external_id.strip().upper()
    )


def new_publication_id() -> str:
    """A fresh publication identifier for this run (legacy behaviour)."""

    return str(uuid.uuid4())


def content_digest(payload: object) -> str:
    """Stable SHA-256 digest of a JSON-serialisable payload."""

    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()



class IdentityAliasMap:
    """Maps ``external_id`` to the threat UUID already present in the API."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._aliases: dict[str, str] = {}
        self._loaded = False

    def load(self) -> None:
        raw = read_json(self._path, default={}) or {}

        aliases = raw.get("aliases", raw) if isinstance(raw, dict) else {}

        self._aliases = {
            str(key).upper(): str(value)
            for key, value in aliases.items()
            if isinstance(key, str) and isinstance(value, str)
        }
        self._loaded = True

    def save(self) -> None:
        write_json_atomic(
            self._path,
            {
                "note": (
                    "Threat UUIDs already published by the API, keyed by "
                    "external identifier. Reused so that publishing never "
                    "creates a duplicate threat."
                ),
                "count": len(self._aliases),
                "aliases": dict(sorted(self._aliases.items())),
            },
        )

    def get(self, external_id: str) -> str | None:
        return self._aliases.get((external_id or "").upper())

    def merge(self, mapping: dict[str, str]) -> int:
        """Adds aliases; returns how many were new."""

        added = 0

        for external_id, threat_uuid_value in mapping.items():
            key = (external_id or "").upper()

            if not key or not THREAT_UUID_PATTERN.match(threat_uuid_value or ""):
                continue

            if self._aliases.get(key) != threat_uuid_value:
                self._aliases[key] = threat_uuid_value
                added += 1

        return added

    @property
    def size(self) -> int:
        return len(self._aliases)

    @property
    def loaded(self) -> bool:
        return self._loaded

    def resolve(self, source_key: str, external_id: str) -> str:
        """Returns the published ID when known, otherwise the derived ID."""

        published = self.get(external_id)

        if published:
            return published

        return threat_id(source_key, external_id)

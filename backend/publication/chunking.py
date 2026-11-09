"""Splitting a publication into requests the API can actually accept.

A publication is sent as JSON in a single POST body, so it must fit the server's
``post_max_size``. That was fine at 1,766 threats and 8 MB; it stopped being fine
once the published set carried bulk infrastructure data. A live run produced a
**10.5 MB** publication, and the quality gate refused it — correctly, because PHP
would have discarded the body and the API would have reported an empty request,
which is a far more confusing failure than a refusal here.

So the publication is split into chunks, each of which fits on its own.

Design rules
------------

* **Every chunk is a valid publication.** It carries the same envelope —
  ``publication_uuid``, ``schema_version``, ``generated_at``, ``summary``,
  ``sources`` — plus a ``chunk`` block and a slice of ``threats``. Nothing has to be
  remembered between requests, so a chunk can be retried on its own.
* **The split is measured, never estimated.** Each threat is serialised once and its
  exact byte length is used, because a guessed average would either waste the budget
  or overflow it. The envelope is measured with a worst-case ``chunk`` block, so the
  real block is never larger than what was budgeted for.
* **A threat that cannot fit is a hard error.** Silently dropping it, or sending it
  anyway and letting the server truncate the body, would lose intelligence. The
  error names the threat and its size, because the fix is to bound that threat — a
  single record carrying an outsized evidence bloat is the usual cause — not to
  raise the limit.
* **Order is preserved.** Chunks are sent in index order and threats keep their
  priority order, so the API accumulates them in the same sequence a single request
  would have produced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

#: Keys carried by every chunk. Everything except ``threats`` is envelope.
ENVELOPE_EXCLUDED = ("threats", "chunk")

#: A deliberately impossible index/count, used only to measure the largest the
#: ``chunk`` block can be. Budgeting against the real values would be circular,
#: since ``count`` is not known until the split is done.
_WORST_CASE_INDEX = 999999


class ChunkingError(RuntimeError):
    """Raised when a publication cannot be split to fit the limit."""


def serialized_size(payload: Any) -> int:
    """The exact byte length of ``payload`` as the publisher will send it."""

    return len(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def build_chunk(publication: dict, *, index: int, count: int, threats: list) -> dict:
    """One chunk: the envelope, a ``chunk`` block, and a slice of threats."""

    chunk = {
        key: value
        for key, value in publication.items()
        if key not in ENVELOPE_EXCLUDED
    }

    chunk["chunk"] = {"index": index, "count": count}
    chunk["threats"] = threats

    return chunk


@dataclass(frozen=True)
class ChunkPlan:
    """The chunks to send, and what they cost."""

    chunks: list[dict]
    total_bytes: int
    largest_threat_bytes: int

    @property
    def count(self) -> int:
        return len(self.chunks)

    @property
    def chunked(self) -> bool:
        return len(self.chunks) > 1

    def sizes(self) -> list[int]:
        return [serialized_size(chunk) for chunk in self.chunks]


def chunk_publication(publication: dict, *, max_bytes: int) -> ChunkPlan:
    """Splits a publication so that every chunk fits in ``max_bytes``."""

    if not isinstance(publication, dict):
        raise ChunkingError("publication is not an object")

    if max_bytes <= 0:
        raise ChunkingError("max_bytes must be positive")

    threats = list(publication.get("threats") or [])

    # Measure the envelope once, with a worst-case chunk block and no threats. What
    # remains is the budget for threats and their separators.
    overhead = serialized_size(
        build_chunk(
            publication,
            index=_WORST_CASE_INDEX,
            count=_WORST_CASE_INDEX,
            threats=[],
        )
    )

    if overhead >= max_bytes:
        raise ChunkingError(
            f"the publication envelope alone is {overhead} bytes, which does not fit "
            f"the {max_bytes}-byte limit; raise publication.max_payload_bytes or "
            "reduce the summary and source list"
        )

    budget = max_bytes - overhead
    sizes = [serialized_size(threat) for threat in threats]

    groups: list[list] = []
    current: list = []
    current_bytes = 0

    for threat, size in zip(threats, sizes):
        if size > budget:
            identifier = threat.get("external_id") if isinstance(threat, dict) else None

            raise ChunkingError(
                f"a single threat does not fit the {max_bytes}-byte limit: "
                f"{identifier!r} serialises to {size} bytes, against a budget of "
                f"{budget}. Raise publication.max_payload_bytes, or bound what that "
                "threat publishes."
            )

        # One byte for the comma that separates this element from the previous one.
        extra = size + (1 if current else 0)

        if current and current_bytes + extra > budget:
            groups.append(current)
            current = []
            current_bytes = 0
            extra = size

        current.append(threat)
        current_bytes += extra

    if current:
        groups.append(current)

    if not groups:
        # An empty publication is still one request, so the API sees the
        # publication rather than nothing at all.
        groups = [[]]

    count = len(groups)

    chunks = [
        build_chunk(publication, index=index, count=count, threats=group)
        for index, group in enumerate(groups)
    ]

    # Verify rather than assume: an off-by-one in the budgeting above would
    # otherwise become an oversized request that PHP discards with no useful error.
    for index, chunk in enumerate(chunks):
        size = serialized_size(chunk)

        if size > max_bytes:
            raise ChunkingError(
                f"internal error: chunk {index} serialises to {size} bytes, above the "
                f"{max_bytes}-byte limit"
            )

    return ChunkPlan(
        chunks=chunks,
        total_bytes=sum(serialized_size(chunk) for chunk in chunks),
        largest_threat_bytes=max(sizes) if sizes else 0,
    )

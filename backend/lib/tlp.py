"""Traffic Light Protocol (TLP) classification and fail-closed enforcement.

ThreatPulse publishes to a **public, unauthenticated** dashboard, so only
material its originator released for unrestricted public use may be ingested,
stored or republished. That rule is enforced here, in one place.

Policy
------

* TLP 2.0 ``TLP:CLEAR`` is ingestible. TLP 1.0 ``TLP:WHITE`` is its predecessor
  and is treated identically (``WHITE`` normalises to ``CLEAR``).
* ``TLP:GREEN``, ``TLP:AMBER``, ``TLP:AMBER+STRICT`` and ``TLP:RED`` are never
  ingested, never written to state and never published.
* Sources that publish openly (a government advisory feed, a public
  vulnerability database) carry no TLP marking. Such a source declares an
  explicit ``tlp_default`` of ``CLEAR`` in the source register, which records the
  justification for treating its material as public. An undeclared source is
  refused: absence of a marking is **not** permission.
* Enforcement is fail-closed three ways: an item marked more restrictively than
  its source default is rejected; an unrecognised TLP-like marking is rejected
  rather than assumed public; an item whose marking conflicts with the declared
  default is rejected.

Rejection is per item, with a reason, so one over-marked advisory cannot destroy
the rest of a feed's intelligence.
"""

from __future__ import annotations

import re
from typing import Iterable

# TLP 2.0, plus the TLP 1.0 spelling that TLP 2.0 renamed.
TLP_CLEAR = "CLEAR"
TLP_GREEN = "GREEN"
TLP_AMBER = "AMBER"
TLP_AMBER_STRICT = "AMBER+STRICT"
TLP_RED = "RED"

#: Every marking recognised here, in ascending order of restriction.
TLP_LEVELS = (TLP_CLEAR, TLP_GREEN, TLP_AMBER, TLP_AMBER_STRICT, TLP_RED)

#: The only markings that may be ingested into a public product.
INGESTIBLE_LEVELS = frozenset({TLP_CLEAR})

#: Markings that must never be ingested.
RESTRICTIVE_LEVELS = frozenset({TLP_GREEN, TLP_AMBER, TLP_AMBER_STRICT, TLP_RED})

#: TLP 1.0 spellings mapped onto their TLP 2.0 equivalents.
_LEGACY_ALIASES = {
    "WHITE": TLP_CLEAR,
    "CLEAR": TLP_CLEAR,
    "GREEN": TLP_GREEN,
    "AMBER": TLP_AMBER,
    "AMBER+STRICT": TLP_AMBER_STRICT,
    "AMBER-STRICT": TLP_AMBER_STRICT,
    "RED": TLP_RED,
}

# Tolerant of real-world spellings: "TLP:CLEAR", "TLP: CLEAR",
# "tlp:amber+strict", "TLP-AMBER", "(TLP:WHITE)".
_MARKING_PATTERN = re.compile(
    r"TLP\s*[:\-]\s*(CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER\-STRICT|AMBER|RED)",
    re.IGNORECASE,
)

class TlpViolation(RuntimeError):
    """Raised when material must not be ingested under the TLP policy."""


def normalize_marking(value: str | None) -> str | None:
    """Normalises one marking token, or returns None when unrecognised."""

    if not isinstance(value, str):
        return None

    token = value.strip().upper().replace(" ", "")

    for prefix in ("TLP:", "TLP-"):
        if token.startswith(prefix):
            token = token[len(prefix) :]
            break

    return _LEGACY_ALIASES.get(token)


def find_markings(*texts: str | None) -> set[str]:
    """Returns every TLP marking found in the supplied text fragments.

    An unrecognised ``TLP``-like token is reported as the sentinel
    ``"UNKNOWN"`` so callers refuse it rather than treat it as public.
    """

    found: set[str] = set()

    for text in texts:
        if not isinstance(text, str) or not text:
            continue

        for match in _MARKING_PATTERN.finditer(text):
            level = normalize_marking(match.group(1))

            if level is not None:
                found.add(level)

        if "TLP" in text.upper() and not _MARKING_PATTERN.search(text):
            found.add("UNKNOWN")

    return found


def is_ingestible(level: str | None) -> bool:
    """True when a marking may be ingested into the public product."""

    return level in INGESTIBLE_LEVELS


def evaluate(
    *,
    source_default: str | None,
    item_markings: Iterable[str] = (),
) -> tuple[bool, str]:
    """Decides whether one item may be ingested.

    Returns ``(allowed, reason)``; ``reason`` is empty when allowed.
    """

    default = normalize_marking(source_default)

    if default is None:
        return False, (
            "source declares no recognised tlp_default; ingestion without a "
            "declared TLP is refused"
        )

    if not is_ingestible(default):
        return False, f"source tlp_default {default} is not ingestible"

    for marking in sorted(set(item_markings)):
        if marking == "UNKNOWN":
            return False, "item carries an unrecognised TLP-like marking"

        if not is_ingestible(marking):
            return False, f"item is marked TLP:{marking}, which is not ingestible"

        if marking != default:
            return False, (
                f"item marking TLP:{marking} conflicts with the declared "
                f"source default TLP:{default}"
            )

    return True, ""


def assert_ingestible(
    *,
    source_key: str,
    source_default: str | None,
    item_markings: Iterable[str] = (),
) -> None:
    """Raises :class:`TlpViolation` when an item must not be ingested."""

    allowed, reason = evaluate(
        source_default=source_default, item_markings=item_markings
    )

    if not allowed:
        raise TlpViolation(f"{source_key}: {reason}")


def policy_summary() -> dict:
    """The published statement of this policy, for the methodology endpoint."""

    return {
        "policy": "TLP:CLEAR/WHITE only",
        "ingestible": sorted(INGESTIBLE_LEVELS),
        "never_ingested": sorted(RESTRICTIVE_LEVELS),
        "legacy_aliases": {"WHITE": TLP_CLEAR},
        "unmarked_sources": (
            "Openly published sources declare an explicit tlp_default of CLEAR "
            "in the source register. An undeclared source is refused: an absent "
            "marking is never treated as permission."
        ),
        "enforcement": (
            "Fail-closed per item. An item marked more restrictively than its "
            "source default, or carrying an unrecognised TLP-like marking, is "
            "rejected with a reason and never reaches state or the publication."
        ),
    }


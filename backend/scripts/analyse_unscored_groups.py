#!/usr/bin/env python3
"""Analysis: what evidence do the CVE groups the priority model cannot score carry?

The published vulnerability set is, today, exactly the CISA KEV catalogue. A CVE
group becomes a threat only when one of its observations carries the fields the
v0.1 priority model reads (``date_added``, ``due_date``). Every group whose
evidence comes only from enrichment sources — CISA Vulnrichment, CIRCL, OSV, MSRC,
Red Hat, EPSS, CSAF advisories — is counted in
``cve_groups_without_scoreable_evidence`` and dropped.

Before widening the model, measure what those groups actually hold. A model built
on fields that half the groups lack would be inventing a number, which is the
failure this codebase refuses to make everywhere else. Everything printed here
comes from a real collection run; none of it is assumed.

Read-only: it collects, correlates and reports. It publishes nothing. The only
files it touches are the collectors' own caches, which a normal run writes anyway.

Usage::

    python3 scripts/analyse_unscored_groups.py
"""

from __future__ import annotations

import sys
from collections import Counter
from datetime import date
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from correlation.engine import group_observations  # noqa: E402
from lib.attribution import load_register  # noqa: E402
from lib.config import load_settings  # noqa: E402
from lib.logging_setup import configure_logging  # noqa: E402
from run_pipeline import collect_sources  # noqa: E402
from scoring.priority import UnscoreableRecord, can_score  # noqa: E402
from scoring.universal import score_group  # noqa: E402
from state.store import StateStore  # noqa: E402

#: Printed for each dropped group, so the shape of the evidence is visible and not
#: only counted.
SAMPLE_GROUPS = 5


def present(value: object) -> bool:
    """Whether a payload value is evidence rather than its absence."""

    if value is None:
        return False

    if isinstance(value, str):
        return bool(value.strip())

    if isinstance(value, (list, dict, tuple, set)):
        return len(value) > 0

    return True


def main() -> int:
    settings = load_settings()
    configure_logging(level="WARNING", log_directory=settings.log_directory)

    state = StateStore(settings.state_directory, settings.data_directory)
    register = load_register()

    results = collect_sources(settings, state, register=register)

    print()
    print("collection")
    print("----------")

    for result in sorted(results, key=lambda item: item.source.key):
        print(
            f"  {result.source.key:26} {result.status:9} "
            f"{len(result.observations):6} observations"
        )

    observations = [
        observation for result in results for observation in result.observations
    ]

    groups = group_observations(observations)
    cve_groups = {key: group for key, group in groups.items() if key[0] == "cve"}

    dropped = {
        key: group
        for key, group in cve_groups.items()
        if not any(can_score(observation.payload) for observation in group)
    }

    print()
    print("correlation")
    print("-----------")
    print(f"  observations        {len(observations):6}")
    print(f"  groups              {len(groups):6}")
    print(f"  cve groups          {len(cve_groups):6}")
    print(f"    scoreable         {len(cve_groups) - len(dropped):6}   (KEV-backed)")
    print(f"    dropped           {len(dropped):6}")

    if not dropped:
        print("\nnothing dropped: the priority model covers every CVE group.")
        return 0

    report(dropped)
    score_summary(dropped)

    return 0


def score_summary(dropped: dict) -> None:
    """What the universal model would do with the groups that are dropped today."""

    scored: list[tuple[float, str, dict]] = []
    refused: Counter = Counter()

    for key, group in dropped.items():
        try:
            result = score_group(group, reference_date=date.today())
        except UnscoreableRecord as error:
            refused[str(error)[:70]] += 1
            continue

        scored.append((result["priority_score"], key[1], result))

    print()
    print("universal model, applied to the dropped groups")
    print("----------------------------------------------")
    print(f"  scored  {len(scored)}")
    print(f"  refused {sum(refused.values())}")

    for reason, count in refused.most_common(5):
        print(f"    {count:5}  {reason}")

    bands = Counter(result["priority_band"] for _, _, result in scored)

    print()
    print("  band distribution:")

    for band in ("critical", "high", "medium", "low", "informational"):
        if bands.get(band):
            print(f"    {bands[band]:5}  {band}")

    print()
    print("  highest scoring:")

    for score, cve, result in sorted(scored, reverse=True)[:8]:
        factors = ", ".join(sorted(result["score_factors"]))
        print(f"    {score:6.2f}  {result['priority_band']:13} {cve}  [{factors}]")

    print()
    print("  lowest scoring:")

    for score, cve, result in sorted(scored)[:5]:
        factors = ", ".join(sorted(result["score_factors"]))
        print(f"    {score:6.2f}  {result['priority_band']:13} {cve}  [{factors}]")


def report(dropped: dict) -> None:
    """Prints what the dropped groups contain."""

    total = len(dropped)

    print()
    print("which sources the dropped groups come from")
    print("------------------------------------------")

    per_source: Counter = Counter()

    for group in dropped.values():
        for source_key in {observation.source_key for observation in group}:
            per_source[source_key] += 1

    for source_key, count in per_source.most_common():
        print(f"  {count:5}  {count * 100 / total:5.1f}%  {source_key}")

    print()
    print("how many sources back a dropped group")
    print("-------------------------------------")

    for size, count in sorted(Counter(len(g) for g in dropped.values()).items()):
        print(f"  {count:5} groups have {size} observation(s)")

    print()
    print("field coverage across the dropped groups")
    print("(share of groups where at least one observation carries a value)")
    print("----------------------------------------------------------------")

    coverage: Counter = Counter()
    occurrences: Counter = Counter()

    for group in dropped.values():
        keys = set()

        for observation in group:
            for key, value in (observation.payload or {}).items():
                if present(value):
                    keys.add(key)
                    occurrences[key] += 1

        for key in keys:
            coverage[key] += 1

    for key, count in coverage.most_common(45):
        print(
            f"  {count * 100 / total:5.1f}%  {count:5}/{total}  "
            f"{key:26} values={occurrences[key]}"
        )

    print()
    print("which required KEV fields are absent")
    print("------------------------------------")

    absent_counts: Counter = Counter()

    for group in dropped.values():
        absent = [
            field
            for field in ("date_added", "due_date")
            if not any(
                present((observation.payload or {}).get(field))
                for observation in group
            )
        ]
        absent_counts[", ".join(absent) or "neither (unexpected)"] += 1

    for description, count in absent_counts.most_common():
        print(f"  {count:5}  missing {description}")

    print()
    print(f"sample dropped groups (first {SAMPLE_GROUPS})")
    print("-----------------------------------------")

    for key in sorted(dropped)[:SAMPLE_GROUPS]:
        group = dropped[key]

        print(f"\n  {key[1]}  ({len(group)} observation(s))")

        for observation in sorted(
            group, key=lambda item: (item.source_key, item.external_id)
        ):
            payload = observation.payload or {}
            shape = ", ".join(
                f"{name}={payload[name]!r}"[:60]
                for name in sorted(payload)
                if present(payload[name])
            )
            print(f"    {observation.source_key:24} {shape}")


if __name__ == "__main__":
    raise SystemExit(main())


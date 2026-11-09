#!/usr/bin/env python3
"""Verify that a published snapshot is actually served by the public API.

ThreatPulse never claims propagation without querying the API. This compares the
local snapshot against what the API returns:

* the publication UUID is present in ``publications.php``;
* the API's threat count matches the snapshot's;
* a sampled threat round-trips with the same identifier, score and sources;
* every source in the snapshot is listed by ``sources.php`` with a real count.

Standard library only, no credentials: every endpoint it calls is public.

Usage::

    python3 scripts/verify_publication.py
    python3 scripts/verify_publication.py --snapshot data/latest_publication.json
    python3 scripts/verify_publication.py --base https://example/api/cti/v1/
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

DEFAULT_BASE = "https://threatpulse.iliadis.net/api/cti/v1/"
DEFAULT_SNAPSHOT = "data/latest_publication.json"

USER_AGENT = "ThreatPulse-Verifier/1.0 (+https://threatpulse.iliadis.net/)"

EXIT_OK = 0
EXIT_FAILED = 1


def fetch(base: str, endpoint: str) -> dict:
    """GET one endpoint and return its JSON object."""

    url = f"{base.rstrip('/')}/{endpoint}"
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", USER_AGENT)
    request.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"GET {url} failed with HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RuntimeError(f"GET {url} failed: {error}") from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"GET {url} did not return JSON: {error}") from error


def collection(payload: dict, *names: str) -> list:
    """First list found at ``data.<name>``, then ``data`` itself."""

    data = payload.get("data") if isinstance(payload, dict) else None

    if isinstance(data, dict):
        for name in names:
            candidate = data.get(name)

            if isinstance(candidate, list):
                return candidate

    return data if isinstance(data, list) else []


def record(payload: dict, *names: str) -> dict:
    """First dict found at ``data.<name>``, then ``data`` itself."""

    data = payload.get("data") if isinstance(payload, dict) else None

    if isinstance(data, dict):
        for name in names:
            candidate = data.get(name)

            if isinstance(candidate, dict):
                return candidate

        return data

    return {}


class Report:
    """Collects check outcomes so every failure is reported, not just the first."""

    def __init__(self) -> None:
        self.failures: list[str] = []

    def check(self, passed: bool, label: str, detail: str = "") -> None:
        mark = "PASS" if passed else "FAIL"

        print(f"  [{mark}] {label}" + (f" — {detail}" if detail else ""))

        if not passed:
            self.failures.append(label)


def threat_source_keys(detail: dict) -> list[str]:
    """The sources the API attributes to one threat.

    ``threat.php`` exposes provenance as a ``sources`` array of objects, each
    carrying its own ``source_key``; there is no flat ``source_keys`` array in the
    response (that key exists only inside the publication payload the backend
    sends). Both shapes are accepted so the check keeps working either way.
    """

    keys = detail.get("source_keys")

    if isinstance(keys, list) and keys:
        return sorted(str(key) for key in keys)

    sources = detail.get("sources")

    if isinstance(sources, list):
        return sorted(
            str(entry.get("source_key"))
            for entry in sources
            if isinstance(entry, dict) and entry.get("source_key")
        )

    return []


def verify(base: str, snapshot_path: Path) -> int:
    if not snapshot_path.exists():
        print(f"ERROR: snapshot not found: {snapshot_path}", file=sys.stderr)
        print(
            "Run `python3 run_pipeline.py --dry-run` first to produce one.",
            file=sys.stderr,
        )
        return EXIT_FAILED

    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

    publication_uuid = snapshot.get("publication_uuid")
    threats = snapshot.get("threats") or []
    expected_sources = sorted(
        {key for threat in threats for key in (threat.get("source_keys") or [])}
    )

    print("ThreatPulse — publication verification")
    print("--------------------------------------")
    print(f"API:        {base}")
    print(f"Snapshot:   {snapshot_path}")
    print(f"Publication {publication_uuid}")
    print(f"Threats:    {len(threats)}")
    print(f"Sources:    {', '.join(expected_sources) or 'none'}")
    print()

    report = Report()

    print("1. The publication is recorded by the API")

    publications = collection(fetch(base, "publications.php?limit=50"), "publications")

    report.check(
        bool(publications), "publications.php returned at least one publication"
    )

    report.check(
        any(
            entry.get("publication_uuid") == publication_uuid
            for entry in publications
        ),
        "the snapshot's publication_uuid is served by the API",
        publication_uuid or "missing from the snapshot",
    )

    print()
    print("2. The threat set matches")

    first_page = fetch(base, "threats.php?limit=1")
    total = (first_page.get("pagination") or {}).get("total")

    report.check(
        total == len(threats),
        "the API's threat count matches the snapshot",
        f"api={total} snapshot={len(threats)}",
    )

    if threats:
        sample = threats[0]
        detail = record(fetch(base, f"threat.php?uuid={sample['threat_uuid']}"), "threat")

        report.check(
            detail.get("external_id") == sample.get("external_id"),
            "a sampled threat round-trips",
            str(sample.get("external_id")),
        )

        try:
            same_score = float(detail.get("priority_score")) == float(
                sample.get("priority_score")
            )
        except (TypeError, ValueError):
            same_score = False

        report.check(
            same_score,
            "the sampled threat's score is unchanged",
            str(sample.get("priority_score")),
        )

        api_sources = threat_source_keys(detail)
        snapshot_sources = sorted(sample.get("source_keys") or [])

        if not api_sources and snapshot_sources:
            report.check(
                False,
                "the API exposes the sampled threat's sources",
                "the record returned neither 'sources' nor 'source_keys'",
            )
        else:
            report.check(
                api_sources == snapshot_sources,
                "the sampled threat's sources are unchanged",
                f"api={api_sources} snapshot={snapshot_sources}",
            )

    print()
    print("3. Every source is attributed by the API")

    api_sources = collection(fetch(base, "sources.php?limit=100"), "sources")

    for key in expected_sources:
        entry = next(
            (item for item in api_sources if item.get("source_key") == key), None
        )

        report.check(
            entry is not None,
            f"source '{key}' is listed",
            f"{entry.get('threat_count')} threats" if entry else "absent",
        )

    print()

    if report.failures:
        print(f"RESULT: {len(report.failures)} check(s) failed.")
        print(
            "The publication may not have been accepted. Check the publisher's "
            "exit code and data/run_report.json."
        )
        return EXIT_FAILED

    print("RESULT: the published snapshot is served by the public API.")

    return EXIT_OK


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a published snapshot against the public API."
    )
    parser.add_argument("--base", default=DEFAULT_BASE, help="API base URL")
    parser.add_argument(
        "--snapshot", default=DEFAULT_SNAPSHOT, help="path to the local snapshot"
    )
    arguments = parser.parse_args()

    try:
        return verify(arguments.base, Path(arguments.snapshot))
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)

        return EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())


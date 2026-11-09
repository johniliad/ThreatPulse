"""Analysis: derive the legacy threatpulse_priority_v0.1 factor thresholds.

The published records expose their own score factors, so the thresholds that
produced them can be recovered empirically instead of guessed. Run this before
changing the scoring module.

Read-only: it pages through the public API and prints a summary.
"""

from __future__ import annotations

import json
import urllib.request
from collections import Counter, defaultdict
from datetime import date, datetime, timezone

BASE = "https://threatpulse.iliadis.net/api/cti/v1/threats.php"
PAGE = 100


def fetch_all() -> list:
    threats = []
    offset = 0

    while True:
        url = f"{BASE}?limit={PAGE}&offset={offset}"

        with urllib.request.urlopen(url, timeout=60) as response:
            payload = json.load(response)

        batch = payload["data"]["threats"]
        threats.extend(batch)

        if not payload["pagination"]["has_more"]:
            break

        offset += PAGE

    return threats


def day_of(value):
    if not value:
        return None

    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def main() -> int:
    threats = fetch_all()
    print(f"fetched {len(threats)} threats")

    generated = datetime.now(timezone.utc).date()

    factor_names = set()
    for threat in threats:
        factors = (threat.get("metadata") or {}).get("score_factors") or {}
        factor_names.update(factors)

    print(f"factor names: {sorted(factor_names)}")

    distributions = defaultdict(Counter)

    for threat in threats:
        factors = (threat.get("metadata") or {}).get("score_factors") or {}
        for name, value in factors.items():
            distributions[name][value] += 1

    for name in sorted(distributions):
        print(f"{name}: {dict(sorted(distributions[name].items()))}")

    recency_days = defaultdict(list)
    for threat in threats:
        factors = (threat.get("metadata") or {}).get("score_factors") or {}
        added = day_of(threat.get("first_seen"))
        recency = factors.get("recency")
        if added is not None and recency is not None:
            recency_days[recency].append((generated - added).days)

    print("\nrecency -> days since first_seen (min..max):")
    for recency in sorted(recency_days):
        days = sorted(recency_days[recency])
        print(f"  {recency}: {days[0]}..{days[-1]}  (n={len(days)})")

    urgency_days = defaultdict(list)
    for threat in threats:
        factors = (threat.get("metadata") or {}).get("score_factors") or {}
        due = day_of((threat.get("metadata") or {}).get("due_date"))
        urgency = factors.get("urgency")
        if due is not None and urgency is not None:
            urgency_days[urgency].append((due - generated).days)

    print("\nurgency -> days until due date (min..max):")
    for urgency in sorted(urgency_days):
        days = sorted(urgency_days[urgency])
        print(f"  {urgency}: {days[0]}..{days[-1]}  (n={len(days)})")

    for field, factor in (
        ("known_ransomware_campaign_use", "ransomware"),
        ("forensic_triage", "forensic"),
    ):
        pairs = Counter()
        for threat in threats:
            metadata = threat.get("metadata") or {}
            factors = metadata.get("score_factors") or {}
            pairs[(metadata.get(field), factors.get(factor))] += 1
        print(f"\n{field} -> {factor}: {dict(pairs)}")

    keyword_impact = Counter()
    keywords = (
        "remote code execution",
        "arbitrary code",
        "command injection",
        "sql injection",
        "authentication bypass",
        "privilege escalation",
        "cross-site scripting",
        "denial of service",
        "server-side request forgery",
        "information disclosure",
        "buffer overflow",
        "integer overflow",
        "deserialization",
        "path traversal",
        "memory corruption",
    )

    for threat in threats:
        factors = (threat.get("metadata") or {}).get("score_factors") or {}
        text = (threat.get("summary") or "").lower()
        impact = factors.get("impact")
        matched = "other"
        for keyword in keywords:
            if keyword in text:
                matched = keyword
                break
        keyword_impact[(matched, impact)] += 1

    print("\ndescription keyword -> impact:")
    for key in sorted(keyword_impact, key=lambda item: (item[0], str(item[1]))):
        print(f"  {key}: {keyword_impact[key]}")

    by_severity = defaultdict(set)
    for threat in threats:
        by_severity[threat.get("severity")].add(threat.get("priority_score"))

    print("\nseverity -> priority_score range:")
    for severity in sorted(by_severity):
        scores = sorted(by_severity[severity])
        print(f"  {severity}: {scores[0]}..{scores[-1]} (n={len(scores)})")

    confidence = Counter()
    for threat in threats:
        confidence[
            (threat.get("confidence_level"), threat.get("confidence_score"))
        ] += 1
    print(f"\nconfidence level -> score: {dict(confidence)}")

    exploitation = Counter(threat.get("exploitation_status") for threat in threats)
    print(f"exploitation_status: {dict(exploitation)}")

    reasoning = Counter()
    for threat in threats:
        for statement in (threat.get("metadata") or {}).get("reasoning") or []:
            reasoning[statement] += 1
    print(f"\ndistinct reasoning statements: {len(reasoning)}")
    for statement, count in reasoning.most_common(30):
        print(f"  ({count}) {statement}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

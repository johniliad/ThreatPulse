"""Sigma normalisation — detection coverage for a technique.

Sigma is a knowledge base, not a feed. It is fetched for one reason: it turns the
ATT&CK techniques this pipeline already publishes into **detection coverage**. A
technique named beside a threat says what an adversary does; a Sigma rule beside that
technique says what a defender can do about it, and whether anyone has written one.

Measured against the live data before building
----------------------------------------------

* the repository archive is **9.1 MB** and holds **3,161 rule files** once the
  ``regression_data`` tree is excluded;
* **2,817** of the files carry an ``attack.t`` tag, mapping **390 distinct techniques**
  through **3,819 rule-to-technique mappings**;
* of the **174 techniques this pipeline publishes**, **128 are covered by a rule** and
  46 are not.

128 of 174 is what justifies a 9.1 MB download, and the 46 that are uncovered are as
useful as the 128: they are the techniques nothing detects yet.

Why no YAML parser
------------------

Sigma rules are YAML, and the project is stdlib-only with no dependency manifest. A
general YAML parser is not needed and is not written here: only four things are read,
all of them line-oriented and unambiguous — the ``tags`` list entries, and the
``title``, ``level`` and ``status`` scalars. A rule whose tags cannot be read is
skipped, so the worst a malformed rule can do is not appear.

The ``regression_data`` tree is excluded deliberately. It holds ``info.yml`` files that
look like rules and sit under a ``rules`` path, and they are test metadata — the first
file this parser ever read was one, and it silently produced zero coverage until the
path filter was corrected.
"""

from __future__ import annotations

import io
import re
import tarfile
from typing import Any

from normalization.cisa import NormalizationError, sanitize_text

INDEX_SCHEMA = 1

#: Where the built index lives, beside the ATT&CK, galaxy and CAPEC indexes.
INDEX_FILENAME = "sigma_index.json"

#: ``attack.t1059`` and the sub-technique form ``attack.t1059.001``, as a tag entry.
TAG_LINE = re.compile(
    r"^\s*-\s*attack\.(t\d{4}(?:\.\d{3})?)\s*$", re.IGNORECASE | re.MULTILINE
)

TITLE_LINE = re.compile(r"^title:\s*(.+)$", re.MULTILINE)
LEVEL_LINE = re.compile(r"^level:\s*(\w+)\s*$", re.MULTILINE)
STATUS_LINE = re.compile(r"^status:\s*(\w+)\s*$", re.MULTILINE)

MAX_TITLE_LENGTH = 200

#: Rules carried per technique.
#:
#: The archive holds 3,819 rule-to-technique mappings, and the most-covered technique
#: has 73 rules. A cap of 60 therefore truncated exactly the techniques with the most
#: detection engineering behind them — the same mistake the ATT&CK index made with
#: ``uses`` relationships. 200 is no truncation at all, and the index records the true
#: rule count per technique so a bound that ever does bite is visible rather than
#: silent.
MAX_RULES_PER_TECHNIQUE = 200

#: Levels a rule can carry, for the summary count.
LEVELS = ("critical", "high", "medium", "low", "informational")


def rule_path(name: str) -> str | None:
    """The repository-relative path of a rule, or None when the file is not one.

    ``regression_data`` is excluded: it holds ``info.yml`` files that sit under a
    ``rules`` path and look like rules but are test metadata.
    """

    if not name.endswith(".yml"):
        return None

    if "/regression_data/" in name or "/rules/" not in name:
        return None

    return name.split("/rules/", 1)[-1]


def parse_rule(text: str, *, path: str) -> dict | None:
    """One rule reduced to what this index keeps, or None when it names no technique."""

    techniques = sorted({match.upper() for match in TAG_LINE.findall(text)})

    if not techniques:
        return None

    title = TITLE_LINE.search(text)
    level = LEVEL_LINE.search(text)
    status = STATUS_LINE.search(text)

    return {
        "title": sanitize_text(
            title.group(1).strip() if title else None, max_length=MAX_TITLE_LENGTH
        ),
        "level": level.group(1).lower() if level else None,
        "status": status.group(1).lower() if status else None,
        "path": path,
        "techniques": techniques,
    }


def parse_archive(payload: bytes) -> list[dict]:
    """Every rule in a repository archive that names an ATT&CK technique."""

    if not isinstance(payload, (bytes, bytearray)):
        raise NormalizationError("Sigma payload is not an archive")

    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz")
    except (tarfile.TarError, OSError) as error:
        raise NormalizationError(f"Sigma archive did not open: {error}") from error

    rules: list[dict] = []

    try:
        for member in archive.getmembers():
            if not member.isfile():
                continue

            path = rule_path(member.name)

            if path is None:
                continue

            handle = archive.extractfile(member)

            if handle is None:
                continue

            try:
                text = handle.read().decode("utf-8", "replace")
            except OSError:
                continue

            rule = parse_rule(text, path=path)

            if rule:
                rules.append(rule)
    finally:
        archive.close()

    if not rules:
        raise NormalizationError(
            "Sigma archive yielded no rules with an ATT&CK tag. Either the archive "
            "layout changed or the path filter is wrong, and both look identical to a "
            "repository that has no tagged rules."
        )

    return rules


def build_index(
    payload: bytes,
    *,
    source_url: str | None = None,
    generated_at: str | None = None,
) -> dict:
    """Builds the technique-to-rules index."""

    rules = parse_archive(payload)

    by_technique: dict[str, list[dict]] = {}
    true_counts: dict[str, int] = {}

    for rule in rules:
        entry = {key: rule[key] for key in ("title", "level", "status", "path")}

        for technique in rule["techniques"]:
            true_counts[technique] = true_counts.get(technique, 0) + 1

            bucket = by_technique.setdefault(technique, [])

            if len(bucket) < MAX_RULES_PER_TECHNIQUE:
                bucket.append(entry)

    level_counts = {level: 0 for level in LEVELS}

    for rule in rules:
        if rule["level"] in level_counts:
            level_counts[rule["level"]] += 1

    # Reported, not hidden: a technique that reaches the cap has been truncated, and a
    # reader should know that rather than assume the list is complete.
    at_cap = sum(1 for count in true_counts.values() if count > MAX_RULES_PER_TECHNIQUE)

    return {
        "schema_version": INDEX_SCHEMA,
        "source_url": source_url,
        "generated_at": generated_at,
        "counts": {
            "rules": len(rules),
            "techniques_covered": len(by_technique),
            "mappings": sum(true_counts.values()),
            "mappings_kept": sum(len(bucket) for bucket in by_technique.values()),
            "techniques_at_cap": at_cap,
            "by_level": level_counts,
        },
        "by_technique": {key: by_technique[key] for key in sorted(by_technique)},
        "rule_counts": {key: true_counts[key] for key in sorted(true_counts)},
    }


def load_index(path) -> dict | None:
    """Reads a previously built Sigma index, or None when it is absent.

    A missing index is not an error: it means Sigma has not been fetched yet, and a
    technique simply carries no detection coverage.
    """

    from lib.atomic import read_json

    try:
        payload = read_json(path)
    except (OSError, ValueError):
        return None

    if not isinstance(payload, dict) or not isinstance(payload.get("by_technique"), dict):
        return None

    return payload


def detection_summary(index: dict | None, technique: str) -> dict | None:
    """The detection coverage for one technique, or None when there is none.

    Bounded deliberately: a count, a severity breakdown and at most three example
    rules. T1003.001 has 73 rules, and publishing all of them beside every threat that
    names the technique would bury the threat in detection engineering.
    """

    rules = ((index or {}).get("by_technique") or {}).get(str(technique).upper())

    if not rules:
        return None

    levels: dict[str, int] = {}

    for rule in rules:
        level = rule.get("level")

        if level:
            levels[level] = levels.get(level, 0) + 1

    examples = [
        {
            "title": rule.get("title"),
            "level": rule.get("level"),
            "path": rule.get("path"),
        }
        for rule in rules[:3]
    ]

    # The true count, not the length of the list: the list is bounded for index size,
    # and reporting the bound as the count would understate the coverage.
    true_count = ((index or {}).get("rule_counts") or {}).get(
        str(technique).upper(), len(rules)
    )

    return {
        "rule_count": true_count,
        "by_level": {key: levels[key] for key in sorted(levels)},
        "examples": examples,
        "source": "Sigma",
        "note": (
            "A detection rule exists for this technique; it is not evidence that any "
            "of these rules would fire on this threat."
        ),
    }

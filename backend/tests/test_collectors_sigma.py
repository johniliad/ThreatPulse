"""Sigma — detection coverage for a technique.

The parser reads four line-oriented things and no YAML at all, so the tests that
matter are the ones about what it refuses: a rule with no ATT&CK tag, a file that is
not a rule, and the ``regression_data`` tree, which holds ``info.yml`` files that sit
under a ``rules`` path and look exactly like rules but are test metadata.
"""

from __future__ import annotations

import io
import sys
import tarfile
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from normalization import sigma as sigma_module  # noqa: E402
from normalization.cisa import NormalizationError  # noqa: E402


def rule_text(
    *,
    title: str = "Suspicious Command Shell",
    level: str = "high",
    status: str = "test",
    techniques: list[str] | None = None,
) -> str:
    tags = "".join(f"\n    - attack.{t}" for t in techniques or ["t1059.001"])

    return (
        f"title: {title}\n"
        f"id: 00000000-0000-0000-0000-000000000001\n"
        f"status: {status}\n"
        f"level: {level}\n"
        f"tags:{tags}\n"
        f"    - attack.execution\n"
        f"logsource:\n"
        f"    category: process_creation\n"
        f"detection:\n"
        f"    selection:\n"
        f"        CommandLine: '*'\n"
        f"    condition: selection\n"
    )


def archive(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()

    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, text in files.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    return buffer.getvalue()


class RulePathTests(unittest.TestCase):
    def test_a_rule_path_is_kept(self) -> None:
        self.assertEqual(
            sigma_module.rule_path("sigma-master/rules/windows/foo.yml"),
            "windows/foo.yml",
        )

    def test_regression_data_is_excluded(self) -> None:
        """It holds info.yml files that sit under a rules path and look like rules but
        are test metadata. The first file this parser ever read was one of them, and it
        produced zero coverage until the filter was corrected."""

        self.assertIsNone(
            sigma_module.rule_path(
                "sigma-master/regression_data/rules/cisco/aaa/info.yml"
            )
        )

    def test_a_non_rule_file_is_excluded(self) -> None:
        self.assertIsNone(sigma_module.rule_path("sigma-master/rules/README.md"))

    def test_a_file_outside_the_rules_tree_is_excluded(self) -> None:
        self.assertIsNone(sigma_module.rule_path("sigma-master/tools/foo.yml"))


class ParseRuleTests(unittest.TestCase):
    def test_the_techniques_are_read_from_the_tags(self) -> None:
        rule = sigma_module.parse_rule(
            rule_text(techniques=["t1059.001", "t1105"]), path="windows/foo.yml"
        )

        self.assertEqual(rule["techniques"], ["T1059.001", "T1105"])

    def test_the_title_level_and_status_are_read(self) -> None:
        rule = sigma_module.parse_rule(rule_text(), path="windows/foo.yml")

        self.assertEqual(rule["title"], "Suspicious Command Shell")
        self.assertEqual(rule["level"], "high")
        self.assertEqual(rule["status"], "test")

    def test_a_tactic_tag_is_not_a_technique(self) -> None:
        """``attack.execution`` names a tactic, not a technique."""

        rule = sigma_module.parse_rule(
            rule_text(techniques=["t1059"]), path="windows/foo.yml"
        )

        self.assertEqual(rule["techniques"], ["T1059"])

    def test_a_rule_with_no_technique_tag_is_skipped(self) -> None:
        text = "title: x\nlevel: low\ntags:\n    - attack.execution\n"

        self.assertIsNone(sigma_module.parse_rule(text, path="windows/foo.yml"))

    def test_an_uppercase_tag_is_read(self) -> None:
        text = "title: x\ntags:\n    - attack.T1059\n"

        self.assertEqual(
            sigma_module.parse_rule(text, path="a.yml")["techniques"], ["T1059"]
        )


class ParseArchiveTests(unittest.TestCase):
    def test_a_rule_is_read_from_the_archive(self) -> None:
        payload = archive({"sigma-master/rules/windows/foo.yml": rule_text()})

        rules = sigma_module.parse_archive(payload)

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["path"], "windows/foo.yml")

    def test_regression_data_is_not_read(self) -> None:
        payload = archive(
            {
                "sigma-master/regression_data/rules/x/info.yml": rule_text(),
                "sigma-master/rules/windows/foo.yml": rule_text(),
            }
        )

        rules = sigma_module.parse_archive(payload)

        self.assertEqual([rule["path"] for rule in rules], ["windows/foo.yml"])

    def test_an_archive_with_no_tagged_rules_is_rejected(self) -> None:
        """It means the layout changed or the filter is wrong, and both look identical
        to a repository that has no tagged rules."""

        payload = archive({"sigma-master/rules/windows/foo.yml": "title: x\n"})

        with self.assertRaises(NormalizationError):
            sigma_module.parse_archive(payload)

    def test_a_non_archive_is_rejected(self) -> None:
        with self.assertRaises(NormalizationError):
            sigma_module.parse_archive("not an archive")


class BuildIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = sigma_module.build_index(
            archive(
                {
                    "sigma-master/rules/a.yml": rule_text(
                        title="A", level="high", techniques=["t1059.001"]
                    ),
                    "sigma-master/rules/b.yml": rule_text(
                        title="B", level="medium", techniques=["t1059.001", "t1105"]
                    ),
                }
            ),
            generated_at="2026-11-01T00:00:00Z",
        )

    def test_a_technique_maps_to_its_rules(self) -> None:
        self.assertEqual(len(self.index["by_technique"]["T1059.001"]), 2)
        self.assertEqual(len(self.index["by_technique"]["T1105"]), 1)

    def test_the_counts_are_reported(self) -> None:
        counts = self.index["counts"]

        self.assertEqual(counts["rules"], 2)
        self.assertEqual(counts["techniques_covered"], 2)
        self.assertEqual(counts["mappings"], 3)
        self.assertEqual(counts["techniques_at_cap"], 0)

    def test_a_rule_covering_two_techniques_is_counted_for_both(self) -> None:
        self.assertEqual(self.index["rule_counts"]["T1059.001"], 2)
        self.assertEqual(self.index["rule_counts"]["T1105"], 1)


class DetectionSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = sigma_module.build_index(
            archive(
                {
                    "sigma-master/rules/a.yml": rule_text(
                        title="A", level="high", techniques=["t1059.001"]
                    ),
                    "sigma-master/rules/b.yml": rule_text(
                        title="B", level="medium", techniques=["t1059.001"]
                    ),
                }
            )
        )

    def test_a_covered_technique_gets_a_summary(self) -> None:
        summary = sigma_module.detection_summary(self.index, "T1059.001")

        self.assertEqual(summary["rule_count"], 2)
        self.assertEqual(summary["by_level"], {"high": 1, "medium": 1})

    def test_an_uncovered_technique_gets_nothing(self) -> None:
        """Which is itself the finding: nothing detects this technique yet."""

        self.assertIsNone(sigma_module.detection_summary(self.index, "T9999"))

    def test_a_missing_index_gets_nothing(self) -> None:
        self.assertIsNone(sigma_module.detection_summary(None, "T1059.001"))

    def test_at_most_three_examples_are_published(self) -> None:
        """A technique with 73 rules would otherwise bury the threat."""

        payload = archive(
            {
                f"sigma-master/rules/{n}.yml": rule_text(
                    title=f"rule-{n}", techniques=["t1059.001"]
                )
                for n in range(10)
            }
        )
        index = sigma_module.build_index(payload)

        summary = sigma_module.detection_summary(index, "T1059.001")

        self.assertEqual(summary["rule_count"], 10)
        self.assertEqual(len(summary["examples"]), 3)

    def test_the_summary_says_it_is_not_evidence_about_the_threat(self) -> None:
        summary = sigma_module.detection_summary(self.index, "T1059.001")

        self.assertIn("not evidence", summary["note"])

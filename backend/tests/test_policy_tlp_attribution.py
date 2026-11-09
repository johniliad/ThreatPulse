"""Phase 1 policy tests: the TLP gate and the attribution register.

These assert the rules that make the product's public claims true: only
TLP:CLEAR/WHITE is ingestible, absence of a marking is never permission, and no
source may be ingested without an attribution record.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lib.attribution import (
    AttributionError,
    assert_enabled_sources_attributed,
    load_register,
)
from lib.tlp import (
    TLP_AMBER,
    TLP_AMBER_STRICT,
    TLP_CLEAR,
    TlpViolation,
    assert_ingestible,
    evaluate,
    find_markings,
    is_ingestible,
    normalize_marking,
    policy_summary,
)


class TlpMarkingTests(unittest.TestCase):
    def test_normalises_real_world_spellings(self) -> None:
        for value in (
            "TLP:CLEAR",
            "tlp:clear",
            "TLP: CLEAR",
            "TLP-CLEAR",
            "CLEAR",
            "WHITE",
            "TLP:WHITE",
        ):
            self.assertEqual(normalize_marking(value), TLP_CLEAR, value)

    def test_recognises_restrictive_levels(self) -> None:
        self.assertEqual(normalize_marking("tlp:amber"), TLP_AMBER)
        self.assertEqual(normalize_marking("TLP:AMBER+STRICT"), TLP_AMBER_STRICT)
        self.assertEqual(normalize_marking("TLP:RED"), "RED")
        self.assertEqual(normalize_marking("TLP:GREEN"), "GREEN")

    def test_unrecognised_markings_return_none(self) -> None:
        self.assertIsNone(normalize_marking("TLP:PURPLE"))
        self.assertIsNone(normalize_marking(None))
        self.assertIsNone(normalize_marking(""))

    def test_find_markings_in_text(self) -> None:
        self.assertEqual(
            find_markings("Advisory (TLP:AMBER) for partners"), {"AMBER"}
        )
        self.assertEqual(find_markings("TLP: CLEAR"), {"CLEAR"})
        self.assertEqual(find_markings("no marking here"), set())

    def test_unrecognised_tlp_token_is_reported_as_unknown(self) -> None:
        self.assertEqual(find_markings("handling: TLP:PURPLE"), {"UNKNOWN"})

    def test_find_markings_across_fragments(self) -> None:
        self.assertEqual(find_markings("TLP:AMBER", None, "TLP:RED"), {"AMBER", "RED"})


class TlpPolicyTests(unittest.TestCase):
    def test_only_clear_is_ingestible(self) -> None:
        self.assertTrue(is_ingestible(TLP_CLEAR))

        for level in (TLP_AMBER, TLP_AMBER_STRICT, "GREEN", "RED"):
            self.assertFalse(is_ingestible(level), level)

    def test_clear_source_clear_item_is_allowed(self) -> None:
        self.assertEqual(
            evaluate(source_default="CLEAR", item_markings=["CLEAR"]), (True, "")
        )

    def test_restrictive_item_is_rejected(self) -> None:
        allowed, reason = evaluate(source_default="CLEAR", item_markings=["AMBER"])

        self.assertFalse(allowed)
        self.assertIn("not ingestible", reason)

    def test_undeclared_source_is_refused(self) -> None:
        allowed, reason = evaluate(source_default=None)

        self.assertFalse(allowed)
        self.assertIn("no recognised tlp_default", reason)

    def test_restrictive_source_default_is_refused(self) -> None:
        allowed, reason = evaluate(source_default="AMBER")

        self.assertFalse(allowed)
        self.assertIn("not ingestible", reason)

    def test_unknown_item_marking_is_refused(self) -> None:
        allowed, reason = evaluate(source_default="CLEAR", item_markings=["UNKNOWN"])

        self.assertFalse(allowed)
        self.assertIn("unrecognised", reason)

    def test_legacy_white_default_accepts_a_clear_item(self) -> None:
        self.assertEqual(
            evaluate(source_default="WHITE", item_markings=["CLEAR"]), (True, "")
        )

    def test_assert_ingestible_raises_with_the_reason(self) -> None:
        with self.assertRaises(TlpViolation) as context:
            assert_ingestible(
                source_key="demo",
                source_default="CLEAR",
                item_markings=["AMBER"],
            )

        self.assertIn("demo", str(context.exception))

    def test_policy_summary_is_publishable(self) -> None:
        summary = policy_summary()

        self.assertEqual(summary["policy"], "TLP:CLEAR/WHITE only")
        self.assertEqual(summary["ingestible"], ["CLEAR"])
        self.assertIn("AMBER", summary["never_ingested"])
        self.assertIn("never treated as permission", summary["unmarked_sources"])


class AttributionRegisterTests(unittest.TestCase):
    def test_real_register_loads(self) -> None:
        register = load_register()

        self.assertGreaterEqual(register.size, 20)
        self.assertIn("cisa_kev", {record.source_key for record in register.all_records()})

    def test_every_record_declares_a_recognised_tlp_default(self) -> None:
        for record in load_register().all_records():
            self.assertIsNotNone(
                normalize_marking(record.tlp_default),
                f"{record.source_key} has an unrecognised tlp_default",
            )

    def test_every_record_carries_attribution_text(self) -> None:
        for record in load_register().all_records():
            self.assertTrue(record.attribution_text.strip(), record.source_key)
            self.assertTrue(record.licence.strip(), record.source_key)

    def test_tier_2_sources_are_recorded_but_not_ingested(self) -> None:
        register = load_register()

        for source_key in ("nvd",):
            record = register.require(source_key)

            self.assertFalse(record.pipeline_enabled, source_key)
            self.assertFalse(record.ingestible, source_key)
            self.assertEqual(record.tier, 2, source_key)


    def test_unknown_source_is_refused(self) -> None:
        with self.assertRaises(AttributionError):
            load_register().require("not_a_real_source")

    def test_ingestible_requires_both_flag_and_tlp(self) -> None:
        record = load_register().require("cisa_kev")

        self.assertTrue(record.pipeline_enabled)
        self.assertTrue(record.ingestible)

    def test_public_dict_shape(self) -> None:
        payload = load_register().require("cert_eu_advisories").to_public_dict()

        for key in (
            "source_key",
            "name",
            "provider",
            "homepage",
            "licence",
            "tlp_default",
            "ingested",
            "attribution_text",
        ):
            self.assertIn(key, payload)

        self.assertEqual(payload["tlp_default"], "CLEAR")
        self.assertTrue(payload["ingested"])

    def test_public_payload_lists_disabled_sources_too(self) -> None:
        payload = load_register().to_public_dict()
        keys = {entry["source_key"] for entry in payload["sources"]}

        self.assertIn("nvd", keys)
        self.assertIn("spamhaus_drop", keys)

    def test_enabled_sources_are_consistent_with_the_register(self) -> None:
        from lib.config import load_settings

        settings = load_settings()

        assert_enabled_sources_attributed(
            load_register(), [source.key for source in settings.enabled_sources]
        )

    def test_missing_attribution_fails_the_check(self) -> None:
        with self.assertRaises(AttributionError) as context:
            assert_enabled_sources_attributed(load_register(), ["ghost_source"])

        self.assertIn("ghost_source", str(context.exception))

    def test_enabled_but_not_ingested_fails_the_check(self) -> None:
        with self.assertRaises(AttributionError):
            assert_enabled_sources_attributed(load_register(), ["nvd"])


class AttributionRegisterValidationTests(unittest.TestCase):
    def _write(self, payload) -> Path:
        directory = tempfile.mkdtemp()

        path = Path(directory) / "attribution.json"
        path.write_text(json.dumps(payload), encoding="utf-8")

        return path

    def _entry(self, **overrides) -> dict:
        entry = {
            "source_key": "demo",
            "name": "Demo",
            "provider": "Demo provider",
            "homepage": "https://example.invalid/",
            "licence": "Demo licence",
            "tlp_default": "CLEAR",
            "pipeline_enabled": True,
            "attribution_text": "Source: Demo.",
        }
        entry.update(overrides)

        return entry

    def test_missing_required_field_is_rejected(self) -> None:
        entry = self._entry()
        del entry["licence"]

        with self.assertRaises(AttributionError):
            load_register(self._write({"sources": [entry]}))

    def test_unrecognised_tlp_default_is_rejected(self) -> None:
        with self.assertRaises(AttributionError):
            load_register(
                self._write({"sources": [self._entry(tlp_default="PURPLE")]})
            )

    def test_duplicate_source_key_is_rejected(self) -> None:
        with self.assertRaises(AttributionError):
            load_register(
                self._write({"sources": [self._entry(), self._entry()]})
            )

    def test_empty_sources_array_is_rejected(self) -> None:
        with self.assertRaises(AttributionError):
            load_register(self._write({"sources": []}))

    def test_missing_file_is_rejected(self) -> None:
        with self.assertRaises(AttributionError):
            load_register(Path(tempfile.mkdtemp()) / "absent.json")

    def test_amber_default_makes_a_source_non_ingestible(self) -> None:
        register = load_register(
            self._write({"sources": [self._entry(tlp_default="AMBER")]})
        )

        self.assertFalse(register.require("demo").ingestible)

    def test_optional_fields_may_be_absent(self) -> None:
        register = load_register(self._write({"sources": [self._entry()]}))
        record = register.require("demo")

        self.assertIsNone(record.licence_url)
        self.assertIsNone(record.terms_url)
        self.assertIsNone(record.notes)
        self.assertIsNone(record.tier)


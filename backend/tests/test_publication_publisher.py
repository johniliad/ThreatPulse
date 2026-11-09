"""Publication-gate, atomic-write and publisher tests.

Standard library only, no credentials, no live network.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import publisher as publisher_module  # noqa: E402
from lib import atomic, config  # noqa: E402
from lib.http import HttpError  # noqa: E402
from lib.logging_setup import redact  # noqa: E402
from publication import quality_gate  # noqa: E402
from tests.test_backend import settings_payload  # noqa: E402

THREAT = {
    "threat_uuid": "394720a7-b42e-cc69-c522-0c68b5d75567",
    "external_id": "CVE-2026-109619",
    "title": "PHP Stale Internal Request-State Vulnerability",
    "threat_type": "vulnerability",
    "severity": "critical",
    "priority_score": 92.5,
    "confidence_score": 100.0,
    "confidence_level": "high",
    "exploitation_status": "confirmed",
    "first_seen": "2026-10-26T00:00:00Z",
    "last_seen": "2026-10-30T10:00:00Z",
    "summary": "Fixture summary",
    "recommended_action": "Apply mitigations.",
    "metadata": {},
    "source_keys": ["cisa_kev"],
    "vulnerabilities": [{"cve_id": "CVE-2026-109619"}],
}

SOURCE = {
    "source_key": "cisa_kev",
    "name": "CISA KEV",
    "source_type": "advisory",
    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "provider": "CISA",
    "reliability": "high",
}


def minimal_publication() -> dict:
    """A valid schema 1.0 document, for exercising the quality gate."""

    return {
        "schema_version": "1.0",
        "publication_uuid": "8585c51f-706c-43a1-bab3-75ad4f4a2e62",
        "generated_at": "2026-10-30T10:00:00Z",
        "summary": {"threat_count": 1, "vulnerability_count": 1},
        "sources": [dict(SOURCE)],
        "threats": [dict(THREAT)],
    }


class PublicationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def settings(self):
        path = self.root / "settings.json"
        path.write_text(json.dumps(settings_payload()), encoding="utf-8")

        return config.load_settings(path, backend_root=self.root)


class PublicationTests(PublicationTestCase):
    def test_accepts_a_valid_publication(self):
        self.assertEqual(quality_gate.validate_publication(minimal_publication()), [])

    def test_quality_gate_rejects_structural_problems(self):
        cases = {
            "schema": lambda p: p.update({"schema_version": "2.0"}),
            "uuid": lambda p: p.update({"publication_uuid": "nope"}),
            "generated_at": lambda p: p.update({"generated_at": "2026-10-30"}),
            "count": lambda p: p["summary"].update({"threat_count": 99}),
            "range": lambda p: p["threats"][0].update({"priority_score": 150}),
            "severity": lambda p: p["threats"][0].update({"severity": "nope"}),
            "duplicate": lambda p: p["threats"].append(dict(THREAT)),
            "source": lambda p: p["threats"][0].update({"source_keys": ["ghost"]}),
            "secret": lambda p: p["summary"].update({"n": "publisher_token=leaked"}),
            "empty": lambda p: p.update({"threats": []}),
        }

        for name, mutate in cases.items():
            payload = minimal_publication()
            mutate(payload)

            with self.assertRaises(quality_gate.QualityGateError, msg=name):
                quality_gate.assert_publishable(payload)

    def test_volume_guard_blocks_a_suspicious_drop(self):
        payload = minimal_publication()

        with self.assertRaises(quality_gate.QualityGateError):
            quality_gate.assert_publishable(
                payload, previous_summary={"threat_count": 100}
            )

        quality_gate.assert_publishable(
            payload, previous_summary={"threat_count": 100}, maximum_drop_ratio=1.0
        )


class AtomicWriteTests(PublicationTestCase):
    def test_writes_and_reads_json_atomically(self):
        path = self.root / "state" / "artifact.json"

        atomic.write_json_atomic(path, {"value": 1})
        self.assertEqual(atomic.read_json(path)["value"], 1)

        atomic.write_json_atomic(path, {"value": 2})
        self.assertEqual(atomic.read_json(path)["value"], 2)

        self.assertEqual(
            [e.name for e in path.parent.iterdir() if e.name.endswith(".tmp")], []
        )

    def test_read_json_returns_default_when_absent(self):
        self.assertIsNone(atomic.read_json(self.root / "missing.json"))


class PublisherTests(PublicationTestCase):
    def test_builds_bearer_authorization_header(self):
        self.assertEqual(
            publisher_module.build_headers("token-value", self.settings())[
                "Authorization"
            ],
            "Bearer token-value",
        )

    def test_successful_publication(self):
        http = mock.Mock()
        http.post_json.return_value = mock.Mock(
            json=lambda: {"status": "ok", "publication_id": 3}, status=201
        )

        outcome = publisher_module.publish_publication(
            minimal_publication(),
            settings=self.settings(),
            token="token-value",
            http=http,
        )

        self.assertTrue(outcome.ok)
        self.assertEqual(
            publisher_module.validate_api_response(outcome, minimal_publication()), []
        )

    def test_duplicate_publication_is_not_a_failure(self):
        http = mock.Mock()
        http.post_json.side_effect = HttpError("dup", transient=False, status=409)

        outcome = publisher_module.publish_publication(
            minimal_publication(),
            settings=self.settings(),
            token="token-value",
            http=http,
        )

        self.assertTrue(outcome.duplicate)
        self.assertTrue(outcome.ok)

    def test_transport_failure_propagates(self):
        http = mock.Mock()
        http.post_json.side_effect = HttpError("timeout", transient=True, attempts=3)

        with self.assertRaises(HttpError):
            publisher_module.publish_publication(
                minimal_publication(),
                settings=self.settings(),
                token="token-value",
                http=http,
            )

    def test_mismatched_uuid_is_reported_and_dry_run_is_silent(self):
        outcome = publisher_module.PublishOutcome(
            status_code=201,
            response={
                "status": "ok",
                "publication_uuid": "00000000-0000-4000-8000-000000000000",
            },
        )

        self.assertTrue(
            publisher_module.validate_api_response(outcome, minimal_publication())
        )

        http = mock.Mock()

        dry = publisher_module.publish_publication(
            {}, settings=self.settings(), token="t", http=http, dry_run=True
        )

        self.assertEqual(dry.status_code, 0)
        http.post_json.assert_not_called()


class RedactionTests(PublicationTestCase):
    def test_redacts_credentials_from_log_messages(self):
        self.assertNotIn("abcdef123456", redact("Authorization: Bearer abcdef123456"))
        self.assertIn("[redacted]", redact("publisher_token=supersecret"))


if __name__ == "__main__":
    unittest.main()


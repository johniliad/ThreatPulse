#!/usr/bin/env python3
"""ThreatPulse pipeline orchestrator.

Stages, in order: collect → normalise → correlate → enrich → score → explain →
quality gate → snapshot → (optionally) publish → verify.

Design rules honoured here:

* a **required** source failing with no usable snapshot aborts the run;
* a **degraded** source (fresh retrieval failed, last known good reused) does not
  erase intelligence from other sources and is reported loudly;
* nothing is transmitted unless the quality gate passes;
* the previous snapshot is only replaced after the gate passes, atomically;
* publishing is opt-in (``--publish``), so an unattended scheduled run cannot
  replace published data by accident during development;
* the run always leaves a machine-readable report and a meaningful exit code.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from collectors.base import SourceResult  # noqa: E402
from collectors.cisa_kev import build_collector, write_normalized_snapshot  # noqa: E402
from collectors.cisa_csaf import CisaCsafCollector  # noqa: E402
from collectors.cisa_vulnrichment import CisaVulnrichmentCollector  # noqa: E402
from collectors.circl_vulnerability_lookup import (  # noqa: E402
    CirclVulnerabilityLookupCollector,
)
from collectors.enisa_euvd import EuvdCollector  # noqa: E402
from collectors.epss import EpssCollector  # noqa: E402
from collectors.exploit_availability import ExploitAvailabilityCollector  # noqa: E402
from collectors.mitre_attack import MitreAttackCollector  # noqa: E402
from collectors.misp_galaxy import MispGalaxyCollector  # noqa: E402
from collectors.capec import CapecCollector  # noqa: E402
from collectors.ubuntu import UbuntuSecurityCollector  # noqa: E402
from collectors.sigma import SigmaCollector  # noqa: E402
from collectors.msrc import MsrcCollector  # noqa: E402
from collectors.circl_misp_osint import CirclMispOsintCollector  # noqa: E402
from collectors.osv_dev import OsvCollector  # noqa: E402
from collectors.ransomware_live import RansomwareLiveCollector  # noqa: E402
from collectors.redhat_security import RedhatSecurityCollector  # noqa: E402
from collectors.rss_feed import RssFeedCollector  # noqa: E402
from correlation.engine import correlate  # noqa: E402
from enrichment.base import run_enrichers  # noqa: E402
from lib.attribution import assert_enabled_sources_attributed, load_register  # noqa: E402
from lib.config import ConfigError, load_settings  # noqa: E402
from lib.http import HttpClient  # noqa: E402
from lib.ids import IdentityAliasMap  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from models.intelligence import Source  # noqa: E402
from publication.builder import build_publication  # noqa: E402
from publication.quality_gate import QualityGateError, assert_publishable  # noqa: E402
from state.cve_first_seen import CveFirstSeen  # noqa: E402
from state.threat_history import ThreatHistory  # noqa: E402
from state.store import StateStore, utc_now_iso  # noqa: E402

LOGGER = get_logger("run_pipeline")

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 2
EXIT_LOCKED = 3
EXIT_PUBLISH = 4


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a ThreatPulse publication from the configured sources."
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="transmit the publication after the quality gate passes",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="build and validate, but never transmit",
    )
    parser.add_argument(
        "--allow-volume-drop",
        action="store_true",
        help="override the volume guard after reviewing why the count dropped",
    )
    parser.add_argument(
        "--log-level", default="INFO", help="logging level (default INFO)"
    )
    return parser.parse_args(argv)


#: Collection order. ``cisa_kev`` runs first because dependent sources — EPSS in
#: particular — are queried with the CVE identifiers it discovers.
COLLECTION_ORDER = {
    "cisa_kev": 0,
    "cisa_advisories": 10,
    "cisa_csaf": 15,
    "cert_eu_advisories": 11,
    "cert_eu_threat_intel": 12,
    "ncsa_greece": 13,
    "national_cert_feeds": 14,
    "ransomware_live": 20,
    # A knowledge base rather than a feed: independent of the CVE candidate list,
    # and its index has to exist before the enrichment stage runs.
    "mitre_attack": 25,
    "enisa_euvd": 30,
    # Dependent on the CVEs the sources above discovered, and bounded per run.
    "cisa_vulnrichment": 35,
    "exploit_availability": 40,
    "redhat_security": 41,
    "osv_dev": 42,
    "circl_vulnerability_lookup": 43,
    "msrc": 44,
    "circl_misp_osint": 45,
    "misp_galaxy": 46,
    # After mitre_attack: the CAPEC index resolves its second hop from the ATT&CK
    # index, so ATT&CK must have been built first.
    "capec": 47,
    "cisco_security_advisories": 48,
    "ubuntu_security": 49,
    "sigma": 50,
    "epss_first": 90,
}

DEFAULT_COLLECTION_ORDER = 50

#: Source keys served by the generic RSS/Atom collector.
RSS_SOURCE_KEYS = frozenset(
    {
        "cisa_advisories",
        "cert_eu_advisories",
        "cert_eu_threat_intel",
        "ncsa_greece",
        "national_cert_feeds",
        # First-party vendor advisories. These are ordinary RSS feeds, so they reuse
        # the generic collector rather than each getting one of their own.
        "fortinet_psirt",
        "wordpress_security",
        "cisco_security_advisories",
    }
)


def build_http_client(settings) -> HttpClient:
    """One HTTP client configured from settings, shared by the collectors."""

    return HttpClient(
        user_agent=settings.http.user_agent,
        connect_timeout_seconds=settings.http.connect_timeout_seconds,
        read_timeout_seconds=settings.http.read_timeout_seconds,
        max_attempts=settings.http.max_attempts,
        backoff_seconds=settings.http.backoff_seconds,
        backoff_multiplier=settings.http.backoff_multiplier,
    )


def build_source_collector(
    source_config,
    settings,
    state: StateStore,
    register,
    *,
    cve_ids: list[str] | None = None,
):
    """Returns a collector for a source key, or None when none is implemented.

    A source that is enabled but has no collector is reported and skipped — it is
    never silently treated as having produced nothing.
    """

    if source_config.key == "cisa_kev":
        return build_collector(settings)

    if source_config.key in RSS_SOURCE_KEYS:
        return RssFeedCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
        )

    if source_config.key == "ransomware_live":
        return RansomwareLiveCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
        )

    if source_config.key == "cisa_csaf":
        return CisaCsafCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
        )

    if source_config.key == "enisa_euvd":
        return EuvdCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
        )

    if source_config.key == "mitre_attack":
        return MitreAttackCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
        )

    if source_config.key == "cisa_vulnrichment":
        return CisaVulnrichmentCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
            cve_ids=cve_ids or (),
        )

    if source_config.key == "redhat_security":
        return RedhatSecurityCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
            cve_ids=cve_ids or (),
        )

    if source_config.key == "osv_dev":
        return OsvCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
            cve_ids=cve_ids or (),
        )

    if source_config.key == "msrc":
        return MsrcCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
            cve_ids=cve_ids or (),
        )

    if source_config.key == "circl_misp_osint":
        return CirclMispOsintCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
        )

    if source_config.key == "misp_galaxy":
        return MispGalaxyCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
        )

    if source_config.key == "capec":
        return CapecCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
        )

    if source_config.key == "ubuntu_security":
        return UbuntuSecurityCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
        )

    if source_config.key == "sigma":
        return SigmaCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
        )

    if source_config.key == "circl_vulnerability_lookup":
        return CirclVulnerabilityLookupCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
            cve_ids=cve_ids or (),
        )

    if source_config.key == "exploit_availability":
        return ExploitAvailabilityCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
            cve_ids=cve_ids or (),
        )

    if source_config.key == "epss_first":
        return EpssCollector(
            source_config,
            build_http_client(settings),
            state,
            register=register,
            cve_ids=cve_ids or (),
        )

    return None


def collect_sources(
    settings, state: StateStore, *, register=None
) -> list[SourceResult]:
    """Runs every enabled collector; a required source failure aborts.

    Before anything is fetched, the attribution and TLP register is checked
    against the enabled sources. A source that is enabled but unregistered, or
    registered as not ingestible, fails the run — absence of a record is not
    permission.
    """

    if register is None:
        register = load_register()

    assert_enabled_sources_attributed(
        register, [source.key for source in settings.enabled_sources]
    )

    results: list[SourceResult] = []
    discovered_cves: set[str] = set()

    ordered = sorted(
        settings.enabled_sources,
        key=lambda source: (
            COLLECTION_ORDER.get(source.key, DEFAULT_COLLECTION_ORDER),
            source.key,
        ),
    )

    for source_config in ordered:
        collector = build_source_collector(
            source_config,
            settings,
            state,
            register,
            cve_ids=sorted(discovered_cves),
        )

        if collector is None:
            log_event(
                LOGGER,
                logging.WARNING,
                "source enabled but no collector implemented yet",
                source_key=source_config.key,
            )
            continue

        result = collector.collect(utc_now_iso())
        results.append(result)

        # Harvest CVE identifiers for the dependent sources that follow.
        for observation in result.observations:
            for entity in observation.entities:
                if entity.kind == "cve":
                    discovered_cves.add(entity.normalized)

        if result.status == "failed":
            log_event(
                LOGGER,
                logging.ERROR,
                "source failed",
                source_key=result.source.key,
                required=source_config.required,
                reason=result.failure_reason,
            )

            if source_config.required:
                raise RuntimeError(
                    f"required source '{source_config.key}' failed and no usable "
                    f"snapshot exists: {result.failure_reason}"
                )
        elif result.status == "degraded":
            log_event(
                LOGGER,
                logging.WARNING,
                "source degraded: using last known good snapshot",
                source_key=result.source.key,
                reason=result.failure_reason,
            )

    return results


def build_sources(results: list[SourceResult]) -> list[Source]:
    return [result.source for result in results if result.usable]


def build_source_health(
    results: list[SourceResult], *, generated_at: str
) -> dict:
    """Per-source run health, for publication.

    ``status`` is the collector's own verdict — ``ok``, ``degraded`` (a retrieval
    failure that fell back to a last-known-good snapshot) or ``failed``. It travels
    with the publication because it is the most useful thing an operator can be told
    and, until now, it existed only in a log line and a local run report.

    Counts are derived rather than asserted, so a declared source that is disabled,
    or one with no collector, simply does not appear.
    """

    sources = sorted(
        (result.summary() for result in results),
        key=lambda item: str(item["source_key"]),
    )

    counts = {"ok": 0, "degraded": 0, "failed": 0}

    for source in sources:
        status = str(source.get("status") or "")

        if status in counts:
            counts[status] += 1

    return {
        "generated_at": generated_at,
        "summary": {**counts, "sources": len(sources)},
        "sources": sources,
    }



def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(list(sys.argv[1:] if argv is None else argv))

    try:
        settings = load_settings()
    except ConfigError as error:
        print(f"CONFIGURATION ERROR: {error}", file=sys.stderr)
        return EXIT_CONFIG

    configure_logging(
        level=arguments.log_level, log_directory=settings.log_directory, console=True
    )

    run_id = str(uuid.uuid4())
    state = StateStore(settings.state_directory, settings.data_directory)
    register = load_register()

    if not state.acquire_run_lock(run_id=run_id):
        log_event(
            LOGGER,
            logging.ERROR,
            "another run holds the lock; refusing to overlap",
            run_id=run_id,
        )
        print("Another ThreatPulse run is in progress.", file=sys.stderr)
        return EXIT_LOCKED

    started_at = utc_now_iso()

    try:
        print("ThreatPulse — pipeline")
        print("----------------------")

        results = collect_sources(settings, state)
        observations = [
            observation
            for result in results
            if result.usable
            for observation in result.observations
        ]

        if not observations:
            print("ERROR: no usable observations from any source.", file=sys.stderr)
            return EXIT_FAILED

        sources = build_sources(results)

        for result in results:
            if result.usable and result.source.key == "cisa_kev":
                write_normalized_snapshot(
                    settings.data_directory / "known_exploited_vulnerabilities.json",
                    result,
                    started_at,
                )

        aliases = IdentityAliasMap(state.state_path("identity_aliases.json"))
        aliases.load()

        reference_date = datetime.now(timezone.utc).date()

        # Filled by correlate with the model split and the counts of evidence it
        # could not use, so a run report says how much was published and by which
        # model rather than only how many records came out.
        correlation_stats: dict = {}

        # The one recency signal the pipeline owns rather than borrows from a
        # source. Recorded before correlation so a CVE first seen in this run is
        # scored with today's date rather than tomorrow's.
        first_seen_registry = CveFirstSeen(state)
        first_seen_registry.load()

        correlation_stats["cves_first_seen_this_run"] = first_seen_registry.observe(
            {
                entity.normalized or entity.value
                for observation in observations
                for entity in observation.entities
                if entity.kind == "cve"
            },
            now=utc_now_iso(),
        )

        if first_seen_registry.dirty:
            first_seen_registry.save()

        correlation_stats["cves_in_first_seen_registry"] = first_seen_registry.size

        threats = correlate(
            observations,
            reference_date=reference_date,
            aliases=aliases,
            source_names={source.key: source.name for source in sources},
            first_seen=first_seen_registry.snapshot(),
            stats=correlation_stats,
        )

        threats, enrichment_notes = run_enrichers(threats, settings=settings)

        # What changed since the last publication. Recorded before the document is
        # built, so the counts describe exactly the set being published rather than
        # a set that has since been enriched further.
        history = ThreatHistory(state)
        history.load()

        change_summary = history.reconcile(threats, now=utc_now_iso())

        if history.dirty:
            history.save()

        publication = build_publication(
            threats,
            sources,
            generated_at=utc_now_iso(),
            max_summary_items=settings.publication.max_summary_items,
            changes=change_summary,
        )

        payload = publication.to_publication_dict()

        # The attribution register travels with the publication.
        #
        # The API is the only thing the public can read, so if the register does not
        # travel, the Sources page can only ever show sources that happened to
        # contribute a threat. It could never show a source that is deliberately not
        # ingested, nor the tier, licence and terms behind any of them — which is the
        # whole reason the register exists. Sending it here also means the register
        # the public reads is the one that produced the data they are reading.
        payload["attribution"] = register.to_public_dict()

        # How each source behaved on this run. The attribution register says what a
        # source is and on what terms; this says whether it actually worked — which
        # is the difference between "declared" and "contributing", and the thing a
        # reader most needs to know when a count looks low.
        payload["source_health"] = build_source_health(
            results, generated_at=payload["generated_at"]
        )

        previous = state.load_previous_publication()

        assert_publishable(
            payload,
            previous_summary=previous,
            register=register,
            max_payload_bytes=settings.publication.max_payload_bytes,
            minimum_threats=settings.publication.minimum_threats,
            maximum_drop_ratio=(
                1.0
                if arguments.allow_volume_drop
                else settings.publication.maximum_drop_ratio
            ),
        )

        snapshot_path = state.save_publication_snapshot(payload)
        state.save_previous_publication(payload["summary"])

        counts = payload["summary"]
        print(f"Sources:         {', '.join(counts['source_keys'])}")
        print(f"Threats:         {counts['threat_count']}")
        print(f"Critical:        {counts['critical_count']}")
        print(f"High:            {counts['high_count']}")
        print(f"Medium:          {counts['medium_count']}")
        print(f"Vulnerabilities: {counts['vulnerability_count']}")
        print(
            f"Changes:         new {change_summary['new']}, "
            f"changed {change_summary['changed']}, "
            f"disappeared {change_summary['disappeared']}"
        )
        print(f"Publication:     {payload['publication_uuid']}")
        print(f"Snapshot:        {snapshot_path}")

        published = False
        publish_problems: list[str] = []

        if arguments.publish and not arguments.dry_run:
            from lib.config import load_publisher_token
            from lib.http import HttpClient
            from publisher import publish_publication, validate_api_response

            token = load_publisher_token(settings.env_file)

            http = HttpClient(
                user_agent=settings.http.user_agent,
                connect_timeout_seconds=settings.http.connect_timeout_seconds,
                read_timeout_seconds=settings.publisher.timeout_seconds,
                max_attempts=settings.publisher.max_attempts,
                backoff_seconds=settings.publisher.backoff_seconds,
                backoff_multiplier=settings.http.backoff_multiplier,
            )

            outcome = publish_publication(
                payload, settings=settings, token=token, http=http
            )

            publish_problems = validate_api_response(outcome, payload)
            published = outcome.ok and not publish_problems

            if outcome.unverified:
                print(
                    "ACCEPTED BUT UNVERIFIED: the API returned HTTP "
                    f"{outcome.status_code} but its response could not be parsed, "
                    "so the integrity check was skipped.",
                    file=sys.stderr,
                )
                print(
                    "Verify with: python3 scripts/verify_publication.py",
                    file=sys.stderr,
                )
            elif outcome.duplicate:
                print("Publication already exists on the API (HTTP 409).")
            elif published:
                print(
                    "Published. Server publication ID: "
                    f"{outcome.response.get('publication_id')}"
                )
        else:
            print("Publishing not requested (use --publish to transmit).")

        state.save_run_report(
            {
                "run_id": run_id,
                "started_at": started_at,
                "finished_at": utc_now_iso(),
                "environment": settings.environment,
                "scoring_model": settings.scoring_model,
                "correlation": correlation_stats,
                "changes": change_summary,
                "sources": [result.summary() for result in results],
                "enrichment": enrichment_notes,
                "publication_uuid": payload["publication_uuid"],
                "summary": counts,
                "published": published,
                "publish_problems": publish_problems,
                "snapshot_path": str(snapshot_path),
            }
        )

        if publish_problems:
            for problem in publish_problems:
                print(f"API RESPONSE PROBLEM: {problem}", file=sys.stderr)

            return EXIT_PUBLISH

        return EXIT_OK

    except QualityGateError as error:
        print(f"QUALITY GATE: {error}", file=sys.stderr)
        log_event(LOGGER, logging.ERROR, "quality gate rejected the publication")
        return EXIT_FAILED
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return EXIT_FAILED
    finally:
        state.release_run_lock()


if __name__ == "__main__":
    raise SystemExit(main())


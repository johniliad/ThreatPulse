#!/usr/bin/env python3
"""Publisher: the only component that talks to the cPanel API.

Migrated from the pre-existing ``publisher.py`` script, with the security and
robustness fixes the requirements demand:

* the Bearer token is read from the environment file (mode 0600), never from
  committed configuration, never from the command line, never logged;
* HTTPS enforced, configurable timeout, bounded retries;
* the API response is validated (status, JSON shape, matching publication UUID);
* HTTP 409 (duplicate publication) means "already published", not a failure,
  because ``publish.php`` is idempotent on ``publication_uuid``;
* explicit exit codes: 0 ok, 1 gate failure, 2 configuration error, 3 rejected by
  the API, 4 transport failure after retries.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.config import (  # noqa: E402
    ConfigError,
    Settings,
    check_env_file_permissions,
    load_publisher_token,
    load_settings,
)
from lib.http import HttpClient, HttpError  # noqa: E402
from lib.logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from publication.chunking import ChunkingError, chunk_publication  # noqa: E402
from publication.quality_gate import QualityGateError, assert_publishable  # noqa: E402

LOGGER = get_logger("publisher")

#: What each of the API's 409 answers means for the operator. publish.php returns
#: three of them and they call for different actions, so the status code alone is
#: not enough to act on. Collapsing them into one line is what let a truncated
#: ENUM pass for a stale deployment across fourteen runs.
DUPLICATE_MEANINGS = {
    "Publication already exists": (
        "The API refused chunk 0 because that publication_uuid is already stored, "
        "so it did not see the chunk block. The deployed api/cti/v1/publish.php "
        "predates chunked publishing: upload the current one, then publish again "
        "with a fresh publication_uuid."
    ),
    "Publication is already complete": (
        "A later chunk arrived for a publication the API considered finished. The "
        "usual cause is that the endpoint cannot record 'receiving': when "
        "publications.status is an ENUM without that member, a non-strict sql_mode "
        "stores '' instead, so the next chunk reads a status that is not "
        "'receiving' and is refused. Give the column room: ALTER TABLE publications "
        "MODIFY status VARCHAR(20) NOT NULL DEFAULT 'published';"
    ),
    "Chunk received before chunk 0; send chunks in order": (
        "Chunks were delivered out of order, so the request that creates the "
        "publication never arrived first."
    ),
}

#: The ``message`` field of the API's JSON error body. HttpError already carries the
#: response body inside its text; these pull out the fields that say why a request
#: was refused, because the status code cannot distinguish three different 409s.
_API_MESSAGE = re.compile(r'"message"\s*:\s*"([^"]+)"')

#: The status the API reports when it refuses a chunk. The interesting value is the
#: empty string: it means the column could not store the value it was given.
_API_PUBLICATION_STATUS = re.compile(r'"publication_status"\s*:\s*"([^"]*)"')


def api_reason(error: HttpError) -> str | None:
    """The API's own explanation of a refusal, or None if it sent none."""

    match = _API_MESSAGE.search(str(error))

    return match.group(1) if match else None


def api_publication_status(error: HttpError) -> str | None:
    """The publication status the API reported when it refused a chunk."""

    match = _API_PUBLICATION_STATUS.search(str(error))

    return match.group(1) if match else None

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 2
EXIT_REJECTED = 3
EXIT_TRANSPORT = 4

ACCEPTED_STATUSES = (200, 201)
#: An intermediate chunk of a multi-chunk publication. The API has stored this
#: slice and is waiting for the rest, so it is neither a success nor a failure.
INTERMEDIATE_STATUS = 202
DUPLICATE_STATUS = 409


@dataclass
class PublishOutcome:
    status_code: int
    response: dict
    duplicate: bool = False
    #: The API accepted the publication but its response body could not be
    #: parsed, so the integrity checks could not run. The HTTP status is
    #: authoritative — publish.php sends 201 only after committing — so this is
    #: not a failure, but it must be reported as *unverified* rather than as
    #: verified, and never as a failure.
    unverified: bool = False
    #: How many chunks were sent, and how many the plan contained. A run that sent
    #: three of five has left the publication incomplete on the server, which is a
    #: different situation from a publication that was never accepted at all.
    chunks_sent: int = 0
    chunks_total: int = 0
    #: A chunk after the first was answered as a duplicate. Against the current API
    #: that means the publication was already complete; against an API that predates
    #: chunking it means each chunk was treated as a whole publication, so only the
    #: first one's threats were stored. Either way this run did not publish the
    #: snapshot, and reporting success would be wrong.
    partial_duplicate: bool = False
    #: The API accepted the first chunk but its response reported no chunk at all,
    #: so it ignored the chunk block and stored only that slice. That is what an
    #: endpoint older than this backend does. Detected on chunk 0 rather than waiting
    #: for the 409 on chunk 1, so the upload stops before the remaining megabytes are
    #: sent and the cause is named instead of the symptom.
    chunk_ignored: bool = False

    @property
    def complete(self) -> bool:
        return self.chunks_total == 0 or self.chunks_sent == self.chunks_total

    @property
    def ok(self) -> bool:
        if self.partial_duplicate or self.chunk_ignored:
            return False

        if self.duplicate:
            return True

        return self.complete and self.status_code in (
            *ACCEPTED_STATUSES,
            INTERMEDIATE_STATUS,
        )


def build_headers(token: str, settings: Settings) -> dict[str, str]:
    """Authorization headers, built in one place so they cannot leak."""

    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": settings.http.user_agent,
        "Accept": "application/json",
    }


def publish_publication(
    publication: dict,
    *,
    settings: Settings,
    token: str,
    http: HttpClient,
    dry_run: bool = False,
) -> PublishOutcome:
    """Splits a validated publication into chunks and POSTs them in order.

    A publication that fits in one request is sent as one chunk, so the
    single-request behaviour is unchanged; the ``chunk`` block is what tells the
    API that a multi-request publication is in progress.

    Chunks are sent sequentially and the run stops at the first failure. Sending the
    rest would grow an incomplete publication that no later chunk could complete,
    and the next scheduled run publishes the whole snapshot again anyway.
    """

    try:
        plan = chunk_publication(
            publication, max_bytes=settings.publication.max_payload_bytes
        )
    except ChunkingError as error:
        # A publication that cannot be split is a configuration problem, not a
        # transport one, so it is not retried.
        raise HttpError(str(error), transient=False) from error

    if dry_run:
        log_event(
            LOGGER,
            logging.INFO,
            "dry run: publication not transmitted",
            chunks=plan.count,
            total_bytes=plan.total_bytes,
            largest_threat_bytes=plan.largest_threat_bytes,
        )

        return PublishOutcome(
            status_code=0,
            response={
                "status": "dry-run",
                "chunks": plan.count,
                "total_bytes": plan.total_bytes,
            },
            chunks_total=plan.count,
        )

    if plan.chunked:
        log_event(
            LOGGER,
            logging.INFO,
            "publication split into chunks",
            chunks=plan.count,
            total_bytes=plan.total_bytes,
            limit_bytes=settings.publication.max_payload_bytes,
        )

    outcomes: list[PublishOutcome] = []

    for index, chunk in enumerate(plan.chunks):
        try:
            outcome = _post_chunk(chunk, settings=settings, token=token, http=http)
        except HttpError as error:
            if index == 0:
                # The publication was never created, so there is nothing partial on
                # the API and the original error is the whole story.
                raise

            # A later chunk failing leaves the publication in 'receiving'. Say so,
            # and say what resolves it: the next run republishes the full snapshot,
            # and threats are upserted rather than duplicated.
            raise HttpError(
                f"chunk {index} of {plan.count} failed: {error}. This publication is "
                "incomplete on the API. The next run publishes the full snapshot "
                "again, and threats are upserted rather than duplicated, so no "
                "operator action is needed beyond checking why the request failed.",
                transient=error.transient,
                status=error.status,
            ) from error

        outcomes.append(outcome)

        log_event(
            LOGGER,
            logging.INFO,
            "publication chunk transmitted",
            chunk_index=index,
            chunk_count=plan.count,
            threats=len(chunk.get("threats") or []),
            status=outcome.status_code,
            duplicate=outcome.duplicate,
        )

        if not outcome.ok or (outcome.duplicate and index > 0):
            break

    return _aggregate_outcomes(outcomes, plan.count)


def _aggregate_outcomes(
    outcomes: list[PublishOutcome], total: int
) -> PublishOutcome:
    """One outcome for the whole run, taken from the last request made."""

    if not outcomes:
        return PublishOutcome(
            status_code=0, response={"status": "nothing-sent"}, chunks_total=total
        )

    last = outcomes[-1]

    # A duplicate is only a whole-publication duplicate when the *first* chunk is
    # one: that is the request that creates the publication row.
    duplicate = outcomes[0].duplicate and len(outcomes) == 1

    return PublishOutcome(
        status_code=last.status_code,
        response=last.response,
        duplicate=duplicate,
        unverified=any(outcome.unverified for outcome in outcomes),
        chunks_sent=len(outcomes),
        chunks_total=total,
        partial_duplicate=any(outcome.duplicate for outcome in outcomes[1:]),
        chunk_ignored=any(outcome.chunk_ignored for outcome in outcomes),
    )


def _post_chunk(
    chunk: dict,
    *,
    settings: Settings,
    token: str,
    http: HttpClient,
) -> PublishOutcome:
    """POSTs one chunk. The response is the API's answer for that request."""

    try:
        response = http.post_json(
            settings.publisher.endpoint,
            chunk,
            timeout_seconds=settings.publisher.timeout_seconds,
            headers=build_headers(token, settings),
        )
    except HttpError as error:
        if error.status == DUPLICATE_STATUS:
            reason = api_reason(error)
            stored_status = api_publication_status(error)

            log_event(
                LOGGER,
                logging.WARNING,
                "publication refused by the API as a duplicate",
                publication_uuid=chunk.get("publication_uuid"),
                chunk_index=(chunk.get("chunk") or {}).get("index"),
                api_message=reason,
                api_publication_status=stored_status,
                meaning=DUPLICATE_MEANINGS.get(reason or ""),
            )

            return PublishOutcome(
                status_code=DUPLICATE_STATUS,
                response={
                    "status": "duplicate",
                    "message": reason,
                    "publication_status": stored_status,
                },
                duplicate=True,
            )

        raise

    try:
        payload = response.json()
    except HttpError as error:
        if response.status not in ACCEPTED_STATUSES:
            raise

        log_event(
            LOGGER,
            logging.WARNING,
            "publication accepted but the response could not be parsed",
            status=response.status,
            reason=str(error),
        )

        return PublishOutcome(
            status_code=response.status,
            response={"status": "accepted-unverified", "reason": str(error)},
            unverified=True,
        )

    if not isinstance(payload, dict):
        raise HttpError(
            "publisher API returned a JSON value that is not an object",
            transient=False,
            status=response.status,
        )

    expected_chunk = chunk.get("chunk")

    if (
        isinstance(expected_chunk, dict)
        and expected_chunk.get("index") == 0
        and expected_chunk.get("count", 1) > 1
        and "chunk_count" not in payload
    ):
        log_event(
            LOGGER,
            logging.WARNING,
            "the API accepted a chunk but did not report it as one",
            publication_uuid=chunk.get("publication_uuid"),
            chunk_count_sent=expected_chunk.get("count"),
            api_status=payload.get("status"),
        )

        return PublishOutcome(
            status_code=response.status, response=payload, chunk_ignored=True
        )

    log_event(
        LOGGER,
        logging.INFO,
        "publication transmitted",
        status=response.status,
        publication_id=payload.get("publication_id"),
        new_threat_count=payload.get("new_threat_count"),
        chunk_index=payload.get("chunk_index"),
        chunk_count=payload.get("chunk_count"),
        complete=payload.get("complete"),
    )

    return PublishOutcome(status_code=response.status, response=payload)


def validate_api_response(outcome: PublishOutcome, publication: dict) -> list[str]:
    """Returns problems with the API's response, if any."""

    if outcome.unverified:
        # There is no body to compare against. The caller reports this as
        # unverified and tells the operator to verify propagation, rather than
        # treating an accepted publication as a failure.
        return []

    problems: list[str] = []

    if outcome.chunk_ignored:
        problems.append(
            "the API accepted the first chunk but did not report it as a chunk, so "
            "it ignored the chunk block and stored only part of the snapshot. That "
            "is what an api/cti/v1/publish.php older than this backend does. Upload "
            "the current endpoint; the next run publishes the full snapshot again."
        )

        return problems

    if outcome.partial_duplicate:
        reason = (outcome.response or {}).get("message")
        stored_status = (outcome.response or {}).get("publication_status")
        meaning = DUPLICATE_MEANINGS.get(reason or "")

        problems.append(
            "the API refused a chunk after the first, so this publication was not "
            "stored completely"
            + (f'. It said: "{reason}".' if reason else ".")
            + (
                " The publication it saw had an empty status, which is what a "
                "status column that cannot store 'receiving' looks like."
                if stored_status == ""
                else ""
            )
            + (
                f" {meaning}"
                if meaning
                else (
                    " The usual cause is an API that predates chunked publishing: it "
                    "ignores the chunk block and treats each chunk as its own "
                    "publication, so only the first chunk's threats land. Deploy "
                    "api/cti/v1/publish.php before the backend that chunks, then run "
                    "again with a fresh publication_uuid."
                )
            )
        )

        return problems

    if outcome.duplicate:
        return problems

    if not outcome.complete:
        problems.append(
            f"only {outcome.chunks_sent} of {outcome.chunks_total} chunk(s) were "
            "accepted, so this publication is incomplete on the API. It is not a "
            "failure of the data: the next run publishes the full snapshot again, "
            "and threats are upserted rather than duplicated."
        )

        return problems

    if outcome.status_code not in ACCEPTED_STATUSES:
        problems.append(f"unexpected HTTP status {outcome.status_code}")

    if outcome.response.get("status") != "ok":
        problems.append(
            f"API status was {outcome.response.get('status')!r}, expected 'ok'"
        )

    # A multi-chunk publication is only finished when the API says the final chunk
    # completed it. Without this, a bug that dropped the last chunk would look like
    # a success.
    if outcome.chunks_total > 1 and outcome.response.get("complete") is not True:
        problems.append(
            "the final chunk did not report complete=true, so the API may still be "
            "waiting for the rest of this publication"
        )

    returned_uuid = outcome.response.get("publication_uuid")

    if returned_uuid and returned_uuid != publication.get("publication_uuid"):
        problems.append(
            "API acknowledged a different publication_uuid "
            f"({returned_uuid} != {publication.get('publication_uuid')})"
        )

    return problems


def load_publication(path: Path) -> dict:
    if not path.exists():
        raise ConfigError(f"Publication file not found: {path}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ConfigError(f"{path}: invalid JSON: {error}") from error

    if not isinstance(payload, dict):
        raise ConfigError(f"{path}: root must be a JSON object")

    return payload


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    dry_run = "--dry-run" in arguments
    arguments = [argument for argument in arguments if argument != "--dry-run"]

    try:
        settings = load_settings()
    except ConfigError as error:
        print(f"CONFIGURATION ERROR: {error}", file=sys.stderr)
        return EXIT_CONFIG

    configure_logging(level="INFO", log_directory=settings.log_directory, console=True)

    publication_path = (
        Path(arguments[0]) if arguments else settings.data_directory / "latest_publication.json"
    )

    try:
        publication = load_publication(publication_path)
        assert_publishable(publication)
        token = load_publisher_token(settings.env_file)
    except QualityGateError as error:
        print(f"QUALITY GATE: {error}", file=sys.stderr)
        return EXIT_FAILED
    except ConfigError as error:
        print(f"CONFIGURATION ERROR: {error}", file=sys.stderr)
        return EXIT_CONFIG

    permission_warning = check_env_file_permissions(settings.env_file)

    if permission_warning:
        log_event(
            LOGGER, logging.WARNING, "secrets file permissions", detail=permission_warning
        )

    http = HttpClient(
        user_agent=settings.http.user_agent,
        connect_timeout_seconds=settings.http.connect_timeout_seconds,
        read_timeout_seconds=settings.publisher.timeout_seconds,
        max_attempts=settings.publisher.max_attempts,
        backoff_seconds=settings.publisher.backoff_seconds,
        backoff_multiplier=settings.http.backoff_multiplier,
    )

    print("ThreatPulse — publication publisher")
    print("-----------------------------------")
    print(f"Publication: {publication.get('publication_uuid')}")
    print(f"Threats:     {publication.get('summary', {}).get('threat_count')}")
    print(f"Destination: {settings.publisher.endpoint}")
    print("Publisher token: loaded from the environment file (not displayed)")
    print()

    try:
        outcome = publish_publication(
            publication, settings=settings, token=token, http=http, dry_run=dry_run
        )
    except HttpError as error:
        print(f"TRANSPORT ERROR: {error}", file=sys.stderr)
        return EXIT_TRANSPORT

    problems = validate_api_response(outcome, publication)

    if problems:
        for problem in problems:
            print(f"API RESPONSE PROBLEM: {problem}", file=sys.stderr)

        return EXIT_REJECTED

    if outcome.duplicate:
        print("Publication already exists on the API (HTTP 409) — nothing to do.")
        return EXIT_OK

    if dry_run:
        print("Dry run complete: nothing was transmitted.")
        return EXIT_OK

    print("Publication SUCCESSFUL.")
    print(f"Server publication ID: {outcome.response.get('publication_id')}")

    return EXIT_OK


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)


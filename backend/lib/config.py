"""Validated backend configuration.

Design rules:

* **Non-secret** configuration lives in ``backend/config/settings.json`` and is
  committed.
* **Secrets** are read only from the environment file
  (``/etc/threatpulse/threatpulse.env`` by default) and never appear in
  configuration objects that get logged or serialised.
* Everything is validated up front: a bad timeout, a non-HTTPS endpoint or a
  missing source key fails the run before any network call is made.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .logging_setup import register_secret

DEFAULT_ENV_FILE = "/etc/threatpulse/threatpulse.env"
PUBLISHER_TOKEN_KEY = "THREATPULSE_PUBLISHER_TOKEN"

#: Every secret the pipeline knows how to read. ``load_secrets`` promotes these
#: out of the process environment as well as the environment file, so a systemd
#: ``EnvironmentFile=`` or an override in the unit works without editing code.
SECRET_KEYS = (PUBLISHER_TOKEN_KEY,)

#: Ceiling for a **single request** to the API. A publication larger than this is
#: split across several requests by ``publication.chunking``, so this is a per-chunk
#: limit rather than a limit on the publication as a whole.
#:
#: 7 MiB is deliberately below a common 8 MB ``post_max_size``: the request body is
#: not the only thing PHP counts, and being wrong here means PHP discards the body
#: and the API reports an empty request, which is far harder to diagnose than a
#: refusal before transmission.
DEFAULT_MAX_PAYLOAD_BYTES = 7 * 1024 * 1024

BACKEND_ROOT = Path(__file__).resolve().parent.parent


class ConfigError(RuntimeError):
    """Raised when configuration is missing, malformed or out of range."""


@dataclass(frozen=True)
class HttpConfig:
    connect_timeout_seconds: float
    read_timeout_seconds: float
    max_attempts: int
    backoff_seconds: float
    backoff_multiplier: float
    user_agent: str


@dataclass(frozen=True)
class SourceConfig:
    key: str
    name: str
    source_type: str
    url: str
    feed_url: str
    provider: str
    reliability: str
    enabled: bool
    required: bool
    timeout_seconds: float
    #: Agreed source tier (1 = open/no key, 2 = keyed, 3 = vendor, 4 = knowledge).
    tier: int = 0
    #: Additional feeds covered by one source key (e.g. many national CERT feeds).
    feeds: tuple[str, ...] = ()

    @property
    def feed_urls(self) -> tuple[str, ...]:
        """Every feed URL this source covers, always at least one."""

        return self.feeds or (self.feed_url,)


@dataclass(frozen=True)
class PublisherConfig:
    endpoint: str
    timeout_seconds: float
    max_attempts: int
    backoff_seconds: float
    verify_tls: bool


@dataclass(frozen=True)
class PublicationConfig:
    """Guards that stop a broken run from replacing good published data."""

    minimum_threats: int
    maximum_drop_ratio: float
    max_summary_items: int
    #: Refuse to transmit a request larger than this. The API is a single PHP
    #: request per chunk, so each chunk must fit the server's post_max_size; failing
    #: here, before transmission, is far clearer than a silently truncated body.
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES


@dataclass(frozen=True)
class Settings:
    schema_version: str
    scoring_model: str
    environment: str
    state_directory: Path
    data_directory: Path
    log_directory: Path
    config_directory: Path
    http: HttpConfig
    publisher: PublisherConfig
    publication: PublicationConfig
    sources: tuple[SourceConfig, ...]
    env_file: Path

    def source(self, key: str) -> SourceConfig:
        for source in self.sources:
            if source.key == key:
                return source

        raise ConfigError(f"Unknown source key: {key}")

    @property
    def enabled_sources(self) -> tuple[SourceConfig, ...]:
        return tuple(source for source in self.sources if source.enabled)


def _require(mapping: dict, key: str, kind: type, where: str) -> Any:
    if key not in mapping:
        raise ConfigError(f"{where}: missing required key '{key}'")

    value = mapping[key]

    if kind is float and isinstance(value, int) and not isinstance(value, bool):
        value = float(value)

    if kind is bool:
        if not isinstance(value, bool):
            raise ConfigError(f"{where}.{key}: expected a boolean")

        return value

    if not isinstance(value, kind) or isinstance(value, bool):
        raise ConfigError(
            f"{where}.{key}: expected {kind.__name__}, got {type(value).__name__}"
        )

    return value


def _positive(value: float, where: str, *, allow_zero: bool = False) -> float:
    if allow_zero and value == 0:
        return value

    if value <= 0:
        raise ConfigError(f"{where}: must be greater than zero, got {value}")

    return value


def _require_https(url: str, where: str) -> str:
    if not url.startswith("https://"):
        raise ConfigError(f"{where}: must be an https:// URL, got '{url}'")

    return url


def parse_env_file(path: Path) -> dict:
    """Parses a ``KEY=VALUE`` environment file.

    Supports comments, blank lines and optional single/double quoting. The
    values are returned but never logged.
    """

    if not path.exists():
        return {}

    values: dict[str, str] = {}

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[len("export ") :].strip()

        if "=" not in line:
            raise ConfigError(
                f"{path}:{line_number}: expected KEY=VALUE, got '{raw_line}'"
            )

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]

        if not key:
            raise ConfigError(f"{path}:{line_number}: empty key")

        values[key] = value

    return values


def load_secrets(env_file: Path | None = None) -> dict:
    """Loads secrets from the environment file, with the process environment
    taking precedence (useful for systemd ``EnvironmentFile=``)."""

    path = env_file or Path(os.environ.get("THREATPULSE_ENV_FILE", DEFAULT_ENV_FILE))

    secrets = parse_env_file(path)

    for key in SECRET_KEYS:
        if os.environ.get(key):
            secrets[key] = os.environ[key]

    return secrets


def load_publisher_token(env_file: Path | None = None) -> str:
    """Returns the publisher token, or raises if it is not configured."""

    token = load_secrets(env_file).get(PUBLISHER_TOKEN_KEY, "").strip()

    if not token:
        raise ConfigError(
            "Publisher token is not configured. Set "
            f"{PUBLISHER_TOKEN_KEY} in the environment file "
            f"({env_file or DEFAULT_ENV_FILE}) with mode 0600."
        )

    return token


def check_env_file_permissions(env_file: Path) -> str | None:
    """Warns when the secrets file is readable by group or others."""

    if not env_file.exists():
        return None

    if os.name == "nt":  # pragma: no cover - development on Windows
        return None

    mode = stat.S_IMODE(env_file.stat().st_mode)

    if mode & 0o077:
        return (
            f"{env_file} has permissions {mode:04o}; expected 0600 so that the "
            "publisher token is not readable by other accounts."
        )

    return None


def _bounded(value: int, where: str, low: int, high: int) -> int:
    if not low <= value <= high:
        raise ConfigError(f"{where}: must be between {low} and {high}, got {value}")

    return value


def _parse_sources(raw: dict) -> tuple[SourceConfig, ...]:
    """Validates the ``sources`` array of the configuration file."""

    sources_raw = raw.get("sources")

    if not isinstance(sources_raw, list) or not sources_raw:
        raise ConfigError("settings.sources: must be a non-empty array")

    sources: list[SourceConfig] = []
    seen_keys: set[str] = set()

    for index, entry in enumerate(sources_raw):
        where = f"settings.sources[{index}]"

        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: must be an object")

        key = _require(entry, "key", str, where)

        if not key.replace("_", "").replace("-", "").isalnum():
            raise ConfigError(
                f"{where}.key: must be alphanumeric, underscore or dash, got '{key}'"
            )

        if key in seen_keys:
            raise ConfigError(f"{where}.key: duplicate source key '{key}'")

        seen_keys.add(key)

        sources.append(
            SourceConfig(
                key=key,
                name=_require(entry, "name", str, where),
                source_type=_require(entry, "source_type", str, where),
                url=_require_https(
                    _require(entry, "url", str, where), f"{where}.url"
                ),
                feed_url=_require_https(
                    _require(entry, "feed_url", str, where), f"{where}.feed_url"
                ),
                provider=_require(entry, "provider", str, where),
                reliability=_require(entry, "reliability", str, where),
                enabled=_require(entry, "enabled", bool, where),
                required=_require(entry, "required", bool, where),
                timeout_seconds=_positive(
                    float(_require(entry, "timeout_seconds", float, where)),
                    f"{where}.timeout_seconds",
                ),
            )
        )

    if not any(source.enabled for source in sources):
        raise ConfigError("settings.sources: at least one source must be enabled")

    return tuple(sources)

    if not low <= value <= high:
        raise ConfigError(f"{where}: must be between {low} and {high}, got {value}")

    return value


def load_settings(
    config_path: Path | None = None,
    *,
    env_file: Path | None = None,
    backend_root: Path | None = None,
) -> Settings:
    """Loads and validates ``config/settings.json``."""

    root = backend_root or BACKEND_ROOT

    path = Path(
        config_path
        or os.environ.get("THREATPULSE_CONFIG")
        or (root / "config" / "settings.json")
    )

    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ConfigError(f"{path}: invalid JSON: {error}") from error

    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: root must be a JSON object")

    schema_version = _require(raw, "schema_version", str, "settings")

    if schema_version != "1.0":
        raise ConfigError(
            f"settings.schema_version: unsupported value '{schema_version}'"
        )

    directories = raw.get("directories") or {}

    if not isinstance(directories, dict):
        raise ConfigError("settings.directories: must be an object")

    http_raw = raw.get("http") or {}

    if not isinstance(http_raw, dict):
        raise ConfigError("settings.http: must be an object")

    http = HttpConfig(
        connect_timeout_seconds=_positive(
            float(_require(http_raw, "connect_timeout_seconds", float, "http")),
            "http.connect_timeout_seconds",
        ),
        read_timeout_seconds=_positive(
            float(_require(http_raw, "read_timeout_seconds", float, "http")),
            "http.read_timeout_seconds",
        ),
        max_attempts=_bounded(
            int(_require(http_raw, "max_attempts", int, "http")),
            "http.max_attempts",
            1,
            10,
        ),
        backoff_seconds=_positive(
            float(_require(http_raw, "backoff_seconds", float, "http")),
            "http.backoff_seconds",
        ),
        backoff_multiplier=_positive(
            float(_require(http_raw, "backoff_multiplier", float, "http")),
            "http.backoff_multiplier",
        ),
        user_agent=_require(http_raw, "user_agent", str, "http"),
    )

    publisher_raw = raw.get("publisher") or {}

    if not isinstance(publisher_raw, dict):
        raise ConfigError("settings.publisher: must be an object")

    publisher = PublisherConfig(
        endpoint=_require_https(
            _require(publisher_raw, "endpoint", str, "publisher"),
            "publisher.endpoint",
        ),
        timeout_seconds=_positive(
            float(_require(publisher_raw, "timeout_seconds", float, "publisher")),
            "publisher.timeout_seconds",
        ),
        max_attempts=_bounded(
            int(_require(publisher_raw, "max_attempts", int, "publisher")),
            "publisher.max_attempts",
            1,
            10,
        ),
        backoff_seconds=_positive(
            float(_require(publisher_raw, "backoff_seconds", float, "publisher")),
            "publisher.backoff_seconds",
        ),
        verify_tls=_require(publisher_raw, "verify_tls", bool, "publisher"),
    )

    publication_raw = raw.get("publication") or {}

    if not isinstance(publication_raw, dict):
        raise ConfigError("settings.publication: must be an object")

    drop_ratio = float(
        _require(publication_raw, "maximum_drop_ratio", float, "publication")
    )

    if not 0.0 <= drop_ratio < 1.0:
        raise ConfigError(
            "publication.maximum_drop_ratio: must be >= 0 and < 1, "
            f"got {drop_ratio}"
        )

    publication = PublicationConfig(
        minimum_threats=int(
            _require(publication_raw, "minimum_threats", int, "publication")
        ),
        maximum_drop_ratio=drop_ratio,
        max_summary_items=_bounded(
            int(_require(publication_raw, "max_summary_items", int, "publication")),
            "publication.max_summary_items",
            1,
            100,
        ),
        max_payload_bytes=_bounded(
            int(
                publication_raw.get(
                    "max_payload_bytes", DEFAULT_MAX_PAYLOAD_BYTES
                )
            ),
            "publication.max_payload_bytes",
            0,
            512 * 1024 * 1024,
        ),
    )

    sources = _apply_source_extras(_parse_sources(raw), raw)

    return Settings(
        schema_version=schema_version,
        scoring_model=_require(raw, "scoring_model", str, "settings"),
        environment=str(raw.get("environment", "production")),
        state_directory=root / str(directories.get("state", "state")),
        data_directory=root / str(directories.get("data", "data")),
        log_directory=root / str(directories.get("logs", "logs")),
        config_directory=root / str(directories.get("config", "config")),
        http=http,
        publisher=publisher,
        publication=publication,
        sources=sources,
        env_file=Path(
            env_file or os.environ.get("THREATPULSE_ENV_FILE", DEFAULT_ENV_FILE)
        ),
    )


def _apply_source_extras(
    sources: tuple[SourceConfig, ...], raw: dict
) -> tuple[SourceConfig, ...]:
    """Applies the optional per-source fields the feed collectors need.

    ``feeds`` lets one source key cover several feeds — the European national
    CERT feeds are one source with many feeds, not twenty sources. ``tier``
    records the agreed source tier so the attribution page can state which tiers
    ThreatPulse actually uses.

    Both are optional, so an existing configuration keeps loading unchanged.
    """

    entries = raw.get("sources")

    if not isinstance(entries, list):
        return sources

    by_key: dict[str, dict] = {}

    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("key"), str):
            by_key[entry["key"]] = entry

    updated: list[SourceConfig] = []

    for source in sources:
        entry = by_key.get(source.key) or {}
        where = f"sources[{source.key}]"

        feeds_raw = entry.get("feeds")
        feeds: tuple[str, ...] = ()

        if feeds_raw is not None:
            if not isinstance(feeds_raw, list) or not feeds_raw:
                raise ConfigError(f"{where}.feeds: must be a non-empty array")

            feeds = tuple(
                _require_https(str(item), f"{where}.feeds") for item in feeds_raw
            )

        tier_raw = entry.get("tier", 0)

        if not isinstance(tier_raw, int) or isinstance(tier_raw, bool):
            raise ConfigError(f"{where}.tier: expected an integer")

        updated.append(replace(source, feeds=feeds, tier=tier_raw))

    return tuple(updated)


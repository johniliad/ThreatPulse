"""The ThreatPulse intelligence model.

The pipeline is object-based, never parallel arrays joined by ``zip()``. The
model distinguishes five levels, because they answer different questions:

* :class:`Source` — where a signal came from (a feed we trust to some degree).
* :class:`Observation` — one raw record as retrieved, with retrieval metadata.
* :class:`Entity` — a normalized thing the signal is about (CVE, vendor/product,
  URL, IP, domain, malware family, software, actor, technique).
* :class:`Evidence` — a provenance-carrying statement linking an observation to
  an entity, with a relationship and a confidence.
* :class:`Threat` — the aggregated intelligence object. **Not** a raw feed
  record: one CVE may contribute to several threats, and one threat may rest on
  evidence from several sources.

Every object can be serialised to the public publication schema 1.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Source:
    key: str
    name: str
    source_type: str
    url: str
    provider: str
    reliability: str

    def to_publication_dict(self) -> dict:
        return {
            "source_key": self.key,
            "name": self.name,
            "source_type": self.source_type,
            "url": self.url,
            "provider": self.provider,
            "reliability": self.reliability,
        }


@dataclass(frozen=True)
class Entity:
    """A normalized subject of intelligence."""

    kind: str
    value: str
    normalized: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "normalized": self.normalized}


@dataclass
class Observation:
    """One record as retrieved from a source, before interpretation."""

    source_key: str
    external_id: str
    observed_at: str
    retrieved_at: str
    source_record_id: str
    payload: dict[str, Any]
    entities: list[Entity] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source_key": self.source_key,
            "external_id": self.external_id,
            "observed_at": self.observed_at,
            "retrieved_at": self.retrieved_at,
            "source_record_id": self.source_record_id,
            "entities": [entity.to_dict() for entity in self.entities],
            "payload": self.payload,
        }


@dataclass(frozen=True)
class Evidence:
    """A provenance-carrying statement supporting a threat assessment."""

    source_key: str
    source_record_id: str
    observed_at: str
    relationship: str
    statement: str
    confidence: float = 1.0
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source_key": self.source_key,
            "source_record_id": self.source_record_id,
            "observed_at": self.observed_at,
            "relationship": self.relationship,
            "statement": self.statement,
            "confidence": round(self.confidence, 4),
            "attributes": self.attributes,
        }


@dataclass
class Vulnerability:
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str = "unknown"
    kev_listed: bool = False
    exploited_in_wild: bool = False
    published_at: str | None = None
    modified_at: str | None = None
    vendor: str | None = None
    product: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_publication_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "kev_listed": self.kev_listed,
            "exploited_in_wild": self.exploited_in_wild,
            "published_at": self.published_at,
            "modified_at": self.modified_at,
            "vendor": self.vendor,
            "product": self.product,
            "metadata": self.metadata or {},
        }


@dataclass
class Threat:
    """An aggregated intelligence object, ready for publication."""

    threat_uuid: str
    external_id: str | None
    title: str
    threat_type: str
    severity: str
    priority_score: float
    confidence_score: float
    confidence_level: str
    exploitation_status: str
    first_seen: str | None
    last_seen: str | None
    summary: str | None
    recommended_action: str | None
    metadata: dict[str, Any] = field(default_factory=dict)
    source_keys: list[str] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def to_publication_dict(self) -> dict:
        return {
            "threat_uuid": self.threat_uuid,
            "external_id": self.external_id,
            "title": self.title,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "priority_score": round(self.priority_score, 2),
            "confidence_score": round(self.confidence_score, 2),
            "confidence_level": self.confidence_level,
            "exploitation_status": self.exploitation_status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "summary": self.summary,
            "recommended_action": self.recommended_action,
            "metadata": self.metadata,
            "source_keys": list(self.source_keys),
            "vulnerabilities": [
                vulnerability.to_publication_dict()
                for vulnerability in self.vulnerabilities
            ],
        }

    def identity_key(self) -> str:
        """The stable key used for reconciliation between runs."""

        return (self.external_id or self.threat_uuid).upper()


@dataclass
class Publication:
    """A complete snapshot, ready to POST to ``publish.php``."""

    publication_uuid: str
    schema_version: str
    generated_at: str
    summary: dict[str, Any]
    sources: list[Source]
    threats: list[Threat]

    def to_publication_dict(self) -> dict:
        return {
            "publication_uuid": self.publication_uuid,
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "summary": self.summary,
            "sources": [source.to_publication_dict() for source in self.sources],
            "threats": [threat.to_publication_dict() for threat in self.threats],
        }

    def counts(self) -> dict[str, int]:
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        vulnerabilities = 0

        for threat in self.threats:
            if threat.severity in severities:
                severities[threat.severity] += 1

            vulnerabilities += len(threat.vulnerabilities)

        return {
            "threats": len(self.threats),
            "vulnerabilities": vulnerabilities,
            **severities,
        }


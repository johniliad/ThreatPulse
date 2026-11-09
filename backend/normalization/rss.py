"""RSS/Atom feed normalisation.

Feed content is untrusted input. Two classes of risk are handled explicitly:

* **XML attacks.** Standard-library ``xml.etree`` does not resolve external
  entities, but a hostile document can still attempt entity expansion
  ("billion laughs") through an internal DTD. DOCTYPE and ENTITY declarations
  are therefore stripped, and an absolute size cap is applied, before parsing.
* **Content abuse.** Every text field is sanitised and length-bounded, and any
  TLP marking found in the item is surfaced so the TLP gate can reject it. HTML
  from the feed is reduced to text; ThreatPulse never republishes feed markup.

An item is attributed to the feed it came from, so a national CERT advisory is
attributed to that CERT and never to ThreatPulse.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from lib.tlp import find_markings
from models.intelligence import Entity, Observation
from normalization.cisa import (
    MAX_DESCRIPTION_LENGTH,
    MAX_TITLE_LENGTH,
    NormalizationError,
    extract_techniques,
    sanitize_text,
)

#: Feeds larger than this are refused outright rather than parsed.
MAX_FEED_BYTES = 8 * 1024 * 1024

#: Items kept per feed, newest first. Advisories are recent-events intelligence.
MAX_ITEMS_PER_FEED = 200

_DOCTYPE_PATTERN = re.compile(rb"<!DOCTYPE[^>[]*(\[[^]]*\])?[^>]*>", re.IGNORECASE | re.DOTALL)
_ENTITY_PATTERN = re.compile(rb"<!ENTITY[^>]*>", re.IGNORECASE)
_TAG_PATTERN = re.compile(r"<[^>]+>")
_CDATA_PATTERN = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.DOTALL)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Element names used by both RSS 2.0 and Atom, without namespace prefixes.
_TITLE_TAGS = ("title",)
_SUMMARY_TAGS = ("description", "summary", "content", "encoded")
_DATE_TAGS = ("pubDate", "published", "updated", "date")
_LINK_TAGS = ("link", "guid", "id")
_CATEGORY_TAGS = ("category",)


def _local_name(tag: str) -> str:
    """Strips an XML namespace, if present."""

    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def strip_dangerous_xml(body: bytes) -> bytes:
    """Removes DOCTYPE and ENTITY declarations before parsing."""

    cleaned = _DOCTYPE_PATTERN.sub(b"", body)

    return _ENTITY_PATTERN.sub(b"", cleaned)


def html_to_text(value: Any) -> str | None:
    """Reduces feed HTML to plain text."""

    if value is None:
        return None

    text = str(value)

    match = _CDATA_PATTERN.search(text)

    if match:
        text = match.group(1)

    text = _TAG_PATTERN.sub(" ", text)

    for entity, replacement in (
        ("&nbsp;", " "),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", '"'),
        ("&#39;", "'"),
    ):
        text = text.replace(entity, replacement)

    return sanitize_text(text, max_length=MAX_DESCRIPTION_LENGTH)


def parse_feed_timestamp(value: Any) -> str | None:
    """Parses the common feed date formats into ``YYYY-MM-DDTHH:MM:SSZ``."""

    text = sanitize_text(value, max_length=64)

    if not text:
        return None

    candidates = (
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    )

    for fmt in candidates:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return None


@dataclass
class FeedItem:
    """One advisory or news item from an RSS 2.0 or Atom feed."""

    external_id: str
    title: str | None
    summary: str | None
    link: str | None
    published_at: str | None
    categories: list[str] = field(default_factory=list)
    tlp_markings: set[str] = field(default_factory=set)

    def to_payload(self, *, source_key: str, feed_url: str) -> dict:
        return {
            "title": self.title,
            "summary": self.summary,
            "link": self.link,
            "published_at": self.published_at,
            "categories": list(self.categories),
            "feed_url": feed_url,
            "source": source_key,
        }


def _first_text(element: ElementTree.Element, tags: tuple[str, ...]) -> str | None:
    """First matching child's text, namespace-insensitive."""

    for child in element:
        if _local_name(child.tag) in tags:
            text = child.text or (child.get("href") if child.tag else None)

            if text:
                return text

    return None


def _collect_texts(element: ElementTree.Element, tags: tuple[str, ...]) -> list[str]:
    values: list[str] = []

    for child in element:
        if _local_name(child.tag) in tags and child.text:
            values.append(child.text)

    return values


def parse_feed(body: bytes) -> list[FeedItem]:
    """Parses an RSS 2.0 or Atom document into items.

    Raises :class:`NormalizationError` when the document cannot be trusted.
    """

    if not isinstance(body, (bytes, bytearray)):
        raise NormalizationError("feed body is not bytes")

    if len(body) > MAX_FEED_BYTES:
        raise NormalizationError(
            f"feed exceeds the {MAX_FEED_BYTES} byte limit ({len(body)} bytes)"
        )

    try:
        root = ElementTree.fromstring(strip_dangerous_xml(bytes(body)))
    except ElementTree.ParseError as error:
        raise NormalizationError(f"feed is not well-formed XML: {error}") from error

    items: list[FeedItem] = []

    for element in root.iter():
        if _local_name(element.tag) not in ("item", "entry"):
            continue

        title = sanitize_text(
            html_to_text(_first_text(element, _TITLE_TAGS)), max_length=MAX_TITLE_LENGTH
        )

        summary = html_to_text(_first_text(element, _SUMMARY_TAGS))

        link = sanitize_text(_first_text(element, _LINK_TAGS), max_length=2000)

        published_at = parse_feed_timestamp(_first_text(element, _DATE_TAGS))

        categories = sorted(
            {
                text.strip()
                for text in (
                    sanitize_text(value, max_length=100)
                    for value in _collect_texts(element, _CATEGORY_TAGS)
                )
                if text
            }
        )

        if title is None and summary is None and link is None:
            continue

        external_id = sanitize_text(link, max_length=500) or (
            sanitize_text(title, max_length=200) or ""
        )

        if not external_id:
            continue

        items.append(
            FeedItem(
                external_id=external_id,
                title=title,
                summary=summary,
                link=link,
                published_at=published_at,
                categories=categories,
                tlp_markings=find_markings(title, summary, " ".join(categories)),
            )
        )

        if len(items) >= MAX_ITEMS_PER_FEED:
            break

    return items


def extract_cve_ids(*texts: str | None) -> list[str]:
    """Every well-formed CVE identifier mentioned, deduplicated and sorted."""

    found: set[str] = set()

    for text in texts:
        if not isinstance(text, str):
            continue

        for match in CVE_PATTERN.finditer(text):
            found.add(match.group(0).upper())

    return sorted(found)


def build_observation(
    item: FeedItem,
    *,
    source_key: str,
    retrieved_at: str,
    feed_url: str,
) -> Observation:
    """Turns a feed item into a provenance-carrying observation."""

    entities = [
        Entity(kind="cve", value=cve, normalized=cve)
        for cve in extract_cve_ids(item.title, item.summary)
    ]

    entities += [
        Entity(kind="technique", value=technique, normalized=technique)
        for technique in extract_techniques(item.title, item.summary)
    ]

    return Observation(
        source_key=source_key,
        external_id=item.external_id,
        observed_at=item.published_at or retrieved_at,
        retrieved_at=retrieved_at,
        source_record_id=item.external_id,
        payload=item.to_payload(source_key=source_key, feed_url=feed_url),
        entities=entities,
    )


"""EPSS (Exploit Prediction Scoring System) normalisation.

EPSS answers a question the CISA KEV catalogue cannot: *how likely* is this
vulnerability to be exploited in the next 30 days? It is deliberately kept as a
**separate scoring dimension**. It never overrides exploitation evidence, so a
high EPSS score cannot promote a vulnerability that is not known to be exploited
in the wild, and a low EPSS score cannot demote one that is.

The feed is an *enrichment* source: it is queried with the CVE identifiers the
pipeline already knows about, not fetched wholesale.
"""

from __future__ import annotations

from dataclasses import dataclass

from lib.ids import CVE_PATTERN
from models.intelligence import Entity, Observation
from normalization.cisa import NormalizationError, sanitize_text

#: The EPSS API returns at most 100 rows per request.
MAX_BATCH_SIZE = 100

#: Bounds a single score. EPSS is a probability in [0, 1].
MIN_SCORE = 0.0
MAX_SCORE = 1.0


@dataclass(frozen=True)
class EpssRecord:
    """One validated EPSS score."""

    cve_id: str
    epss: float
    percentile: float
    score_date: str | None

    def to_payload(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "epss": round(self.epss, 8),
            "percentile": round(self.percentile, 8),
            "score_date": self.score_date,
            "source": "epss_first",
        }


def _probability(value: object, *, field: str) -> float | None:
    """EPSS returns numbers as strings; anything outside [0, 1] is rejected."""

    if value is None or isinstance(value, bool):
        return None

    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None

    if number != number:  # NaN
        return None

    if not MIN_SCORE <= number <= MAX_SCORE:
        return None

    return number


def parse_epss_payload(payload: object) -> tuple[list[EpssRecord], list[str]]:
    """Validates an EPSS response.

    Returns ``(records, rejections)``. A structurally invalid response raises
    :class:`NormalizationError` — the feed cannot be trusted at all. Individual
    malformed rows are rejected with a reason instead, so one bad row cannot
    discard a whole batch.
    """

    if not isinstance(payload, dict):
        raise NormalizationError("EPSS response is not an object")

    rows = payload.get("data")

    if not isinstance(rows, list):
        raise NormalizationError("EPSS response has no 'data' array")

    records: list[EpssRecord] = []
    rejections: list[str] = []

    for index, row in enumerate(rows):
        where = f"data[{index}]"

        if not isinstance(row, dict):
            rejections.append(f"{where}: not an object")
            continue

        raw_cve = row.get("cve")

        if not isinstance(raw_cve, str):
            rejections.append(f"{where}: missing cve")
            continue

        cve_id = raw_cve.strip().upper()

        if not CVE_PATTERN.match(cve_id):
            rejections.append(f"{where}: invalid CVE identifier {raw_cve!r}")
            continue

        epss = _probability(row.get("epss"), field="epss")
        percentile = _probability(row.get("percentile"), field="percentile")

        if epss is None:
            rejections.append(f"{where}: invalid epss value {row.get('epss')!r}")
            continue

        if percentile is None:
            rejections.append(
                f"{where}: invalid percentile value {row.get('percentile')!r}"
            )
            continue

        records.append(
            EpssRecord(
                cve_id=cve_id,
                epss=epss,
                percentile=percentile,
                score_date=sanitize_text(row.get("date"), max_length=10),
            )
        )

    return records, rejections


def build_epss_observation(
    record: EpssRecord, *, source_key: str, retrieved_at: str
) -> Observation:
    """Turns an EPSS score into a provenance-carrying observation."""

    return Observation(
        source_key=source_key,
        external_id=record.cve_id,
        observed_at=record.score_date or retrieved_at,
        retrieved_at=retrieved_at,
        source_record_id=record.cve_id,
        payload=record.to_payload(),
        entities=[Entity(kind="cve", value=record.cve_id, normalized=record.cve_id)],
    )

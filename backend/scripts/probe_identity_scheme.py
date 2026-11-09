"""Development probe: recover the existing threat_uuid derivation scheme.

Fetches real (CVE -> threat_uuid) pairs from the public ThreatPulse API and
tries a large space of plausible deterministic derivations, so that the new
backend can generate IDs that match the ones already stored.

This is a development aid; it is not part of the pipeline runtime.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import sys
import urllib.request
import uuid

API = "https://threatpulse.iliadis.net/api/cti/v1/threats.php?limit=8"

PREFIXES = [
    "",
    "threatpulse",
    "ThreatPulse",
    "THREATPULSE",
    "threatpulse_",
    "threatpulse-",
    "threatpulse:",
    "tp",
    "tp:",
    "kev",
    "cisa",
    "cisa_kev",
    "CISA",
    "cisa-kev",
    "threat",
]

SEPARATORS = ["", ":", "|", "/", "-", "_", " ", "#", "."]

NAMESPACE_BYTES = {
    "nil": uuid.UUID(int=0).bytes,
    "dns": uuid.NAMESPACE_DNS.bytes,
    "url": uuid.NAMESPACE_URL.bytes,
    "oid": uuid.NAMESPACE_OID.bytes,
    "x500": uuid.NAMESPACE_X500.bytes,
    "threatpulse_md5": hashlib.md5(b"threatpulse").digest(),
    "threatpulse_sha1": hashlib.sha1(b"threatpulse").digest()[:16],
}


def hashes() -> dict:
    return {
        "md5": lambda b: hashlib.md5(b).hexdigest(),
        "sha1_32": lambda b: hashlib.sha1(b).hexdigest()[:32],
        "sha256_32": lambda b: hashlib.sha256(b).hexdigest()[:32],
        "sha512_32": lambda b: hashlib.sha512(b).hexdigest()[:32],
        "blake2b16": lambda b: hashlib.blake2b(b, digest_size=16).hexdigest(),
        "blake2s16": lambda b: hashlib.blake2s(b, digest_size=16).hexdigest(),
        "sha3_256_32": lambda b: hashlib.sha3_256(b).hexdigest()[:32],
    }


def as_uuid_text(hex32: str) -> str:
    return (
        f"{hex32[0:8]}-{hex32[8:12]}-{hex32[12:16]}-"
        f"{hex32[16:20]}-{hex32[20:32]}"
    )


def fetch_records() -> list:
    with urllib.request.urlopen(API, timeout=30) as response:
        payload = json.load(response)

    records = []

    for threat in payload["data"]["threats"]:
        metadata = threat.get("metadata") or {}
        attribution = metadata.get("source_attribution") or {}

        records.append(
            {
                "cve": threat.get("external_id") or "",
                "uuid": (threat.get("threat_uuid") or "").lower(),
                "vendor": metadata.get("vendor") or "",
                "product": metadata.get("product") or "",
                "title": threat.get("title") or "",
                "summary": threat.get("summary") or "",
                "due_date": metadata.get("due_date") or "",
                "source_key": attribution.get("source_key") or "",
                "source_name": attribution.get("source_name") or "",
            }
        )

    return [record for record in records if record["cve"] and record["uuid"]]


def build_candidates(record: dict) -> dict:
    cve = record["cve"]
    vendor = record["vendor"]
    product = record["product"]
    title = record["title"]

    fields = {
        "cve": cve,
        "cve_lower": cve.lower(),
        "vendor": vendor,
        "product": product,
        "title": title,
        "source_key": record["source_key"],
        "source_name": record["source_name"],
        "nvd": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "kev_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "due_date": record["due_date"],
    }

    out = {}

    for name, value in fields.items():
        if value:
            out[f"field:{name}"] = value

    for prefix, separator in itertools.product(PREFIXES, SEPARATORS):
        for name in ("cve", "cve_lower"):
            out[f"pre[{prefix}]+sep[{separator}]+{name}"] = (
                f"{prefix}{separator}{fields[name]}"
            )

    for name in ("vendor", "product", "title", "source_key", "source_name"):
        if not fields[name]:
            continue

        for separator in SEPARATORS:
            out[f"cve+sep[{separator}]+{name}"] = f"{cve}{separator}{fields[name]}"
            out[f"{name}+sep[{separator}]+cve"] = f"{fields[name]}{separator}{cve}"

    for sep1, sep2 in itertools.product(SEPARATORS, SEPARATORS):
        out[f"vendor{sep1}product{sep2}cve"] = f"{vendor}{sep1}{product}{sep2}{cve}"
        out[f"cve{sep1}vendor{sep2}product"] = f"{cve}{sep1}{vendor}{sep2}{product}"
        out[f"cve{sep1}title{sep2}source"] = (
            f"{cve}{sep1}{title}{sep2}{record['source_key']}"
        )
        out[f"source{sep1}cve{sep2}vendor{sep1}product"] = (
            f"{record['source_key']}{sep1}{cve}{sep2}{vendor}{sep1}{product}"
        )

    out["json:cve"] = json.dumps({"cve": cve}, sort_keys=True)
    out["json:external_id"] = json.dumps(
        {"external_id": cve}, sort_keys=True, separators=(",", ":")
    )

    return {name: value.encode("utf-8") for name, value in out.items()}


def main() -> int:
    records = fetch_records()

    if not records:
        print("no records fetched")
        return 1

    print(f"sampled {len(records)} records")
    for record in records:
        print(f"  {record['cve']} -> {record['uuid']}")

    hash_functions = hashes()
    candidates = {record["uuid"]: build_candidates(record) for record in records}
    names = list(next(iter(candidates.values())).keys())

    matches = []

    for name in names:
        for hash_name, hash_function in hash_functions.items():
            if all(
                as_uuid_text(hash_function(candidates[record["uuid"]][name]))
                == record["uuid"]
                for record in records
            ):
                matches.append(f"{hash_name}({name})")

        for namespace_name, namespace in NAMESPACE_BYTES.items():
            for hash_name, hash_function in hash_functions.items():
                if all(
                    as_uuid_text(
                        hash_function(
                            namespace + candidates[record["uuid"]][name]
                        )
                    )
                    == record["uuid"]
                    for record in records
                ):
                    matches.append(f"{hash_name}(ns:{namespace_name}+{name})")

    if matches:
        print("MATCHES:")
        for match in matches:
            print(f"  {match}")
    else:
        print(f"no match found in the searched space ({len(names)} inputs)")

    return 0


if __name__ == "__main__":
    sys.exit(main())

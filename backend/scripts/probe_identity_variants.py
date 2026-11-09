"""Development probe 2: structural variants of the threat_uuid derivation.

Probe 1 searched plain digests of concatenated strings. This one additionally
varies how the digest bytes are turned into a UUID string (little-endian field
order, reversed bytes, trailing digest bytes) and how the input string is
terminated, because the observed IDs carry non-standard version/variant nibbles
and could therefore come from any raw digest.
"""

from __future__ import annotations

import hashlib
import itertools
import uuid

RECORDS = [
    ("CVE-2026-109619", "394720a7-b42e-cc69-c522-0c68b5d75567", "PHP Group", "PHP", "PHP Stale Internal Request-State Vulnerability", "cisa_kev"),
    ("CVE-2026-109618", "3b1bb43f-d68c-5865-5230-923d12c35c18", "PHP Group", "PHP", "PHP Memory Corruption Vulnerability", "cisa_kev"),
    ("CVE-2026-97229", "03d6df8f-7cb5-899e-5817-31e2c78af383", "GitLab", "Community Edition and Enterprise Edition", "GitLab Community Edition and Enterprise Edition Integer Overflow or Wraparound Vulnerability", "cisa_kev"),
    ("CVE-2026-110447", "91ceb4af-38c1-4d97-bd06-7189f72b7043", "Collabora", "Collabora Online - Built-in CODE Server", "Collabora Online - Built-in CODE Server OS Command Injection Vulnerability", "cisa_kev"),
    ("CVE-2026-102764", "82b27738-ed95-128b-1f8d-9d9d7fb4d64c", "BeyondTrust", "Remote Support", "BeyondTrust Remote Support Authentication Bypass by Spoofing Vulnerability", "cisa_kev"),
    ("CVE-2026-102489", "cb54e792-edb3-17bb-6876-9344359989f1", "Zammad GmbH", "Zammad", "Zammad GmbH Zammad Session Fixation Vulnerability", "cisa_kev"),
    ("CVE-2021-3199", "c6bec5ff-37c6-b9c1-ff1c-a16f28333174", "Apache", "OFBiz", "Apache OFBiz", "cisa_kev"),
    ("CVE-2023-22894", "2d33a473-8e0f-40b2-efc4-2090f22aa51a", "Zoho", "ManageEngine", "Zoho ManageEngine", "cisa_kev"),
]

PREFIXES = ["", "threatpulse", "ThreatPulse", "tp", "kev", "cisa", "cisa_kev", "CISA", "threat", "cti"]
SEPARATORS = ["", ":", "|", "/", "-", "_", " ", "#"]
SUFFIXES = ["", "\n", "\r\n", " ", "\t"]


def digests():
    return {
        "md5": lambda b: hashlib.md5(b).digest(),
        "sha1": lambda b: hashlib.sha1(b).digest(),
        "sha256": lambda b: hashlib.sha256(b).digest(),
        "sha512": lambda b: hashlib.sha512(b).digest(),
        "blake2b": lambda b: hashlib.blake2b(b, digest_size=16).digest(),
        "blake2s": lambda b: hashlib.blake2s(b, digest_size=16).digest(),
        "sha3": lambda b: hashlib.sha3_256(b).digest(),
    }


def transforms():
    return {
        "hex16": lambda d: d[:16].hex(),
        "hex16_le": lambda d: uuid.UUID(bytes_le=d[:16]).hex,
        "hex_reversed": lambda d: d[:16][::-1].hex(),
        "hex32": lambda d: d.hex()[:32],
        "hex32_tail": lambda d: d.hex()[-32:],
    }


def as_uuid_text(hex32: str) -> str:
    return f"{hex32[0:8]}-{hex32[8:12]}-{hex32[12:16]}-{hex32[16:20]}-{hex32[20:32]}"


def inputs(record) -> dict:
    cve, _, vendor, product, title, source = record

    out = {}

    for prefix, separator, suffix in itertools.product(PREFIXES, SEPARATORS, SUFFIXES):
        out[f"pre[{prefix}]sep[{separator}]cve{repr(suffix)}"] = (
            f"{prefix}{separator}{cve}{suffix}"
        )
        out[f"pre[{prefix}]sep[{separator}]cve_lower{repr(suffix)}"] = (
            f"{prefix}{separator}{cve.lower()}{suffix}"
        )

    for separator, suffix in itertools.product(SEPARATORS, SUFFIXES):
        out[f"cve{separator}vendor{suffix}"] = f"{cve}{separator}{vendor}{suffix}"
        out[f"cve{separator}product{suffix}"] = f"{cve}{separator}{product}{suffix}"
        out[f"cve{separator}vendor{separator}product{suffix}"] = (
            f"{cve}{separator}{vendor}{separator}{product}{suffix}"
        )
        out[f"vendor{separator}product{separator}cve{suffix}"] = (
            f"{vendor}{separator}{product}{separator}{cve}{suffix}"
        )
        out[f"source{separator}cve{suffix}"] = f"{source}{separator}{cve}{suffix}"
        out[f"cve{separator}title{suffix}"] = f"{cve}{separator}{title}{suffix}"

    return {name: value.encode("utf-8") for name, value in out.items()}


def main() -> int:
    hash_functions = digests()
    transform_functions = transforms()

    sample = inputs(RECORDS[0])
    print(f"sampled {len(RECORDS)} records; {len(sample)} input shapes each")

    matches = []

    for name in sample:
        for hash_name, hash_function in hash_functions.items():
            for transform_name, transform in transform_functions.items():
                if all(
                    as_uuid_text(transform(hash_function(inputs(record)[name])))
                    == record[1]
                    for record in RECORDS
                ):
                    matches.append(f"{hash_name}/{transform_name}({name})")

    if matches:
        print("MATCHES:")
        for match in matches:
            print(f"  {match}")
    else:
        print("no match found")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

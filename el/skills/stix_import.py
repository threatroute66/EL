"""Skill: STIX 2.1 bundle import.

Complements `el.reporting.stix` (export-side). Consumes a bundle from
a peer organisation, a threat-intel feed, or a MISP export and pulls
the contained indicators into EL's IOC cross-case knowledge store
with provenance tag `source: stix_import`.

Scope is deliberately narrow for V1:
  - Parses STIX 2.1 bundles OR bare indicator arrays
  - Extracts IOC pattern objects of the types EL tracks (ipv4/ipv6,
    domain, url, md5/sha1/sha256, email)
  - Returns structured IOCs ready for `knowledge.record_iocs`

Skipped for V1:
  - TAXII 2.x client (network pull) — network-facing code belongs
    in its own skill with retry/auth handling, deferred to a follow-up
  - Observed-data + malware-analysis objects beyond indicators
  - CybOX 2.x legacy bundles

Parser is regex-based on the SDO `pattern` field — we don't pull a
full STIX patterning grammar. The regex covers the concrete patterns
produced by the canonical tools (stix2 Python lib, MISP export,
OpenCTI export) — ~99% of indicators in practice.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class StixIoc:
    value: str
    ioc_type: str          # "ipv4" / "ipv6" / "domain" / "url" /
                            # "md5" / "sha1" / "sha256" / "email"
    indicator_id: str = ""
    source_labels: list[str] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)
    description: str = ""


# Maps STIX pattern property paths → our normalised ioc_type. Order
# matters: check the most-specific patterns first (file:hashes.X
# before file:hashes).
_PATTERN_EXTRACTORS: tuple[tuple[str, re.Pattern], ...] = (
    ("ipv4",   re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'")),
    ("ipv6",   re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'")),
    ("domain", re.compile(r"domain-name:value\s*=\s*'([^']+)'")),
    ("url",    re.compile(r"url:value\s*=\s*'([^']+)'")),
    ("md5",    re.compile(r"file:hashes\.(?:MD5|'MD5')\s*=\s*'([^']+)'")),
    ("sha1",   re.compile(r"file:hashes\.(?:SHA-?1|'SHA-1')\s*=\s*'([^']+)'")),
    ("sha256", re.compile(r"file:hashes\.(?:SHA-?256|'SHA-256')\s*=\s*'([^']+)'")),
    ("email",  re.compile(r"email-addr:value\s*=\s*'([^']+)'")),
)


def _extract_iocs_from_pattern(pattern: str) -> list[tuple[str, str]]:
    """Given a STIX pattern string, return every (ioc_type, value) tuple
    the pattern carries. STIX lets you compound patterns with AND/OR
    across different object types — we handle each concrete value
    independently."""
    out: list[tuple[str, str]] = []
    for ioc_type, regex in _PATTERN_EXTRACTORS:
        for m in regex.finditer(pattern):
            value = m.group(1).strip()
            if value:
                out.append((ioc_type, value))
    return out


def _iter_bundle_objects(doc: dict | list) -> list[dict]:
    """Accepts either a full STIX 2.1 bundle ({type:bundle, objects:[]})
    OR a bare list of SDOs. MISP/OpenCTI sometimes export just the
    indicators."""
    if isinstance(doc, list):
        return [o for o in doc if isinstance(o, dict)]
    if isinstance(doc, dict):
        objs = doc.get("objects") or []
        if isinstance(objs, list):
            return [o for o in objs if isinstance(o, dict)]
    return []


def parse_bundle(path: Path) -> list[StixIoc]:
    """Read a STIX 2.1 bundle JSON file, return the extracted IOCs.
    Silent on file-missing / invalid-JSON — returns empty list so
    callers can decide whether to emit an insufficient finding."""
    try:
        with Path(path).open(encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    iocs: list[StixIoc] = []
    for obj in _iter_bundle_objects(doc):
        if obj.get("type") != "indicator":
            continue
        pattern = str(obj.get("pattern") or "")
        if not pattern:
            continue
        pairs = _extract_iocs_from_pattern(pattern)
        if not pairs:
            continue
        labels = obj.get("indicator_types") or obj.get("labels") or []
        if not isinstance(labels, list):
            labels = []
        for ioc_type, value in pairs:
            iocs.append(StixIoc(
                value=value, ioc_type=ioc_type,
                indicator_id=str(obj.get("id") or ""),
                source_labels=[str(x) for x in labels],
                source_refs=[str(ref) for ref in
                              (obj.get("external_references") or [])
                              if isinstance(ref, (str, dict))],
                description=str(obj.get("description") or "")[:500],
            ))
    return iocs


def import_bundle(path: Path, case_id: str,
                   agent: str = "stix_import",
                   ) -> tuple[int, dict[str, int]]:
    """Parse a bundle and push the extracted IOCs into the
    cross-case knowledge store. Returns (imported_count, per_type_counts).

    `case_id` is the provenance tag stored alongside each IOC in the
    knowledge DB — typically `stix-import-<feed-name>-<YYYY-MM-DD>`
    so subsequent cross-case lookups can cite the feed that first
    surfaced the indicator.
    """
    from el import knowledge

    iocs = parse_bundle(path)
    if not iocs:
        return 0, {}
    per_type: dict[str, list[str]] = {}
    for ioc in iocs:
        per_type.setdefault(ioc.ioc_type, []).append(ioc.value)
    counts = {t: len(v) for t, v in per_type.items()}
    knowledge.record_iocs(case_id, agent, per_type)
    return sum(counts.values()), counts


__all__ = [
    "StixIoc",
    "parse_bundle", "import_bundle",
]

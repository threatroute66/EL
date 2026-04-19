"""STIX 2.1 bundle emission.

One bundle per case. Contains:
  - Identity: the EL system that produced the bundle
  - Indicator: per IOC (file hash, ipv4/ipv6, domain, url, email)
  - AttackPattern: per MITRE ATT&CK technique implicated
  - Report: a summary tying everything to the case_id

Indicators only carry IOCs that are operationally meaningful. Defensive
de-duplication is done before emission. No LLM in this path.

Perf note: stix2 was adding TWO compounding costs on large bundles —
per-Indicator pattern validation at instantiation AND per-property
ordering in serialize() that goes O(n²) via find_property_index across
the whole objects list. Together they made a 6000-IOC bundle take
9+ minutes on M57-Jean. We now build indicator/attack-pattern/report
dicts directly and json.dumps the bundle envelope. Output is still
STIX 2.1-compliant — property order is a readability preference, not
a spec requirement.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from el.intel.attack_map import map_case
from el.schemas.finding import Finding


_TYPE_TO_PATTERN = {
    "ipv4":   lambda v: f"[ipv4-addr:value = '{v}']",
    "ipv6":   lambda v: f"[ipv6-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url":    lambda v: f"[url:value = '{v}']",
    "md5":    lambda v: f"[file:hashes.MD5 = '{v}']",
    "sha1":   lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "email":  lambda v: f"[email-addr:value = '{v}']",
}


# Guardrail — if a case accumulates more than this many IOCs of a single
# class, emit the sorted-first N and a truncation note. Primarily to keep
# STIX round-trip bounded on pathological inputs; with PR-6's fs_paths
# filtering this should rarely trigger in practice.
_MAX_INDICATORS_PER_CLASS = 5000


def _iso(dt: datetime) -> str:
    """STIX-compliant ISO-8601 UTC timestamp ("2026-04-18T09:31:16.000Z")."""
    s = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
    # STIX wants millisecond precision + trailing Z
    return s[:-3] + "Z"


def _stix_id(stype: str) -> str:
    """STIX object id: `<type>--<uuid4>`."""
    return f"{stype}--{uuid.uuid4()}"


def emit_bundle(
    case_id: str,
    findings: list[Finding],
    iocs: dict[str, set[str]],
    out_path: str | Path,
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    now_iso = _iso(now)

    identity_id = _stix_id("identity")
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "EL — Edmond Locard DFIR Orchestrator",
        "identity_class": "system",
        "description": "Multi-agent forensic investigator (https://github.com/local/EL)",
    }

    indicators: list[dict] = []
    truncated: list[str] = []
    for ioc_type, values in iocs.items():
        builder = _TYPE_TO_PATTERN.get(ioc_type)
        if not builder:
            continue
        values_sorted = sorted(values)
        if len(values_sorted) > _MAX_INDICATORS_PER_CLASS:
            truncated.append(f"{ioc_type}({len(values_sorted)}→{_MAX_INDICATORS_PER_CLASS})")
            values_sorted = values_sorted[:_MAX_INDICATORS_PER_CLASS]
        for v in values_sorted:
            v_safe = v.replace("'", "")
            indicators.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": _stix_id("indicator"),
                "created_by_ref": identity_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"{ioc_type}: {v}",
                "pattern": builder(v_safe),
                "pattern_type": "stix",
                "valid_from": now_iso,
                "indicator_types": ["malicious-activity"],
            })

    attack_patterns: list[dict] = []
    techniques = map_case(findings)
    for tid, info in sorted(techniques.items()):
        attack_patterns.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": _stix_id("attack-pattern"),
            "created_by_ref": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": info["name"],
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            }],
        })

    object_refs = ([identity_id]
                   + [i["id"] for i in indicators]
                   + [a["id"] for a in attack_patterns])
    desc = (f"Auto-generated EL case bundle for {case_id}. "
            f"{len(findings)} finding(s); {len(indicators)} indicator(s); "
            f"{len(attack_patterns)} ATT&CK technique(s) implicated.")
    if truncated:
        desc += f" Truncated IOC classes: {', '.join(truncated)}."
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": _stix_id("report"),
        "created_by_ref": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"EL case {case_id}",
        "report_types": ["incident"],
        "published": now_iso,
        "description": desc,
        "object_refs": object_refs,
    }

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": [identity, *indicators, *attack_patterns, report],
    }
    out_path.write_text(json.dumps(bundle, indent=2, sort_keys=False))
    return out_path

"""STIX 2.1 bundle emission.

One bundle per case. Contains:
  - Identity: the EL system that produced the bundle (stable per-deployment)
  - Indicator: per IOC (file hash, ipv4/ipv6, domain, url, email) — IDs are
    deterministic UUID5(case_id, ioc_type, value) so re-runs of the same
    case produce the same indicator IDs, which lets MISP / OpenCTI
    deduplicate cleanly on re-import (Tier 4.5)
  - AttackPattern: per MITRE ATT&CK technique implicated
  - Report: a summary tying everything to the case_id, with a stable id

Indicators only carry IOCs that are operationally meaningful. Defensive
de-duplication is done before emission. No LLM in this path.

**Tier 4.5 — bidirectional Layer-3 STIX**: each indicator is enriched
with ``labels`` reflecting cross-case observations from
``~/.el/knowledge.sqlite``. An IOC seen in N prior EL cases gets a
``el-recurrence-N-cases`` label so the analyst (and the receiving TIP)
can spot recurring infrastructure across investigations. The cross-case
data is suggestive, not load-bearing — it does NOT alter the per-case
finding ledger; it only annotates the published bundle.

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
    """STIX object id: `<type>--<uuid4>`. Used for ad-hoc objects whose
    identity doesn't need to be deterministic across re-runs."""
    return f"{stype}--{uuid.uuid4()}"


# Tier 4.5: a stable, EL-wide UUID namespace. Combined with case_id +
# IOC tuple → UUID5 yields deterministic identifiers that survive
# re-runs, so MISP / OpenCTI can deduplicate cleanly on bundle re-import.
# This UUID is itself a UUID5 of "EL DFIR Orchestrator" against the
# DNS namespace, so it's stable forever without any persisted state.
_EL_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "el-dfir-orchestrator")


def _stix_id_deterministic(stype: str, *parts: str) -> str:
    """STIX object id whose UUID is derived deterministically from *parts*.

    The same (stype, parts) tuple always yields the same id, which is the
    contract MISP / OpenCTI rely on for upsert-style imports.
    """
    seed = "|".join(str(p) for p in parts)
    return f"{stype}--{uuid.uuid5(_EL_NAMESPACE, f'{stype}|{seed}')}"


def emit_bundle(
    case_id: str,
    findings: list[Finding],
    iocs: dict[str, set[str]],
    out_path: str | Path,
    *,
    enrich_with_knowledge: bool = True,
) -> Path:
    """Emit the per-case STIX 2.1 bundle.

    Args:
        case_id: the EL case identifier; used in deterministic STIX IDs
            so re-runs of the same case emit the same indicator IDs (Tier
            4.5 — TIP-side dedup contract).
        findings: the case's structured findings (drives ATT&CK mapping).
        iocs: ``{ioc_type: {value, ...}}`` from the per-case IOC catalog.
        out_path: destination path for the bundle JSON.
        enrich_with_knowledge: when True (default), each indicator gets
            an ``el-recurrence-N-cases`` label reflecting cross-case
            sightings in Layer-3 knowledge. Disable to produce a
            knowledge-free bundle (e.g. for offline-only fixtures).
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    now_iso = _iso(now)

    # Tier 4.5: stable identity_id per EL deployment so the same Identity
    # SDO references survive re-imports.
    identity_id = _stix_id_deterministic("identity", "el-system")
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

    # Optional Layer-3 enrichment: pre-fetch cross-case sightings for
    # every IOC value before building Indicator dicts. We tolerate any
    # error from the knowledge store — the bundle must publish even if
    # ~/.el/knowledge.sqlite is unavailable on this run.
    knowledge_hits: dict[str, int] = {}
    if enrich_with_knowledge:
        try:
            from el import knowledge as kb
            all_values: list[str] = []
            for ioc_type, values in iocs.items():
                if ioc_type in _TYPE_TO_PATTERN:
                    all_values.extend(values)
            if all_values:
                hits = kb.lookup_iocs(all_values, current_case_id=case_id)
                knowledge_hits = {v: len(observations)
                                   for v, observations in hits.items()}
        except Exception:
            knowledge_hits = {}

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
            labels = ["el-emitted"]
            recurrence = knowledge_hits.get(v, 0)
            if recurrence > 0:
                labels.append(f"el-recurrence-{recurrence}-cases")
            indicators.append({
                "type": "indicator",
                "spec_version": "2.1",
                # Tier 4.5: deterministic per-(case, ioc) UUID5.
                "id": _stix_id_deterministic("indicator",
                                                case_id, ioc_type, v),
                "created_by_ref": identity_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"{ioc_type}: {v}",
                "pattern": builder(v_safe),
                "pattern_type": "stix",
                "valid_from": now_iso,
                "indicator_types": ["malicious-activity"],
                "labels": labels,
            })

    attack_patterns: list[dict] = []
    techniques = map_case(findings)
    for tid, info in sorted(techniques.items()):
        attack_patterns.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            # Stable per-technique id — stays the same across all EL bundles.
            "id": _stix_id_deterministic("attack-pattern", tid),
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
    recur_count = sum(1 for v in knowledge_hits.values() if v > 0)
    desc = (f"Auto-generated EL case bundle for {case_id}. "
            f"{len(findings)} finding(s); {len(indicators)} indicator(s); "
            f"{len(attack_patterns)} ATT&CK technique(s) implicated.")
    if recur_count:
        desc += (f" Layer-3 enrichment: {recur_count} indicator(s) "
                 f"observed in prior EL cases.")
    if truncated:
        desc += f" Truncated IOC classes: {', '.join(truncated)}."
    report = {
        "type": "report",
        "spec_version": "2.1",
        # Stable per-case report id.
        "id": _stix_id_deterministic("report", case_id),
        "created_by_ref": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"EL case {case_id}",
        "report_types": ["incident"],
        "published": now_iso,
        "description": desc,
        "object_refs": object_refs,
        "external_references": [{
            "source_name": "el-case-id",
            "external_id": case_id,
        }],
    }

    bundle = {
        "type": "bundle",
        # Stable per-case bundle id (a re-run overwrites the same logical
        # bundle on the TIP side).
        "id": _stix_id_deterministic("bundle", case_id),
        "objects": [identity, *indicators, *attack_patterns, report],
    }
    out_path.write_text(json.dumps(bundle, indent=2, sort_keys=False))
    return out_path

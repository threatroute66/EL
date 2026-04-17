"""STIX 2.1 bundle emission.

One bundle per case. Contains:
  - Identity: the EL system that produced the bundle
  - Indicator: per IOC (file hash, ipv4/ipv6, domain, url, email)
  - AttackPattern: per MITRE ATT&CK technique implicated
  - Report: a summary tying everything to the case_id

Indicators only carry IOCs that are operationally meaningful. Defensive
de-duplication is done before emission. No LLM in this path.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import stix2

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


def emit_bundle(
    case_id: str,
    findings: list[Finding],
    iocs: dict[str, set[str]],
    out_path: str | Path,
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)

    identity = stix2.Identity(
        name="EL — Edmond Locard DFIR Orchestrator",
        identity_class="system",
        description="Multi-agent forensic investigator (https://github.com/local/EL)",
    )

    indicators: list[stix2.Indicator] = []
    for ioc_type, values in iocs.items():
        builder = _TYPE_TO_PATTERN.get(ioc_type)
        if not builder:
            continue
        for v in sorted(values):
            v_safe = v.replace("'", "")
            try:
                indicators.append(stix2.Indicator(
                    name=f"{ioc_type}: {v}",
                    pattern=builder(v_safe),
                    pattern_type="stix",
                    valid_from=now,
                    indicator_types=["malicious-activity"],
                    created_by_ref=identity.id,
                ))
            except Exception:
                continue

    attack_patterns: list[stix2.AttackPattern] = []
    techniques = map_case(findings)
    for tid, info in sorted(techniques.items()):
        attack_patterns.append(stix2.AttackPattern(
            name=info["name"],
            external_references=[stix2.ExternalReference(
                source_name="mitre-attack",
                external_id=tid,
                url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            )],
            created_by_ref=identity.id,
        ))

    object_refs = [identity.id] + [i.id for i in indicators] + [a.id for a in attack_patterns]
    report = stix2.Report(
        name=f"EL case {case_id}",
        report_types=["incident"],
        published=now,
        description=(
            f"Auto-generated EL case bundle for {case_id}. "
            f"{len(findings)} finding(s); {len(indicators)} indicator(s); "
            f"{len(attack_patterns)} ATT&CK technique(s) implicated."
        ),
        object_refs=object_refs,
        created_by_ref=identity.id,
    )

    bundle = stix2.Bundle(objects=[identity, *indicators, *attack_patterns, report], allow_custom=False)
    out_path.write_text(bundle.serialize(pretty=True))
    return out_path

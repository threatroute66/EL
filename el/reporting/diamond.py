"""Render a Diamond Model view for the leading hypothesis.

The Diamond Model of Intrusion Analysis (Caltagirone, Pendergast,
Betz 2013) organises every intrusion event around four vertices:

    Adversary ─ Capability
       │           │
       │           │
    Victim   ─ Infrastructure

EL doesn't attempt attribution to a named actor — the Adversary
vertex is populated from external entities (non-RFC1918 IPs / public
domains) observed in findings that support the ACH-leading
hypothesis; the Infrastructure vertex lists every IP + domain
referenced by any supporting finding; Capability is MITRE ATT&CK
techniques extracted from those findings' extracted_facts; Victim is
derived from the local host + local users mentioned in the
manifest + findings.

The view is deliberately a summary table, not a graph visualisation —
the per-case Kùzu graph already holds the full substrate for
analysts who want to pivot. This is a human-readable projection.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

from el.schemas.finding import Finding


def _is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _collect_ips_domains(iocs: dict[str, list[str]] | None) -> tuple[set, set, set]:
    """Return (public_ips, internal_ips, domains) from the case IOC
    catalog. The IOC catalog keys we care about: 'ipv4', 'ipv6',
    'domain'."""
    public_ips: set[str] = set()
    internal_ips: set[str] = set()
    domains: set[str] = set()
    if not iocs:
        return public_ips, internal_ips, domains
    for v in iocs.get("ipv4", []) + iocs.get("ipv6", []):
        if _is_internal_ip(v):
            internal_ips.add(v)
        else:
            public_ips.add(v)
    for d in iocs.get("domain", []):
        domains.add(d)
    return public_ips, internal_ips, domains


def _collect_techniques(findings: list[Finding],
                         supporting_hyp: str) -> list[str]:
    """Pull MITRE technique IDs from findings' extracted_facts for
    every finding whose hypotheses_supported includes the leader."""
    seen: Counter = Counter()
    for f in findings:
        if supporting_hyp and supporting_hyp not in f.hypotheses_supported:
            continue
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            # Most of our agents store the ATT&CK IDs under this key:
            for tid in facts.get("attack_techniques") or []:
                seen[str(tid)] += 1
            # capa stores under "rules_matched" + "attack_techniques"
            for tid in facts.get("attack_techniques_list") or []:
                seen[str(tid)] += 1
    return [t for t, _ in seen.most_common(20)]


def build_diamond_markdown(
    findings: list[Finding],
    ach_ranking: list,
    iocs: dict[str, list[str]] | None,
    manifest: dict[str, Any] | None,
) -> list[str]:
    """Render a Diamond Model summary for the leading hypothesis.
    Empty list when there's no ranking or no supporting findings."""
    if not ach_ranking:
        return []
    leader = ach_ranking[0]
    leader_hyp = leader.hyp_id
    leader_name = leader.name

    supporting = [f for f in findings
                   if leader_hyp in f.hypotheses_supported]
    if not supporting:
        return []

    pub_ips, int_ips, domains = _collect_ips_domains(iocs)
    techniques = _collect_techniques(findings, leader_hyp)

    # Adversary = public IPs + public domains (external attribution surface)
    adversary_lines = sorted(pub_ips | domains)
    # Infrastructure = internal IPs + all pivot points (both internal + external)
    infrastructure_lines = sorted(int_ips) + sorted(pub_ips) + sorted(domains)
    # Capability = MITRE techniques
    capability_lines = techniques
    # Victim = local host + local users (from manifest + findings)
    victim_hosts: set[str] = set()
    victim_users: set[str] = set()
    if manifest:
        if manifest.get("case_id"):
            victim_hosts.add(str(manifest["case_id"]))
    for f in supporting:
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            for key in ("top_principals", "top_targets", "top_sources"):
                for item in facts.get(key) or []:
                    # Items are (name, count) tuples in most of our skills
                    if isinstance(item, (list, tuple)) and item:
                        name = str(item[0]).lower()
                        if "@" in name:
                            victim_users.add(name)
                        elif "\\" in name or name.startswith("s-1-"):
                            victim_users.add(name)
    victim_lines = sorted(victim_hosts) + sorted(victim_users)

    lines: list[str] = []
    lines.append("## Diamond Model — Leading Hypothesis")
    lines.append("")
    lines.append(f"Projection across the four intrusion-analysis vertices "
                  f"for **{leader_name}** (`{leader_hyp}`, score "
                  f"{leader.score}). This is a summary view; the full "
                  f"Kùzu graph at `graph.kuzu/` holds the complete "
                  f"entity substrate for pivoting.")
    lines.append("")
    lines.append("| Vertex | Extracted entities |")
    lines.append("|---|---|")
    lines.append(f"| **Adversary** (public attribution surface) | "
                  f"{_format_list(adversary_lines) or '_no public IPs/domains observed_'} |")
    lines.append(f"| **Capability** (MITRE ATT&CK) | "
                  f"{_format_list(capability_lines) or '_no technique IDs tagged_'} |")
    lines.append(f"| **Infrastructure** (internal + external pivots) | "
                  f"{_format_list(infrastructure_lines) or '_none_'} |")
    lines.append(f"| **Victim** (local hosts + users) | "
                  f"{_format_list(victim_lines) or '_none_'} |")
    lines.append("")
    return lines


def _format_list(items: list[str], cap: int = 20) -> str:
    if not items:
        return ""
    shown = items[:cap]
    out = ", ".join(f"`{x}`" for x in shown)
    if len(items) > cap:
        out += f", _+{len(items) - cap} more_"
    return out


__all__ = ["build_diamond_markdown"]

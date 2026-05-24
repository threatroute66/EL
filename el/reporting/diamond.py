"""Render a Diamond Model view for the leading hypothesis.

The Diamond Model of Intrusion Analysis (Caltagirone, Pendergast,
Betz 2013) organises every intrusion event around four vertices:

    Adversary ─ Capability
       │           │
       │           │
    Victim   ─ Infrastructure

The four vertices are DISTINCT by definition:

  * Adversary — the actor; who did this. Attribution-quality
    artifacts only: emails the attacker controls, persona handles,
    threat-actor names. For insider hypotheses
    (H_PRE_ATTACK_PLANNING, H_INSIDER_*), the host's own local user
    IS the adversary. An IP or domain alone is NOT an adversary —
    it's a pivot point. When EL has no attribution signal, the
    vertex says so honestly rather than reprinting Infrastructure.

  * Capability — the how: tools / techniques. MITRE ATT&CK IDs
    from supporting findings.

  * Infrastructure — the where: IPs, domains, hostnames the
    activity used to deliver or control. Internal + external both
    qualify; the "internal" / "external" distinction is a property
    of the IP, not a separate vertex.

  * Victim — the who-against: local hosts, local users, victim
    organisations. EL pulls the local user from extracted_facts
    (`user_profile`, `username`, `user`, `account`, `profile`) and
    from claim-text patterns like `profile 'jcloudy'`. Excluded
    from this list under insider hypotheses where the same user
    has been promoted to Adversary.

Earlier versions of this renderer populated Adversary with the same
public IPs + domains that landed in Infrastructure. That was a
category error — it made the two vertices identical whenever there
were no email IOCs and no internal IPs (the common single-host
insider case). The current code keeps IPs/domains in Infrastructure
only; Adversary stays restricted to attribution-grade signals.

The view is deliberately a summary table, not a graph visualisation —
the per-case Kùzu graph already holds the full substrate for
analysts who want to pivot. This is a human-readable projection.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Any

from el.schemas.finding import Finding


# Conservative email regex. The diamond extractor walks every string
# value in every supporting finding's extracted_facts, so over-broad
# matching would put substrings like "from_smtp" into the Victim list.
# The `re.fullmatch`-friendly shape would be too strict (real PST
# addresses sometimes include unicode + dotless TLDs); this is a
# pragmatic middle ground that requires `@` + at least one dot in the
# domain part.
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+\b"
)


def _infer_local_domains(findings: list[Finding]) -> set[str]:
    """Parse 'Inferred local domain(s): X, Y, Z' out of any finding's
    claim text. EL's email_forensicator emits this on the PST-parsed
    finding for every mailbox it processes; pst_triage classifies a
    domain as "local" when the principal appears on the sender side of
    sent-items messages above a threshold. Empty set when no PST was
    parsed (e.g. a memory-only case).
    """
    out: set[str] = set()
    for f in findings:
        # Capture greedy-to-EOL, then split on commas + strip. The
        # earlier version excluded `.` from the character class which
        # truncated `google.com, m57.biz` after `google` — that was the
        # M57-Jean bug that hid the Victim quarter even when this
        # function was wired in correctly downstream.
        m = re.search(r"Inferred local domain\(s\):\s*([^\n]+)",
                       f.claim or "")
        if not m:
            continue
        for token in m.group(1).split(","):
            d = token.strip().rstrip(".").lower()
            if d and d != "unknown":
                out.add(d)
    return out


def _walk_fact_values(facts: dict):
    """Yield every scalar string from an extracted_facts dict, including
    strings nested inside list values. Skips dict/list-of-dict shapes
    that the per-agent skills use for structured sub-records (top_X
    handling stays on its dedicated tuple-iteration path)."""
    for v in (facts or {}).values():
        if isinstance(v, str):
            yield v
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    yield item


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


# Hypotheses where the host's OWN local user is the adversary, not a
# victim. Lifted from el/intel/hypotheses.py — when the leading
# hypothesis is one of these, the user-profile extractor below
# promotes the user from Victim to Adversary so the model row
# accurately names who the actor is.
INSIDER_HYPOTHESES = frozenset({
    "H_PRE_ATTACK_PLANNING",
    "H_INSIDER_DATA_EXFIL",
    "H_INSIDER_EMAIL_EXFIL",
    "H_MULTI_CLOUD_MIRROR",
})


# Service / well-known account names that should never appear in the
# Victim row even if they show up in extracted_facts. They're identity
# noise, not real principals.
_USER_NOISE = frozenset({
    "system", "local service", "network service",
    "anonymous logon", "nt authority", "trusted installer",
    "default", "all users", "public", "default user", "administrator",
    "guest",
})


# Keys that EL's agents use to surface the host's local user. The
# values are either a bare username or a Windows path under
# .../Users/<name>/ — both shapes resolve to the same principal.
_USER_FACT_KEYS = (
    "user_profile", "username", "user", "account", "profile",
    "principal", "owner",
)


# Match `profile '<name>'` and `under profile '<name>'` idioms used
# in many DiskForensicator / WindowsArtifact claims. Captures the
# bare account name so a Windows path doesn't leak into Victim.
_PROFILE_NAME_RE = re.compile(
    r"\bprofile\s+'([A-Za-z0-9._\-]+)'")


def _normalise_user(value: str) -> str | None:
    """Reduce a user-profile value (bare name OR `.../Users/<name>`
    path OR `<name>/...`) to a single lowercase account label.
    Returns None for noise (service accounts, empty strings, …)."""
    if not value:
        return None
    s = value.strip()
    # `.../Users/<name>` or `.../home/<name>` → take the segment
    # after the marker.
    for marker in ("/Users/", "\\Users\\", "/home/", "\\home\\"):
        idx = s.find(marker)
        if idx >= 0:
            tail = s[idx + len(marker):]
            s = tail.split("/", 1)[0].split("\\", 1)[0]
            break
    # Stop at a trailing path component (jcloudy/AppData → jcloudy)
    s = s.split("/", 1)[0].split("\\", 1)[0].strip()
    low = s.lower()
    if not low or low in _USER_NOISE:
        return None
    # Reject obvious non-username noise (numeric SIDs handled
    # separately by the caller; uuid-style strings; very long).
    if len(low) > 64 or "@" in low:
        return None
    return low


def _collect_local_users(supporting: list[Finding]) -> set[str]:
    """Extract local-user account names from supporting findings.
    Two collection paths:
      (a) Direct fact lookup under the keys agents actually use
          (`user_profile`, `username`, `profile`, …).
      (b) Claim-text regex over `profile '<name>'` idiom — many of
          DiskForensicator's claims surface the profile in prose
          without a structured field for it.
    """
    users: set[str] = set()
    for f in supporting:
        # (b) regex over claim text
        for m in _PROFILE_NAME_RE.finditer(f.claim or ""):
            u = _normalise_user(m.group(1))
            if u:
                users.add(u)
        # (a) structured fact lookup
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            for key in _USER_FACT_KEYS:
                raw = facts.get(key)
                if isinstance(raw, str):
                    u = _normalise_user(raw)
                    if u:
                        users.add(u)
                elif isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, str):
                            u = _normalise_user(item)
                            if u:
                                users.add(u)
    return users


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

    # Adversary email collection — mirrors the Victim email-regex
    # path but with the FILTER INVERTED: external (non-local) email
    # addresses found in supporting findings' extracted_facts are
    # the attacker's attribution surface in BEC-shaped cases. Walks
    # the same scalar string fact values (sender / actual_recipient /
    # display_name / from_smtp / etc) and skips any address whose
    # domain is in the inferred-local-domain set (those are victims,
    # already handled below).
    local_domains = _infer_local_domains(findings)
    adversary_emails: set[str] = set()
    for f in supporting:
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            for s in _walk_fact_values(facts):
                for em in _EMAIL_RE.finditer(s):
                    addr = em.group(0).lower()
                    dom = addr.split("@", 1)[1]
                    if dom not in local_domains:
                        adversary_emails.add(addr)

    # Local-user extraction — feeds Adversary (insider hypotheses)
    # OR Victim (everything else). Computed once; routed below based
    # on the leading hypothesis identity.
    local_users = _collect_local_users(supporting)
    is_insider_case = leader_hyp in INSIDER_HYPOTHESES

    # Adversary = attribution-grade signals ONLY. Emails the
    # attacker controls + (under insider hypotheses) the local user
    # whose activity is being attributed. NEVER public IPs/domains —
    # those are pivot points; they belong in Infrastructure. When
    # there's no attribution signal at all the row says so honestly
    # instead of duplicating Infrastructure.
    adversary_lines = sorted(adversary_emails)
    if is_insider_case:
        adversary_lines += sorted(local_users)
    # Infrastructure = all pivot points (internal + external IPs +
    # domains). This is the right home for IPs/domains regardless of
    # whether attribution succeeded.
    infrastructure_lines = sorted(int_ips) + sorted(pub_ips) + sorted(domains)
    # Capability = MITRE techniques
    capability_lines = techniques
    # Victim = real principals named in supporting findings. NOT the
    # case_id (which is EL's internal handle, not a victim). NOT
    # external recipients (those land in Adversary). Two collection
    # paths run together:
    #
    # (a) top_principals / top_targets / top_sources lists — the
    #     legacy agent-curated path; used by the credential analyst
    #     (Kerberoasted SPNs as victim accounts) and lateral movement
    #     (targeted hostnames). Items are (name, count) tuples.
    #
    # (b) Free-text email regex against every scalar string fact —
    #     catches the email_forensicator path (sender / display_name /
    #     actual_recipient / from_smtp / etc.) where the agent-emitted
    #     structure doesn't fit top_X. Filtered by inferred-local-
    #     domain so only victim-side addresses qualify; external
    #     recipients are explicitly excluded so they don't double-
    #     count under Adversary (where the inverse filter put them
    #     above).
    # local_domains was already computed above for the Adversary
    # email pass — reuse the same set.
    victim_hosts: set[str] = set()
    victim_users: set[str] = set()

    # Optional: if the manifest carries a real hostname (not the
    # case_id), surface it. EL's CaseManifest doesn't currently
    # populate this — left as a hook for when WindowsArtifactAgent
    # extracts ComputerName from the SYSTEM hive.
    if manifest and manifest.get("hostname"):
        victim_hosts.add(str(manifest["hostname"]))

    # (c) Local users surfaced via `user_profile` / `profile '<x>'`
    #     idioms — added EXCEPT when this is an insider case, in
    #     which case the same names have already been promoted to
    #     Adversary above. The diamond model's two vertices stay
    #     mutually exclusive on the same principal.
    if not is_insider_case:
        victim_users.update(local_users)

    for f in supporting:
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            # (a) Legacy structured-principal lists
            for key in ("top_principals", "top_targets", "top_sources"):
                for item in facts.get(key) or []:
                    if isinstance(item, (list, tuple)) and item:
                        name = str(item[0]).lower()
                        if "@" in name:
                            dom = name.split("@", 1)[1]
                            if not local_domains or dom in local_domains:
                                victim_users.add(name)
                        elif "\\" in name or name.startswith("s-1-"):
                            victim_users.add(name)
            # (b) Free-text email regex over every scalar string value
            #     (sender, display_name, actual_recipient, from_smtp, …).
            for s in _walk_fact_values(facts):
                for m in _EMAIL_RE.finditer(s):
                    addr = m.group(0).lower()
                    dom = addr.split("@", 1)[1]
                    if local_domains and dom in local_domains:
                        victim_users.add(addr)
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
    adversary_sub = ("attribution surface — emails + insider user"
                       if is_insider_case
                       else "attribution surface — emails / actor names")
    adversary_empty = (
        "_no attribution-grade signals (insider hypothesis: no local "
        "user surfaced)_"
        if is_insider_case else
        "_no attribution surface (emails / actor names) observed — "
        "IPs / domains alone are pivots, not attribution_"
    )
    lines.append(f"| **Adversary** ({adversary_sub}) | "
                  f"{_format_list(adversary_lines) or adversary_empty} |")
    lines.append(f"| **Capability** (MITRE ATT&CK) | "
                  f"{_format_list(capability_lines) or '_no technique IDs tagged_'} |")
    lines.append(f"| **Infrastructure** (pivots — IPs + domains) | "
                  f"{_format_list(infrastructure_lines) or '_none_'} |")
    victim_sub = ("local hosts (insider case: user promoted to Adversary)"
                   if is_insider_case
                   else "local hosts + users")
    lines.append(f"| **Victim** ({victim_sub}) | "
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

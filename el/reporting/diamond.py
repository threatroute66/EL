"""Render a Diamond Model view for the leading hypothesis.

Faithful to Caltagirone, Pendergast & Betz, *The Diamond Model of
Intrusion Analysis* (2013) — DTIC ADA586960. Vertex definitions and
sub-features below follow the paper directly.

    Adversary ─ Capability
       │           │
       │           │
    Victim   ─ Infrastructure

CORE VERTICES (§4.1–§4.4)
-------------------------

  * Adversary (§4.1) — the actor. Two roles per paper:
      - Operator: the actual person(s) conducting the activity
      - Customer: who benefits from the result (often = Operator)
    "Adversary knowledge is generally elusive and this feature is
    likely to be empty for most events" — empty Adversary is the
    honest state, not a bug.

  * Capability (§4.2) — the how. Tools + techniques. Sub-features:
      - Techniques (MITRE ATT&CK IDs from supporting findings)
      - Capacity: the vulns / exposures this capability can exploit
        (lsass, krbtgt, lateral SMB, …)

  * Infrastructure (§4.3) — physical / logical communication
    structures the adversary uses to deliver capability, maintain
    control, and effect results. Three role-types per paper:
      - Type 1: adversary-owned/controlled
      - Type 2: intermediary (compromised hosts, compromised email
        accounts, hop-through points) — what the victim SEES as the
        adversary
      - Service Providers: ISPs, registrars, webmail
    Paper §4.3 explicitly lists email addresses as Infrastructure;
    BEC sender addresses are Type 2 (compromised accounts).

  * Victim (§4.4) — the target. Two sub-features:
      - Persona: people / organisations (names, industries, roles)
      - Asset: networks / systems / hosts / IPs / accounts

EXTENDED DIAMOND (§5)
---------------------

  * Social-Political (§5.1) — adversary-victim relationship,
    motivation, intent. The "why this victim." Derived per leading
    hypothesis below (insider violence, espionage, fraud, …).

  * Direction (§4.5.4) — directionality of activity. Seven values
    in the paper: Victim-to-Infrastructure, Infrastructure-to-
    Victim, Infrastructure-to-Infrastructure, Adversary-to-
    Infrastructure, Infrastructure-to-Adversary, Bidirectional,
    Unknown. Derived from supporting-finding claim text patterns.

INSIDER CASES
-------------

Axiom 2 explicitly admits insiders. When the leading hypothesis is
an insider hypothesis, the host's own local user is promoted to
Adversary Operator; the same name is then suppressed from Victim
Persona so the two vertices stay mutually exclusive on the same
principal.

Earlier versions of this renderer populated Adversary with the same
public IPs + domains that landed in Infrastructure (category error —
the two rows rendered identically whenever there were no emails and
no internal IPs). And earlier still, emails were placed in
Adversary, which contradicts paper §4.3. Both bugs are fixed: IPs
and domains live only in Infrastructure; emails live in Type 2
Infrastructure (per §4.3).

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


# Social-Political mapping per paper §5.1 — each hypothesis carries
# an intrinsic "why this victim" interpretation. Values are plain-
# English motivation labels suitable for a non-technical reader.
# When a hypothesis isn't listed the renderer falls back to a
# neutral string; H_ANTI_FORENSICS is annotated specially because
# anti-forensics is a HOW (cleanup), not a WHY — the operator
# needs to look at the runner-up to find the motive.
_MOTIVATION_MAP: dict[str, str] = {
    "H_PRE_ATTACK_PLANNING":
        "Personal preparation for a violent / kinetic real-world "
        "attack — host is being used as the planning workspace.",
    "H_INSIDER_DATA_EXFIL":
        "Insider data theft — local user removing organisational "
        "material via local channels (USB / personal cloud sync).",
    "H_INSIDER_EMAIL_EXFIL":
        "Insider data theft via email — local user forwarding "
        "organisational material to personal / external addresses.",
    "H_MULTI_CLOUD_MIRROR":
        "Insider staging — local user duplicating files across "
        "multiple personal cloud-sync folders for portability.",
    "H_APT_ESPIONAGE":
        "Targeted intelligence collection — external actor seeking "
        "sustained access to specific organisational material.",
    "H_RANSOMWARE":
        "Financial extortion via encryption + ransom demand.",
    "H_BEC_ACCOUNT_TAKEOVER":
        "Financial fraud via business-email compromise — "
        "attacker impersonates a trusted sender to redirect funds.",
    "H_OPPORTUNISTIC_COMMODITY":
        "Opportunistic infection — commodity malware / banker / "
        "info-stealer monetised at scale, no specific target.",
    "H_C2_BEACONING":
        "Persistent remote access — adversary maintaining control; "
        "downstream motive (espionage / theft / disruption) is the "
        "secondary question.",
    "H_SCAN_RECON":
        "Reconnaissance — adversary surveying the attack surface; "
        "follow-on motive depends on what they targeted next.",
    "H_BRUTE_FORCE":
        "Initial-access brute force — credential trial to gain a "
        "foothold; downstream motive depends on what they do "
        "after gaining one.",
    "H_CREDENTIAL_ACCESS":
        "Credential theft — adversary harvesting authentication "
        "material to expand access or impersonate users.",
    "H_LATERAL_MOVEMENT":
        "Lateral expansion — adversary moving from foothold to "
        "additional internal systems, typically toward a target.",
    "H_CLOUD_PERSISTENCE":
        "Cloud-resident persistence — adversary establishing "
        "long-term access in the cloud control plane.",
    "H_PERSISTENCE_SCHEDULED_TASK":
        "Reboot-survival — adversary planting a scheduled task to "
        "regain execution after every restart.",
    "H_PERSISTENCE_SERVICE":
        "Reboot-survival — adversary planting a Windows service "
        "to regain execution after every restart.",
    "H_SUPPLY_CHAIN":
        "Supply-chain compromise — trusted dependency / vendor "
        "leveraged to reach the downstream victim.",
    "H_ANTI_FORENSICS":
        "Evidence-destruction activity — note this is a HOW (the "
        "operator covering tracks), not a WHY. The motive lies in "
        "the runner-up hypothesis; this row tells you what was "
        "being hidden, not why.",
    "H_NTFS_ADS_PRESENT":
        "Concealed payload / data hiding — alternate data stream "
        "in use, typical of capability delivery or anti-forensics.",
    "H_SHADOW_COPY_ARTIFACT_DELETED":
        "Evidence destruction via Volume Shadow Copy tampering — "
        "operator removing historical state.",
    "H_DISK_ENCRYPTED":
        "Encrypted-at-rest evidence — investigation requires key "
        "recovery; motive is unrecoverable without decryption.",
    "H_CONTAINER_ESCAPE":
        "Container-host breakout — adversary escalating from "
        "container into the host to access the broader environment.",
    "H_K8S_PRIVILEGE_ESCALATION":
        "Kubernetes privilege escalation — adversary widening "
        "rights inside the orchestration plane.",
    "H_MAC_LAUNCH_DAEMON_PERSISTENCE":
        "Reboot-survival on macOS — LaunchDaemon plist planted "
        "for execution at boot.",
    "H_MAC_TCC_BYPASS":
        "macOS privacy-controls bypass — adversary defeating TCC "
        "to access protected resources (Camera / Microphone / Disk).",
    "H_MAC_FILELESS_AMFI_BYPASS":
        "macOS code-signing bypass — fileless execution evading "
        "AppleMobileFileIntegrity checks.",
    "H_MOBILE_SPYWARE_PERSISTENCE":
        "Targeted mobile surveillance — spyware planted for "
        "long-term collection from the device.",
    "H_MOBILE_SIDELOADED_APP":
        "Sideloaded application — non-store app installed, "
        "bypassing platform vetting.",
    "H_MOBILE_MDM_ABUSE":
        "MDM profile abuse — attacker enrolling the device into "
        "an unauthorised management profile for control.",
    "H_BENIGN_NO_INCIDENT":
        "No malicious motive identified — baseline state.",
    "H_NOT_CLEAN_BASELINE":
        "Paired-capture caveat — the baseline side wasn't actually "
        "clean, so this is not a motive but a methodological flag.",
    "H_PAIRED_CAPTURE_CANDIDATE":
        "Methodological — paired pre/post captures detected; "
        "this is a study design, not a motive.",
}


# Direction inference heuristics. Each pattern (case-insensitive
# substring in a finding's claim) maps to one of the seven direction
# values from paper §4.5.4. Multiple matches accumulate.
_DIRECTION_PATTERNS: tuple[tuple[str, str], ...] = (
    # Inbound from outside → Infrastructure-to-Victim
    ("inbound rdp",          "Infrastructure-to-Victim"),
    ("inbound tcp",          "Infrastructure-to-Victim"),
    ("inbound connection",   "Infrastructure-to-Victim"),
    ("from external ip",     "Infrastructure-to-Victim"),
    ("brute-force",          "Infrastructure-to-Victim"),
    ("phish",                "Infrastructure-to-Victim"),
    ("spear-phish",          "Infrastructure-to-Victim"),
    ("delivery",             "Infrastructure-to-Victim"),
    # Outbound from host → Victim-to-Infrastructure (exfil / C2)
    ("beacon",               "Victim-to-Infrastructure"),
    ("c2 callback",          "Victim-to-Infrastructure"),
    ("command-and-control",  "Victim-to-Infrastructure"),
    ("outbound",             "Victim-to-Infrastructure"),
    ("exfil",                "Victim-to-Infrastructure"),
    ("data staging",         "Victim-to-Infrastructure"),
    ("cloud-sync",           "Victim-to-Infrastructure"),
    ("cloud sync",           "Victim-to-Infrastructure"),
    ("multi-cloud",          "Victim-to-Infrastructure"),
    # Internal-to-internal → Infrastructure-to-Infrastructure
    ("lateral movement",     "Infrastructure-to-Infrastructure"),
    ("rfc1918",              "Infrastructure-to-Infrastructure"),
    ("smb lateral",          "Infrastructure-to-Infrastructure"),
    ("rdp lateral",          "Infrastructure-to-Infrastructure"),
    ("psexec",               "Infrastructure-to-Infrastructure"),
)


# Patterns indicating host-local activity with no network direction
# (anti-forensics, persistence implant, credential dump, etc.). Paper
# direction values don't cover host-local cleanly — we surface this
# as a separate note rather than forcing it into one of the seven.
_HOST_LOCAL_PATTERNS: tuple[str, ...] = (
    "anti-forensic",
    "vss diff",
    "shadow copy",
    "wipe",
    "timestomp",
    "log scrubb",
    "scheduled task persistence",
    "registry persistence",
    "lsass dump",
    "credential dump",
    "ntfs alternate data stream",
    "disk anomaly",
    "ntfs ads",
)


def _infer_directions(supporting: list[Finding]) -> dict[str, int]:
    """Return {direction_label: count} observed across supporting
    findings. Host-local-only events get a synthetic "n/a (host-local
    activity)" bucket so the row is never empty when the case has
    real host evidence but no network flow."""
    counts: Counter = Counter()
    for f in supporting:
        claim = (f.claim or "").lower()
        matched_any = False
        for needle, label in _DIRECTION_PATTERNS:
            if needle in claim:
                counts[label] += 1
                matched_any = True
        if not matched_any:
            if any(p in claim for p in _HOST_LOCAL_PATTERNS):
                counts["n/a (host-local activity)"] += 1
    return dict(counts)


# Heuristic: phrases in a finding's claim that suggest the IP /
# domain / email it surfaces belongs to **Type 2 Infrastructure**
# (intermediary — compromised account, staging host, hop-through).
# When none of these appear we default to Type 1 (adversary-owned).
# Service Providers cannot be inferred without TI / WHOIS lookup and
# are left empty.
_TYPE2_CLAIM_HINTS: tuple[str, ...] = (
    "compromised account",
    "compromised mailbox",
    "compromised email",
    "spoof",
    "hop-through",
    "intermediary",
    "staging server",
    "watering-hole",
    "watering hole",
    "bec",
    "account takeover",
)


def _classify_infrastructure_type(claim: str) -> str:
    """Return 'type2' when claim text suggests an intermediary,
    else 'type1' (adversary-owned by default). Service Providers
    require external WHOIS / TI and are returned as 'type1' here —
    callers can promote them when they have that data."""
    low = (claim or "").lower()
    if any(h in low for h in _TYPE2_CLAIM_HINTS):
        return "type2"
    return "type1"


def _collect_infrastructure_by_type(
    supporting: list[Finding],
    iocs: dict[str, list[str]] | None,
    local_domains: set[str],
) -> tuple[set[str], set[str], set[str]]:
    """Return (type1, type2, service_providers) — three disjoint
    sets of entities (IPs / domains / emails). The IOC catalog's
    raw entries default to Type 1; entries surfaced by Type-2-
    shaped findings get re-classified to Type 2. Emails from
    supporting findings always land in Type 2 per paper §4.3
    (Type 2 explicitly includes 'compromised email accounts')."""
    pub_ips, int_ips, domains = _collect_ips_domains(iocs)
    type1: set[str] = set(int_ips) | set(pub_ips) | set(domains)
    type2: set[str] = set()
    service_providers: set[str] = set()

    # Per-finding pass: when the finding's claim hints at Type 2,
    # any IP / domain / email it carries gets promoted out of Type 1.
    for f in supporting:
        kind = _classify_infrastructure_type(f.claim or "")
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            for s in _walk_fact_values(facts):
                # Emails — all into Type 2 per paper §4.3
                for em in _EMAIL_RE.finditer(s):
                    addr = em.group(0).lower()
                    type2.add(addr)
                    type1.discard(addr)
                # Type-2-hinted IPs / domains
                if kind == "type2":
                    for token in s.split():
                        tok = token.strip(",;)(\"'<>")
                        if not tok:
                            continue
                        if tok in type1:
                            type2.add(tok)
                            type1.discard(tok)
    return type1, type2, service_providers


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

    techniques = _collect_techniques(findings, leader_hyp)
    local_domains = _infer_local_domains(findings)
    local_users = _collect_local_users(supporting)
    is_insider_case = leader_hyp in INSIDER_HYPOTHESES

    # Infrastructure (paper §4.3) — three role-types. Emails always
    # land in Type 2 per paper text ("compromised email accounts").
    inf_t1, inf_t2, inf_sp = _collect_infrastructure_by_type(
        supporting, iocs, local_domains)

    # Adversary (paper §4.1) — Operator + Customer. Operator is the
    # actor doing the work; under insider hypotheses that's the
    # host's own local user. Customer is who benefits (often the
    # same; usually empty for EL since we don't model commissioning
    # relationships). NEVER IPs / domains / emails — those are
    # Infrastructure per §4.3.
    adversary_operator: list[str] = []
    if is_insider_case:
        adversary_operator = sorted(local_users)
    adversary_customer: list[str] = []  # left empty — see docstring

    # Victim (paper §4.4) — Persona (people / orgs) + Asset
    # (systems / IPs / accounts). Persona excludes the local user
    # when they've been promoted to Adversary Operator above.
    persona: set[str] = set()
    if not is_insider_case:
        persona.update(local_users)
    asset: set[str] = set()
    if manifest and manifest.get("hostname"):
        asset.add(str(manifest["hostname"]))

    for f in supporting:
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            # Legacy structured-principal lists feed Persona
            for key in ("top_principals", "top_targets", "top_sources"):
                for item in facts.get(key) or []:
                    if isinstance(item, (list, tuple)) and item:
                        name = str(item[0]).lower()
                        if "@" in name:
                            dom = name.split("@", 1)[1]
                            if not local_domains or dom in local_domains:
                                persona.add(name)
                        elif "\\" in name or name.startswith("s-1-"):
                            persona.add(name)
            # Local-domain emails surfaced anywhere → Persona
            for s in _walk_fact_values(facts):
                for m in _EMAIL_RE.finditer(s):
                    addr = m.group(0).lower()
                    dom = addr.split("@", 1)[1]
                    if local_domains and dom in local_domains:
                        persona.add(addr)
            # Concrete asset markers — file paths to credential
            # stores, cleartext keys, exposed accounts surface here
            # as Victim Assets (the thing the operator captured /
            # exposed). Conservative — only pick fact keys that
            # always name an asset.
            for key in ("aws_access_key_id", "access_key_id",
                         "compromised_account", "credential_store"):
                v = facts.get(key)
                if isinstance(v, str) and v:
                    asset.add(v)

    # Social-Political (paper §5.1) — adversary-victim motivation.
    motivation = _MOTIVATION_MAP.get(
        leader_hyp,
        f"Motivation not mapped for {leader_hyp}; see runner-up "
        f"hypothesis for context.",
    )

    # Direction (paper §4.5.4) — observed directionality
    direction_counts = _infer_directions(supporting)

    lines: list[str] = []
    lines.append("## Diamond Model — Leading Hypothesis")
    lines.append("")
    lines.append(f"Projection across the four intrusion-analysis vertices "
                  f"for **{leader_name}** (`{leader_hyp}`, score "
                  f"{leader.score}). Sub-features and the extended "
                  f"Social-Political / Direction rows follow the original "
                  f"Caltagirone/Pendergast/Betz (2013) paper, §4.1–§5.1. "
                  f"Full entity substrate for pivoting lives in the Kùzu "
                  f"graph at `graph.kuzu/`.")
    lines.append("")
    lines.append("| Vertex / Sub-feature | Entities |")
    lines.append("|---|---|")

    # Adversary
    if adversary_operator:
        lines.append(f"| **Adversary** — Operator (who acted) | "
                      f"{_format_list(adversary_operator)} |")
    else:
        empty_op = (
            "_no local user surfaced under insider hypothesis_"
            if is_insider_case else
            "_unknown (paper §4.1: Adversary is often empty at "
            "discovery time — attribution requires non-host data)_"
        )
        lines.append(f"| **Adversary** — Operator (who acted) | "
                      f"{empty_op} |")
    lines.append(f"| _Adversary — Customer (who benefited)_ | "
                  f"{_format_list(adversary_customer) or '_unknown (no commissioning relationship inferable from host evidence)_'} |")

    # Capability
    lines.append(f"| **Capability** — Techniques (MITRE ATT&CK) | "
                  f"{_format_list(techniques) or '_no technique IDs tagged on supporting findings_'} |")
    lines.append(f"| _Capability — Capacity (vulns / exposures)_ | "
                  f"_not catalogued — populate when capa / exploit-DB "
                  f"enrichment is wired in_ |")

    # Infrastructure (Type 1 / Type 2 / Service Provider)
    lines.append(f"| **Infrastructure** — Type 1 (adversary-owned) | "
                  f"{_format_list(sorted(inf_t1)) or '_none_'} |")
    lines.append(f"| _Infrastructure — Type 2 (intermediary)_ | "
                  f"{_format_list(sorted(inf_t2)) or '_none observed (no compromised account / hop-through pattern in supporting findings)_'} |")
    lines.append(f"| _Infrastructure — Service Providers (ISPs / registrars)_ | "
                  f"{_format_list(sorted(inf_sp)) or '_not enumerated (requires WHOIS / TI lookup)_'} |")

    # Victim (Persona + Asset)
    persona_sub = ("local people / orgs — insider case: local user "
                    "promoted to Adversary Operator above"
                    if is_insider_case
                    else "local people / orgs")
    lines.append(f"| **Victim** — Persona ({persona_sub}) | "
                  f"{_format_list(sorted(persona)) or '_none_'} |")
    lines.append(f"| _Victim — Asset (systems / accounts targeted)_ | "
                  f"{_format_list(sorted(asset)) or '_none surfaced — manifest carried no hostname and no compromised account fact_'} |")

    # Social-Political (extended diamond §5.1)
    lines.append(f"| **Social-Political** — motivation | {motivation} |")

    # Direction (meta-feature §4.5.4)
    if direction_counts:
        dir_str = ", ".join(
            f"{label} (×{n})"
            for label, n in sorted(direction_counts.items(),
                                     key=lambda kv: -kv[1])
        )
    else:
        dir_str = "_no directional signal in supporting findings_"
    lines.append(f"| **Direction** — observed | {dir_str} |")

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

"""APT actor-playbook fingerprinting — score a case's observed
ATT&CK techniques against known threat-actor TTP sequences.

Closes the gap-doc bullet "APT-actor playbook fingerprint". The
classic ACH ranks *what kind of incident* (commodity / APT /
ransomware / insider). This is the layer below: *which actor's
playbook does this resemble?* The answer is suggestive, not
attributive — confidence stays low because attribution is a
non-forensic claim and EL doesn't make those.

A playbook is a curated list of MITRE ATT&CK technique IDs that
the actor reliably uses across documented intrusions (e.g.
FIN7's spearphish→VBA→mshta→Carbanak→creddump→lateral chain). Given
the set of techniques EL observed in the current case, we compute:

- ``matched``    — techniques in both the case and the playbook
- ``missing``    — playbook techniques the case did NOT observe
- ``coverage``   — matched / |playbook|  (0..1)
- ``score``      — coverage × sqrt(|matched|)   (rewards depth +
                    breadth so a 1/2-technique match doesn't tie
                    a 5/10-technique match)

The seed playbook list is intentionally narrow and high-confidence:
each entry comes from a published MITRE ATT&CK Group profile
(group ID in ``references``). This is one of those modules that
benefits from analyst review before auto-rolling — currently it
emits one ``confidence='low'`` Finding per match above threshold,
explicitly framed as "the case resembles X's playbook" not
"X did this."
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class ActorPlaybook:
    actor: str                              # canonical name, e.g. "FIN7"
    aliases: tuple[str, ...] = ()           # e.g. ("Carbanak", "Carbon Spider")
    techniques: tuple[str, ...] = ()        # ATT&CK T-IDs in rough kill-chain order
    description: str = ""
    references: tuple[str, ...] = ()        # MITRE Group ID + CTI URLs
    target_sectors: tuple[str, ...] = ()    # informational

    @property
    def technique_set(self) -> frozenset[str]:
        return frozenset(self.techniques)


@dataclass
class PlaybookMatch:
    actor: str
    playbook: ActorPlaybook
    matched: tuple[str, ...]
    missing: tuple[str, ...]
    coverage: float                         # 0..1 — fraction of playbook covered
    score: float                            # coverage × sqrt(|matched|)


# --- Seed playbook library ---------------------------------------------
# Curated from MITRE ATT&CK Group profiles. Each technique list is
# the *core* TTP sequence the actor is documented to use; we don't
# include every technique the actor has *ever* been associated with
# (that bloats the playbook and dilutes match scores).

PLAYBOOKS: tuple[ActorPlaybook, ...] = (
    ActorPlaybook(
        actor="FIN7",
        aliases=("Carbanak", "Carbon Spider", "Navigator Group"),
        techniques=(
            "T1566.001",     # Spearphish attachment
            "T1204.002",     # User Execution: Malicious File
            "T1059.005",     # Visual Basic
            "T1218.005",     # Mshta
            "T1055",         # Process Injection (Carbanak)
            "T1003.001",     # LSASS dumping
            "T1021.002",     # SMB / admin shares
            "T1486",         # Data Encrypted for Impact (REvil partnership)
        ),
        description=(
            "Financially-motivated retail/hospitality intrusion set. "
            "Spearphish with VBA-loaded mshta dropper, Carbanak DLL "
            "injection, lateral via admin shares, occasional ransomware "
            "partnership."),
        references=("G0046",
                     "https://attack.mitre.org/groups/G0046/"),
        target_sectors=("retail", "hospitality", "financial"),
    ),
    ActorPlaybook(
        actor="APT29",
        aliases=("Cozy Bear", "The Dukes", "Midnight Blizzard",
                  "NOBELIUM"),
        techniques=(
            "T1190",         # Exploit Public-Facing Application
            "T1078.004",     # Valid Cloud Accounts
            "T1059.001",     # PowerShell
            "T1027",         # Obfuscated Files
            "T1003.001",     # LSASS
            "T1021.001",     # RDP
            "T1021.006",     # WinRM
            "T1567.002",     # Exfil to Cloud Storage
        ),
        description=(
            "Russian SVR-attributed espionage actor. SolarWinds "
            "supply-chain operator + post-2020 cloud-identity-focused "
            "intrusions (M365, Azure)."),
        references=("G0016",
                     "https://attack.mitre.org/groups/G0016/"),
        target_sectors=("government", "thinktank", "defense"),
    ),
    ActorPlaybook(
        actor="APT28",
        aliases=("Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"),
        techniques=(
            "T1566.001",     # Spearphish attachment
            "T1204.002",     # User Execution
            "T1547.001",     # Registry Run Keys
            "T1059.003",     # Windows Command Shell
            "T1003.003",     # NTDS dumping
            "T1071.001",     # HTTP/S C2
        ),
        description=(
            "Russian GRU-attributed actor. Spearphish-driven access, "
            "registry persistence, custom HTTP C2 (X-Agent / Zebrocy)."),
        references=("G0007",
                     "https://attack.mitre.org/groups/G0007/"),
        target_sectors=("government", "military", "media"),
    ),
    ActorPlaybook(
        actor="Lazarus",
        aliases=("HIDDEN COBRA", "ZINC", "Diamond Sleet",
                  "Andariel"),
        techniques=(
            "T1566.001",     # Spearphish attachment
            "T1059.001",     # PowerShell
            "T1027",         # Obfuscated Files
            "T1547.001",     # Registry Run Keys
            "T1003",         # OS Credential Dumping
            "T1071.001",     # HTTP/S C2
            "T1041",         # Exfil over C2 channel
        ),
        description=(
            "DPRK-attributed actor with both espionage and "
            "financially-motivated streams. Heavy obfuscation, "
            "long dwell time, supply-chain (3CX, JumpCloud)."),
        references=("G0032",
                     "https://attack.mitre.org/groups/G0032/"),
        target_sectors=("financial", "cryptocurrency", "defense"),
    ),
    ActorPlaybook(
        actor="SaltTyphoon",
        aliases=("Earth Estries", "GhostEmperor", "FamousSparrow"),
        techniques=(
            "T1190",         # Exploit Public-Facing
            "T1078",         # Valid Accounts
            "T1021.004",     # SSH (network devices)
            "T1136",         # Create Account
            "T1059",         # Command/Scripting Interpreter
            "T1071.001",     # HTTP/S C2
        ),
        description=(
            "PRC-attributed actor targeting US/global telecom carriers "
            "via network-device exploitation (Cisco IOS XE, switches). "
            "2024 disclosure ramp; Splunk attack_data carries IOS "
            "telemetry samples."),
        references=("G1059",
                     "https://attack.mitre.org/groups/G1059/"),
        target_sectors=("telecommunications", "government"),
    ),
    ActorPlaybook(
        actor="Conti",
        aliases=("WizardSpider-affiliate", "Ryuk-successor"),
        techniques=(
            "T1566.001",     # Spearphish (BazarLoader / Trickbot)
            "T1059.001",     # PowerShell
            "T1218.011",     # Rundll32
            "T1003.001",     # LSASS
            "T1021.002",     # SMB lateral
            "T1490",         # Inhibit System Recovery (VSS delete)
            "T1486",         # Data Encrypted for Impact
        ),
        description=(
            "Ransomware affiliate-driven intrusion set, prolific 2020-22. "
            "Cobalt Strike post-ex, vssadmin delete, RDP / SMB lateral, "
            "double-extortion data leak."),
        references=("G0144",
                     "https://attack.mitre.org/groups/G0144/"),
        target_sectors=("healthcare", "manufacturing", "education"),
    ),
    ActorPlaybook(
        actor="LockBit",
        aliases=("LockBit 3.0", "LockBit Black"),
        techniques=(
            "T1566",         # Phishing (broad initial access)
            "T1078",         # Valid Accounts (RDP brokered access)
            "T1059.001",     # PowerShell
            "T1547.001",     # Registry Run Keys
            "T1021.002",     # SMB lateral
            "T1490",         # Inhibit System Recovery
            "T1486",         # Data Encrypted for Impact
        ),
        description=(
            "Ransomware-as-a-service operator. Affiliate model means "
            "high TTP variance, but the persistence + lateral + "
            "shadow-copy-delete + encrypt chain is consistent."),
        references=("G1100",
                     "https://attack.mitre.org/groups/G1100/"),
        target_sectors=("manufacturing", "retail", "professional"),
    ),
)


def by_actor() -> dict[str, ActorPlaybook]:
    return {p.actor: p for p in PLAYBOOKS}


# --- Scoring -----------------------------------------------------------


def _normalize_tid(tid: str) -> str:
    """Strip whitespace; uppercase the leading T."""
    if not tid:
        return ""
    s = tid.strip()
    if s and s[0] in "tT":
        return "T" + s[1:]
    return s


def score_against_case(observed: Iterable[str],
                        *, playbooks: Iterable[ActorPlaybook] = PLAYBOOKS,
                        min_coverage: float = 0.0,
                        min_matched: int = 1,
                        ) -> list[PlaybookMatch]:
    """Score every playbook against the observed-T-ID set. Returns
    matches with ``coverage >= min_coverage`` AND ``len(matched) >=
    min_matched``, sorted by score descending.

    Sub-techniques are matched both ways: an observed ``T1003.001``
    counts toward a playbook listing the parent ``T1003``, and a
    playbook listing ``T1003.001`` matches an observed parent
    ``T1003``. This handles the gap between EL's parent-grained
    extraction and Mitre's sub-technique granularity.
    """
    obs_set = {_normalize_tid(t) for t in observed if t}
    obs_set.discard("")
    # Build the parent index for sub-technique tolerance
    obs_parents = {t.split(".", 1)[0] for t in obs_set}
    obs_with_parents = obs_set | obs_parents

    matches: list[PlaybookMatch] = []
    for pb in playbooks:
        pb_set = pb.technique_set
        pb_parents = {t.split(".", 1)[0] for t in pb_set}
        pb_with_parents = pb_set | pb_parents
        # Match if either direction's exact-or-parent overlap fires
        matched: set[str] = set()
        for t in pb_set:
            parent = t.split(".", 1)[0]
            if t in obs_set or parent in obs_set:
                matched.add(t)
                continue
            if any(o.startswith(t + ".") for o in obs_set):
                # observed sub-technique satisfies playbook parent
                matched.add(t)
        missing = pb_set - matched
        coverage = (len(matched) / len(pb_set)) if pb_set else 0.0
        score = coverage * math.sqrt(len(matched))
        if coverage < min_coverage or len(matched) < min_matched:
            continue
        matches.append(PlaybookMatch(
            actor=pb.actor, playbook=pb,
            matched=tuple(sorted(matched)),
            missing=tuple(sorted(missing)),
            coverage=coverage, score=score,
        ))
    matches.sort(key=lambda m: -m.score)
    return matches


def score_findings(findings) -> list[PlaybookMatch]:
    """Convenience over ``score_against_case`` — extract observed
    technique IDs from a list of EL ``Finding`` objects.

    Reads from ``EvidenceItem.extracted_facts['attack_techniques']``
    (where every detector emits its T-IDs as a list) AND from any
    ``[("Tnnnn", "name")]`` tuples that appear under that key. No
    Finding shape-coupling beyond that — same contract the report
    renderer uses."""
    observed: set[str] = set()
    for f in findings:
        for ev in getattr(f, "evidence", []):
            facts = getattr(ev, "extracted_facts", {}) or {}
            tids = facts.get("attack_techniques") or []
            for t in tids:
                if isinstance(t, str):
                    observed.add(_normalize_tid(t))
                elif isinstance(t, (list, tuple)) and t:
                    observed.add(_normalize_tid(str(t[0])))
    return score_against_case(observed)


__all__ = [
    "ActorPlaybook", "PlaybookMatch",
    "PLAYBOOKS", "by_actor",
    "score_against_case", "score_findings",
]

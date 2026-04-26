"""Skill: Credential-access / brute-force detectors over EvtxECmd CSV.

Parallels `el.skills.evtx_triage` (lateral movement) — same CSV input,
same `EvtxEvent` primitive, different MITRE phase. Three detectors:

1. `detect_4625_password_burst` — classify security 4625 clusters as
   either targeted brute force (N failures against one account from any
   source) or password spray (one source hitting M distinct accounts).

2. `detect_4769_rc4_kerberoasting` — security 4769 TGS-request events
   with `TicketEncryptionType = RC4-HMAC` on a modern AD (2019+) are
   an atypical encryption downgrade used by Rubeus / Invoke-Kerberoast
   to obtain crackable offline hashes.

3. `detect_4776_ntlm_spray` — security 4776 NTLM validation requests
   coming from a single workstation against many distinct target
   accounts — classic NTLM password spray / Responder-style relay.

Payload shape — EvtxECmd packs fields into PayloadData1-6; we grep the
known substrings in order of appearance rather than parsing a strict
schema, so small map-file version drift doesn't break us.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from el.skills.evtx_triage import (
    EvtxEvent, EvtxTriageError, _build_index_streaming,
    _summary, by_channel_eid, iter_events,
)


_TARGET_RE = re.compile(r"Target[^\S\n]*:\s*(.+?)(?:\s*$|\s{2,})", re.IGNORECASE)
_WORKSTATION_RE = re.compile(r"Workstation[^\S\n]*:\s*(.+?)(?:\s*$|\s{2,})",
                              re.IGNORECASE)
_SERVICE_RE = re.compile(r"ServiceName[^\S\n]*:\s*(.+?)(?:\s*$|\s{2,})",
                          re.IGNORECASE)
_ENC_RE = re.compile(r"TicketEncryptionType[^\S\n]*:\s*(.+?)(?:\s*$|\s{2,})",
                      re.IGNORECASE)


def _payload_field(e: EvtxEvent, regex: re.Pattern) -> str:
    for v in e.payload.values():
        if not v:
            continue
        m = regex.search(v)
        if m:
            return m.group(1).strip()
    return ""


@dataclass
class CredHit:
    technique: str                    # "brute_force" / "password_spray" / ...
    subtechnique: str = ""
    description: str = ""
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    sample_events: list[EvtxEvent] = field(default_factory=list)
    # Technique-specific top entities surfaced to the analyst
    top_targets: list[tuple[str, int]] = field(default_factory=list)
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


# --- 4625 — failed logon, brute-force / password-spray --------------------

# Conservative thresholds — SRL-2018 DC has 1008 × 4625 across many months
# from service-account typos, so we want real bursts, not baseline noise.
_BRUTE_FAILURES_PER_TARGET_MIN = 10
_SPRAY_DISTINCT_TARGETS_MIN = 5


def detect_4625_password_burst(
    events: list[EvtxEvent],
    idx: dict[tuple[str, int], list[EvtxEvent]],
) -> list[CredHit]:
    hits = idx.get(("security", 4625), [])
    if not hits:
        return []

    by_target: Counter = Counter()
    for e in hits:
        tgt = _payload_field(e, _TARGET_RE)
        if tgt:
            by_target[tgt] += 1

    out: list[CredHit] = []

    # Targeted brute force: one account absorbing ≥N failures.
    brute_targets = [(t, n) for t, n in by_target.items()
                     if n >= _BRUTE_FAILURES_PER_TARGET_MIN]
    if brute_targets:
        brute_targets.sort(key=lambda kv: -kv[1])
        total = sum(n for _, n in brute_targets)
        first, last = _summary(hits)
        out.append(CredHit(
            technique="brute_force",
            subtechnique="failed_logon_burst",
            description=(f"Security EID 4625 concentrated on "
                         f"{len(brute_targets)} account(s) with "
                         f"≥{_BRUTE_FAILURES_PER_TARGET_MIN} failures each "
                         f"({total} total failures across those). "
                         f"first={first}, last={last}."),
            event_count=total, first_seen=first, last_seen=last,
            sample_events=hits[:3],
            top_targets=brute_targets[:10],
            attack=[("T1110.001", "Brute Force: Password Guessing")],
        ))

    # Password spray: single source touching many distinct accounts.
    # EvtxECmd sometimes surfaces source as Workstation field when local,
    # or the 4625 payload may contain IpAddress in PayloadData5.
    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    by_source: dict[str, set[str]] = defaultdict(set)
    for e in hits:
        src = (_payload_field(e, _WORKSTATION_RE)
               or next(iter(_IP_RE.findall(" ".join(e.payload.values()))),
                       ""))
        tgt = _payload_field(e, _TARGET_RE)
        if src and tgt:
            by_source[src].add(tgt)
    spray_sources = [(s, len(ts)) for s, ts in by_source.items()
                     if len(ts) >= _SPRAY_DISTINCT_TARGETS_MIN]
    if spray_sources:
        spray_sources.sort(key=lambda kv: -kv[1])
        first, last = _summary(hits)
        total = sum(len(by_source[s]) for s, _ in spray_sources)
        out.append(CredHit(
            technique="password_spray",
            subtechnique="distinct_targets_single_source",
            description=(f"Security EID 4625 shows {len(spray_sources)} "
                         f"source(s) each attempting "
                         f"≥{_SPRAY_DISTINCT_TARGETS_MIN} distinct account(s) — "
                         f"password-spray / credential-stuffing pattern. "
                         f"first={first}, last={last}."),
            event_count=len(hits), first_seen=first, last_seen=last,
            sample_events=hits[:3],
            top_sources=spray_sources[:10],
            attack=[("T1110.003", "Brute Force: Password Spraying")],
        ))

    return out


# --- 4769 — RC4 Kerberoasting -------------------------------------------

_RC4_MIN_HITS = 3   # even 1 is suspicious on AES-by-default modern AD,
                    # but 3 beats out the occasional legacy-client false flag


def detect_4769_rc4_kerberoasting(
    events: list[EvtxEvent],
    idx: dict[tuple[str, int], list[EvtxEvent]],
) -> list[CredHit]:
    candidates = idx.get(("security", 4769), [])
    if not candidates:
        return []

    rc4 = []
    by_spn: Counter = Counter()
    by_user: Counter = Counter()
    for e in candidates:
        enc = _payload_field(e, _ENC_RE).lower()
        # "RC4-HMAC", "rc4_hmac_md5", 0x17 — match the common variants
        if "rc4" not in enc and "0x17" not in enc:
            continue
        rc4.append(e)
        spn = _payload_field(e, _SERVICE_RE)
        if spn:
            by_spn[spn] += 1
        tgt = _payload_field(e, _TARGET_RE)
        if tgt:
            by_user[tgt] += 1

    if len(rc4) < _RC4_MIN_HITS:
        return []

    first, last = _summary(rc4)
    return [CredHit(
        technique="kerberoasting",
        subtechnique="tgs_rc4_downgrade",
        description=(f"Kerberos TGS requests (EID 4769) with RC4-HMAC "
                     f"encryption observed ×{len(rc4)} — RC4 ticket "
                     f"encryption on an AES-capable domain is the "
                     f"signature of Rubeus/Invoke-Kerberoast offline "
                     f"cracking workflow. SPNs targeted: "
                     f"{len(by_spn)}. first={first}, last={last}."),
        event_count=len(rc4), first_seen=first, last_seen=last,
        sample_events=rc4[:3],
        top_targets=by_spn.most_common(10),
        top_sources=by_user.most_common(10),
        attack=[("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting")],
    )]


# --- 4776 — NTLM password spray ------------------------------------------

_NTLM_DISTINCT_TARGETS_MIN = 5


def detect_4776_ntlm_spray(
    events: list[EvtxEvent],
    idx: dict[tuple[str, int], list[EvtxEvent]],
) -> list[CredHit]:
    hits = idx.get(("security", 4776), [])
    if not hits:
        return []

    by_ws: dict[str, set[str]] = defaultdict(set)
    for e in hits:
        ws = _payload_field(e, _WORKSTATION_RE)
        tgt = _payload_field(e, _TARGET_RE)
        if ws and tgt:
            by_ws[ws].add(tgt)

    spray = [(w, len(ts)) for w, ts in by_ws.items()
             if len(ts) >= _NTLM_DISTINCT_TARGETS_MIN]
    if not spray:
        return []

    spray.sort(key=lambda kv: -kv[1])
    first, last = _summary(hits)
    return [CredHit(
        technique="ntlm_spray",
        subtechnique="distinct_targets_single_workstation",
        description=(f"NTLM auth requests (EID 4776) from "
                     f"{len(spray)} workstation(s) each validating "
                     f"≥{_NTLM_DISTINCT_TARGETS_MIN} distinct account(s) — "
                     f"classic NTLM password-spray or Responder-style "
                     f"relay shape. first={first}, last={last}."),
        event_count=len(hits), first_seen=first, last_seen=last,
        sample_events=hits[:3],
        top_sources=spray[:10],
        attack=[("T1110.003", "Brute Force: Password Spraying")],
    )]


ALL_DETECTORS = (
    detect_4625_password_burst,
    detect_4769_rc4_kerberoasting,
    detect_4776_ntlm_spray,
)


def run_all(csv_path: Path) -> list[CredHit]:
    """One-shot: stream the EvtxECmd CSV → build (channel, EventId)
    index → run every credential detector. Streaming index keeps
    DC-class CSVs (5 M+ rows) within memory."""
    idx = _build_index_streaming(csv_path)
    out: list[CredHit] = []
    for fn in ALL_DETECTORS:
        out.extend(fn([], idx))
    return out


__all__ = [
    "CredHit",
    "EvtxTriageError",
    "detect_4625_password_burst",
    "detect_4769_rc4_kerberoasting",
    "detect_4776_ntlm_spray",
    "ALL_DETECTORS",
    "run_all",
]

"""Skill: Kerberos triage over Zeek's kerberos.log.

Parallels the PR-E EVTX-based `credential_triage` skill at the wire
layer. Zeek already parses Kerberos on every pcap replay; this skill
turns the ticket-traffic rows into Findings that corroborate the
EVTX detectors.

Three detectors, matching the 4769/4625/4776 family on the credential
side but derived from network evidence (works even when Windows
auditing is disabled, local, or cleared — we saw EID 1102 log-clears
six times in the SRL-2018 shakedown):

1. `detect_rc4_tgs_kerberoasting` — TGS-REQ with RC4-HMAC cipher on
   an AES-capable modern AD. Zeek normalises the cipher string to
   something like "rc4-hmac"; any TGS-REQ with that cipher is the
   network-layer signature of Rubeus / Invoke-Kerberoast downgrade.

2. `detect_as_req_failure_burst` — AS-REQ with `success=F` clustered
   per client (≥10 failures per principal → targeted brute force)
   or per source IP (≥5 distinct principals from one source →
   password spray, Kerberos variant of 4625).

3. `detect_krbtgt_service_ticket` — TGS-REQ where `service` starts
   with `krbtgt/` is rare on a healthy domain — normal clients ask
   for service tickets to real SPNs. Suggestive of golden-ticket
   construction or TGT-renewal abuse; worth flagging for analyst
   review.

Pure functions. No I/O beyond a single stream read of the Zeek TSV.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


# Zeek kerberos.log column names (v5.x layout; v4 is a subset of the same
# names). We don't hard-code the column order — the #fields header is
# parsed at read time so order drift across Zeek versions doesn't bite.
_INTERESTING_COLS = (
    "ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "request_type", "client", "service", "success",
    "error_msg", "cipher", "forwardable",
)

_CONSERVATIVE_FAILURE_MIN = 10        # per-client AS-REQ brute threshold
_CONSERVATIVE_SPRAY_CLIENTS_MIN = 5   # distinct clients per source IP


@dataclass
class KerbHit:
    technique: str                    # "kerberoasting" / "kerberos_brute" /
                                      # "kerberos_spray" / "krbtgt_tgs"
    subtechnique: str = ""
    description: str = ""
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    top_targets: list[tuple[str, int]] = field(default_factory=list)
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    sample_rows: list[dict] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


def parse_kerberos_log(log_path: Path) -> list[dict]:
    """Stream a Zeek TSV kerberos.log into row dicts. Understands the
    standard Zeek header block (#separator / #fields). Silent on rows
    that are malformed — production logs occasionally have field
    overflow from embedded newlines in principal names."""
    rows: list[dict] = []
    log_path = Path(log_path)
    if not log_path.is_file():
        return rows

    sep = "\t"
    field_names: list[str] = []
    with log_path.open(errors="ignore") as f:
        for line in f:
            if not line:
                continue
            if line.startswith("#separator"):
                parts = line.strip().split(" ", 1)
                if len(parts) == 2 and parts[1].startswith("\\x"):
                    sep = bytes(parts[1], "ascii").decode("unicode_escape")
                continue
            if line.startswith("#fields"):
                field_names = line.rstrip().split(sep)[1:]
                continue
            if line.startswith("#"):
                continue
            if not field_names:
                continue
            cells = line.rstrip("\n").split(sep)
            if len(cells) < len(field_names):
                continue
            row = {name: cells[i] for i, name in enumerate(field_names)}
            rows.append(row)
    return rows


def _summary(rows: list[dict]) -> tuple[str, str]:
    stamps = [r.get("ts", "") for r in rows if r.get("ts")]
    if not stamps:
        return "", ""
    return min(stamps), max(stamps)


def _is_rc4_cipher(value: str) -> bool:
    """RC4-family cipher in Zeek's kerberos.log `cipher` field.

    Zeek emits names like:
      rc4-hmac
      rc4-hmac-exp
      rc4-hmac-old
      rc4-md4 (rare legacy)
    plus the numeric ETYPEs 0x17 / 23 / 24 if symbol mapping is missing.
    """
    v = (value or "").lower()
    return "rc4" in v or v in ("0x17", "23", "24")


# --- Detector 1: RC4 TGS-REQ → Kerberoasting ----------------------------

def detect_rc4_tgs_kerberoasting(rows: list[dict]) -> list[KerbHit]:
    rc4: list[dict] = []
    for r in rows:
        if (r.get("request_type") or "").upper() != "TGS":
            continue
        if not _is_rc4_cipher(r.get("cipher", "")):
            continue
        rc4.append(r)
    if not rc4:
        return []

    by_spn: Counter = Counter(
        (r.get("service") or "").strip() for r in rc4
        if r.get("service")
    )
    by_client: Counter = Counter(
        (r.get("client") or "").strip() for r in rc4
        if r.get("client")
    )
    first, last = _summary(rc4)
    return [KerbHit(
        technique="kerberoasting",
        subtechnique="tgs_rc4_downgrade_wire",
        description=(
            f"Zeek kerberos.log shows {len(rc4)} TGS-REQ event(s) with "
            f"RC4-HMAC cipher — the wire-layer signature of Rubeus / "
            f"Invoke-Kerberoast offline-cracking workflow. SPNs "
            f"targeted: {len(by_spn)}. first={first}, last={last}."
        ),
        event_count=len(rc4), first_seen=first, last_seen=last,
        sample_rows=rc4[:3],
        top_targets=by_spn.most_common(10),
        top_sources=by_client.most_common(10),
        attack=[("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting")],
    )]


# --- Detector 2: AS-REQ failure burst -----------------------------------

def detect_as_req_failure_burst(rows: list[dict]) -> list[KerbHit]:
    failures = [
        r for r in rows
        if (r.get("request_type") or "").upper() == "AS"
        and (r.get("success") or "").upper() == "F"
    ]
    if not failures:
        return []

    out: list[KerbHit] = []
    by_client: Counter = Counter()
    for r in failures:
        client = (r.get("client") or "").strip()
        if client:
            by_client[client] += 1
    brute_clients = [(c, n) for c, n in by_client.items()
                     if n >= _CONSERVATIVE_FAILURE_MIN]
    if brute_clients:
        brute_clients.sort(key=lambda kv: -kv[1])
        total = sum(n for _, n in brute_clients)
        first, last = _summary(failures)
        out.append(KerbHit(
            technique="kerberos_brute",
            subtechnique="as_req_failure_burst",
            description=(
                f"Zeek kerberos.log shows AS-REQ failures concentrated "
                f"on {len(brute_clients)} principal(s) with "
                f"≥{_CONSERVATIVE_FAILURE_MIN} failures each "
                f"({total} total). Kerberos brute-force at wire level; "
                f"corroborates EVTX 4625/4771 if present. "
                f"first={first}, last={last}."
            ),
            event_count=total, first_seen=first, last_seen=last,
            sample_rows=failures[:3],
            top_targets=brute_clients[:10],
            attack=[("T1110.001", "Brute Force: Password Guessing")],
        ))

    by_source: dict[str, set[str]] = defaultdict(set)
    for r in failures:
        src = (r.get("id.orig_h") or "").strip()
        client = (r.get("client") or "").strip()
        if src and client:
            by_source[src].add(client)
    spray_sources = [(s, len(cs)) for s, cs in by_source.items()
                     if len(cs) >= _CONSERVATIVE_SPRAY_CLIENTS_MIN]
    if spray_sources:
        spray_sources.sort(key=lambda kv: -kv[1])
        first, last = _summary(failures)
        out.append(KerbHit(
            technique="kerberos_spray",
            subtechnique="as_req_distinct_clients_single_source",
            description=(
                f"Zeek kerberos.log shows {len(spray_sources)} source "
                f"IP(s) each failing AS-REQ against "
                f"≥{_CONSERVATIVE_SPRAY_CLIENTS_MIN} distinct "
                f"principal(s) — password-spray shape at the wire. "
                f"first={first}, last={last}."
            ),
            event_count=len(failures), first_seen=first, last_seen=last,
            sample_rows=failures[:3],
            top_sources=spray_sources[:10],
            attack=[("T1110.003", "Brute Force: Password Spraying")],
        ))

    return out


# --- Detector 3: KRBTGT service in TGS-REQ (golden-ticket smell) --------

_KRBTGT_RE = re.compile(r"^krbtgt/", re.IGNORECASE)


def detect_krbtgt_service_ticket(rows: list[dict]) -> list[KerbHit]:
    hits = [
        r for r in rows
        if (r.get("request_type") or "").upper() == "TGS"
        and _KRBTGT_RE.search((r.get("service") or ""))
    ]
    if not hits:
        return []
    by_client: Counter = Counter(
        (r.get("client") or "").strip() for r in hits if r.get("client")
    )
    by_source: Counter = Counter(
        (r.get("id.orig_h") or "").strip() for r in hits if r.get("id.orig_h")
    )
    first, last = _summary(hits)
    return [KerbHit(
        technique="krbtgt_tgs",
        subtechnique="tgs_req_for_krbtgt_service",
        description=(
            f"Zeek kerberos.log shows {len(hits)} TGS-REQ event(s) "
            f"whose `service` principal begins with 'krbtgt/' — "
            f"suggestive of golden-ticket construction or TGT-renewal "
            f"abuse. Rare on a healthy AD; worth analyst review. "
            f"first={first}, last={last}."
        ),
        event_count=len(hits), first_seen=first, last_seen=last,
        sample_rows=hits[:3],
        top_targets=by_client.most_common(10),
        top_sources=by_source.most_common(10),
        attack=[("T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket")],
    )]


ALL_DETECTORS = (
    detect_rc4_tgs_kerberoasting,
    detect_as_req_failure_burst,
    detect_krbtgt_service_ticket,
)


def run_all(kerberos_log: Path) -> list[KerbHit]:
    """One-shot: parse Zeek kerberos.log and run every detector."""
    rows = parse_kerberos_log(kerberos_log)
    if not rows:
        return []
    hits: list[KerbHit] = []
    for fn in ALL_DETECTORS:
        hits.extend(fn(rows))
    return hits


__all__ = [
    "KerbHit",
    "parse_kerberos_log",
    "detect_rc4_tgs_kerberoasting",
    "detect_as_req_failure_burst",
    "detect_krbtgt_service_ticket",
    "ALL_DETECTORS",
    "run_all",
]

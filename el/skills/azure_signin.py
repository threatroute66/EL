"""Skill: Azure AD / Entra sign-in log parsing + detectors.

Sign-in logs are Microsoft Graph's authoritative identity-layer audit
feed. Exported via `Get-MgAuditLogSignIn` or Graph API
`auditLogs/signIns`. JSON is either a bare array of records or a Graph
wrapper `{"@odata.context": ..., "value": [...]}`.

Four V1 detectors, sized to the enterprise identity-compromise shape:

1. `detect_signin_failure_burst` — ≥10 failures per principal
   (targeted brute force) or ≥5 distinct principals from one source
   IP (password spray). Matches the EVTX 4625 / Kerberos AS-REQ tiers
   so cross-layer reinforcement stays symmetrical.

2. `detect_legacy_auth_bypass` — successful sign-in using a legacy
   authentication protocol (IMAP4 / POP3 / SMTP / Exchange
   ActiveSync / older Office clients / basic auth). Legacy auth
   bypasses MFA; any success is an MFA-bypass smell.

3. `detect_risky_signin` — Entra's own risk classifier marked the
   sign-in `riskLevelAggregated = high` or `riskState = atRisk`.

4. `detect_impossible_travel` — same principal logs in successfully
   from two distinct `location.countryOrRegion` values within 60
   minutes. Deliberately conservative (countries, not haversine
   radius) to avoid time-zone noise while still catching the
   token-theft pattern.

Pure functions. Input is a list of dicts shaped like Graph sign-in
log records; `parse_signin_log` normalises the file to that list.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


LEGACY_AUTH_CLIENT_APPS = {
    "authenticated smtp",
    "imap4", "imap",
    "pop3", "pop",
    "exchange activesync",
    "autodiscover",
    "other clients; imap",
    "other clients; pop",
    "other clients; older office clients",
    "other clients",
    "exchange online powershell",
    "reporting web services",
    "exchange web services",
    "offline address book",
    "mapi over http",        # legacy Outlook desktop
}


@dataclass
class SigninHit:
    technique: str                   # signin_brute / signin_spray / legacy_auth / ...
    subtechnique: str = ""
    description: str = ""
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    top_principals: list[tuple[str, int]] = field(default_factory=list)
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


def parse_signin_log(path: Path) -> list[dict]:
    """Load Azure sign-in log JSON. Accepts either a Graph wrapper or
    a bare array. Silent on parse error (returns empty list)."""
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, dict):
        # Graph wrapper form
        if isinstance(data.get("value"), list):
            return data["value"]
        # Some tools emit {"records": [...]}
        if isinstance(data.get("records"), list):
            return data["records"]
        return []
    if isinstance(data, list):
        return data
    return []


def _ts(row: dict) -> str:
    return str(row.get("createdDateTime")
               or row.get("CreationTime") or "")


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    # Graph emits ISO 8601 with Z — tolerate trailing Z and fractional seconds
    v = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None


def _summary(rows: list[dict]) -> tuple[str, str]:
    stamps = [_ts(r) for r in rows if _ts(r)]
    if not stamps:
        return "", ""
    return min(stamps), max(stamps)


def _is_failure(row: dict) -> bool:
    """A sign-in failed when its `status.errorCode` is non-zero.
    0 is success; every other value (50053 = account locked, 50126 =
    invalid creds, 50074 = strong-auth required failure, etc.) is a
    failure."""
    status = row.get("status") or {}
    code = status.get("errorCode")
    if code is None or code == 0:
        return False
    try:
        return int(code) != 0
    except (TypeError, ValueError):
        return True


# --- Detector 1: signin brute / spray -----------------------------------

_BRUTE_MIN = 10
_SPRAY_MIN = 5


def detect_signin_failure_burst(rows: list[dict]) -> list[SigninHit]:
    failures = [r for r in rows if _is_failure(r)]
    if not failures:
        return []

    out: list[SigninHit] = []

    by_upn: Counter = Counter()
    for r in failures:
        upn = (r.get("userPrincipalName") or r.get("UserId") or "").lower()
        if upn:
            by_upn[upn] += 1

    brute = [(u, n) for u, n in by_upn.items() if n >= _BRUTE_MIN]
    if brute:
        brute.sort(key=lambda kv: -kv[1])
        total = sum(n for _, n in brute)
        first, last = _summary(failures)
        out.append(SigninHit(
            technique="signin_brute",
            subtechnique="failures_per_principal",
            description=(f"Entra sign-in failures concentrated on "
                         f"{len(brute)} principal(s) with ≥{_BRUTE_MIN} "
                         f"each ({total} total). Identity-layer brute "
                         f"force — corroborates on-prem 4625 / AS-REQ "
                         f"if present. first={first}, last={last}."),
            event_count=total, first_seen=first, last_seen=last,
            top_principals=brute[:10],
            attack=[("T1110.001", "Brute Force: Password Guessing")],
        ))

    by_source: dict[str, set[str]] = defaultdict(set)
    for r in failures:
        ip = (r.get("ipAddress") or "").strip()
        upn = (r.get("userPrincipalName") or r.get("UserId") or "").lower()
        if ip and upn:
            by_source[ip].add(upn)
    spray = [(s, len(us)) for s, us in by_source.items()
             if len(us) >= _SPRAY_MIN]
    if spray:
        spray.sort(key=lambda kv: -kv[1])
        first, last = _summary(failures)
        out.append(SigninHit(
            technique="signin_spray",
            subtechnique="distinct_principals_per_source_ip",
            description=(f"Entra sign-in failures from {len(spray)} "
                         f"source IP(s) each touching ≥{_SPRAY_MIN} "
                         f"distinct principal(s) — password spray / "
                         f"credential-stuffing shape. first={first}, "
                         f"last={last}."),
            event_count=len(failures), first_seen=first, last_seen=last,
            top_sources=spray[:10],
            attack=[("T1110.003", "Brute Force: Password Spraying")],
        ))
    return out


# --- Detector 2: legacy auth bypass -------------------------------------

def detect_legacy_auth_bypass(rows: list[dict]) -> list[SigninHit]:
    legacy = []
    for r in rows:
        if _is_failure(r):
            continue
        app = (r.get("clientAppUsed") or "").strip().lower()
        if app and app in LEGACY_AUTH_CLIENT_APPS:
            legacy.append(r)
    if not legacy:
        return []
    by_upn: Counter = Counter(
        (r.get("userPrincipalName") or r.get("UserId") or "").lower()
        for r in legacy if r.get("userPrincipalName") or r.get("UserId")
    )
    by_source: Counter = Counter(
        (r.get("ipAddress") or "").strip() for r in legacy
        if r.get("ipAddress")
    )
    first, last = _summary(legacy)
    return [SigninHit(
        technique="legacy_auth",
        subtechnique="successful_signin_via_legacy_protocol",
        description=(f"{len(legacy)} successful Entra sign-in(s) via "
                     f"legacy protocol(s) that bypass modern MFA "
                     f"(IMAP / POP3 / SMTP / Exchange ActiveSync / older "
                     f"Office clients). {len(by_upn)} distinct "
                     f"principal(s). first={first}, last={last}."),
        event_count=len(legacy), first_seen=first, last_seen=last,
        top_principals=by_upn.most_common(10),
        top_sources=by_source.most_common(10),
        attack=[("T1078.004", "Valid Accounts: Cloud Accounts"),
                ("T1556.006", "Modify Authentication Process: MFA")],
    )]


# --- Detector 3: Entra risk-classifier trigger --------------------------

_RISK_HIGH_VALUES = {"high"}
_RISK_STATE_TRIGGERS = {"atrisk", "confirmed-compromised"}


def detect_risky_signin(rows: list[dict]) -> list[SigninHit]:
    risky = []
    for r in rows:
        ra = (r.get("riskLevelAggregated") or "").lower()
        rd = (r.get("riskLevelDuringSignIn") or "").lower()
        rs = (r.get("riskState") or "").lower()
        if (ra in _RISK_HIGH_VALUES or rd in _RISK_HIGH_VALUES
                or rs in _RISK_STATE_TRIGGERS):
            risky.append(r)
    if not risky:
        return []
    by_upn: Counter = Counter(
        (r.get("userPrincipalName") or r.get("UserId") or "").lower()
        for r in risky if r.get("userPrincipalName") or r.get("UserId")
    )
    first, last = _summary(risky)
    return [SigninHit(
        technique="risky_signin",
        subtechnique="entra_risk_classifier_triggered",
        description=(f"Entra's own risk classifier flagged "
                     f"{len(risky)} sign-in(s) as high risk OR the "
                     f"user state as at-risk / confirmed-compromised. "
                     f"{len(by_upn)} distinct principal(s). "
                     f"first={first}, last={last}. Investigate any "
                     f"success that follows these events."),
        event_count=len(risky), first_seen=first, last_seen=last,
        top_principals=by_upn.most_common(10),
        attack=[("T1078.004", "Valid Accounts: Cloud Accounts")],
    )]


# --- Detector 4: impossible travel --------------------------------------

_IMPOSSIBLE_TRAVEL_WINDOW = timedelta(minutes=60)


def detect_impossible_travel(rows: list[dict]) -> list[SigninHit]:
    """Pairs of successful sign-ins for the same principal from
    different countries within a 60-minute window. Single detector
    output per principal that exhibits the pattern."""
    by_principal: dict[str, list[tuple[datetime, str, dict]]] = defaultdict(list)
    for r in rows:
        if _is_failure(r):
            continue
        upn = (r.get("userPrincipalName") or r.get("UserId") or "").lower()
        if not upn:
            continue
        ts = _parse_ts(_ts(r))
        if ts is None:
            continue
        loc = r.get("location") or {}
        country = (loc.get("countryOrRegion") or "").strip().upper()
        if not country:
            continue
        by_principal[upn].append((ts, country, r))

    offenders: list[tuple[str, list[dict]]] = []
    for upn, events in by_principal.items():
        events.sort(key=lambda e: e[0])
        for i in range(len(events) - 1):
            t1, c1, r1 = events[i]
            t2, c2, r2 = events[i + 1]
            if c1 != c2 and (t2 - t1) <= _IMPOSSIBLE_TRAVEL_WINDOW:
                offenders.append((upn, [r1, r2]))
                break
    if not offenders:
        return []

    all_hits = [r for _, pair in offenders for r in pair]
    first, last = _summary(all_hits)
    top: Counter = Counter(u for u, _ in offenders)
    return [SigninHit(
        technique="impossible_travel",
        subtechnique="country_change_within_60min",
        description=(f"{len(offenders)} principal(s) successfully signed "
                     f"in from two distinct countries within "
                     f"60 minutes — impossible-travel shape; classic "
                     f"token-theft or credential-share signal. "
                     f"first={first}, last={last}."),
        event_count=len(offenders), first_seen=first, last_seen=last,
        top_principals=top.most_common(10),
        attack=[("T1078.004", "Valid Accounts: Cloud Accounts")],
    )]


ALL_DETECTORS = (
    detect_signin_failure_burst,
    detect_legacy_auth_bypass,
    detect_risky_signin,
    detect_impossible_travel,
)


def run_all(path: Path) -> tuple[int, list[SigninHit]]:
    """One-shot: parse the sign-in log and return (record_count, hits)."""
    rows = parse_signin_log(path)
    if not rows:
        return 0, []
    hits: list[SigninHit] = []
    for fn in ALL_DETECTORS:
        hits.extend(fn(rows))
    return len(rows), hits


def looks_like_signin_log(sample: bytes) -> bool:
    """Content sniff — first few KB. Distinctive field combinations
    appear in Graph sign-in log exports."""
    return (b'"userPrincipalName"' in sample
            and (b'"appDisplayName"' in sample
                 or b'"conditionalAccessStatus"' in sample
                 or b'"riskLevelAggregated"' in sample))


__all__ = [
    "SigninHit",
    "parse_signin_log", "run_all", "looks_like_signin_log",
    "detect_signin_failure_burst", "detect_legacy_auth_bypass",
    "detect_risky_signin", "detect_impossible_travel",
    "ALL_DETECTORS",
]

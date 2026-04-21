"""Skill: Microsoft 365 Unified Audit Log (UAL) parsing + detectors.

UAL is the authoritative cross-workload audit feed exported via
`Search-UnifiedAuditLog` or Graph. Records are JSON objects with a
top-level `Operation`, `Workload` (Exchange / SharePoint / OneDrive /
AzureActiveDirectory / MicrosoftTeams / etc.), `RecordType`, `UserId`,
`ClientIP`, and an `AuditData` dict holding operation-specific fields.
The `AuditData` value is sometimes a JSON string inside the outer
record — we transparently unpack that case.

Four V1 detectors, each grounded in a well-documented BEC / insider /
OAuth-abuse pattern:

1. `detect_inbox_rule_external_forward` — `New-InboxRule` /
   `Set-InboxRule` / `Update-InboxRules` with a ForwardTo /
   RedirectTo / ForwardAsAttachmentTo parameter pointing at an
   external domain. Classic BEC persistence.

2. `detect_mail_items_accessed_bulk` — `MailItemsAccessed` records
   spiking for a single user (≥50 in the log), indicative of
   post-compromise mailbox scraping.

3. `detect_oauth_consent_grant` — `Consent to application` /
   `Add OAuth2PermissionGrant`. Illicit-consent attack surface.

4. `detect_userlogin_failed_burst` — `UserLoginFailed` clusters.
   Same ≥10/user brute and ≥5/source spray thresholds as the rest
   of EL's credential-ingress detectors.

Pure functions; no network or subprocess.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class UalHit:
    technique: str
    subtechnique: str = ""
    description: str = ""
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    top_principals: list[tuple[str, int]] = field(default_factory=list)
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    samples: list[dict] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


def parse_ual_log(path: Path) -> list[dict]:
    """Load UAL JSON into a normalised list. Accepts three export
    shapes in the wild:
      - Bare JSON array of records (PowerShell `ConvertTo-Json`)
      - Graph wrapper `{"value": [...]}`
      - Search-UnifiedAuditLog PS output where `AuditData` is a JSON
        STRING inside each outer record — we unpack it in place so
        downstream code can treat AuditData as a dict uniformly.
    """
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, dict):
        rows = data.get("value") or data.get("records") or []
    elif isinstance(data, list):
        rows = data
    else:
        return []

    out: list[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        ad = r.get("AuditData")
        if isinstance(ad, str):
            try:
                r = {**r, "AuditData": json.loads(ad)}
            except json.JSONDecodeError:
                pass
        out.append(r)
    return out


def _ts(row: dict) -> str:
    return str(row.get("CreationTime") or row.get("createdDateTime") or "")


def _summary(rows: list[dict]) -> tuple[str, str]:
    stamps = [_ts(r) for r in rows if _ts(r)]
    if not stamps:
        return "", ""
    return min(stamps), max(stamps)


def _op(row: dict) -> str:
    return str(row.get("Operation") or "").strip()


def _user(row: dict) -> str:
    u = row.get("UserId") or row.get("UserKey") or ""
    return str(u).lower()


def _ip(row: dict) -> str:
    ip = (row.get("ClientIP") or "").strip()
    # Some UAL exports wrap IPv6 in brackets with a port suffix
    return ip.lstrip("[").split("]")[0].split(":")[0]


# --- Detector 1: inbox rule creation with external forwarding -----------

_EXTERNAL_FORWARD_PARAMS = {
    "forwardto", "redirectto", "forwardasattachmentto",
    "sendtorecipients",
}


def _extract_rule_params(row: dict) -> dict[str, Any]:
    """UAL stores Exchange cmdlet parameters under
    AuditData.Parameters = [{Name, Value}, ...].
    """
    out: dict[str, Any] = {}
    ad = row.get("AuditData")
    if not isinstance(ad, dict):
        return out
    params = ad.get("Parameters") or []
    if not isinstance(params, list):
        return out
    for p in params:
        if not isinstance(p, dict):
            continue
        name = (p.get("Name") or "").lower()
        if name:
            out[name] = p.get("Value")
    return out


def _is_external_forward_target(value: str,
                                  tenant_domains: set[str]) -> bool:
    """`value` is what the rule's ForwardTo/RedirectTo param points at.
    Can be an email address, SMTP:addr, or a DL. We look for the @
    domain and compare against the tenant's local domains (if we have
    them). If we don't, we assume all forwarding is suspicious —
    the detector still fires, just with wider reach."""
    if not value:
        return False
    # Pull the domain out of the first email-like substring
    m = re.search(r"[\w.+-]+@([\w.-]+)", str(value))
    if not m:
        # Pure-DL / display-name reference — can't evaluate, skip
        return False
    dom = m.group(1).lower()
    if tenant_domains and dom not in tenant_domains:
        return True
    if not tenant_domains:
        # No anchor — only flag if domain looks external (has TLD, not
        # local). Err on the side of flagging; analyst can dismiss.
        return "." in dom
    return False


def detect_inbox_rule_external_forward(
    rows: list[dict],
    tenant_domains: set[str] | None = None,
) -> list[UalHit]:
    tenant_domains = {d.lower() for d in (tenant_domains or set())}
    rule_ops = {"new-inboxrule", "set-inboxrule", "update-inboxrules",
                "new-transportrule"}
    hits: list[dict] = []
    forward_targets: Counter = Counter()
    for r in rows:
        if _op(r).lower() not in rule_ops:
            continue
        params = _extract_rule_params(r)
        for param_name, value in params.items():
            if param_name not in _EXTERNAL_FORWARD_PARAMS:
                continue
            if _is_external_forward_target(value, tenant_domains):
                hits.append(r)
                m = re.search(r"[\w.+-]+@[\w.-]+", str(value))
                if m:
                    forward_targets[m.group(0).lower()] += 1
                break
    if not hits:
        return []
    first, last = _summary(hits)
    by_user: Counter = Counter(_user(r) for r in hits if _user(r))
    return [UalHit(
        technique="inbox_rule_forward_external",
        subtechnique="new_or_set_inbox_rule_external_target",
        description=(f"M365 UAL shows {len(hits)} inbox-rule "
                     f"creation/modification event(s) that set "
                     f"forwarding / redirection to an external address "
                     f"— classic BEC persistence. Top external targets: "
                     f"{dict(forward_targets.most_common(5))}. "
                     f"first={first}, last={last}."),
        event_count=len(hits), first_seen=first, last_seen=last,
        samples=hits[:3],
        top_principals=by_user.most_common(10),
        top_sources=list(forward_targets.most_common(10)),
        attack=[("T1564.008", "Hide Artifacts: Email Hiding Rules"),
                ("T1114.003", "Email Collection: Email Forwarding Rule")],
    )]


# --- Detector 2: MailItemsAccessed bulk ---------------------------------

_MAIL_ITEMS_MIN = 50


def detect_mail_items_accessed_bulk(rows: list[dict]) -> list[UalHit]:
    accessed = [r for r in rows if _op(r) == "MailItemsAccessed"]
    if not accessed:
        return []
    by_user: Counter = Counter(_user(r) for r in accessed if _user(r))
    bulk = [(u, n) for u, n in by_user.items() if n >= _MAIL_ITEMS_MIN]
    if not bulk:
        return []
    bulk.sort(key=lambda kv: -kv[1])
    first, last = _summary(accessed)
    return [UalHit(
        technique="mail_items_accessed_bulk",
        subtechnique="per_user_access_volume_spike",
        description=(f"M365 UAL: {len(bulk)} mailbox user(s) with "
                     f"≥{_MAIL_ITEMS_MIN} MailItemsAccessed record(s) "
                     f"each — post-compromise mailbox-scraping shape. "
                     f"first={first}, last={last}."),
        event_count=sum(n for _, n in bulk),
        first_seen=first, last_seen=last,
        top_principals=bulk[:10],
        attack=[("T1114.002", "Email Collection: Remote Email Collection")],
    )]


# --- Detector 3: OAuth consent grant ------------------------------------

_OAUTH_CONSENT_OPS = {
    "consent to application",
    "add oauth2permissiongrant",
    "add app role assignment grant to user",
    "add delegated permission grant",
    "add service principal",
}


def detect_oauth_consent_grant(rows: list[dict]) -> list[UalHit]:
    hits = [r for r in rows if _op(r).lower() in _OAUTH_CONSENT_OPS]
    if not hits:
        return []
    # Pull the app identifier out of AuditData where available — UAL
    # stores it under ModifiedProperties or Target.
    apps: Counter = Counter()
    for r in hits:
        ad = r.get("AuditData") or {}
        if isinstance(ad, dict):
            target = ad.get("Target") or []
            if isinstance(target, list):
                for t in target:
                    if isinstance(t, dict) and t.get("ID"):
                        apps[str(t["ID"])] += 1
    by_user: Counter = Counter(_user(r) for r in hits if _user(r))
    first, last = _summary(hits)
    return [UalHit(
        technique="oauth_consent_grant",
        subtechnique="app_or_permission_grant_added",
        description=(f"M365 UAL: {len(hits)} OAuth consent / permission "
                     f"grant event(s). Illicit-consent attacks pivot "
                     f"through this surface by tricking users into "
                     f"approving attacker-owned OAuth apps that then "
                     f"read mail / files. first={first}, last={last}."),
        event_count=len(hits), first_seen=first, last_seen=last,
        samples=hits[:3],
        top_principals=by_user.most_common(10),
        top_sources=list(apps.most_common(10)),
        attack=[("T1528", "Steal Application Access Token")],
    )]


# --- Detector 4: UserLoginFailed burst ----------------------------------

_UAL_BRUTE_MIN = 10
_UAL_SPRAY_MIN = 5


def detect_userlogin_failed_burst(rows: list[dict]) -> list[UalHit]:
    fails = [r for r in rows if _op(r) == "UserLoginFailed"]
    if not fails:
        return []
    out: list[UalHit] = []

    by_user: Counter = Counter(_user(r) for r in fails if _user(r))
    brute = [(u, n) for u, n in by_user.items() if n >= _UAL_BRUTE_MIN]
    if brute:
        brute.sort(key=lambda kv: -kv[1])
        total = sum(n for _, n in brute)
        first, last = _summary(fails)
        out.append(UalHit(
            technique="signin_brute",
            subtechnique="ual_userloginfailed_per_principal",
            description=(f"UAL UserLoginFailed concentrated on "
                         f"{len(brute)} principal(s) with "
                         f"≥{_UAL_BRUTE_MIN} failures each "
                         f"({total} total). Identity-layer brute force "
                         f"visible in UAL even when the Entra sign-in "
                         f"log wasn't exported. first={first}, last={last}."),
            event_count=total, first_seen=first, last_seen=last,
            top_principals=brute[:10],
            attack=[("T1110.001", "Brute Force: Password Guessing")],
        ))

    by_source: dict[str, set[str]] = defaultdict(set)
    for r in fails:
        ip = _ip(r)
        upn = _user(r)
        if ip and upn:
            by_source[ip].add(upn)
    spray = [(s, len(us)) for s, us in by_source.items()
             if len(us) >= _UAL_SPRAY_MIN]
    if spray:
        spray.sort(key=lambda kv: -kv[1])
        first, last = _summary(fails)
        out.append(UalHit(
            technique="signin_spray",
            subtechnique="ual_userloginfailed_per_source_ip",
            description=(f"UAL UserLoginFailed from {len(spray)} "
                         f"source IP(s) each touching ≥{_UAL_SPRAY_MIN} "
                         f"distinct principal(s) — spray shape. "
                         f"first={first}, last={last}."),
            event_count=len(fails), first_seen=first, last_seen=last,
            top_sources=spray[:10],
            attack=[("T1110.003", "Brute Force: Password Spraying")],
        ))
    return out


ALL_DETECTORS = (
    detect_inbox_rule_external_forward,
    detect_mail_items_accessed_bulk,
    detect_oauth_consent_grant,
    detect_userlogin_failed_burst,
)


def run_all(path: Path,
            tenant_domains: set[str] | None = None,
            ) -> tuple[int, list[UalHit]]:
    rows = parse_ual_log(path)
    if not rows:
        return 0, []
    hits: list[UalHit] = []
    for fn in ALL_DETECTORS:
        if fn is detect_inbox_rule_external_forward:
            hits.extend(fn(rows, tenant_domains))
        else:
            hits.extend(fn(rows))
    return len(rows), hits


def looks_like_ual(sample: bytes) -> bool:
    """Content sniff — UAL records have Operation + Workload + RecordType
    at the top level, none of which appear in CloudTrail or Entra
    sign-in logs."""
    return (b'"Operation"' in sample
            and (b'"Workload"' in sample
                 or b'"RecordType"' in sample)
            and b'"AuditData"' in sample)


__all__ = [
    "UalHit",
    "parse_ual_log", "run_all", "looks_like_ual",
    "detect_inbox_rule_external_forward",
    "detect_mail_items_accessed_bulk",
    "detect_oauth_consent_grant",
    "detect_userlogin_failed_burst",
    "ALL_DETECTORS",
]

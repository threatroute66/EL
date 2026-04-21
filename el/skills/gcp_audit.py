"""Skill: GCP Cloud Audit Logs.

GCP Audit Logs come in four subtypes, exported as JSONL from either
BigQuery or Cloud Logging:
  - Admin Activity: admin writes (IAM changes, resource lifecycle)
  - Data Access: data-plane reads (BigQuery queries, Storage reads)
  - System Event: Google-initiated admin actions
  - Policy Denied: requests denied by policy (strong attack signal)

V1 detectors target the high-value post-compromise shapes:

1. `detect_service_account_key_creation` — IAM
   CreateServiceAccountKey. Classic persistence / lateral pivot.
2. `detect_iam_privileged_grant` — SetIamPolicy adding owner /
   editor / admin roles to principals.
3. `detect_policy_denied_burst` — ≥N Policy Denied events for one
   principal indicates recon / credential-stuffing style probing.
4. `detect_storage_bucket_public_open` — storage.setIamPermissions
   granting allUsers / allAuthenticatedUsers access on a bucket.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class GcpAuditHit:
    technique: str
    subtechnique: str = ""
    description: str = ""
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    top_principals: list[tuple[str, int]] = field(default_factory=list)
    top_resources: list[tuple[str, int]] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


_PRIVILEGED_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin".lower(),
    "roles/resourcemanager.organizationAdmin".lower(),
    "roles/resourcemanager.projectIamAdmin".lower(),
    "roles/iam.serviceAccountAdmin".lower(),
    "roles/iam.serviceAccountKeyAdmin".lower(),
    "roles/iam.serviceAccountTokenCreator".lower(),
}

_PUBLIC_PRINCIPALS = {"allusers", "allauthenticatedusers"}


def _ts(row: dict) -> str:
    return str(row.get("timestamp")
               or row.get("receiveTimestamp")
               or row.get("protoPayload", {}).get("requestTime") or "")


def _method(row: dict) -> str:
    pp = row.get("protoPayload") or {}
    return str(pp.get("methodName") or "")


def _principal(row: dict) -> str:
    pp = row.get("protoPayload") or {}
    auth = pp.get("authenticationInfo") or {}
    email = auth.get("principalEmail") or ""
    return str(email).lower()


def _resource_name(row: dict) -> str:
    pp = row.get("protoPayload") or {}
    return str(pp.get("resourceName") or "")


def parse_audit_log(path: Path) -> list[dict]:
    """Load GCP Cloud Audit Log export. Supports three common
    formats: JSONL (one record per line), bare array, and the
    BigQuery-exported `{"logs": [...]}` wrapper."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    text = text.strip()
    if not text:
        return []
    # Bare array or wrapped dict
    if text.startswith("[") or text.startswith("{"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, list):
            return [r for r in doc if isinstance(r, dict)]
        if isinstance(doc, dict):
            for key in ("logs", "items", "entries"):
                if isinstance(doc.get(key), list):
                    return [r for r in doc[key] if isinstance(r, dict)]
            # Single record
            if "protoPayload" in doc:
                return [doc]
    # JSONL fallback
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return [r for r in rows if isinstance(r, dict)]


def detect_service_account_key_creation(rows: list[dict]) -> list[GcpAuditHit]:
    hits = []
    for r in rows:
        method = _method(r).lower()
        if "serviceaccountkey" in method and "create" in method:
            hits.append(r)
    if not hits:
        return []
    by_principal: Counter = Counter(_principal(r) for r in hits
                                      if _principal(r))
    stamps = sorted(_ts(r) for r in hits if _ts(r))
    return [GcpAuditHit(
        technique="service_account_key_creation",
        subtechnique="gcp_iam_createkey",
        description=(f"GCP IAM: {len(hits)} CreateServiceAccountKey "
                     f"operation(s). Creating a service-account key "
                     f"gives long-lived programmatic access — the "
                     f"classic GCP persistence / lateral-pivot primitive."),
        event_count=len(hits),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_principals=by_principal.most_common(10),
        attack=[("T1098.001", "Account Manipulation: Additional Cloud Credentials")],
    )]


def detect_iam_privileged_grant(rows: list[dict]) -> list[GcpAuditHit]:
    hits = []
    for r in rows:
        method = _method(r).lower()
        if "setiampolicy" not in method:
            continue
        pp = r.get("protoPayload") or {}
        req = pp.get("request") or {}
        policy = req.get("policy") if isinstance(req, dict) else None
        if not isinstance(policy, dict):
            continue
        for binding in policy.get("bindings") or []:
            if not isinstance(binding, dict):
                continue
            role = str(binding.get("role") or "").lower()
            if role in _PRIVILEGED_ROLES:
                hits.append(r)
                break
    if not hits:
        return []
    by_principal: Counter = Counter(_principal(r) for r in hits
                                      if _principal(r))
    stamps = sorted(_ts(r) for r in hits if _ts(r))
    return [GcpAuditHit(
        technique="iam_privileged_grant",
        subtechnique="setiampolicy_adds_privileged_role",
        description=(f"GCP IAM: {len(hits)} SetIamPolicy operation(s) "
                     f"binding a privileged role (roles/owner, editor, "
                     f"security admin, service-account admin, …). "
                     f"Post-compromise privilege escalation."),
        event_count=len(hits),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_principals=by_principal.most_common(10),
        attack=[("T1098.003", "Account Manipulation: Additional Cloud Roles")],
    )]


def detect_policy_denied_burst(rows: list[dict],
                                 min_denied: int = 20) -> list[GcpAuditHit]:
    by_principal: Counter = Counter()
    rows_by_principal: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        log_name = str(r.get("logName") or "")
        if "policy" not in log_name.lower() or "denied" not in log_name.lower():
            # Fallback: severity ERROR + status PERMISSION_DENIED
            pp = r.get("protoPayload") or {}
            status = pp.get("status") or {}
            if str(status.get("code") or "") != "7":
                continue
        principal = _principal(r)
        if not principal:
            continue
        by_principal[principal] += 1
        rows_by_principal[principal].append(r)
    flagged = [(p, n) for p, n in by_principal.items() if n >= min_denied]
    if not flagged:
        return []
    flagged.sort(key=lambda kv: -kv[1])
    stamps = sorted(_ts(r) for p, _ in flagged
                    for r in rows_by_principal[p] if _ts(r))
    return [GcpAuditHit(
        technique="policy_denied_burst",
        subtechnique="single_principal_permission_denied",
        description=(f"GCP: {len(flagged)} principal(s) triggered "
                     f"≥{min_denied} policy-denied event(s). "
                     f"Recon / credential-stuffing shape — attacker "
                     f"probes resources they don't yet have access to."),
        event_count=sum(n for _, n in flagged),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_principals=flagged[:10],
        attack=[("T1087.004", "Account Discovery: Cloud Account")],
    )]


def detect_storage_bucket_public_open(rows: list[dict]) -> list[GcpAuditHit]:
    hits = []
    for r in rows:
        method = _method(r).lower()
        if "setiampermissions" not in method and "updatebucket" not in method:
            continue
        pp = r.get("protoPayload") or {}
        req = pp.get("request") or {}
        policy = req.get("policy") if isinstance(req, dict) else None
        if not isinstance(policy, dict):
            continue
        for binding in policy.get("bindings") or []:
            if not isinstance(binding, dict):
                continue
            members = binding.get("members") or []
            for m in members:
                if not isinstance(m, str):
                    continue
                if m.lower() in (f"allusers", "alltypedusers",
                                 "allauthenticatedusers"):
                    hits.append(r)
                    break
    if not hits:
        return []
    by_resource: Counter = Counter(_resource_name(r) for r in hits
                                     if _resource_name(r))
    stamps = sorted(_ts(r) for r in hits if _ts(r))
    return [GcpAuditHit(
        technique="storage_bucket_public_open",
        subtechnique="bucket_iam_grants_allusers",
        description=(f"GCP Cloud Storage: {len(hits)} bucket IAM "
                     f"change(s) granted allUsers / "
                     f"allAuthenticatedUsers — bucket effectively made "
                     f"publicly readable. Data-exfiltration staging or "
                     f"misconfiguration."),
        event_count=len(hits),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_resources=by_resource.most_common(10),
        attack=[("T1537", "Transfer Data to Cloud Account")],
    )]


ALL_DETECTORS = (
    detect_service_account_key_creation,
    detect_iam_privileged_grant,
    detect_policy_denied_burst,
    detect_storage_bucket_public_open,
)


def run_all(path: Path) -> tuple[int, list[GcpAuditHit]]:
    rows = parse_audit_log(path)
    if not rows:
        return 0, []
    hits: list[GcpAuditHit] = []
    for fn in ALL_DETECTORS:
        hits.extend(fn(rows))
    return len(rows), hits


def looks_like_gcp_audit(sample: bytes) -> bool:
    """GCP Cloud Audit Log distinguishing fields."""
    return (b'"protoPayload"' in sample
            or (b'"logName"' in sample and b'googleapis.com' in sample))


__all__ = [
    "GcpAuditHit",
    "parse_audit_log", "run_all", "looks_like_gcp_audit",
    "detect_service_account_key_creation",
    "detect_iam_privileged_grant",
    "detect_policy_denied_burst",
    "detect_storage_bucket_public_open",
    "ALL_DETECTORS",
]

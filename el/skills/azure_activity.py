"""Skill: Azure Activity Logs (resource-plane audit).

Azure Activity Logs are distinct from Entra Sign-in Logs:
  - Sign-in Logs: identity-layer (who authenticated where)
  - Activity Logs: resource-plane (who did what to which Azure resource)

Together they form the full Azure IR picture. Activity Log JSON has
one record per Azure Resource Manager operation: role assignments,
NSG rule changes, resource creation/deletion, key-vault access,
policy changes.

V1 detectors target the highest-signal BEC/APT shapes:

1. `detect_privileged_role_assignment` — role additions to
   Global Administrator / Privileged Role Administrator / Security
   Administrator / User Access Administrator. Classic post-compromise
   privilege-escalation footprint.
2. `detect_nsg_open_to_world` — Network Security Group rules added
   with source '*' / '0.0.0.0/0' / 'Any' / 'Internet' on sensitive
   ports (22, 3389, 5985, 1433). Cloud lateral-movement opener.
3. `detect_keyvault_bulk_access` — single principal reading ≥N
   distinct secrets within a short window (post-compromise
   secret-hoovering).
4. `detect_resource_mass_delete` — destructive-impact shape;
   attacker wipe / ransomware pattern.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AzActivityHit:
    technique: str
    subtechnique: str = ""
    description: str = ""
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    top_principals: list[tuple[str, int]] = field(default_factory=list)
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


_PRIVILEGED_ROLE_NAMES = {
    "global administrator",
    "privileged role administrator",
    "security administrator",
    "user access administrator",
    "application administrator",
    "cloud application administrator",
    "privileged authentication administrator",
}


_SENSITIVE_NSG_PORTS = {"22", "3389", "5985", "5986", "1433", "3306",
                        "5432", "27017", "6379", "9200"}


def _ts(row: dict) -> str:
    return str(row.get("eventTimestamp")
               or row.get("time")
               or row.get("CreationTime") or "")


def _operation_name(row: dict) -> str:
    op = row.get("operationName")
    if isinstance(op, dict):
        return str(op.get("value") or op.get("localizedValue") or "")
    return str(op or "")


def _principal(row: dict) -> str:
    caller = row.get("caller") or ""
    if not caller:
        identity = row.get("identity") or {}
        if isinstance(identity, dict):
            caller = (identity.get("claims", {}) or {}).get(
                "http://schemas.xmlsoap.org/ws/2005/05/identity/"
                "claims/name") or identity.get("userPrincipalName") or ""
    return str(caller).lower()


def parse_activity_log(path: Path) -> list[dict]:
    """Read Azure Activity Log JSON. Azure exports in three shapes:
      - Bare array of log entries
      - Graph-style wrapper `{"value": [...]}`
      - Azure Monitor export with `{"records": [...]}`
    """
    try:
        with Path(path).open(encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        for key in ("records", "value"):
            if isinstance(doc.get(key), list):
                return [r for r in doc[key] if isinstance(r, dict)]
    return []


def detect_privileged_role_assignment(rows: list[dict]) -> list[AzActivityHit]:
    hits = []
    for r in rows:
        op = _operation_name(r).lower()
        if "roleassignments/write" not in op and "add member to role" not in op:
            continue
        props = r.get("properties") or {}
        if not isinstance(props, dict):
            continue
        role_name = (props.get("roleName") or props.get("role") or "").lower()
        # Azure logs sometimes store just the role GUID; we fall back to
        # flagging ANY roleAssignments/write when role name isn't
        # resolvable (a follow-up could look up the GUID via Graph).
        if role_name and role_name not in _PRIVILEGED_ROLE_NAMES:
            continue
        hits.append(r)
    if not hits:
        return []
    by_principal: Counter = Counter(_principal(r) for r in hits
                                      if _principal(r))
    stamps = sorted(_ts(r) for r in hits if _ts(r))
    return [AzActivityHit(
        technique="privileged_role_assignment",
        subtechnique="directory_role_added",
        description=(f"Azure Activity Log: {len(hits)} privileged "
                     f"role assignment(s) (Global Admin / Privileged "
                     f"Role Admin / Security Admin / etc). Post-"
                     f"compromise privilege-escalation footprint. "
                     f"first={stamps[0] if stamps else '?'}, "
                     f"last={stamps[-1] if stamps else '?'}."),
        event_count=len(hits),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_principals=by_principal.most_common(10),
        attack=[("T1098.003", "Account Manipulation: Additional Cloud Roles")],
    )]


def detect_nsg_open_to_world(rows: list[dict]) -> list[AzActivityHit]:
    hits = []
    for r in rows:
        op = _operation_name(r).lower()
        if "networksecuritygroups/securityrules/write" not in op:
            continue
        props = r.get("properties") or {}
        if not isinstance(props, dict):
            continue
        rp = props.get("requestBody") or props.get("properties") or {}
        if isinstance(rp, str):
            try:
                rp = json.loads(rp)
            except json.JSONDecodeError:
                rp = {}
        if not isinstance(rp, dict):
            continue
        src = str(rp.get("sourceAddressPrefix")
                  or rp.get("source") or "").strip()
        dst_port = str(rp.get("destinationPortRange")
                        or rp.get("destinationPort") or "").strip()
        if src.lower() in ("*", "0.0.0.0/0", "any", "internet"):
            if dst_port in _SENSITIVE_NSG_PORTS or dst_port == "*":
                hits.append(r)
    if not hits:
        return []
    stamps = sorted(_ts(r) for r in hits if _ts(r))
    by_principal: Counter = Counter(_principal(r) for r in hits
                                      if _principal(r))
    return [AzActivityHit(
        technique="nsg_open_to_world",
        subtechnique="inbound_admin_port_from_any",
        description=(f"Azure Activity Log: {len(hits)} NSG rule "
                     f"create/update(s) that allow inbound traffic "
                     f"from Any/0.0.0.0/0 on sensitive admin ports "
                     f"(SSH/RDP/WinRM/SQL/etc). Classic cloud "
                     f"lateral-movement opener."),
        event_count=len(hits),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_principals=by_principal.most_common(10),
        attack=[("T1562.007", "Impair Defenses: Disable/Modify Cloud Firewall")],
    )]


def detect_keyvault_bulk_access(rows: list[dict],
                                  min_secrets: int = 10) -> list[AzActivityHit]:
    by_principal: dict[str, set[str]] = defaultdict(set)
    all_rows_by_principal: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        op = _operation_name(r).lower()
        if "vaults/secrets" not in op or ("/read" not in op and "get " not in op):
            continue
        principal = _principal(r)
        props = r.get("properties") or {}
        if isinstance(props, dict):
            secret = str(props.get("id")
                          or props.get("resourceName") or "")
            if secret:
                by_principal[principal].add(secret)
                all_rows_by_principal[principal].append(r)

    flagged = [(p, len(s)) for p, s in by_principal.items()
               if len(s) >= min_secrets]
    if not flagged:
        return []
    flagged.sort(key=lambda kv: -kv[1])
    sample_rows = all_rows_by_principal[flagged[0][0]][:3]
    stamps = sorted(_ts(r) for p, _ in flagged
                    for r in all_rows_by_principal[p] if _ts(r))
    return [AzActivityHit(
        technique="keyvault_bulk_access",
        subtechnique="single_principal_multi_secret",
        description=(f"Azure Key Vault: {len(flagged)} principal(s) "
                     f"read ≥{min_secrets} distinct secret(s). "
                     f"Post-compromise secret-hoovering — attacker "
                     f"collects keys for lateral / persistence use. "
                     f"Top: {flagged[0][0]} ×{flagged[0][1]} secrets."),
        event_count=sum(n for _, n in flagged),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_principals=flagged[:10],
        attack=[("T1552.001", "Unsecured Credentials: Credentials In Files"),
                ("T1555.006", "Credentials from Password Stores: Cloud Secrets Management Stores")],
    )]


def detect_resource_mass_delete(rows: list[dict],
                                  min_deletes: int = 20) -> list[AzActivityHit]:
    by_principal: Counter = Counter()
    rows_by_principal: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        op = _operation_name(r).lower()
        if "/delete" not in op:
            continue
        principal = _principal(r)
        by_principal[principal] += 1
        rows_by_principal[principal].append(r)
    flagged = [(p, n) for p, n in by_principal.items()
               if n >= min_deletes]
    if not flagged:
        return []
    flagged.sort(key=lambda kv: -kv[1])
    stamps = sorted(_ts(r) for p, _ in flagged
                    for r in rows_by_principal[p] if _ts(r))
    return [AzActivityHit(
        technique="resource_mass_delete",
        subtechnique="destructive_resource_manager_ops",
        description=(f"Azure Activity Log: {len(flagged)} principal(s) "
                     f"performed ≥{min_deletes} resource-delete "
                     f"operation(s). Destructive-impact shape — "
                     f"attacker wipe or ransomware. Top: "
                     f"{flagged[0][0]} ×{flagged[0][1]} deletes."),
        event_count=sum(n for _, n in flagged),
        first_seen=stamps[0] if stamps else "",
        last_seen=stamps[-1] if stamps else "",
        top_principals=flagged[:10],
        attack=[("T1485", "Data Destruction"),
                ("T1496", "Resource Hijacking")],
    )]


ALL_DETECTORS = (
    detect_privileged_role_assignment,
    detect_nsg_open_to_world,
    detect_keyvault_bulk_access,
    detect_resource_mass_delete,
)


def run_all(path: Path) -> tuple[int, list[AzActivityHit]]:
    rows = parse_activity_log(path)
    if not rows:
        return 0, []
    hits: list[AzActivityHit] = []
    for fn in ALL_DETECTORS:
        hits.extend(fn(rows))
    return len(rows), hits


def looks_like_azure_activity(sample: bytes) -> bool:
    """Azure Activity Log distinguishing markers. Must not collide
    with sign-in log (which has userPrincipalName + appDisplayName)."""
    return (b'"operationName"' in sample
            and (b'"resourceProviderName"' in sample
                 or b'"resourceGroupName"' in sample
                 or b'"subscriptionId"' in sample))


__all__ = [
    "AzActivityHit",
    "parse_activity_log", "run_all", "looks_like_azure_activity",
    "detect_privileged_role_assignment",
    "detect_nsg_open_to_world",
    "detect_keyvault_bulk_access",
    "detect_resource_mass_delete",
    "ALL_DETECTORS",
]

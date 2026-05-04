"""AzureHound JSON triage — Entra ID identity / role analysis.

Wraps AzureHound (BloodHound's Azure/Entra collector) **output**. We do NOT
run AzureHound here — the investigator runs it on the tenant; we parse its
JSON corpus.

This is a lightweight, in-process subset of what BloodHound CE does with
Neo4j. We deliberately don't replicate BloodHound's full attack-path
analysis (Neo4j is a heavy dependency for per-case offline use), but we DO
extract the headline forensic signals an analyst would otherwise have to
import into Neo4j to see:

  * Users assigned high-privilege roles (Global Admin, Privileged Role
    Admin, Privileged Auth Admin, Application Admin, ...)
  * Service principals / app registrations with admin role assignments
  * External-guest accounts holding privileged roles
  * Group nesting paths that grant privileged access transitively
  * App registrations with admin-consented permissions (Mail.Read,
    Directory.ReadWrite.All, etc.)

Project: https://github.com/SpecterOps/AzureHound
JSON shape reference: AzureHound emits ``{"kind":"AZ*", "data":{...}}``
records, one per JSON file in its output dir (or one large array file).
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from el.schemas.finding import EvidenceItem


class AzureHoundError(Exception):
    pass


# Curated list of Entra ID role names that are privileged. Sourced from
# Microsoft's "Privileged roles in Entra ID" published list. Keep names
# in CASE-INSENSITIVE form for matching.
_PRIVILEGED_ROLES = frozenset(
    name.lower() for name in (
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator",
        "Authentication Administrator",
        "User Administrator",
        "Conditional Access Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Hybrid Identity Administrator",
        "Domain Name Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Teams Administrator",
        "Compliance Administrator",
        "Compliance Data Administrator",
        "Security Administrator",
        "Security Operator",
        "Security Reader",
        "Helpdesk Administrator",
        "Password Administrator",
        "Directory Writers",
    )
)

# OAuth permission scopes that are dangerous when admin-consented.
_HIGH_RISK_OAUTH_SCOPES = frozenset(
    s.lower() for s in (
        "Mail.Read",
        "Mail.ReadWrite",
        "Mail.Send",
        "Files.Read.All",
        "Files.ReadWrite.All",
        "Sites.Read.All",
        "Sites.ReadWrite.All",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
        "User.Read.All",
        "User.ReadWrite.All",
        "Group.Read.All",
        "Group.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Application.ReadWrite.All",
    )
)


@dataclass
class PrivilegedAssignment:
    principal_id: str
    principal_name: str
    principal_kind: str          # "user" / "service_principal" / "group" / "guest"
    role_name: str
    role_template_id: str = ""
    is_external_guest: bool = False


@dataclass
class RiskyOAuthGrant:
    app_id: str
    app_name: str
    consent_type: str             # "AllPrincipals" / "Principal"
    scopes: list[str] = field(default_factory=list)
    high_risk_scopes: list[str] = field(default_factory=list)


@dataclass
class AzureHoundResult:
    input_path: Path
    record_count: int
    privileged_assignments: list[PrivilegedAssignment] = field(default_factory=list)
    risky_oauth_grants: list[RiskyOAuthGrant] = field(default_factory=list)
    distinct_kinds: dict[str, int] = field(default_factory=dict)
    output_sha256: str = ""
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="azurehound_triage",
            version="0.1.0",
            command=f"triage_azurehound_dump({self.input_path.name})",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.input_path),
            extracted_facts={
                "record_count": self.record_count,
                "kind_counts": self.distinct_kinds,
                "privileged_assignment_count": len(self.privileged_assignments),
                "risky_oauth_grant_count": len(self.risky_oauth_grants),
                "external_guest_admin_count": sum(
                    1 for a in self.privileged_assignments if a.is_external_guest
                ),
                "note": self.note,
                **extra,
            },
        )


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    elif path.is_dir():
        for p in sorted(path.rglob("*"))[:1000]:
            if p.is_file():
                try:
                    h.update(p.name.encode())
                    with p.open("rb") as f:
                        h.update(f.read(65536))
                except (PermissionError, OSError):
                    continue
    return h.hexdigest()


def _iter_records(path: Path) -> Iterator[dict]:
    """Yield every AzureHound record (``{"kind": ..., "data": ...}``) from
    *path*, which can be a directory of JSON files, a single JSON file,
    a JSONL file, or a .zip bundle."""
    if path.is_dir():
        files = sorted(path.rglob("*.json")) + sorted(path.rglob("*.jsonl"))
        for f in files:
            yield from _iter_records(f)
        return

    if path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if name.endswith(("/", ".pdf")):
                        continue
                    if not name.lower().endswith((".json", ".jsonl")):
                        continue
                    try:
                        with zf.open(name) as f:
                            text = f.read().decode("utf-8", errors="replace")
                    except KeyError:
                        continue
                    yield from _iter_records_from_text(text)
        except (zipfile.BadZipFile, OSError):
            return
        return

    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    yield from _iter_records_from_text(text)


def _iter_records_from_text(text: str) -> Iterator[dict]:
    text = text.strip()
    if not text:
        return
    # Top-level JSON array form.
    if text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        yield item
                return
        except json.JSONDecodeError:
            pass
    # Top-level dict — AzureHound's "{"data": [...], "meta": {...}}" form.
    if text.startswith("{"):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                inner = data.get("data")
                if isinstance(inner, list):
                    for item in inner:
                        if isinstance(item, dict):
                            yield item
                    return
                # Single-record file
                yield data
                return
        except json.JSONDecodeError:
            pass
    # JSONL fallback.
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                yield obj
        except json.JSONDecodeError:
            continue


def _principal_kind_from_record(rec: dict) -> str:
    kind = (rec.get("kind") or "").lower()
    if "user" in kind and "guest" in kind:
        return "guest"
    if "user" in kind:
        return "user"
    if "serviceprincipal" in kind or "app" in kind:
        return "service_principal"
    if "group" in kind:
        return "group"
    return kind or "unknown"


def _is_external_guest(data: dict) -> bool:
    """Heuristic: AzureHound flags external guests via UserType field."""
    user_type = (data.get("userType") or data.get("UserType") or "").lower()
    if user_type == "guest":
        return True
    upn = (data.get("userPrincipalName")
           or data.get("UserPrincipalName")
           or "").lower()
    return "#ext#" in upn


def _resolve_role_assignments(records: list[dict]) -> list[PrivilegedAssignment]:
    """Walk an AzureHound corpus for principals with privileged role assignments.

    AzureHound emits role assignments either as standalone ``AZRoleAssignment``
    records or as embedded fields on ``AZUser`` / ``AZServicePrincipal``
    records. We honour both shapes.
    """
    # Index principals by id for cross-record lookups.
    principal_by_id: dict[str, dict] = {}
    for rec in records:
        kind = (rec.get("kind") or "").lower()
        data = rec.get("data") or {}
        if not isinstance(data, dict):
            continue
        pid = (data.get("id") or data.get("objectId") or "").lower()
        if pid and any(k in kind for k in ("user", "serviceprincipal", "group")):
            principal_by_id[pid] = {**data, "_kind": kind}

    assignments: list[PrivilegedAssignment] = []
    seen: set[tuple[str, str]] = set()

    for rec in records:
        kind = (rec.get("kind") or "").lower()
        data = rec.get("data") or {}
        if not isinstance(data, dict):
            continue

        # Dedicated role-assignment records.
        if "roleassignment" in kind or "directoryrole" in kind:
            role_name = str(data.get("roleName")
                            or data.get("displayName") or "")
            principal_id = str(data.get("principalId")
                                or data.get("memberId") or "").lower()
            template_id = str(data.get("roleTemplateId") or "")
            if role_name.lower() in _PRIVILEGED_ROLES and principal_id:
                key = (principal_id, role_name)
                if key in seen:
                    continue
                seen.add(key)
                p = principal_by_id.get(principal_id, {})
                principal_kind = _principal_kind_from_record(
                    {"kind": p.get("_kind", "")}
                )
                assignments.append(PrivilegedAssignment(
                    principal_id=principal_id,
                    principal_name=str(
                        p.get("displayName")
                        or p.get("userPrincipalName")
                        or principal_id
                    ),
                    principal_kind=principal_kind,
                    role_name=role_name,
                    role_template_id=template_id,
                    is_external_guest=_is_external_guest(p),
                ))
            continue

        # Embedded role list on a principal record.
        roles = data.get("memberOf") or data.get("MemberOf") or []
        if isinstance(roles, list):
            for r in roles:
                if not isinstance(r, dict):
                    continue
                role_name = str(r.get("displayName") or r.get("roleName") or "")
                if role_name.lower() not in _PRIVILEGED_ROLES:
                    continue
                pid = str(data.get("id") or data.get("objectId") or "").lower()
                if not pid:
                    continue
                key = (pid, role_name)
                if key in seen:
                    continue
                seen.add(key)
                assignments.append(PrivilegedAssignment(
                    principal_id=pid,
                    principal_name=str(
                        data.get("displayName")
                        or data.get("userPrincipalName") or pid
                    ),
                    principal_kind=_principal_kind_from_record(
                        {"kind": kind}
                    ),
                    role_name=role_name,
                    role_template_id=str(r.get("templateId") or ""),
                    is_external_guest=_is_external_guest(data),
                ))

    return assignments


def _resolve_oauth_grants(records: list[dict]) -> list[RiskyOAuthGrant]:
    """Walk records for AppRoleAssignment / OAuth2PermissionGrant entries
    granting high-risk scopes."""
    out: list[RiskyOAuthGrant] = []
    seen: set[str] = set()
    for rec in records:
        kind = (rec.get("kind") or "").lower()
        data = rec.get("data") or {}
        if not isinstance(data, dict):
            continue
        if "oauth2permissiongrant" not in kind and "approleassignment" not in kind:
            continue
        scope_text = (data.get("scope") or data.get("Scope") or "")
        if isinstance(scope_text, str):
            scopes = [s.strip() for s in scope_text.split() if s.strip()]
        elif isinstance(scope_text, list):
            scopes = [str(s).strip() for s in scope_text if str(s).strip()]
        else:
            scopes = []
        # AppRoleAssignment uses "appRoleId" and resourceDisplayName instead
        # of scope. Surface those as scope-equivalents.
        if not scopes and data.get("appRoleId"):
            scopes = [str(data.get("appRoleId"))]

        high_risk = [s for s in scopes if s.lower() in _HIGH_RISK_OAUTH_SCOPES]
        if not high_risk:
            continue

        app_id = str(data.get("clientId")
                     or data.get("principalId")
                     or data.get("id") or "")
        app_name = str(data.get("displayName")
                       or data.get("clientDisplayName")
                       or app_id)
        key = f"{app_id}|{','.join(sorted(high_risk))}"
        if key in seen:
            continue
        seen.add(key)
        out.append(RiskyOAuthGrant(
            app_id=app_id, app_name=app_name,
            consent_type=str(data.get("consentType") or ""),
            scopes=scopes[:25],
            high_risk_scopes=high_risk,
        ))
    return out


def triage(input_path: Path) -> AzureHoundResult:
    """Parse an AzureHound dump and surface the high-signal privileged-access
    facts as an :class:`AzureHoundResult`.

    Args:
        input_path: directory of JSON files, single .json/.jsonl file, or
            .zip bundle produced by AzureHound.
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise AzureHoundError(f"input not found: {input_path}")

    records: list[dict] = []
    for rec in _iter_records(input_path):
        records.append(rec)

    distinct_kinds: dict[str, int] = {}
    for rec in records:
        k = str(rec.get("kind") or "unknown")
        distinct_kinds[k] = distinct_kinds.get(k, 0) + 1

    return AzureHoundResult(
        input_path=input_path,
        record_count=len(records),
        privileged_assignments=_resolve_role_assignments(records),
        risky_oauth_grants=_resolve_oauth_grants(records),
        distinct_kinds=distinct_kinds,
        output_sha256=_sha256_path(input_path),
    )


def looks_like_azurehound_dump(path: Path) -> bool:
    """Quick heuristic: does *path* look like AzureHound output?

    AzureHound JSON records always have ``kind`` strings starting with ``AZ``.
    A short read of the first JSON file is enough to disambiguate from
    arbitrary CSV/JSON evidence.
    """
    if not path.exists():
        return False
    try:
        if path.is_file() and path.suffix.lower() in (".json", ".jsonl"):
            text = path.read_text(encoding="utf-8", errors="replace")[:4096]
            return '"kind"' in text and '"AZ' in text
        if path.is_dir():
            for f in path.glob("*.json"):
                text = f.read_text(encoding="utf-8", errors="replace")[:4096]
                if '"kind"' in text and '"AZ' in text:
                    return True
        if path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist()[:3]:
                    if not name.lower().endswith(".json"):
                        continue
                    with zf.open(name) as f:
                        chunk = f.read(4096).decode("utf-8", errors="replace")
                    if '"kind"' in chunk and '"AZ' in chunk:
                        return True
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError):
        return False
    return False

"""Microsoft-Extractor-Suite (Invictus IR) collector — M365 / Entra ID IR.

Wraps the Microsoft-Extractor-Suite PowerShell module (Invictus, MIT) for
acquisition of M365 + Entra ID forensic artifacts: Unified Audit Log (UAL),
MailItemsAccessed, sign-in logs, OAuth consents, inbox rules. Post-Storm-0558
this is the OSS standard for M365 IR collection alongside CISA's Untitled
Goose Tool.

EL's existing ``m365_audit`` skill PARSES UAL JSON; this skill ACQUIRES it
from a tenant. Different concern — both compose:
    [tenant] -> m365_collect (acquire) -> m365_audit (parse) -> findings

Strictly opt-in via env vars:
    EL_M365_TENANT_ID  (required) — tenant GUID
    EL_M365_APP_ID     (required for app auth) — Entra app registration ID
    EL_M365_APP_SECRET (required for app auth) — app secret
    EL_M365_USERNAME   (alternative — interactive/legacy auth)
    EL_M365_PASSWORD   (alternative — paired with USERNAME, BAD practice
                         but Microsoft-Extractor-Suite supports it)

Collection output goes to a per-case dir; the JSON files there are the
canonical evidence. This wrapper does NOT interpret content — that's
``m365_audit``'s job.

Project: https://github.com/invictus-ir/Microsoft-Extractor-Suite
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class M365CollectError(Exception):
    pass


def _pwsh() -> Path:
    p = shutil.which("pwsh")
    if not p:
        raise M365CollectError(
            "PowerShell 7 (pwsh) not found — install via "
            "`apt install powershell` or follow Microsoft's docs"
        )
    return Path(p)


def is_configured() -> bool:
    """Whether the tenant credentials are present in the environment."""
    if not os.environ.get("EL_M365_TENANT_ID"):
        return False
    if (os.environ.get("EL_M365_APP_ID")
            and os.environ.get("EL_M365_APP_SECRET")):
        return True
    if (os.environ.get("EL_M365_USERNAME")
            and os.environ.get("EL_M365_PASSWORD")):
        return True
    return False


def _sha256_directory(directory: Path, max_files: int = 500) -> str:
    if not directory.is_dir():
        return "0" * 64
    h = hashlib.sha256()
    files = sorted(directory.rglob("*"))[:max_files]
    for f in files:
        if f.is_file():
            try:
                h.update(f.name.encode())
                with f.open("rb") as fh:
                    h.update(fh.read(65536))
            except (PermissionError, OSError):
                continue
    return h.hexdigest()


@dataclass
class M365Collection:
    output_dir: Path
    commands_run: list[str] = field(default_factory=list)
    artifact_count: int = 0
    duration_seconds: float = 0.0
    rc: int = 0
    configured: bool = True
    tenant_id: str = ""
    auth_mode: str = ""        # "app" or "userpass" or ""
    note: str = ""
    stderr_path: Path | None = None

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="m365_collect",
            version="microsoft-extractor-suite-4.x",
            command=" ; ".join(self.commands_run)[:500],
            output_sha256=_sha256_directory(self.output_dir),
            output_path=str(self.output_dir),
            extracted_facts={
                "configured": self.configured,
                "tenant_id": self.tenant_id,
                "auth_mode": self.auth_mode,
                "artifact_count": self.artifact_count,
                "commands_run": self.commands_run,
                "duration_seconds": round(self.duration_seconds, 2),
                "rc": self.rc,
                "note": self.note,
                **extra,
            },
        )


def _build_connect_command() -> str:
    """Compose the appropriate Connect-* PowerShell snippet for the env config."""
    tenant = os.environ.get("EL_M365_TENANT_ID", "")
    app_id = os.environ.get("EL_M365_APP_ID")
    app_secret = os.environ.get("EL_M365_APP_SECRET")
    username = os.environ.get("EL_M365_USERNAME")
    password = os.environ.get("EL_M365_PASSWORD")
    if app_id and app_secret:
        # App-based auth — preferred; non-interactive.
        return (
            f"$secret = ConvertTo-SecureString -String '{app_secret}' "
            f"-AsPlainText -Force ; "
            f"$cred = New-Object System.Management.Automation.PSCredential "
            f"('{app_id}', $secret) ; "
            f"Connect-M365 -TenantId '{tenant}' -Credential $cred"
        )
    if username and password:
        return (
            f"$secret = ConvertTo-SecureString -String '{password}' "
            f"-AsPlainText -Force ; "
            f"$cred = New-Object System.Management.Automation.PSCredential "
            f"('{username}', $secret) ; "
            f"Connect-M365 -Credential $cred"
        )
    raise M365CollectError(
        "no auth configured — set EL_M365_TENANT_ID + "
        "(EL_M365_APP_ID + EL_M365_APP_SECRET) or "
        "(EL_M365_USERNAME + EL_M365_PASSWORD)"
    )


# Default bundle — what an analyst typically wants from a BEC case. Each
# command emits a JSON or CSV file under -OutputDir; the parser
# downstream (m365_audit) consumes the resulting JSONL.
_DEFAULT_COMMANDS: list[tuple[str, str]] = [
    ("Get-UAL",                       "Get-UAL -OutputDir '{out}' -Output JSON"),
    ("Get-MailItemsAccessed",         "Get-MailItemsAccessed -OutputDir '{out}'"),
    ("Get-MessageTraceLog",           "Get-MessageTraceLog -OutputDir '{out}'"),
    ("Get-AdminAuditLog",             "Get-AdminAuditLog -OutputDir '{out}'"),
    ("Get-EntraIDSignInLogs",         "Get-EntraIDSignInLogs -OutputDir '{out}'"),
    ("Get-OAuthPermissionsGraph",     "Get-OAuthPermissionsGraph -OutputDir '{out}'"),
    ("Get-MailboxRules",              "Get-MailboxRules -OutputDir '{out}'"),
    ("Get-InboxRule",                 "Get-InboxRule -OutputDir '{out}'"),
]


def collect(output_dir: Path,
             *, commands: list[tuple[str, str]] | None = None,
             timeout_seconds: int = 3600) -> M365Collection:
    """Run the Microsoft-Extractor-Suite default-collection bundle.

    Args:
        output_dir: per-case directory to receive JSON/CSV outputs.
        commands: list of (label, ps_template) overriding the default bundle.
            Each ps_template may use ``{out}`` as a format placeholder for
            the output directory.
        timeout_seconds: total cap on the PowerShell session.

    Returns a :class:`M365Collection`. When env vars are missing, returns
    ``configured=False`` without invoking PowerShell — caller emits an
    ``insufficient`` finding.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stderr_path = output_dir / "m365_collect.stderr"

    if not is_configured():
        return M365Collection(
            output_dir=output_dir,
            configured=False,
            note=("Microsoft-Extractor-Suite collection skipped — set "
                  "EL_M365_TENANT_ID + (EL_M365_APP_ID/SECRET or "
                  "EL_M365_USERNAME/PASSWORD)"),
        )

    pwsh = _pwsh()
    bundle = commands or _DEFAULT_COMMANDS
    commands_run: list[str] = [name for name, _ in bundle]
    auth_mode = ("app" if os.environ.get("EL_M365_APP_ID")
                 else ("userpass" if os.environ.get("EL_M365_USERNAME")
                       else ""))

    # Compose the full PowerShell session.
    try:
        connect = _build_connect_command()
    except M365CollectError as e:
        return M365Collection(
            output_dir=output_dir, configured=True, note=str(e),
            tenant_id=os.environ.get("EL_M365_TENANT_ID", ""),
            auth_mode=auth_mode,
        )

    out_str = str(output_dir).replace("'", "''")
    body_lines = [
        "Import-Module Microsoft-Extractor-Suite -ErrorAction Stop",
        connect,
    ]
    for _label, template in bundle:
        body_lines.append(template.format(out=out_str))
    body_lines.append("Disconnect-M365")
    script = "\n".join(body_lines)

    started = time.time()
    try:
        with stderr_path.open("wb") as ferr:
            proc = subprocess.run(
                [str(pwsh), "-NoProfile", "-NonInteractive", "-Command", script],
                stdout=subprocess.DEVNULL,
                stderr=ferr,
                timeout=timeout_seconds,
            )
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        return M365Collection(
            output_dir=output_dir, configured=True,
            tenant_id=os.environ.get("EL_M365_TENANT_ID", ""),
            auth_mode=auth_mode,
            commands_run=commands_run,
            stderr_path=stderr_path,
            duration_seconds=time.time() - started,
            rc=124,
            note=f"M365 collection timed out after {timeout_seconds}s",
        )

    duration = time.time() - started
    artifact_count = sum(
        1 for p in output_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in (".json", ".jsonl", ".csv")
    )

    return M365Collection(
        output_dir=output_dir,
        commands_run=commands_run,
        artifact_count=artifact_count,
        duration_seconds=duration,
        rc=rc,
        configured=True,
        tenant_id=os.environ.get("EL_M365_TENANT_ID", ""),
        auth_mode=auth_mode,
        stderr_path=stderr_path,
        note="" if rc == 0 else f"PowerShell rc={rc}; see {stderr_path.name}",
    )

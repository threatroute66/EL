"""Skill: parse User Access Logging (UAL) ESE database files.

Windows Server 2012+ logs per-user / per-service access into
``C:\\Windows\\System32\\LogFiles\\Sum\\<GUID>.mdb`` ESE databases:

- ``SystemIdentity.mdb`` — server identity (hostname, OS) + roles
- ``Current.mdb`` — running per-day client-access table
- ``<year>.mdb`` archives — annual rollups

The CLIENTS table is the analyst pivot: each row is
``(role_id, tenant_id, address, username, days_seen[366], total)``
giving per-day access counts for every (user, source-IP, role) tuple
that authenticated to the server in the year.

Skill wraps ``esedbexport`` (libesedb, SIFT default) — exports each
table to a TSV the caller can stream-parse, plus a metadata block.
Output is parked under ``<analysis>/ual/<mdb-name>/`` so the existing
evidence chain captures it.
"""
from __future__ import annotations

import csv
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


class UalError(RuntimeError):
    pass


@dataclass
class UalAccess:
    """One row of the CLIENTS table — distilled."""
    address: str = ""                  # source IP (str form)
    username: str = ""                 # SID or domain\\user
    role_guid: str = ""                # role being accessed
    total_accesses: int = 0
    first_seen_utc: str = ""           # column "InsertDate"
    last_seen_utc: str = ""            # column "LastAccess"


@dataclass
class UalDatabase:
    path: Path
    export_dir: Path                   # esedbexport-d output dir
    table_files: dict[str, Path] = field(default_factory=dict)
    accesses: list[UalAccess] = field(default_factory=list)
    error: str = ""


def _esedbexport() -> str:
    p = shutil.which("esedbexport")
    if not p:
        raise UalError("esedbexport not on PATH (libesedb-tools)")
    return p


def export_database(mdb: Path, export_dir: Path,
                    timeout: int = 600) -> UalDatabase:
    """Run `esedbexport <mdb>` against a UAL .mdb and parse the
    CLIENTS table if present. Each call writes to a fresh
    `<export_dir>/<mdb_name>.export/` subdir."""
    mdb = Path(mdb)
    export_dir = Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    db = UalDatabase(path=mdb, export_dir=export_dir)
    cmd = [_esedbexport(), "-T", str(export_dir), str(mdb)]
    try:
        r = subprocess.run(cmd, check=False, capture_output=True,
                            text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        db.error = f"esedbexport invocation failed: {e}"
        return db
    if r.returncode != 0:
        db.error = (f"esedbexport rc={r.returncode}: "
                    f"{(r.stderr or '').strip()[-300:]}")
        return db

    # esedbexport produces <mdb>.export/<table>.<idx>
    out_subdir = export_dir / f"{mdb.name}.export"
    if out_subdir.is_dir():
        for f in out_subdir.iterdir():
            if not f.is_file():
                continue
            db.table_files[f.name] = f
        db.accesses = _parse_clients_table(out_subdir)
    return db


def _parse_clients_table(out_subdir: Path) -> list[UalAccess]:
    """Find a CLIENTS table dump (esedbexport names it CLIENTS.<idx>
    or CLIENTS) and parse the canonical UAL columns. Returns at most
    a few hundred rows — the per-day count vector is dropped, only
    the totals + first/last seen are kept."""
    out: list[UalAccess] = []
    for f in out_subdir.iterdir():
        if "client" not in f.name.lower():
            continue
        try:
            with f.open("r", errors="replace") as fh:
                reader = csv.reader(fh, delimiter="\t")
                try:
                    headers = [h.strip() for h in next(reader)]
                except StopIteration:
                    continue
                idx = {h: i for i, h in enumerate(headers)}
                # Column names are stable in libesedb's dump
                # `idx.get(name)` returns the column index (could be 0!),
                # so we use the explicit two-arg form instead of `or`
                # chains — `or` would treat index 0 as falsy and skip
                # the column.
                col_addr = idx.get("Address", -1)
                col_user = -1
                for name in ("AuthenticatedUserName",
                              "authenticated_user_name", "UserName"):
                    if name in idx:
                        col_user = idx[name]
                        break
                col_role = idx.get("RoleGuid", -1)
                col_total = idx.get("TotalAccesses", -1)
                col_first = idx.get("InsertDate", -1)
                col_last = idx.get("LastAccess", -1)
                for row in reader:
                    if not row:
                        continue
                    def _get(col):
                        if col is None or col < 0 or col >= len(row):
                            return ""
                        return row[col].strip()
                    try:
                        total = int(_get(col_total) or 0)
                    except ValueError:
                        total = 0
                    out.append(UalAccess(
                        address=_get(col_addr),
                        username=_get(col_user) if col_user is not None else "",
                        role_guid=_get(col_role),
                        total_accesses=total,
                        first_seen_utc=_get(col_first),
                        last_seen_utc=_get(col_last),
                    ))
                    if len(out) >= 5000:
                        break
        except OSError:
            continue
    out.sort(key=lambda a: -a.total_accesses)
    return out


def is_ual_available() -> bool:
    return bool(shutil.which("esedbexport"))


__all__ = [
    "UalAccess", "UalDatabase", "UalError",
    "export_database", "is_ual_available",
]

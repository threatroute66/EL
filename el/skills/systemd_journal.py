"""Skill: systemd journal parser via `journalctl -o json`.

systemd keeps its binary journal under /var/log/journal/. The
files aren't plain text — they're a custom FSS-signed database.
`journalctl --file <path> -o json` is the canonical reader; we
subprocess-wrap it and emit one JSON line per record.

Two surfaces matter for DFIR:
  1. sshd logins — failed/accepted/invalid-user events
  2. sudo / su escalations — `COMMAND=...` audit trail
  3. unit start/stop of unexpected services (persistence)

When journalctl isn't installed (SIFT is Ubuntu → it's always
available), the caller falls back to a raw binary read that just
scans for known marker strings — strictly low-confidence.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class JournalEntry:
    ts_utc: str                 # ISO-8601
    priority: int               # 0 emerg → 7 debug
    unit: str                   # _SYSTEMD_UNIT (sshd.service, …)
    hostname: str
    syslog_id: str              # SYSLOG_IDENTIFIER
    pid: int                    # _PID
    uid: int                    # _UID (best-effort)
    message: str
    raw: dict = field(default_factory=dict)


class JournalError(RuntimeError):
    pass


def _which() -> str | None:
    return shutil.which("journalctl")


def parse_journal_dir(journal_dir: str | Path,
                       timeout: int = 300) -> list[JournalEntry]:
    """Run journalctl against every .journal file in a dir and return
    structured entries. Empty list on any error — caller decides
    whether that's worth a finding."""
    jd = Path(journal_dir)
    if not jd.is_dir():
        return []
    exe = _which()
    if not exe:
        return []
    journal_files = sorted(jd.rglob("*.journal"))
    if not journal_files:
        return []
    args = [exe, "-o", "json", "--no-pager"]
    for f in journal_files:
        args.extend(["--file", str(f)])
    try:
        r = subprocess.run(args, capture_output=True,
                           timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return []
    if r.returncode != 0:
        return []
    out: list[JournalEntry] = []
    for raw_line in (r.stdout or b"").splitlines():
        if not raw_line.strip():
            continue
        try:
            rec = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        # __REALTIME_TIMESTAMP is microseconds since epoch; fall back
        # to SYSLOG_TIMESTAMP when missing.
        ts = ""
        rt = rec.get("__REALTIME_TIMESTAMP")
        if rt:
            try:
                ts = datetime.fromtimestamp(
                    int(rt) / 1_000_000, tz=timezone.utc).isoformat(
                    timespec="seconds").replace("+00:00", "Z")
            except (OSError, ValueError):
                ts = ""
        try:
            prio = int(rec.get("PRIORITY", 6))
        except (TypeError, ValueError):
            prio = 6
        try:
            pid = int(rec.get("_PID", 0))
        except (TypeError, ValueError):
            pid = 0
        try:
            uid = int(rec.get("_UID", -1))
        except (TypeError, ValueError):
            uid = -1
        out.append(JournalEntry(
            ts_utc=ts, priority=prio,
            unit=str(rec.get("_SYSTEMD_UNIT", "")),
            hostname=str(rec.get("_HOSTNAME", "")),
            syslog_id=str(rec.get("SYSLOG_IDENTIFIER", "")),
            pid=pid, uid=uid,
            message=str(rec.get("MESSAGE", "")),
            raw=rec,
        ))
    return out


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

@dataclass
class SshAuthEvent:
    kind: str               # "failed" / "accepted" / "invalid_user"
    user: str
    source_host: str
    ts_utc: str
    message: str
    pid: int


def extract_ssh_auth(entries: list[JournalEntry]) -> list[SshAuthEvent]:
    """Pull sshd auth events (accepted / failed / invalid-user) from
    the journal stream. These are the core Linux lateral-movement
    signals at the journal layer."""
    out: list[SshAuthEvent] = []
    for e in entries:
        if e.syslog_id != "sshd" and "sshd" not in e.unit:
            continue
        msg = e.message
        kind = ""
        if msg.startswith("Failed password for"):
            kind = "failed"
        elif msg.startswith("Accepted password for") or \
                msg.startswith("Accepted publickey for"):
            kind = "accepted"
        elif "Invalid user" in msg:
            kind = "invalid_user"
        if not kind:
            continue
        # Parse: "Failed password for root from 203.0.113.7 port 22 ssh2"
        #        "Invalid user foo from 1.2.3.4 port 22"
        user = ""
        src = ""
        tokens = msg.split()
        try:
            if "for" in tokens:
                user = tokens[tokens.index("for") + 1]
            elif "user" in tokens:
                user = tokens[tokens.index("user") + 1]
        except (ValueError, IndexError):
            pass
        try:
            if "from" in tokens:
                src = tokens[tokens.index("from") + 1]
        except (ValueError, IndexError):
            pass
        out.append(SshAuthEvent(
            kind=kind, user=user, source_host=src,
            ts_utc=e.ts_utc, message=msg[:200], pid=e.pid))
    return out


@dataclass
class SudoEvent:
    user: str                # invoker
    as_user: str             # target
    command: str
    ts_utc: str
    message: str


def extract_sudo_invocations(entries: list[JournalEntry]) -> list[SudoEvent]:
    """Pull sudo / su escalations. Classic post-compromise pivot
    signal. Format: 'pam_unix(sudo:session): session opened for user'
    or 'COMMAND=/bin/bash' in the MESSAGE."""
    out: list[SudoEvent] = []
    for e in entries:
        if e.syslog_id not in ("sudo", "su"):
            continue
        msg = e.message
        if "COMMAND=" not in msg:
            continue
        # Example: "pat : TTY=pts/0 ; PWD=/home/pat ; USER=root ; COMMAND=/bin/bash"
        invoker = ""
        as_user = ""
        cmd = ""
        if " : " in msg:
            invoker = msg.split(" : ", 1)[0].strip()
        for part in msg.split(";"):
            part = part.strip()
            if part.startswith("USER="):
                as_user = part.split("=", 1)[1]
            elif part.startswith("COMMAND="):
                cmd = part.split("=", 1)[1]
        out.append(SudoEvent(
            user=invoker, as_user=as_user,
            command=cmd, ts_utc=e.ts_utc, message=msg[:200]))
    return out


__all__ = [
    "JournalEntry", "JournalError",
    "SshAuthEvent", "SudoEvent",
    "parse_journal_dir",
    "extract_ssh_auth", "extract_sudo_invocations",
]

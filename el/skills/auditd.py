"""Skill: normalise raw auditd ``audit.log`` lines into structured
records.

Closes gap-doc Linux-depth bullet "Full auditd ausearch normalisation
into structured events" — the existing pattern-scan in
``linux_triage`` only flags strings like ``systemctl stop auditd``;
this skill turns the actual auditd records into queryable
``AuditEvent`` dataclasses ready for the ``linux_forensicator`` to
emit findings against.

Two entry points:

- ``parse_audit_log(path)`` — pure-python tokeniser. No external
  binary required; works on the raw rotated logs we copy under
  ``cases/<id>/raw/linux_artifacts/var_log/audit/`` during intake.
- ``run_ausearch(path, *, key=None, msgtype=None)`` — shells out to
  the system ``ausearch`` (when present) for richer interpretation
  (``-i`` resolves UIDs / syscalls). Returns the same shape as
  ``parse_audit_log`` so callers can swap freely.

Both group multi-record events by their ``msg=audit(<ts>:<serial>)``
key so a SYSCALL + EXECVE + CWD + PATH combo arrives as a single
``AuditEvent`` with a ``records`` list. The convenience accessors
(``executable``, ``argv``, ``user``, ``cwd``) flatten the common
case for downstream rule callers.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


_MSG_RE = re.compile(r"audit\(([\d.]+):(\d+)\)")
_TYPE_RE = re.compile(r"^type=(\S+)\s")
# key="value" | key='value' | key=value (value is an unquoted token).
_KV_RE = re.compile(r'(\w[\w.\-]*)=(?:"((?:[^"\\]|\\.)*)"'
                    r'|\'((?:[^\'\\]|\\.)*)\'|(\S+))')


@dataclass
class AuditRecord:
    """One ``type=...`` line within a multi-record event."""
    type: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    raw: str = ""


@dataclass
class AuditEvent:
    """All records sharing the same ``audit(ts:serial)`` tuple. The
    aggregate is what an analyst actually wants — a single SYSCALL
    decision joined to its EXECVE argv, CWD, PATHs, etc."""
    ts_unix: float = 0.0
    serial: int = 0
    records: list[AuditRecord] = field(default_factory=list)

    @property
    def ts_utc(self) -> datetime:
        return datetime.fromtimestamp(self.ts_unix, tz=timezone.utc)

    @property
    def types(self) -> list[str]:
        return [r.type for r in self.records]

    def first(self, type_name: str) -> AuditRecord | None:
        for r in self.records:
            if r.type == type_name:
                return r
        return None

    def field_(self, name: str) -> str:
        """Return the first occurrence of ``name`` across all records.
        Trailing-underscore name to dodge ``dataclasses.field``."""
        for r in self.records:
            if name in r.fields:
                return r.fields[name]
        return ""

    @property
    def syscall(self) -> str:
        return self.field_("syscall")

    @property
    def success(self) -> str:
        return self.field_("success")

    @property
    def exit(self) -> str:
        return self.field_("exit")

    @property
    def auid(self) -> str:
        return self.field_("auid")

    @property
    def uid(self) -> str:
        return self.field_("uid")

    @property
    def pid(self) -> str:
        return self.field_("pid")

    @property
    def ppid(self) -> str:
        return self.field_("ppid")

    @property
    def comm(self) -> str:
        return self.field_("comm")

    @property
    def exe(self) -> str:
        return self.field_("exe")

    @property
    def cwd(self) -> str:
        return self.field_("cwd")

    @property
    def key(self) -> str:
        """The audit rule's ``-k <key>`` tag (``key=`` field)."""
        return self.field_("key")

    @property
    def argv(self) -> list[str]:
        """EXECVE records carry ``a0=`` ``a1=`` ... — assemble in
        order. Quoted args from ausearch -i and raw hex-encoded args
        from un-interpreted logs are both surfaced as-is."""
        ex = self.first("EXECVE")
        if ex is None:
            return []
        out: list[str] = []
        for i in range(0, 64):
            v = ex.fields.get(f"a{i}")
            if v is None:
                break
            out.append(v)
        return out

    @property
    def paths(self) -> list[str]:
        """PATH records (one per file referenced) — list the names."""
        return [r.fields.get("name", "") for r in self.records
                if r.type == "PATH" and r.fields.get("name")]


def _tokenise(line: str) -> tuple[str, dict[str, str]]:
    """Split a single audit line into (type, kv-dict). Tolerant of
    quoted values, escapes, and the ``a0='single quoted'`` shape
    ausearch -i emits."""
    m = _TYPE_RE.match(line)
    type_name = m.group(1) if m else ""
    kv: dict[str, str] = {}
    for km in _KV_RE.finditer(line):
        k = km.group(1)
        v = km.group(2) or km.group(3) or km.group(4) or ""
        # Don't clobber 'key' with later 'keyfoo=' style false positives.
        if k not in kv:
            kv[k] = v
    return type_name, kv


def _parse_lines(lines):
    """Group lines by (ts, serial) and yield AuditEvent in seen order."""
    buckets: dict[tuple[float, int], AuditEvent] = {}
    order: list[tuple[float, int]] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line or line.lstrip().startswith("#"):
            continue
        m = _MSG_RE.search(line)
        if not m:
            continue
        try:
            ts = float(m.group(1))
        except ValueError:
            continue
        try:
            serial = int(m.group(2))
        except ValueError:
            continue
        type_name, kv = _tokenise(line)
        key = (ts, serial)
        ev = buckets.get(key)
        if ev is None:
            ev = AuditEvent(ts_unix=ts, serial=serial)
            buckets[key] = ev
            order.append(key)
        ev.records.append(AuditRecord(type=type_name, fields=kv, raw=line))
    for k in order:
        yield buckets[k]


def parse_audit_log(path: Path,
                     *, max_events: int = 200_000
                     ) -> list[AuditEvent]:
    """Pure-python tokeniser over a raw or gzipped audit.log file.
    Empty list when the file is missing — the wrapper is
    side-effect-free so ``linux_forensicator`` can call it
    unconditionally."""
    p = Path(path)
    if not p.is_file():
        return []
    if p.suffix == ".gz":
        import gzip
        opener = lambda: gzip.open(p, "rt", errors="replace")
    else:
        opener = lambda: p.open("r", errors="replace")
    out: list[AuditEvent] = []
    with opener() as fh:
        for ev in _parse_lines(fh):
            out.append(ev)
            if len(out) >= max_events:
                break
    return out


def parse_audit_dir(directory: Path,
                     *, max_events: int = 200_000
                     ) -> list[AuditEvent]:
    """Glob ``audit.log*`` under ``directory`` and concatenate their
    parsed events in chronological (ts, serial) order across rotated
    files."""
    d = Path(directory)
    if not d.is_dir():
        return []
    files = sorted(list(d.glob("audit.log"))
                   + list(d.glob("audit.log.*")))
    out: list[AuditEvent] = []
    for f in files:
        out.extend(parse_audit_log(f, max_events=max_events - len(out)))
        if len(out) >= max_events:
            break
    out.sort(key=lambda e: (e.ts_unix, e.serial))
    return out


# --- ausearch wrapper -----------------------------------------------------


def _ausearch_bin() -> str | None:
    return shutil.which("ausearch")


def run_ausearch(path: Path,
                  *, key: str | None = None,
                  msgtype: str | None = None,
                  interpret: bool = True,
                  timeout: int = 60,
                  ) -> tuple[list[AuditEvent], str]:
    """Run ``ausearch -if <file>`` with the requested filter and parse
    its stdout. Returns ``(events, error)``. ``error`` is a non-empty
    string when ausearch is missing or the call failed; ``events``
    falls back to the pure-python parse so callers always get
    structured records."""
    p = Path(path)
    if not p.is_file():
        return [], f"file not found: {p}"
    binr = _ausearch_bin()
    if binr is None:
        return parse_audit_log(p), "ausearch binary not available"
    cmd = [binr, "-if", str(p)]
    if interpret:
        cmd.append("-i")
    if key:
        cmd.extend(["-k", key])
    if msgtype:
        cmd.extend(["-m", msgtype])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return parse_audit_log(p), f"ausearch failed: {e}"
    if proc.returncode != 0 and not proc.stdout:
        return parse_audit_log(p), \
            f"ausearch rc={proc.returncode}: {proc.stderr.strip()[:200]}"
    return list(_parse_lines(proc.stdout.splitlines())), ""


# --- aggregations ---------------------------------------------------------


def by_type(events: list[AuditEvent]) -> dict[str, int]:
    c: dict[str, int] = defaultdict(int)
    for ev in events:
        for t in ev.types:
            c[t] += 1
    return dict(c)


def by_user(events: list[AuditEvent]) -> dict[str, int]:
    """Count events per ``auid`` (the audit-uid that survives su /
    sudo). Falls back to ``uid`` when ``auid`` is unset (e.g. early
    boot)."""
    c: dict[str, int] = defaultdict(int)
    for ev in events:
        u = ev.auid or ev.uid
        if u and u != "unset" and u != "-1" and u != "4294967295":
            c[u] += 1
    return dict(c)


def by_key(events: list[AuditEvent]) -> dict[str, int]:
    """Count events per audit-rule ``-k`` tag. Empty key bucket =
    events from rules without a key (or auto-generated records)."""
    c: dict[str, int] = defaultdict(int)
    for ev in events:
        c[ev.key or "(no-key)"] += 1
    return dict(c)


# Suspicious commands — minimal seed list. Match on basename(exe) or
# argv[0] basename. Keeps false-positive surface low.
_SUSPICIOUS_BASENAMES = {
    "nc", "ncat", "netcat", "socat", "wget", "curl", "tftp",
    "powershell", "pwsh", "msfconsole", "msfvenom",
    "chattr", "shred", "wipe", "dd",
    "iptables", "nft", "ufw",
    "useradd", "usermod", "passwd",
    "auditctl", "service", "systemctl",
    "base64", "xxd",
    "python", "python3", "perl", "ruby", "bash", "sh",
}


def suspicious_executions(events: list[AuditEvent],
                           *, basenames: set[str] | None = None
                           ) -> list[AuditEvent]:
    """Return EXECVE-bearing events whose argv[0] / exe basename is
    in the watchlist. Defaults to a minimal seed list of post-exploit
    favourites + tools commonly abused for persistence; callers can
    pass their own set."""
    watch = basenames or _SUSPICIOUS_BASENAMES
    out: list[AuditEvent] = []
    for ev in events:
        if "EXECVE" not in ev.types:
            continue
        argv = ev.argv
        exe = ev.exe
        cands: list[str] = []
        if argv:
            cands.append(argv[0])
        if exe:
            cands.append(exe)
        hit = False
        for c in cands:
            base = c.rsplit("/", 1)[-1]
            if base in watch:
                hit = True
                break
        if hit:
            out.append(ev)
    return out


__all__ = [
    "AuditRecord", "AuditEvent",
    "parse_audit_log", "parse_audit_dir",
    "run_ausearch",
    "by_type", "by_user", "by_key",
    "suspicious_executions",
]

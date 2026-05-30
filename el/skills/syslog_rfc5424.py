"""RFC 5424 syslog parser (with a light RFC 3164/BSD fallback).

Modern Linux daemons emit RFC 5424 syslog::

    <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    <30>1 2024-05-14T12:00:10.274719Z WEB-BO-01 polkitd 54246 - - <message>

``PRI`` encodes facility (PRI // 8) and severity (PRI % 8). This parser pulls
host / app / procid / severity and the message, normalising the timestamp to
UTC, and exposes per-app and per-severity views. Cisco ASA's BSD-syslog has
its own richer parser (:mod:`el.skills.cisco_asa`); this covers generic host
syslog. Pure-Python, read-only.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_SEVERITY = {0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warning",
             5: "notice", 6: "info", 7: "debug"}

# <PRI>VER TIMESTAMP HOST APP PROCID MSGID  <rest = SD + MSG>
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d+)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$")
# BSD/RFC3164 fallback: <PRI>Mon DD HH:MM:SS HOST TAG: MSG
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>\w{3}\s+\d+\s+\d{1,2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<app>[^:\[\s]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")


class SyslogError(Exception):
    pass


def _ts_to_utc(ts: str) -> str:
    if not ts or ts == "-":
        return ""
    s = ts.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ""


def _split_sd_msg(rest: str) -> tuple[str, str]:
    """Split STRUCTURED-DATA from MSG. SD is '-' or one-or-more '[...]'."""
    rest = rest.lstrip()
    if rest.startswith("-"):
        return "-", rest[1:].lstrip()
    if rest.startswith("["):
        depth = 0
        for i, ch in enumerate(rest):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    return rest[: i + 1], rest[i + 1:].lstrip()
    return "", rest


@dataclass
class SyslogEvent:
    timestamp_utc: str = ""
    host: str = ""
    app: str = ""
    procid: str = ""
    msgid: str = ""
    facility: int | None = None
    severity: int | None = None
    severity_name: str = ""
    message: str = ""

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SyslogRun:
    src_path: Path
    events: list[SyslogEvent] = field(default_factory=list)
    parsed: int = 0
    skipped: int = 0
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return len(self.events)

    def by_app(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.events:
            out[e.app] = out.get(e.app, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.events:
            out[e.severity_name or "?"] = out.get(e.severity_name or "?", 0) + 1
        return out

    def high_severity(self, threshold: int = 3) -> list[SyslogEvent]:
        """severity <= threshold (0 emerg … 3 err)."""
        return [e for e in self.events
                if e.severity is not None and e.severity <= threshold]

    def find(self, needle: str) -> list[SyslogEvent]:
        t = needle.lower()
        return [e for e in self.events
                if t in e.message.lower() or t in e.app.lower()]

    def date_range(self) -> tuple[str, str]:
        ds = [e.timestamp_utc for e in self.events if e.timestamp_utc]
        return (min(ds), max(ds)) if ds else ("", "")

    def as_evidence(self, *, facts: dict | None = None):
        from el.schemas.finding import EvidenceItem
        extra = facts or {}
        lo, hi = self.date_range()
        return EvidenceItem(
            tool="el.syslog_rfc5424", version="0.1.0",
            command=f"parse syslog -- {self.src_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.src_path),
            extracted_facts={
                "src_path": str(self.src_path),
                "event_count": self.total,
                "by_app": dict(list(self.by_app().items())[:12]),
                "by_severity": self.by_severity(),
                "first_event_utc": lo, "last_event_utc": hi,
                **extra,
            },
        )


def _event_from_match(m, kind: str) -> SyslogEvent:
    pri = int(m.group("pri"))
    sev = pri % 8
    fac = pri // 8
    if kind == "5424":
        _sd, msg = _split_sd_msg(m.group("rest"))
        return SyslogEvent(
            timestamp_utc=_ts_to_utc(m.group("ts")), host=m.group("host"),
            app=m.group("app"), procid=m.group("procid"),
            msgid=m.group("msgid"), facility=fac, severity=sev,
            severity_name=_SEVERITY.get(sev, ""), message=msg)
    return SyslogEvent(  # 3164
        timestamp_utc="", host=m.group("host"), app=m.group("app"),
        facility=fac, severity=sev, severity_name=_SEVERITY.get(sev, ""),
        message=m.group("msg"))


def parse(path: Path, output_dir: Path | None = None) -> SyslogRun:
    path = Path(path)
    if not path.is_file():
        raise SyslogError(f"syslog file not found: {path}")

    run = SyslogRun(src_path=path)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = _RFC5424.match(line)
            kind = "5424"
            if not m:
                m = _RFC3164.match(line)
                kind = "3164"
            if not m:
                run.skipped += 1
                continue
            run.parsed += 1
            run.events.append(_event_from_match(m, kind))

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "syslog_events.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for e in run.events:
                f.write(json.dumps(e.as_dict(), ensure_ascii=False) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run

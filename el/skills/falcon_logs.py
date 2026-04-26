"""Skill: parse CrowdStrike Falcon EDR JSON-line logs into
structured ``FalconEvent`` records.

Closes the gap-doc bullet "CrowdStrike Falcon EDR log support". EL's
prior coverage was Sysmon + Windows Security via EvtxECmd; Falcon
shows up at every real enterprise IR engagement and is the dominant
EDR telemetry shape in the Splunk ``attack_data`` corpus.

Format: one JSON object per line. The ``event_simpleName`` field
keys the schema — different families carry different fields:

  ProcessRollup2          → CommandLine, ImageFileName, ParentBaseFileName,
                            UserSid, RawProcessId, SHA256HashData
  ProcessHandleOpDetectInfo → SourceProcessId, TargetProcessImageFileName,
                              GrantedAccess (lsass-dump fingerprint)
  DnsRequest              → DomainName, RequestType
  NetworkConnect{IP4,IP6} → RemoteAddressIP4 / RemotePort
  FileWritten / FileDeleteInfo → TargetFileName
  DmpFileWritten          → TargetFileName, ContextProcessId
  ScriptControlScanResult → ScriptContent, ScriptContentName

The skill returns ``FalconEvent`` dataclasses with the JSON payload
preserved in ``data`` so callers can pattern-match without
re-parsing. Common-field accessors (image, command_line,
target_image, granted_access, query_name) work across the
ProcessRollup / ProcessHandleOp / DnsRequest variants.
"""
from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


@dataclass
class FalconEvent:
    event_name: str = ""             # event_simpleName
    aid: str = ""                     # agent ID (host)
    cid: str = ""                     # customer ID
    ts_unix: float = 0.0              # parsed from timestamp (ms) or ContextTimeStamp
    data: dict = field(default_factory=dict)

    @property
    def ts_utc(self) -> str:
        if not self.ts_unix:
            return ""
        return datetime.fromtimestamp(
            self.ts_unix, tz=timezone.utc).isoformat()

    @property
    def image(self) -> str:
        # ProcessRollup2 carries ImageFileName; ProcessHandleOp uses
        # ContextImageFileName. Normalise to a single accessor.
        return (self.data.get("ImageFileName", "")
                or self.data.get("ContextImageFileName", ""))

    @property
    def parent_image(self) -> str:
        return self.data.get("ParentBaseFileName", "")

    @property
    def grandparent_image(self) -> str:
        return self.data.get("GrandParentBaseFileName", "")

    @property
    def command_line(self) -> str:
        return (self.data.get("CommandLine", "")
                or self.data.get("WindowTitle", ""))

    @property
    def target_image(self) -> str:
        return (self.data.get("TargetProcessImageFileName", "")
                or self.data.get("TargetImageFileName", ""))

    @property
    def target_file(self) -> str:
        return self.data.get("TargetFileName", "")

    @property
    def granted_access(self) -> str:
        return self.data.get("GrantedAccess", "")

    @property
    def process_id(self) -> str:
        return (str(self.data.get("RawProcessId", ""))
                or str(self.data.get("ContextProcessId", "")))

    @property
    def query_name(self) -> str:
        return self.data.get("DomainName", "")

    @property
    def remote_ip(self) -> str:
        return (self.data.get("RemoteAddressIP4", "")
                or self.data.get("RemoteAddressIP6", ""))

    @property
    def remote_port(self) -> str:
        return str(self.data.get("RemotePort", ""))

    @property
    def sha256(self) -> str:
        return self.data.get("SHA256HashData", "").lower()


def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    return path.open("r", errors="replace")


def parse_event(line: str) -> FalconEvent | None:
    """Parse one Falcon JSON line. Returns None if the line isn't
    a JSON object or lacks ``event_simpleName``."""
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(d, dict):
        return None
    name = d.get("event_simpleName", "")
    if not name:
        return None
    # Falcon emits two different time fields:
    #   timestamp          → milliseconds since epoch (string)
    #   ContextTimeStamp   → seconds since epoch (string, with decimals)
    ts: float = 0.0
    raw_ts = d.get("ContextTimeStamp") or d.get("timestamp")
    if raw_ts:
        try:
            v = float(raw_ts)
            # >1e12 = milliseconds; otherwise seconds
            ts = v / 1000.0 if v > 1e12 else v
        except (TypeError, ValueError):
            ts = 0.0
    return FalconEvent(
        event_name=name,
        aid=d.get("aid", ""),
        cid=d.get("cid", ""),
        ts_unix=ts,
        data=d,
    )


def iter_events(path: Path,
                 *, max_events: int = 1_000_000
                 ) -> Iterator[FalconEvent]:
    """Stream Falcon events from a ``.log`` / ``.log.gz`` file.
    Empty iterator when the file is missing — wrapper is
    side-effect-free."""
    p = Path(path)
    if not p.is_file():
        return
    seen = 0
    with _open(p) as fh:
        for line in fh:
            ev = parse_event(line)
            if ev is None:
                continue
            yield ev
            seen += 1
            if seen >= max_events:
                return


def parse_file(path: Path,
                *, max_events: int = 1_000_000
                ) -> list[FalconEvent]:
    return list(iter_events(path, max_events=max_events))


# --- aggregations / detectors ------------------------------------------


def by_event_name(events: list[FalconEvent]) -> dict[str, int]:
    out: dict[str, int] = {}
    for e in events:
        out[e.event_name] = out.get(e.event_name, 0) + 1
    return out


def filter_event(events: list[FalconEvent], name: str
                  ) -> list[FalconEvent]:
    return [e for e in events if e.event_name == name]


# Same benign-source list as the Sysmon side. Falcon paths use
# the \\Device\\HarddiskVolumeN\\... form; basename match still
# works because we split on the trailing backslash.
_LSASS_BENIGN_SOURCE_BASENAMES = frozenset({
    "svchost.exe", "services.exe", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "lsass.exe",
    "msmpeng.exe", "mssense.exe", "securityhealthservice.exe",
    "taskhostw.exe", "runtimebroker.exe", "searchindexer.exe",
    "wermgr.exe",
    "sysmon.exe", "sysmon64.exe",
    "procexp.exe", "procexp64.exe", "taskmgr.exe",
})


def find_lsass_handles(events: list[FalconEvent]
                        ) -> list[FalconEvent]:
    """ProcessHandleOpDetectInfo against lsass.exe from a
    NON-system source. Falcon's detector itself fires only on
    suspicious handle-ops, but the corpus contains some benign
    SYSTEM-source events too — the basename filter keeps parity
    with the Sysmon side."""
    out: list[FalconEvent] = []
    for e in events:
        if e.event_name != "ProcessHandleOpDetectInfo":
            continue
        target = e.target_image.lower()
        if not target.endswith("\\lsass.exe"):
            continue
        source = e.image.lower()
        source_base = source.rsplit("\\", 1)[-1] if source else ""
        if source_base in _LSASS_BENIGN_SOURCE_BASENAMES:
            continue
        granted = e.granted_access.lower()
        if not granted or granted == "0x1000":
            continue
        out.append(e)
    return out


def find_lsass_dump_files(events: list[FalconEvent]
                           ) -> list[FalconEvent]:
    """DmpFileWritten / FileWritten where the target filename
    contains 'lsass' — the after-the-fact persistence side of
    T1003.001 (the dump file landing on disk). Falcon often
    catches this even when Sysmon EID 10 missed the handle
    open."""
    out: list[FalconEvent] = []
    for e in events:
        if e.event_name not in ("DmpFileWritten", "FileWritten"):
            continue
        f = e.target_file.lower()
        if "lsass" in f and (f.endswith(".dmp") or "dump" in f):
            out.append(e)
    return out


def find_process_creates(events: list[FalconEvent],
                          *, image_substr: str | None = None,
                          cmdline_substr: str | None = None,
                          ) -> list[FalconEvent]:
    """ProcessRollup2 (and its Synthetic variant) filtered by image
    or command-line substring. Both filters case-insensitive."""
    out: list[FalconEvent] = []
    img_n = (image_substr or "").lower() or None
    cl_n = (cmdline_substr or "").lower() or None
    for e in events:
        if e.event_name not in ("ProcessRollup2",
                                  "SyntheticProcessRollup2"):
            continue
        img = e.image.lower()
        cl = e.command_line.lower()
        if img_n and img_n not in img:
            continue
        if cl_n and cl_n not in cl:
            continue
        out.append(e)
    return out


def find_dns_queries(events: list[FalconEvent],
                      *, query_substr: str | None = None
                      ) -> list[FalconEvent]:
    """DnsRequest events optionally filtered by domain substring."""
    out: list[FalconEvent] = []
    n = (query_substr or "").lower() or None
    for e in events:
        if e.event_name != "DnsRequest":
            continue
        if n and n not in e.query_name.lower():
            continue
        out.append(e)
    return out


__all__ = [
    "FalconEvent",
    "parse_event", "iter_events", "parse_file",
    "by_event_name", "filter_event",
    "find_lsass_handles", "find_lsass_dump_files",
    "find_process_creates", "find_dns_queries",
]

"""Skill: parse Sysmon XML-stream logs (raw winlogbeat / Splunk
``XmlWinEventLog`` shape) into structured ``SysmonEvent`` records.

Closes the gap-doc bullet "Sysmon XML-stream parser companion to the
EVTX path". EL's existing Windows-side detection consumes native
EVTX via EvtxECmd, but the wider corpus — Splunk ``attack_data``,
SOC log-shippers, Sysmon-on-Linux exports — distributes Sysmon
records as **XML text streams**, one ``<Event …/>`` per line. This
skill reads those streams without requiring an EVTX round-trip.

The parser is regex-driven (deliberately — Sysmon XML is loose
enough that ``xml.etree.ElementTree`` chokes on real-world streams
with unescaped entities, and the per-record schema is small enough
to extract by name). One ``SysmonEvent`` per record; the
``data`` dict carries every ``<Data Name='X'>v</Data>`` pair as
``X → v`` so callers can pattern-match without re-parsing.

Common Sysmon EIDs we extract:
- 1   ProcessCreate
- 3   NetworkConnection
- 5   ProcessTerminate
- 6   DriverLoad
- 7   ImageLoad
- 8   CreateRemoteThread
- 10  ProcessAccess          (LSASS-handle credential dumping)
- 11  FileCreate
- 12/13/14  RegistryEvents
- 22  DnsQuery
- 23  FileDelete (archived)

The skill returns dataclasses; downstream agents emit Findings with
the EID + matched fields as ``EvidenceItem.extracted_facts``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


_EVENT_RE = re.compile(r"<Event\b.*?</Event>", re.DOTALL)
_EID_RE = re.compile(r"<EventID>(\d+)</EventID>")
_TIME_RE = re.compile(r"<TimeCreated\s+SystemTime='([^']+)'")
_COMPUTER_RE = re.compile(r"<Computer>([^<]+)</Computer>")
_DATA_RE = re.compile(
    r"<Data Name='([^']+)'>([^<]*)</Data>")


# Friendly names for the EIDs we expect to surface. Anything not in
# this map still parses — name just stays empty.
EID_NAMES: dict[int, str] = {
    1:  "ProcessCreate",
    2:  "FileCreateTimeChanged",
    3:  "NetworkConnection",
    4:  "SysmonStateChange",
    5:  "ProcessTerminate",
    6:  "DriverLoad",
    7:  "ImageLoad",
    8:  "CreateRemoteThread",
    9:  "RawAccessRead",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryEventCreateDelete",
    13: "RegistryEventValueSet",
    14: "RegistryEventKeyRename",
    15: "FileCreateStreamHash",
    16: "ServiceConfigChange",
    17: "PipeCreated",
    18: "PipeConnected",
    19: "WmiEventFilter",
    20: "WmiEventConsumer",
    21: "WmiEventConsumerToFilter",
    22: "DnsQuery",
    23: "FileDeleteArchived",
    24: "ClipboardChange",
    25: "ProcessTampering",
    26: "FileDeleteLogged",
    27: "FileBlockExecutable",
    28: "FileBlockShredding",
    29: "FileExecutableDetected",
}


@dataclass
class SysmonEvent:
    eid: int = 0
    name: str = ""                     # human-readable EID label
    ts_utc: str = ""                   # ISO-8601 string from TimeCreated
    computer: str = ""
    data: dict[str, str] = field(default_factory=dict)
    raw_offset: int = 0                # byte position in source file

    # Convenience — most detectors care about a small subset of
    # the per-EID Data fields. These accessors normalise across the
    # variants Sysmon configs emit (with/without certain fields).
    @property
    def image(self) -> str:
        return (self.data.get("Image", "")
                or self.data.get("SourceImage", ""))

    @property
    def parent_image(self) -> str:
        return self.data.get("ParentImage", "")

    @property
    def target_image(self) -> str:
        return self.data.get("TargetImage", "")

    @property
    def command_line(self) -> str:
        return self.data.get("CommandLine", "")

    @property
    def process_id(self) -> str:
        return (self.data.get("ProcessId", "")
                or self.data.get("SourceProcessId", ""))

    @property
    def parent_process_id(self) -> str:
        return self.data.get("ParentProcessId", "")

    @property
    def user(self) -> str:
        return self.data.get("User", "")

    @property
    def query_name(self) -> str:
        return self.data.get("QueryName", "")

    @property
    def destination(self) -> str:
        return (self.data.get("DestinationIp", "")
                or self.data.get("DestinationHostname", ""))


def parse_event(blob: str) -> SysmonEvent | None:
    """Parse one ``<Event …/>`` blob. Returns None if the blob lacks
    an EventID (corruption / partial line)."""
    m_eid = _EID_RE.search(blob)
    if m_eid is None:
        return None
    try:
        eid = int(m_eid.group(1))
    except ValueError:
        return None
    m_t = _TIME_RE.search(blob)
    m_c = _COMPUTER_RE.search(blob)
    data: dict[str, str] = {}
    for km in _DATA_RE.finditer(blob):
        name, value = km.group(1), km.group(2)
        if name not in data:
            data[name] = value
    return SysmonEvent(
        eid=eid, name=EID_NAMES.get(eid, ""),
        ts_utc=m_t.group(1) if m_t else "",
        computer=m_c.group(1) if m_c else "",
        data=data,
    )


def iter_events(path: Path,
                 *, max_events: int = 1_000_000
                 ) -> Iterator[SysmonEvent]:
    """Stream Sysmon events from a ``.log`` file (or `.gz`).

    Sysmon-stream lines aren't always one-event-per-line — long
    CallTrace / hash blocks wrap. We tokenise on the
    ``<Event …</Event>`` regex so multi-line records reassemble
    correctly. Empty list when the file is missing — wrapper is
    side-effect-free."""
    p = Path(path)
    if not p.is_file():
        return
    if p.suffix == ".gz":
        import gzip
        opener = lambda: gzip.open(p, "rt", errors="replace")
    else:
        opener = lambda: p.open("r", errors="replace")
    seen = 0
    with opener() as fh:
        # Read in chunks; reassemble across boundaries by carrying
        # the trailing partial-record in a buffer.
        buf = ""
        for chunk in iter(lambda: fh.read(1 << 20), ""):
            buf += chunk
            last_end = 0
            for m in _EVENT_RE.finditer(buf):
                ev = parse_event(m.group(0))
                if ev is not None:
                    ev.raw_offset = m.start()
                    yield ev
                    seen += 1
                    if seen >= max_events:
                        return
                last_end = m.end()
            buf = buf[last_end:]
        # tail
        for m in _EVENT_RE.finditer(buf):
            ev = parse_event(m.group(0))
            if ev is not None:
                yield ev
                seen += 1
                if seen >= max_events:
                    return


def parse_file(path: Path,
                *, max_events: int = 1_000_000
                ) -> list[SysmonEvent]:
    """Eager wrapper — collect all events. Use ``iter_events`` for
    streaming over large logs."""
    return list(iter_events(path, max_events=max_events))


# --- aggregations / helpers --------------------------------------------


def by_eid(events: list[SysmonEvent]) -> dict[int, int]:
    out: dict[int, int] = {}
    for e in events:
        out[e.eid] = out.get(e.eid, 0) + 1
    return out


def filter_eid(events: list[SysmonEvent], eid: int
                 ) -> list[SysmonEvent]:
    return [e for e in events if e.eid == eid]


# System processes that legitimately handle lsass continuously —
# the local session manager, csrss, wininit, services control,
# Defender, etc. Sysmon EID 10 against lsass from these basenames
# is background noise, not credential dumping. Restrict the
# detector to NON-system source images.
_LSASS_BENIGN_SOURCE_BASENAMES = frozenset({
    "svchost.exe", "services.exe", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "lsass.exe",
    "msmpeng.exe", "mssense.exe", "securityhealthservice.exe",
    "taskhostw.exe", "runtimebroker.exe", "searchindexer.exe",
    "wermgr.exe", "system",
    # Sysmon itself opens lsass briefly for telemetry
    "sysmon.exe", "sysmon64.exe",
    # Process Explorer / similar admin tools — operator-attended
    # rather than attacker-typical
    "procexp.exe", "procexp64.exe", "taskmgr.exe",
})

# Access masks that indicate read-of-memory intent. Anything
# strictly less is QueryLimitedInformation-class background.
_LSASS_DUMPING_MASKS = frozenset({
    "0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff",
    "0x101010", "0x1410ff", "0x143aff",
})


def find_lsass_handles(events: list[SysmonEvent],
                        *, strict_mask: bool = True
                        ) -> list[SysmonEvent]:
    """ProcessAccess (EID 10) targeting lsass.exe from a NON-system
    source process with a memory-read access mask. The fingerprint
    of ``T1003.001`` (LSASS dumping).

    Strict-mask mode (default) requires the GrantedAccess to be in
    the canonical creddump set (0x1410, 0x1438, 0x1fffff,
    PROCESS_VM_READ-bearing variants). Non-strict mode keeps the
    older "any non-0x1000" behaviour for callers that want a wider
    net.
    """
    out: list[SysmonEvent] = []
    for e in events:
        if e.eid != 10:
            continue
        target = e.data.get("TargetImage", "").lower()
        if not target.endswith("\\lsass.exe"):
            continue
        source = e.data.get("SourceImage", "").lower()
        source_base = source.rsplit("\\", 1)[-1] if source else ""
        if source_base in _LSASS_BENIGN_SOURCE_BASENAMES:
            continue
        granted = e.data.get("GrantedAccess", "").lower()
        if not granted or granted == "0x1000":
            continue
        if strict_mask and granted not in _LSASS_DUMPING_MASKS:
            continue
        out.append(e)
    return out


def find_process_creates(events: list[SysmonEvent],
                          *, image_substr: str | None = None,
                          cmdline_substr: str | None = None,
                          ) -> list[SysmonEvent]:
    """ProcessCreate (EID 1) filtered by image basename or command-
    line substring. Both filters are case-insensitive."""
    out: list[SysmonEvent] = []
    img_n = (image_substr or "").lower() or None
    cl_n = (cmdline_substr or "").lower() or None
    for e in events:
        if e.eid != 1:
            continue
        img = e.image.lower()
        cl = e.command_line.lower()
        if img_n and img_n not in img:
            continue
        if cl_n and cl_n not in cl:
            continue
        out.append(e)
    return out


def find_dns_queries(events: list[SysmonEvent],
                      *, query_substr: str | None = None
                      ) -> list[SysmonEvent]:
    """DnsQuery (EID 22), optionally filtered by a substring of the
    queried name. Useful for C2-callback fingerprinting."""
    out: list[SysmonEvent] = []
    n = (query_substr or "").lower() or None
    for e in events:
        if e.eid != 22:
            continue
        if n and n not in e.query_name.lower():
            continue
        out.append(e)
    return out


__all__ = [
    "EID_NAMES",
    "SysmonEvent",
    "parse_event", "iter_events", "parse_file",
    "by_eid", "filter_eid",
    "find_lsass_handles", "find_process_creates", "find_dns_queries",
]

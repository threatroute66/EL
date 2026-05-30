"""Windows Event Log XML parser — pre-exported ``.evtx`` → XML.

EL's normal EVTX path is binary ``.evtx`` → EvtxECmd → CSV. But event logs
are often delivered already exported to XML (``wevtutil``, PowerShell
``Get-WinEvent | … | Export``, SIEM pulls) as
``<Events><Event xmlns="…/event"> … </Event></Events>``. EvtxECmd cannot read
that. This parses the XML directly — Security and Sysmon channels alike —
pulling EventID, time, computer, provider, channel and the
``EventData/Data`` name→value pairs.

Streamed with ``iterparse`` (clears each element) so multi-hundred-MB exports
parse in bounded memory. Pure-Python, read-only.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

# Channel-agnostic high-value Event IDs (Security + Sysmon).
LOGON_IDS = {"4624", "4625", "4634", "4647", "4648", "4672"}
PROCESS_IDS = {"4688", "4689", "1"}          # Security 4688/4689, Sysmon 1
NETWORK_IDS = {"5156", "5158", "3"}          # WFP + Sysmon 3


class EvtxXmlError(Exception):
    pass


def _local(tag: str) -> str:
    """Strip an XML namespace: '{ns}EventID' -> 'EventID'."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


@dataclass
class EvtxXmlEvent:
    event_id: str = ""
    time_utc: str = ""
    computer: str = ""
    provider: str = ""
    channel: str = ""
    level: str = ""
    data: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"event_id": self.event_id, "time_utc": self.time_utc,
                "computer": self.computer, "provider": self.provider,
                "channel": self.channel, "level": self.level,
                "data": self.data}


@dataclass
class EvtxXmlRun:
    src_path: Path
    events: list[EvtxXmlEvent] = field(default_factory=list)
    parsed: int = 0
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return len(self.events)

    def by_event_id(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.events:
            out[e.event_id] = out.get(e.event_id, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def by_provider(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.events:
            out[e.provider] = out.get(e.provider, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def with_id(self, *ids: str) -> list[EvtxXmlEvent]:
        s = set(ids)
        return [e for e in self.events if e.event_id in s]

    def logons(self) -> list[EvtxXmlEvent]:
        return [e for e in self.events if e.event_id in LOGON_IDS]

    def process_creations(self) -> list[EvtxXmlEvent]:
        return [e for e in self.events if e.event_id in PROCESS_IDS]

    def find(self, needle: str) -> list[EvtxXmlEvent]:
        t = needle.lower()
        out = []
        for e in self.events:
            if any(t in str(v).lower() for v in e.data.values()):
                out.append(e)
        return out

    def date_range(self) -> tuple[str, str]:
        ds = [e.time_utc for e in self.events if e.time_utc]
        return (min(ds), max(ds)) if ds else ("", "")

    def as_evidence(self, *, facts: dict | None = None):
        from el.schemas.finding import EvidenceItem
        extra = facts or {}
        lo, hi = self.date_range()
        return EvidenceItem(
            tool="el.evtx_xml", version="0.1.0",
            command=f"parse exported Windows Event XML -- {self.src_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.src_path),
            extracted_facts={
                "src_path": str(self.src_path),
                "event_count": self.total,
                "top_event_ids": dict(list(self.by_event_id().items())[:15]),
                "providers": dict(list(self.by_provider().items())[:8]),
                "logon_events": len(self.logons()),
                "process_events": len(self.process_creations()),
                "first_event_utc": lo, "last_event_utc": hi,
                **extra,
            },
        )


def _parse_event(elem) -> EvtxXmlEvent:
    ev = EvtxXmlEvent()
    for child in elem:
        tag = _local(child.tag)
        if tag == "System":
            for s in child:
                st = _local(s.tag)
                if st == "EventID":
                    ev.event_id = (s.text or "").strip()
                elif st == "TimeCreated":
                    ev.time_utc = _normalise_time(
                        s.attrib.get("SystemTime", ""))
                elif st == "Computer":
                    ev.computer = (s.text or "").strip()
                elif st == "Provider":
                    ev.provider = s.attrib.get("Name", "")
                elif st == "Channel":
                    ev.channel = (s.text or "").strip()
                elif st == "Level":
                    ev.level = (s.text or "").strip()
        elif tag in ("EventData", "UserData"):
            idx = 0
            for d in child.iter():
                if _local(d.tag) != "Data":
                    continue
                name = d.attrib.get("Name")
                if not name:
                    idx += 1
                    name = f"Data{idx}"
                ev.data[name] = (d.text or "").strip()
    return ev


def _normalise_time(systemtime: str) -> str:
    """'2024-05-14T12:00:07.6293825Z' -> '2024-05-14 12:00:07' (UTC)."""
    if not systemtime:
        return ""
    s = systemtime.replace("T", " ").rstrip("Z")
    return s.split(".")[0]


def parse(path: Path, output_dir: Path | None = None,
          *, max_events: int = 5_000_000) -> EvtxXmlRun:
    """Parse an exported Windows Event-log XML file. Streamed; lenient on
    malformed events. Writes a JSONL dump under *output_dir* when given."""
    path = Path(path)
    if not path.is_file():
        raise EvtxXmlError(f"Event XML not found: {path}")

    run = EvtxXmlRun(src_path=path)
    try:
        for _evt, elem in ET.iterparse(str(path), events=("end",)):
            if _local(elem.tag) != "Event":
                continue
            run.parsed += 1
            try:
                if run.total < max_events:
                    run.events.append(_parse_event(elem))
            finally:
                elem.clear()
    except ET.ParseError as e:
        if not run.events:
            raise EvtxXmlError(f"XML parse error in {path}: {e}") from e
        # partial parse — keep what we got (truncated export)

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / (path.stem + "_events.jsonl")
        with out.open("w", encoding="utf-8") as f:
            for e in run.events:
                f.write(json.dumps(e.as_dict(), ensure_ascii=False) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run

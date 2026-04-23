"""Skill: Windows XP / 2003 legacy event-log (.evt) parser.

Wraps `evtexport` from libevt. Pre-Vista event logs are in the binary
`.evt` format (not `.evtx`) and are NOT readable by EvtxECmd — this
is why the M57-Jean run landed `credential_analyst` + `lateral_movement
_analyst` on confidence=insufficient (no evtx_parsed.csv). This skill
produces an evtx-shaped CSV so those downstream agents have something
to consume.

Output: a CSV with the same columns EvtxECmd emits, good enough for
the SIGMA engine + credential / lateral movement detectors:
  RecordNumber, EventRecordId, TimeCreated, Channel, Provider,
  EventId, Level, Computer, UserId, UserName, ExecutableInfo,
  MapDescription, PayloadData1..6, Payload
"""
from __future__ import annotations

import csv
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


@dataclass
class EvtRun:
    source_path: Path
    csv_path: Path
    rc: int
    event_count: int = 0
    raw_path: Path | None = None

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        import hashlib
        sha = "0" * 64
        if self.csv_path.is_file():
            sha = hashlib.sha256(self.csv_path.read_bytes()).hexdigest()
        base = {"source": str(self.source_path),
                "event_count": self.event_count, "rc": self.rc,
                "csv_path": str(self.csv_path)}
        if facts:
            base.update(facts)
        return EvidenceItem(
            tool="evtexport", version="libevt-20240421",
            command=f"evtexport {self.source_path}",
            output_sha256=sha, output_path=str(self.csv_path),
            extracted_facts=base,
        )


class XpEvtError(RuntimeError):
    pass


def _which() -> str:
    p = shutil.which("evtexport")
    if not p:
        raise XpEvtError(
            "evtexport not on PATH — apt install libevt-tools")
    return p


def _export_stdout(evt_path: Path, out_dir: Path,
                    timeout: int = 300) -> tuple[Path, int]:
    """Run evtexport against a single .evt, capture stdout to out_dir.
    Returns (raw stdout path, subprocess rc)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = out_dir / f"{evt_path.name}.raw.txt"
    exe = _which()
    try:
        r = subprocess.run(
            [exe, str(evt_path)],
            capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        raw.write_bytes(b"")
        return raw, -2
    raw.write_bytes(r.stdout or b"")
    return raw, r.returncode


_EVENT_HEAD_RE = re.compile(
    r"^Event number\s*:\s*(\d+)", re.MULTILINE)
_KV_RE = re.compile(
    r"^([\w ()]+?)\s*:\s*(.*)$", re.MULTILINE)
_STRING_RE = re.compile(
    r"^String:\s*(\d+)\s*:\s*(.*)$", re.MULTILINE)
_EVENT_ID_RE = re.compile(r"\((\d+)\)")


def _parse_records(text: str) -> list[dict]:
    """Split evtexport stdout into per-record dicts. Format is:

        Event number            : 1
        Creation time           : May 13, 2008 21:23:42 UTC
        Written time            : May 13, 2008 21:23:42 UTC
        Event type              : Information event (4)
        Computer name           : JEAN-13FBF038A3
        Source name             : LoadPerf
        Event category          : 0
        Event identifier        : 0x400003e8 (1073742824)
        Number of strings       : 2
        String: 1               : RSVP
        String: 2               : QoS RSVP

    One blank line separates records."""
    records: list[dict] = []
    # Split text into per-record chunks by locating "Event number" lines
    header_positions = [m.start() for m in _EVENT_HEAD_RE.finditer(text)]
    if not header_positions:
        return records
    # Append end-of-text so the last record slices cleanly
    header_positions.append(len(text))
    for idx in range(len(header_positions) - 1):
        chunk = text[header_positions[idx]:header_positions[idx + 1]]
        fields: dict[str, str] = {}
        # Extract numbered strings first (String: 1, String: 2, …)
        for sm in _STRING_RE.finditer(chunk):
            fields[f"string_{sm.group(1)}"] = sm.group(2).strip()
        # Then general key:value pairs. Skip string lines (already captured).
        for m in _KV_RE.finditer(chunk):
            raw_k = m.group(1).strip()
            if raw_k.lower().startswith("string"):
                continue
            k = raw_k.lower().replace(" ", "_")
            v = m.group(2).strip()
            if k not in fields:
                fields[k] = v
        # Normalise event-identifier to just the decimal number
        eid = fields.get("event_identifier", "")
        m = _EVENT_ID_RE.search(eid)
        if m:
            fields["event_identifier"] = m.group(1)
        records.append(fields)
    return records


_EVT_CSV_HEADERS = (
    "RecordNumber", "EventRecordId", "TimeCreated", "Channel",
    "Provider", "EventId", "Level", "Computer", "UserId", "UserName",
    "ExecutableInfo", "MapDescription",
    "PayloadData1", "PayloadData2", "PayloadData3",
    "PayloadData4", "PayloadData5", "PayloadData6", "Payload",
)


def _records_to_evtx_csv(records: list[dict], channel_hint: str,
                          csv_out: Path) -> int:
    """Write an EvtxECmd-shaped CSV. channel_hint is the log-name
    inferred from the .evt filename (SecEvent.Evt → Security,
    AppEvent.Evt → Application, SysEvent.Evt → System)."""
    n = 0
    with csv_out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow(_EVT_CSV_HEADERS)
        for r in records:
            eid = r.get("event_identifier", "").split()[0] or "0"
            # evtexport embeds numeric + flag bits, keep just the number
            try:
                eid_int = int(re.findall(r"\d+", eid)[0])
            except (IndexError, ValueError):
                eid_int = 0
            ts = r.get("creation_time", "")
            provider = r.get("source_name", "")
            computer = r.get("computer_name", "")
            user = r.get("user_security_identifier", "")
            payload = " | ".join(
                (r.get(f"string_{i}", "") for i in range(1, 10))
            ).strip()
            w.writerow([
                r.get("record_number", ""),
                r.get("record_number", ""),
                ts,
                channel_hint,
                provider,
                eid_int,
                r.get("event_type", ""),
                computer,
                user,
                r.get("user_name", ""),
                "",       # ExecutableInfo — XP EVT doesn't carry
                "",       # MapDescription — not applicable
                r.get("string_1", ""),
                r.get("string_2", ""),
                r.get("string_3", ""),
                r.get("string_4", ""),
                r.get("string_5", ""),
                r.get("string_6", ""),
                payload,
            ])
            n += 1
    return n


_NAME_TO_CHANNEL = {
    "secevent.evt": "Security",
    "appevent.evt": "Application",
    "sysevent.evt": "System",
}


def convert_evt_to_evtx_csv(evt_path: str | Path,
                             csv_out: str | Path,
                             analysis_dir: str | Path) -> EvtRun:
    """Full pipeline: evtexport → parse → EvtxECmd-shaped CSV.
    Returns EvtRun with .event_count populated."""
    src = Path(evt_path)
    csv_path = Path(csv_out)
    ad = Path(analysis_dir)
    raw_path, rc = _export_stdout(src, ad)
    if rc not in (0,):
        return EvtRun(source_path=src, csv_path=csv_path,
                      rc=rc, event_count=0, raw_path=raw_path)
    text = raw_path.read_text(encoding="utf-8", errors="replace")
    records = _parse_records(text)
    channel = _NAME_TO_CHANNEL.get(src.name.lower(), src.stem)
    n = _records_to_evtx_csv(records, channel, csv_path)
    return EvtRun(source_path=src, csv_path=csv_path, rc=rc,
                   event_count=n, raw_path=raw_path)


def convert_all_evt(evt_dir: str | Path,
                     csv_out: str | Path,
                     analysis_dir: str | Path) -> EvtRun:
    """Convert every .evt under evt_dir and concatenate into a single
    EvtxECmd-shaped CSV at csv_out. Returns the aggregate EvtRun."""
    root = Path(evt_dir)
    csv_path = Path(csv_out)
    ad = Path(analysis_dir)
    if not root.exists():
        return EvtRun(source_path=root, csv_path=csv_path,
                      rc=-1, event_count=0)
    all_records: list[tuple[str, dict]] = []
    rc_sum = 0
    # Case-insensitive .evt match (XP filenames like SecEvent.Evt are
    # mixed-case and case-sensitive on Linux)
    evt_files = sorted([p for p in root.rglob("*")
                        if p.is_file() and p.suffix.lower() == ".evt"])
    for evt in evt_files:
        raw_path, rc = _export_stdout(evt, ad)
        rc_sum = max(rc_sum, rc if rc >= 0 else abs(rc))
        if rc != 0:
            continue
        text = raw_path.read_text(encoding="utf-8", errors="replace")
        channel = _NAME_TO_CHANNEL.get(evt.name.lower(), evt.stem)
        for rec in _parse_records(text):
            all_records.append((channel, rec))
    # Write aggregate CSV
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    if all_records:
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            w.writerow(_EVT_CSV_HEADERS)
            for channel, r in all_records:
                eid_raw = r.get("event_identifier", "0")
                try:
                    eid_int = int(re.findall(r"\d+", eid_raw)[0])
                except (IndexError, ValueError):
                    eid_int = 0
                payload = " | ".join(
                    (r.get(f"string_{i}", "") for i in range(1, 10))
                ).strip()
                w.writerow([
                    r.get("record_number", ""),
                    r.get("record_number", ""),
                    r.get("creation_time", ""),
                    channel,
                    r.get("source_name", ""),
                    eid_int,
                    r.get("event_type", ""),
                    r.get("computer_name", ""),
                    r.get("user_security_identifier", ""),
                    r.get("user_name", ""),
                    "", "",
                    r.get("string_1", ""), r.get("string_2", ""),
                    r.get("string_3", ""), r.get("string_4", ""),
                    r.get("string_5", ""), r.get("string_6", ""),
                    payload,
                ])
                n += 1
    return EvtRun(source_path=root, csv_path=csv_path,
                   rc=0 if n else rc_sum, event_count=n)


__all__ = [
    "EvtRun", "XpEvtError",
    "convert_evt_to_evtx_csv", "convert_all_evt",
]

"""eCAR (Endpoint Common Activity Record) EDR-telemetry parser.

eCAR is a host-telemetry JSONL format (one record per line) modelled on the
MITRE CAR object/action taxonomy — the shape produced by EDR sensors in the
OpTC / "ecar" datasets and several commercial sensors. Each record is an
``object`` (PROCESS / FLOW / MODULE / REGISTRY / FILE / THREAD /
USER_SESSION) + ``action`` (CREATE / CONNECT / LOAD / MODIFY / REMOTE_CREATE
/ LOGIN …), with ``timestamp_ms``, ``hostname``, ``pid`` / ``ppid`` /
``principal`` and a per-type ``properties`` dict (command_line, image_path,
src/dst ip+port, registry_key, file_path, target_pid …).

It is the richest endpoint source in a SOC log set — process trees, network
flows, module loads, and remote-thread injection — and no SIFT-bundled CLI
parses it, so this is a native parser. Read-only.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


class ECARError(Exception):
    pass


def _ms_to_utc(value) -> str:
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return ""
    if ms <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class ECAREvent:
    timestamp_utc: str = ""
    hostname: str = ""
    object: str = ""
    action: str = ""
    pid: int | None = None
    ppid: int | None = None
    principal: str = ""
    image_path: str = ""
    command_line: str = ""
    src_ip: str = ""
    src_port: str = ""
    dst_ip: str = ""
    dst_port: str = ""
    protocol: str = ""
    registry_key: str = ""
    registry_value: str = ""
    file_path: str = ""
    target_pid: int | None = None

    @property
    def oa(self) -> str:
        return f"{self.object}/{self.action}"

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ECARRun:
    src_path: Path
    events: list[ECAREvent] = field(default_factory=list)
    parsed: int = 0
    skipped: int = 0
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return len(self.events)

    def by_object_action(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.events:
            out[e.oa] = out.get(e.oa, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def processes(self) -> list[ECAREvent]:
        return [e for e in self.events
                if e.object == "PROCESS" and e.action == "CREATE"]

    def network_flows(self) -> list[ECAREvent]:
        return [e for e in self.events if e.object == "FLOW"]

    def remote_thread_creations(self) -> list[ECAREvent]:
        """THREAD/REMOTE_CREATE — cross-process thread injection."""
        return [e for e in self.events
                if e.object == "THREAD" and e.action == "REMOTE_CREATE"]

    def hosts(self) -> list[str]:
        return sorted({e.hostname for e in self.events if e.hostname})

    def find(self, needle: str) -> list[ECAREvent]:
        t = needle.lower()
        out = []
        for e in self.events:
            blob = " ".join((e.command_line, e.image_path, e.file_path,
                             e.registry_key, e.registry_value, e.dst_ip,
                             e.src_ip)).lower()
            if t in blob:
                out.append(e)
        return out

    def date_range(self) -> tuple[str, str]:
        ds = [e.timestamp_utc for e in self.events if e.timestamp_utc]
        return (min(ds), max(ds)) if ds else ("", "")

    def as_evidence(self, *, facts: dict | None = None):
        from el.schemas.finding import EvidenceItem
        extra = facts or {}
        lo, hi = self.date_range()
        return EvidenceItem(
            tool="el.ecar", version="0.1.0",
            command=f"parse eCAR JSONL -- {self.src_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.src_path),
            extracted_facts={
                "src_path": str(self.src_path),
                "event_count": self.total,
                "hosts": self.hosts(),
                "by_object_action": dict(list(self.by_object_action().items())[:12]),
                "process_creates": len(self.processes()),
                "network_flows": len(self.network_flows()),
                "remote_thread_creations": len(self.remote_thread_creations()),
                "first_event_utc": lo, "last_event_utc": hi,
                **extra,
            },
        )


def _event_from(d: dict) -> ECAREvent:
    p = d.get("properties") or {}
    if not isinstance(p, dict):
        p = {}

    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    return ECAREvent(
        timestamp_utc=_ms_to_utc(d.get("timestamp_ms")),
        hostname=str(d.get("hostname") or ""),
        object=str(d.get("object") or ""),
        action=str(d.get("action") or ""),
        pid=_int(d.get("pid")),
        ppid=_int(d.get("ppid")),
        principal=str(d.get("principal") or ""),
        image_path=str(p.get("image_path") or ""),
        command_line=str(p.get("command_line") or ""),
        src_ip=str(p.get("src_ip") or ""),
        src_port=str(p.get("src_port") or ""),
        dst_ip=str(p.get("dst_ip") or ""),
        dst_port=str(p.get("dst_port") or ""),
        protocol=str(p.get("protocol") or ""),
        registry_key=str(p.get("registry_key") or ""),
        registry_value=str(p.get("registry_value") or ""),
        file_path=str(p.get("file_path") or ""),
        target_pid=_int(p.get("target_pid")),
    )


def parse(path: Path, output_dir: Path | None = None,
          *, max_events: int = 2_000_000) -> ECARRun:
    """Parse an eCAR JSONL file into events. Writes a normalised JSONL dump
    under *output_dir* when given. Lenient: malformed lines are counted and
    skipped, not fatal."""
    path = Path(path)
    if not path.is_file():
        raise ECARError(f"eCAR file not found: {path}")

    run = ECARRun(src_path=path)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                run.skipped += 1
                continue
            if not isinstance(d, dict) or "object" not in d:
                run.skipped += 1
                continue
            run.parsed += 1
            if run.total < max_events:
                run.events.append(_event_from(d))

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "ecar_events.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for e in run.events:
                f.write(json.dumps(e.as_dict(), ensure_ascii=False) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run

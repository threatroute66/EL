"""Cisco ASA syslog parser.

Cisco ASA firewalls emit syslog lines tagged ``%ASA-<sev>-<msgid>``. The
connection-lifecycle and access-control messages are the forensically useful
ones:

  302013/302015/302020  Built TCP/UDP/ICMP connection
  302014/302016/302021  Teardown TCP/UDP/ICMP connection (carries byte count)
  305011/305012         Built / Teardown dynamic NAT translation
  106023                Deny <proto> ... by access-group   (ACL deny)

Each carries ``<iface>:<ip>/<port>`` source and destination tuples. This
parser extracts action / protocol / src+dst / bytes / severity and surfaces
the ACL denies — without depending on any external tool. Read-only.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path


class CiscoASAError(Exception):
    pass

# <pri> Mon DD HH:MM:SS host %ASA-sev-msgid: message
_LINE = re.compile(
    r"^(?:<\d+>)?(?P<ts>\w{3}\s+\d+\s+\d{1,2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+%ASA-(?P<sev>\d)-(?P<msgid>\d+):\s*(?P<msg>.*)$")
# iface:ip/port tuple
_IFTUPLE = re.compile(r"([A-Za-z0-9_\-]+):(\d{1,3}(?:\.\d{1,3}){3})/(\d+)")
_PROTO = re.compile(r"\b(TCP|UDP|ICMP|GRE|ESP)\b", re.I)
_BYTES = re.compile(r"\bbytes\s+(\d+)", re.I)


@dataclass
class ASAEvent:
    timestamp: str = ""
    host: str = ""
    severity: int = 6
    msg_id: str = ""
    action: str = ""          # Built / Teardown / Deny / other
    protocol: str = ""
    src_iface: str = ""
    src_ip: str = ""
    src_port: str = ""
    dst_iface: str = ""
    dst_ip: str = ""
    dst_port: str = ""
    bytes: int | None = None
    raw: str = ""

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ASARun:
    src_path: Path
    events: list[ASAEvent] = field(default_factory=list)
    parsed: int = 0
    skipped: int = 0
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return len(self.events)

    def by_msg_id(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.events:
            out[e.msg_id] = out.get(e.msg_id, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def denies(self) -> list[ASAEvent]:
        return [e for e in self.events if e.action == "Deny"]

    def connections(self) -> list[ASAEvent]:
        return [e for e in self.events if e.action in ("Built", "Teardown")]

    def find_ip(self, ip: str) -> list[ASAEvent]:
        return [e for e in self.events if ip in (e.src_ip, e.dst_ip)]

    def as_evidence(self, *, facts: dict | None = None):
        from el.schemas.finding import EvidenceItem
        extra = facts or {}
        return EvidenceItem(
            tool="el.cisco_asa", version="0.1.0",
            command=f"parse Cisco ASA syslog -- {self.src_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.src_path),
            extracted_facts={
                "src_path": str(self.src_path),
                "event_count": self.total,
                "by_msg_id": dict(list(self.by_msg_id().items())[:12]),
                "deny_count": len(self.denies()),
                "connection_count": len(self.connections()),
                **extra,
            },
        )


def _action_for(msgid: str, msg: str) -> str:
    if msgid in ("106023",) or msg.startswith("Deny"):
        return "Deny"
    if msg.startswith("Built"):
        return "Built"
    if msg.startswith("Teardown"):
        return "Teardown"
    return "other"


def parse(path: Path, output_dir: Path | None = None) -> ASARun:
    path = Path(path)
    if not path.is_file():
        raise CiscoASAError(f"Cisco ASA log not found: {path}")

    run = ASARun(src_path=path)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = _LINE.match(line)
            if not m:
                run.skipped += 1
                continue
            run.parsed += 1
            msg = m.group("msg")
            tuples = _IFTUPLE.findall(msg)
            src = tuples[0] if len(tuples) >= 1 else ("", "", "")
            dst = tuples[1] if len(tuples) >= 2 else ("", "", "")
            pm = _PROTO.search(msg)
            bm = _BYTES.search(msg)
            run.events.append(ASAEvent(
                timestamp=m.group("ts"),
                host=m.group("host"),
                severity=int(m.group("sev")),
                msg_id=m.group("msgid"),
                action=_action_for(m.group("msgid"), msg),
                protocol=(pm.group(1).upper() if pm else ""),
                src_iface=src[0], src_ip=src[1], src_port=src[2],
                dst_iface=dst[0], dst_ip=dst[1], dst_port=dst[2],
                bytes=int(bm.group(1)) if bm else None,
                raw=line[:500],
            ))

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "cisco_asa_events.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for e in run.events:
                f.write(json.dumps(e.as_dict(), ensure_ascii=False) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run

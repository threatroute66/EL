"""Snort (and ET) fast-alert log parser.

Snort's "fast" alert format (also emitted by Suricata in fast mode), one line
per alert::

    MM/DD-HH:MM:SS.ffffff [**] [GID:SID:REV] MSG [**] \\
        [Classification: CLASS] [Priority: N] {PROTO} SRC[:PORT] -> DST[:PORT]

This complements :mod:`el.skills.suricata_eve` (Suricata's richer EVE-JSON):
many sensors only ship the text fast-alert log. Extracts the rule identity
(gid/sid/rev), message, classification, priority, protocol and src/dst, and
surfaces the high-priority alerts and top signatures. Read-only.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path


class SnortAlertError(Exception):
    pass

_LINE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.*?)\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<cls>[^\]]*)\]\s+)?"
    r"\[Priority:\s*(?P<prio>\d+)\]\s+\{(?P<proto>[^}]+)\}\s+"
    r"(?P<src>[0-9a-fA-F:.]+?)(?::(?P<sport>\d+))?\s+->\s+"
    r"(?P<dst>[0-9a-fA-F:.]+?)(?::(?P<dport>\d+))?$")


@dataclass
class SnortAlert:
    timestamp: str = ""
    gid: str = ""
    sid: str = ""
    rev: str = ""
    msg: str = ""
    classification: str = ""
    priority: int = 0
    protocol: str = ""
    src_ip: str = ""
    src_port: str = ""
    dst_ip: str = ""
    dst_port: str = ""

    @property
    def rule(self) -> str:
        return f"{self.gid}:{self.sid}:{self.rev}"

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class SnortRun:
    src_path: Path
    alerts: list[SnortAlert] = field(default_factory=list)
    parsed: int = 0
    skipped: int = 0
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return len(self.alerts)

    def by_classification(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for a in self.alerts:
            out[a.classification or "(none)"] = out.get(
                a.classification or "(none)", 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def by_priority(self) -> dict[int, int]:
        out: dict[int, int] = {}
        for a in self.alerts:
            out[a.priority] = out.get(a.priority, 0) + 1
        return dict(sorted(out.items()))

    def high_priority(self, threshold: int = 1) -> list[SnortAlert]:
        """Alerts at priority <= threshold (1 = highest)."""
        return [a for a in self.alerts if 0 < a.priority <= threshold]

    def top_signatures(self, n: int = 10) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for a in self.alerts:
            counts[a.msg] = counts.get(a.msg, 0) + 1
        return sorted(counts.items(), key=lambda kv: -kv[1])[:n]

    def find_ip(self, ip: str) -> list[SnortAlert]:
        return [a for a in self.alerts if ip in (a.src_ip, a.dst_ip)]

    def as_evidence(self, *, facts: dict | None = None):
        from el.schemas.finding import EvidenceItem
        extra = facts or {}
        return EvidenceItem(
            tool="el.snort_alert", version="0.1.0",
            command=f"parse Snort fast-alert log -- {self.src_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.src_path),
            extracted_facts={
                "src_path": str(self.src_path),
                "alert_count": self.total,
                "by_priority": {str(k): v for k, v in self.by_priority().items()},
                "by_classification": dict(list(self.by_classification().items())[:10]),
                "high_priority_count": len(self.high_priority()),
                "top_signatures": dict(self.top_signatures(8)),
                **extra,
            },
        )


def parse(path: Path, output_dir: Path | None = None) -> SnortRun:
    path = Path(path)
    if not path.is_file():
        raise SnortAlertError(f"Snort alert log not found: {path}")

    run = SnortRun(src_path=path)
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
            run.alerts.append(SnortAlert(
                timestamp=m.group("ts"),
                gid=m.group("gid"), sid=m.group("sid"), rev=m.group("rev"),
                msg=m.group("msg"),
                classification=(m.group("cls") or "").strip(),
                priority=int(m.group("prio")),
                protocol=m.group("proto"),
                src_ip=m.group("src"), src_port=m.group("sport") or "",
                dst_ip=m.group("dst"), dst_port=m.group("dport") or "",
            ))

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "snort_alerts.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for a in run.alerts:
                f.write(json.dumps(a.as_dict(), ensure_ascii=False) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run

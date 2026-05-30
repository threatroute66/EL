"""iOS knowledgeC.db parser — app-usage / activity timeline.

``/private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db`` is the
CoreDuet "knowledge" store: a per-event stream of what the device was doing —
app foreground usage (``/app/usage``), activities, Siri/app intents
(``/app/intents``), in-app web usage (``/app/webUsage``), notifications,
lock state, backlight. Each ``ZOBJECT`` row carries a stream name, an optional
value (usually the app bundle id), and start/end timestamps (Mac absolute
seconds since 2001).

Read-only via :mod:`el.skills._sqlite` (WAL-applied copy). No SIFT CLI
structures knowledgeC, so this is a native parser built on EL's primitives.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from el.schemas.finding import EvidenceItem
from el.skills._sqlite import EvidenceDBError, open_evidence_db

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


class IOSKnowledgeCError(Exception):
    pass


def _abs_to_utc(value) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        return (_MAC_EPOCH + timedelta(seconds=v)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class KnowledgeEvent:
    stream: str = ""
    value: str = ""          # usually the app bundle id
    start_utc: str = ""
    end_utc: str = ""
    duration_s: float = 0.0

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class KnowledgeRun:
    db_path: Path
    events: list[KnowledgeEvent] = field(default_factory=list)
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return len(self.events)

    def by_stream(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.events:
            out[e.stream] = out.get(e.stream, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def app_usage(self) -> list[KnowledgeEvent]:
        return [e for e in self.events if e.stream == "/app/usage" and e.value]

    def top_apps(self, n: int = 10) -> list[tuple[str, float]]:
        """Apps by total foreground seconds (from /app/usage)."""
        secs: dict[str, float] = {}
        for e in self.app_usage():
            secs[e.value] = secs.get(e.value, 0.0) + e.duration_s
        return sorted(secs.items(), key=lambda kv: -kv[1])[:n]

    def app_in_focus_at(self, utc: str) -> list[KnowledgeEvent]:
        """/app/usage events whose [start,end] window covers *utc*
        ('YYYY-MM-DD HH:MM:SS')."""
        return [e for e in self.app_usage()
                if e.start_utc and e.end_utc and e.start_utc <= utc <= e.end_utc]

    def date_range(self) -> tuple[str, str]:
        ds = [e.start_utc for e in self.events if e.start_utc]
        return (min(ds), max(ds)) if ds else ("", "")

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        lo, hi = self.date_range()
        return EvidenceItem(
            tool="el.ios_knowledgec", version="0.1.0",
            command=f"parse knowledgeC.db ZOBJECT -- {self.db_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.db_path),
            extracted_facts={
                "db_path": str(self.db_path),
                "event_count": self.total,
                "by_stream": dict(list(self.by_stream().items())[:15]),
                "app_usage_events": len(self.app_usage()),
                "top_apps_by_seconds": {a: round(s) for a, s in self.top_apps(8)},
                "first_event_utc": lo,
                "last_event_utc": hi,
                **extra,
            },
        )


def find_knowledgec(fs_root: Path) -> Path | None:
    fs_root = Path(fs_root)
    for rel in (("private", "var", "mobile", "Library", "CoreDuet",
                 "Knowledge", "knowledgeC.db"),
                ("var", "mobile", "Library", "CoreDuet", "Knowledge",
                 "knowledgeC.db")):
        p = fs_root.joinpath(*rel)
        if p.is_file():
            return p
    if fs_root.name == "knowledgeC.db" and fs_root.is_file():
        return fs_root
    direct = fs_root / "knowledgeC.db"
    return direct if direct.is_file() else None


def parse(db_path: Path, output_dir: Path | None = None) -> KnowledgeRun:
    db_path = Path(db_path)
    if not db_path.is_file():
        raise IOSKnowledgeCError(f"knowledgeC.db not found: {db_path}")

    run = KnowledgeRun(db_path=db_path)
    workdir = Path(output_dir) / "_dbcopy" if output_dir else None
    try:
        with open_evidence_db(db_path, workdir=workdir,
                              row_factory=sqlite3.Row) as conn:
            try:
                cur = conn.execute(
                    "SELECT ZSTREAMNAME AS s, ZVALUESTRING AS v, "
                    "ZSTARTDATE AS sd, ZENDDATE AS ed FROM ZOBJECT")
            except sqlite3.Error as e:
                raise IOSKnowledgeCError(
                    f"knowledgeC.db schema unexpected: {e}") from e
            for r in cur:
                start = _abs_to_utc(r["sd"])
                end = _abs_to_utc(r["ed"])
                dur = 0.0
                try:
                    if r["sd"] and r["ed"]:
                        dur = max(0.0, float(r["ed"]) - float(r["sd"]))
                except (TypeError, ValueError):
                    dur = 0.0
                run.events.append(KnowledgeEvent(
                    stream=str(r["s"] or ""),
                    value=str(r["v"] or ""),
                    start_utc=start, end_utc=end,
                    duration_s=round(dur, 3),
                ))
    except EvidenceDBError as e:
        raise IOSKnowledgeCError(str(e)) from e

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "knowledgec_events.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for e in run.events:
                f.write(json.dumps(e.as_dict(), ensure_ascii=False) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run

"""Forensic audit log — Protocol SIFT convention.

Appends a single line per event to <case_dir>/analysis/forensic_audit.log.
Lines are designed to be human-readable AND grep-friendly (key=value).
Append-only; never rewritten. Crash-safe via line-buffered writes.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditLog:
    def __init__(self, case_dir: Path, case_id: str):
        self.case_id = case_id
        self.dir = Path(case_dir) / "analysis"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "forensic_audit.log"

    def event(self, level: str, event: str, **fields) -> None:
        parts = [
            _ts(),
            f"[{level.upper()}]",
            f"case={self.case_id}",
            f"event={event}",
            f"pid={os.getpid()}",
        ]
        for k, v in fields.items():
            if v is None:
                continue
            if isinstance(v, (dict, list)):
                v = json.dumps(v, separators=(",", ":"))
            else:
                v = str(v)
            if " " in v or "=" in v:
                v = f'"{v.replace(chr(34), chr(39))}"'
            parts.append(f"{k}={v}")
        line = " ".join(parts) + "\n"
        with self.path.open("a", buffering=1) as f:
            f.write(line)

    def info(self, event: str, **fields) -> None:
        self.event("INFO", event, **fields)

    def warn(self, event: str, **fields) -> None:
        self.event("WARN", event, **fields)

    def error(self, event: str, **fields) -> None:
        self.event("ERROR", event, **fields)

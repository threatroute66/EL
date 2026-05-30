"""Zeek JSON log ingester — parse EXISTING Zeek output.

EL's :mod:`el.skills.zeek` *generates* Zeek logs by replaying a pcap. This
skill is the complement: it ingests Zeek logs that already exist as JSON
(``conn.json`` / ``dns.json`` / ``http.json`` / ``ssl.json`` / ``x509.json`` /
``files.json`` / ``dhcp.json`` …, one JSON object per line) — the form a SOC
ships from a sensor. It normalises the ``ts`` epoch to UTC and exposes the
high-value behavioural views (connections, DNS queries, HTTP requests, TLS
SNI, x509 certs, transferred files).

Pure-Python, read-only. No SIFT CLI ingests Zeek JSON into structured Findings.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Recognised Zeek log types (filename stem, with or without .json).
LOG_TYPES = (
    "conn", "dns", "http", "ssl", "x509", "files", "dhcp", "smb_files",
    "smb_mapping", "ntlm", "kerberos", "ssh", "rdp", "dce_rpc", "ntp",
    "notice", "weird", "pe", "ocsp", "tunnel", "dpd",
)


class ZeekJsonError(Exception):
    pass


def _ts_to_utc(value) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        return datetime.fromtimestamp(v, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class ZeekJsonRun:
    src: Path
    logs: dict[str, list[dict]] = field(default_factory=dict)
    output_dir: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.logs.values())

    def counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in sorted(self.logs.items())}

    def connections(self) -> list[dict]:
        return self.logs.get("conn", [])

    def dns_queries(self) -> list[dict]:
        return self.logs.get("dns", [])

    def http_requests(self) -> list[dict]:
        return self.logs.get("http", [])

    def ssl(self) -> list[dict]:
        return self.logs.get("ssl", [])

    def x509(self) -> list[dict]:
        return self.logs.get("x509", [])

    def files(self) -> list[dict]:
        return self.logs.get("files", [])

    def date_range(self) -> tuple[str, str]:
        ds = [r["_ts_utc"] for recs in self.logs.values() for r in recs
              if r.get("_ts_utc")]
        return (min(ds), max(ds)) if ds else ("", "")

    def find(self, needle: str, *, logtype: str | None = None) -> list[dict]:
        t = needle.lower()
        recs = (self.logs.get(logtype, []) if logtype
                else [r for v in self.logs.values() for r in v])
        out = []
        for r in recs:
            for v in r.values():
                if isinstance(v, str) and t in v.lower():
                    out.append(r)
                    break
                if isinstance(v, list) and any(
                        isinstance(x, str) and t in x.lower() for x in v):
                    out.append(r)
                    break
        return out

    def as_evidence(self, *, facts: dict | None = None):
        from el.schemas.finding import EvidenceItem
        extra = facts or {}
        lo, hi = self.date_range()
        return EvidenceItem(
            tool="el.zeek_json", version="0.1.0",
            command=f"ingest Zeek JSON logs -- {self.src}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_dir or self.src),
            extracted_facts={
                "src": str(self.src),
                "record_count": self.total,
                "logs": self.counts(),
                "first_ts_utc": lo, "last_ts_utc": hi,
                **extra,
            },
        )


def _logtype_for(path: Path) -> str | None:
    stem = path.name
    for suffix in (".json", ".log"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return stem if stem in LOG_TYPES else None


def parse_log(path: Path, logtype: str | None = None,
              *, max_records: int = 2_000_000) -> list[dict]:
    """Parse a single Zeek JSON(L) file into a list of records, each with an
    added ``_ts_utc`` field. Lenient on malformed lines."""
    path = Path(path)
    if not path.is_file():
        raise ZeekJsonError(f"Zeek log not found: {path}")
    out: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(d, dict):
                continue
            d["_ts_utc"] = _ts_to_utc(d.get("ts"))
            out.append(d)
            if len(out) >= max_records:
                break
    return out


def find_zeek_logs(directory: Path) -> dict[str, Path]:
    """Map recognised Zeek log types to their JSON file under *directory*."""
    directory = Path(directory)
    found: dict[str, Path] = {}
    if not directory.is_dir():
        return found
    for p in sorted(directory.iterdir()):
        if not p.is_file():
            continue
        lt = _logtype_for(p)
        if lt and lt not in found:
            found[lt] = p
    return found


def parse_dir(directory: Path, output_dir: Path | None = None) -> ZeekJsonRun:
    """Ingest every recognised Zeek JSON log under *directory*."""
    directory = Path(directory)
    run = ZeekJsonRun(src=directory)
    for lt, path in find_zeek_logs(directory).items():
        try:
            run.logs[lt] = parse_log(path, lt)
        except ZeekJsonError:
            continue

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        summary = output_dir / "zeek_summary.json"
        summary.write_text(json.dumps({
            "counts": run.counts(),
            "date_range": run.date_range(),
        }, indent=1))
        run.output_dir = output_dir
        run.output_sha256 = hashlib.sha256(summary.read_bytes()).hexdigest()

    return run

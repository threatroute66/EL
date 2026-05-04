"""JA4+ family TLS / HTTP / SSH client fingerprinting.

Wraps FoxIO's reference ``ja4.py`` script (BSD-3-Clause for JA4 itself, FoxIO
License 1.1 for the JA4+ extensions JA4S / JA4H / JA4L / JA4X / JA4SSH).

JA3 was officially deprecated by FoxIO in 2024 — JA4 covers TLS, HTTP, SSH,
and QUIC client behaviour with stable-against-randomization fingerprints.

This skill **supplements** ``el.skills.ja3_reputation`` (JA3) rather than
replacing it: many published threat-intel feeds still index by JA3, so
keeping both gives broader hit coverage during the migration window.

Project: https://github.com/FoxIO-LLC/ja4
Install: install.sh stages /opt/ja4-tools/python (clone of FoxIO's repo);
the script depends on tshark >= 4.0.6 (already on SIFT).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from el.schemas.finding import EvidenceItem


class JA4Error(Exception):
    pass


def _which() -> Path:
    """Locate FoxIO ja4.py. install.sh stages it under /opt/ja4-tools/."""
    candidates = [
        Path("/opt/ja4-tools/python/ja4.py"),
        Path("/opt/ja4/python/ja4.py"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    raise JA4Error(
        "FoxIO ja4.py not found — install via install.sh; "
        "clone github.com/FoxIO-LLC/ja4 to /opt/ja4-tools/"
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class JA4Flow:
    """A single JA4-fingerprinted network flow extracted from a pcap."""
    src: str = ""
    dst: str = ""
    src_port: str = ""
    dst_port: str = ""
    protocol: str = ""
    ja4: str = ""
    ja4s: str = ""
    ja4h: str = ""
    ja4x: str = ""
    ja4ssh: str = ""
    sni: str = ""
    user_agent: str = ""

    @classmethod
    def from_record(cls, rec: dict) -> "JA4Flow":
        # FoxIO ja4.py JSON output uses a nested-ish shape with src/dst at top
        # level and JA4 family keys mixed in. Be tolerant of casing + missing
        # keys — different protocols populate different subsets.
        return cls(
            src=str(rec.get("src", "")),
            dst=str(rec.get("dst", "")),
            src_port=str(rec.get("src_port", "")),
            dst_port=str(rec.get("dst_port", "")),
            protocol=str(rec.get("protocol", rec.get("protos", ""))),
            ja4=str(rec.get("JA4", rec.get("ja4", ""))),
            ja4s=str(rec.get("JA4S", rec.get("ja4s", ""))),
            ja4h=str(rec.get("JA4H", rec.get("ja4h", ""))),
            ja4x=str(rec.get("JA4X", rec.get("ja4x", ""))),
            ja4ssh=str(rec.get("JA4SSH", rec.get("ja4ssh", ""))),
            sni=str(rec.get("server_name", rec.get("sni", "")))[:200],
            user_agent=str(rec.get("user_agent", ""))[:300],
        )

    def has_any_fingerprint(self) -> bool:
        return any((self.ja4, self.ja4s, self.ja4h, self.ja4x, self.ja4ssh))


@dataclass
class JA4ScanResult:
    pcap_path: Path
    output_path: Path
    rc: int
    duration_seconds: float = 0.0
    flow_count: int = 0
    distinct_ja4: list[str] = field(default_factory=list)
    distinct_ja4s: list[str] = field(default_factory=list)
    distinct_ja4h: list[str] = field(default_factory=list)
    distinct_ja4x: list[str] = field(default_factory=list)
    distinct_ja4ssh: list[str] = field(default_factory=list)
    output_sha256: str = ""
    command: list[str] = field(default_factory=list)
    stderr_path: Path | None = None
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="ja4",
            version="foxio-ja4",
            command=" ".join(str(p) for p in self.command),
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path),
            extracted_facts={
                "pcap": str(self.pcap_path),
                "flow_count": self.flow_count,
                "distinct_ja4_count": len(self.distinct_ja4),
                "distinct_ja4s_count": len(self.distinct_ja4s),
                "distinct_ja4h_count": len(self.distinct_ja4h),
                "distinct_ja4x_count": len(self.distinct_ja4x),
                "distinct_ja4ssh_count": len(self.distinct_ja4ssh),
                "sample_ja4": self.distinct_ja4[:10],
                "sample_ja4h": self.distinct_ja4h[:10],
                "duration_seconds": round(self.duration_seconds, 2),
                "rc": self.rc,
                "note": self.note,
                **extra,
            },
        )

    def all_distinct_fingerprints(self) -> list[str]:
        out: list[str] = []
        for fp_list in (self.distinct_ja4, self.distinct_ja4s,
                          self.distinct_ja4h, self.distinct_ja4x,
                          self.distinct_ja4ssh):
            out.extend(fp_list)
        return out


def _parse_ja4_output(output_path: Path) -> tuple[int, list[JA4Flow]]:
    """Parse FoxIO ja4.py JSON output. Tolerates both array and JSONL shapes."""
    if not output_path.is_file():
        return 0, []
    try:
        text = output_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0, []

    flows: list[JA4Flow] = []
    text = text.strip()
    if not text:
        return 0, []

    # FoxIO emits a top-level JSON array by default.
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for rec in data:
                if isinstance(rec, dict):
                    flows.append(JA4Flow.from_record(rec))
            return len(flows), flows
        if isinstance(data, dict):
            return 1, [JA4Flow.from_record(data)]
    except json.JSONDecodeError:
        pass

    # Fall back: JSONL (one record per line).
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            if isinstance(rec, dict):
                flows.append(JA4Flow.from_record(rec))
        except json.JSONDecodeError:
            continue
    return len(flows), flows


def _distinct(values: Iterable[str], cap: int = 500) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
        if len(out) >= cap:
            break
    return out


def scan_pcap(pcap_path: Path, output_dir: Path,
                *, timeout_seconds: int = 1200) -> JA4ScanResult:
    """Run FoxIO ja4.py against a pcap, harvest JA4-family fingerprints.

    Args:
        pcap_path: pcap / pcapng to fingerprint.
        output_dir: where to write the JSON output + stderr.
        timeout_seconds: cap on the tshark-driven extraction.
    """
    pcap_path = Path(pcap_path)
    output_dir = Path(output_dir)
    if not pcap_path.is_file():
        raise JA4Error(f"pcap not found: {pcap_path}")
    output_dir.mkdir(parents=True, exist_ok=True)

    script = _which()
    output_json = output_dir / f"ja4_{pcap_path.name}.json"
    stderr_path = output_dir / f"ja4_{pcap_path.name}.stderr"
    cmd = [
        "python3", str(script),
        "-J",  # JSON output
        "-f", str(output_json),
        str(pcap_path),
    ]

    started = time.time()
    try:
        with stderr_path.open("wb") as ferr:
            proc = subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=ferr,
                timeout=timeout_seconds,
            )
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        return JA4ScanResult(
            pcap_path=pcap_path, output_path=output_json,
            rc=124, command=cmd, stderr_path=stderr_path,
            duration_seconds=time.time() - started,
            note=f"ja4 extraction timed out after {timeout_seconds}s",
        )

    duration = time.time() - started
    flow_count, flows = _parse_ja4_output(output_json)

    return JA4ScanResult(
        pcap_path=pcap_path,
        output_path=output_json,
        rc=rc,
        duration_seconds=duration,
        flow_count=flow_count,
        distinct_ja4=_distinct(f.ja4 for f in flows),
        distinct_ja4s=_distinct(f.ja4s for f in flows),
        distinct_ja4h=_distinct(f.ja4h for f in flows),
        distinct_ja4x=_distinct(f.ja4x for f in flows),
        distinct_ja4ssh=_distinct(f.ja4ssh for f in flows),
        output_sha256=_sha256_file(output_json) if output_json.is_file() else "",
        command=cmd,
        stderr_path=stderr_path,
    )


# Curated JA4 fingerprints associated with known-bad client implementations.
# Same maintenance pattern as KNOWN_BAD_JA3 in ja3_reputation.py:
# every entry must come from a published threat-intel source so a future
# auditor can verify the attribution. Empty by default — populate from
# operator-supplied JA4 IOC feeds (FoxIO ja4-fingerprints repo, etc.).
KNOWN_BAD_JA4: dict[str, tuple[str, str]] = {
    # ja4_hash: (family_label, source_reference)
    # e.g. "t13d1516h2_8daaf6152771_b186095e22b6": ("Cobalt Strike default",
    #     "FoxIO ja4-fingerprints repo, 2024"),
}


def lookup_ja4(fingerprint: str) -> tuple[str, str] | None:
    """Return (family, source) when *fingerprint* matches the curated table."""
    if not fingerprint:
        return None
    return KNOWN_BAD_JA4.get(fingerprint.strip())

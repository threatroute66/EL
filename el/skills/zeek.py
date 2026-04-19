"""Skill: Zeek — passive network analyzer.

Replays a pcap and produces structured per-protocol logs (conn.log,
http.log, dns.log, ssl.log, x509.log, files.log, weird.log, notice.log).
Where suricata gives signature-based alerts and tshark gives raw protocol
fields, Zeek gives high-level *behavioural* records: full connection
state, file extraction with mime-typing, x509 cert chains, DNS
query/response correlation. Cheap second opinion on every pcap.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class ZeekError(RuntimeError):
    pass


def _bin() -> str:
    p = shutil.which("zeek") or "/opt/zeek/bin/zeek"
    if not Path(p).is_file():
        raise ZeekError("zeek not on PATH (looked in /opt/zeek/bin/zeek)")
    return p


def _version() -> str:
    try:
        r = subprocess.run([_bin(), "--version"], capture_output=True,
                           text=True, timeout=5)
        return (r.stdout or r.stderr).strip().splitlines()[0]
    except Exception:
        return "present"


@dataclass
class ZeekRun:
    pcap: Path
    out_dir: Path
    rc: int
    log_files: list[Path] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    notable: dict[str, list[str]] = field(default_factory=dict)
    command: list[str] = field(default_factory=list)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        h = hashlib.sha256()
        for p in sorted(self.log_files):
            try:
                h.update(p.read_bytes()[:1024 * 1024])
            except Exception:
                continue
        merged = {"rc": self.rc,
                  "logs": [p.name for p in self.log_files],
                  "row_counts": self.summary,
                  "notable": {k: v[:10] for k, v in self.notable.items()}}
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool="zeek", version=_version(),
            command=" ".join(self.command),
            output_sha256=h.hexdigest() or "0" * 64,
            output_path=str(self.out_dir),
            extracted_facts=merged,
        )


def _count_rows(p: Path) -> int:
    try:
        with p.open(errors="ignore") as f:
            return sum(1 for line in f if line and not line.startswith("#"))
    except Exception:
        return 0


def _extract_column(p: Path, col_name: str, max_rows: int = 200) -> list[str]:
    """Pull one column from a Zeek TSV log by header name."""
    out: list[str] = []
    try:
        with p.open(errors="ignore") as f:
            field_names: list[str] = []
            sep = "\t"
            for line in f:
                if line.startswith("#separator"):
                    parts = line.strip().split(" ", 1)
                    if len(parts) == 2 and parts[1].startswith("\\x"):
                        sep = bytes(parts[1], "ascii").decode("unicode_escape")
                elif line.startswith("#fields"):
                    field_names = line.rstrip().split(sep)[1:]
                elif line.startswith("#"):
                    continue
                else:
                    if not field_names or col_name not in field_names:
                        return out
                    cells = line.rstrip("\n").split(sep)
                    idx = field_names.index(col_name)
                    if idx < len(cells):
                        v = cells[idx]
                        if v and v != "-" and v != "(empty)":
                            out.append(v)
                            if len(out) >= max_rows:
                                return out
    except Exception:
        pass
    return out


def replay_pcap(pcap: Path, out_dir: Path, timeout: int = 1800) -> ZeekRun:
    """Run `zeek -r <pcap>` in out_dir; parse the resulting *.log files."""
    pcap = Path(pcap).resolve()
    if not pcap.exists():
        raise ZeekError(f"pcap not found: {pcap}")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [_bin(), "-r", str(pcap), "LogAscii::use_json=F"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, cwd=str(out_dir))
    except subprocess.TimeoutExpired as e:
        raise ZeekError(f"zeek timeout after {timeout}s") from e

    logs = sorted(out_dir.glob("*.log"))
    summary = {p.stem: _count_rows(p) for p in logs}
    notable: dict[str, list[str]] = {}

    http_log = out_dir / "http.log"
    if http_log.exists():
        notable["http_hosts"] = sorted(set(_extract_column(http_log, "host", 100)))
        notable["http_uris"] = sorted(set(_extract_column(http_log, "uri", 100)))
        notable["http_user_agents"] = sorted(set(_extract_column(http_log, "user_agent", 100)))
    dns_log = out_dir / "dns.log"
    if dns_log.exists():
        notable["dns_queries"] = sorted(set(_extract_column(dns_log, "query", 100)))
    ssl_log = out_dir / "ssl.log"
    if ssl_log.exists():
        notable["tls_sni"] = sorted(set(_extract_column(ssl_log, "server_name", 100)))
        notable["ja3"] = sorted(set(_extract_column(ssl_log, "ja3", 100)))
    x509_log = out_dir / "x509.log"
    if x509_log.exists():
        notable["cert_subjects"] = sorted(set(_extract_column(x509_log, "certificate.subject", 100)))
    notice_log = out_dir / "notice.log"
    if notice_log.exists():
        notable["notices"] = sorted(set(_extract_column(notice_log, "note", 50)))
    # PR-M: surface the additional Zeek logs the SANS Network Forensics
    # poster calls out — each is a distinct DFIR signal that the agent
    # can turn into its own finding.
    weird_log = out_dir / "weird.log"
    if weird_log.exists():
        notable["weird_names"] = sorted(set(
            _extract_column(weird_log, "name", 100)))
    sig_log = out_dir / "signatures.log"
    if sig_log.exists():
        notable["signature_ids"] = sorted(set(
            _extract_column(sig_log, "sig_id", 50)))
        notable["signature_notes"] = sorted(set(
            _extract_column(sig_log, "note", 50)))
    software_log = out_dir / "software.log"
    if software_log.exists():
        notable["software_names"] = sorted(set(
            _extract_column(software_log, "name", 100)))
        notable["software_hosts"] = sorted(set(
            _extract_column(software_log, "host", 50)))
    kh_log = out_dir / "known_hosts.log"
    if kh_log.exists():
        notable["known_hosts"] = sorted(set(
            _extract_column(kh_log, "host", 200)))
    ks_log = out_dir / "known_services.log"
    if ks_log.exists():
        notable["known_services"] = sorted(set(
            _extract_column(ks_log, "service", 100)))
    files_log = out_dir / "files.log"
    if files_log.exists():
        notable["file_mime_types"] = sorted(set(
            _extract_column(files_log, "mime_type", 100)))
        notable["file_sha256"] = sorted(set(
            _extract_column(files_log, "sha256", 200)))

    return ZeekRun(pcap=pcap, out_dir=out_dir, rc=proc.returncode,
                   log_files=logs, summary=summary, notable=notable,
                   command=cmd)

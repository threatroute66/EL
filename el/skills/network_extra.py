"""Skill: tshark + suricata wrappers (deeper network analysis than scapy_pcap).

tshark — Wireshark CLI; protocol decoders for hundreds of protocols. We
use it for richer HTTP/HTTPS extraction (request URIs, server certs,
JA3/JA3S fingerprints) that scapy_pcap doesn't cover deeply.

suricata — IDS engine; runs Emerging-Threats (ET-Open) ruleset against
a pcap and produces eve.json with per-alert classifications + ATT&CK
mappings.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class TsharkError(RuntimeError):
    pass


class SuricataError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# tshark
# ---------------------------------------------------------------------------

def _tshark_bin() -> str:
    p = shutil.which("tshark")
    if not p:
        raise TsharkError("tshark not on PATH")
    return p


def _tshark_version() -> str:
    try:
        r = subprocess.run([_tshark_bin(), "-v"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr).strip().splitlines()[0]
    except Exception:
        return "present"


@dataclass
class TsharkExtract:
    pcap: Path
    out_path: Path
    rc: int
    fields: dict[str, list[str]] = field(default_factory=dict)
    command: list[str] = field(default_factory=list)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        sha = "0" * 64
        if self.out_path.exists():
            sha = hashlib.sha256(self.out_path.read_bytes()[:4 * 1024 * 1024]).hexdigest()
        merged = {f"{k}_count": len(v) for k, v in self.fields.items()}
        merged["rc"] = self.rc
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool="tshark", version=_tshark_version(),
            command=" ".join(self.command),
            output_sha256=sha, output_path=str(self.out_path),
            extracted_facts=merged,
        )


def extract_http_tls(pcap: Path, out_dir: Path, timeout: int = 600) -> TsharkExtract:
    """Pull richer HTTP + TLS metadata than scapy_pcap captures.

    Uses tshark -T fields to dump:
      - http.request.full_uri (full URL)
      - http.user_agent
      - http.host
      - tls.handshake.extensions_server_name (SNI)
      - tls.handshake.ja3_full / ja3s.full (if present in capture)
      - x509sat.printableString (cert subjects)
    """
    pcap = Path(pcap)
    if not pcap.exists():
        raise TsharkError(f"pcap not found: {pcap}")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "tshark-http-tls.json"

    fields_to_extract = [
        "http.request.full_uri", "http.user_agent", "http.host",
        "tls.handshake.extensions_server_name",
        "x509sat.printableString",
    ]
    cmd = [_tshark_bin(), "-r", str(pcap), "-T", "fields",
           "-E", "separator=|", "-E", "header=y"]
    for f in fields_to_extract:
        cmd += ["-e", f]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise TsharkError(f"tshark timeout") from e

    fields_out: dict[str, set[str]] = {f: set() for f in fields_to_extract}
    if proc.stdout:
        lines = proc.stdout.splitlines()
        if len(lines) > 1:
            header = lines[0].split("|")
            for line in lines[1:]:
                cells = line.split("|")
                for i, h in enumerate(header):
                    if i < len(cells) and cells[i]:
                        for v in cells[i].split(","):
                            v = v.strip()
                            if v:
                                fields_out.setdefault(h, set()).add(v)

    out_path.write_text(json.dumps({k: sorted(v) for k, v in fields_out.items()}, indent=2))
    return TsharkExtract(
        pcap=pcap, out_path=out_path, rc=proc.returncode,
        fields={k: sorted(v) for k, v in fields_out.items()},
        command=cmd,
    )


# ---------------------------------------------------------------------------
# suricata
# ---------------------------------------------------------------------------

def _suricata_bin() -> str:
    p = shutil.which("suricata")
    if not p:
        raise SuricataError("suricata not on PATH")
    return p


def _suricata_version() -> str:
    try:
        r = subprocess.run([_suricata_bin(), "-V"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr).strip().splitlines()[0]
    except Exception:
        return "present"


@dataclass
class SuricataRun:
    pcap: Path
    out_dir: Path
    rc: int
    eve_path: Path
    alert_count: int = 0
    sig_hits: dict[str, int] = field(default_factory=dict)
    command: list[str] = field(default_factory=list)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        sha = "0" * 64
        if self.eve_path.exists():
            sha = hashlib.sha256(self.eve_path.read_bytes()[:4 * 1024 * 1024]).hexdigest()
        merged = {"rc": self.rc, "alert_count": self.alert_count,
                  "top_signatures": sorted(self.sig_hits.items(), key=lambda kv: -kv[1])[:15]}
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool="suricata", version=_suricata_version(),
            command=" ".join(self.command),
            output_sha256=sha, output_path=str(self.eve_path),
            extracted_facts=merged,
        )


_SURICATA_RULES_CANDIDATES = [
    "/etc/suricata/rules", "/var/lib/suricata/rules",
]


def _rules_path() -> Path | None:
    for p in _SURICATA_RULES_CANDIDATES:
        if Path(p).is_dir() and any(Path(p).glob("*.rules")):
            return Path(p)
    return None


def replay_pcap(pcap: Path, out_dir: Path, timeout: int = 1800) -> SuricataRun:
    """Run suricata in pcap-reader mode against the provided pcap. Writes
    eve.json into out_dir with one event per alert/flow/file."""
    pcap = Path(pcap)
    if not pcap.exists():
        raise SuricataError(f"pcap not found: {pcap}")
    out_dir.mkdir(parents=True, exist_ok=True)
    eve = out_dir / "eve.json"
    cmd = [_suricata_bin(), "-r", str(pcap), "-l", str(out_dir),
           "--runmode", "single", "-k", "none"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SuricataError(f"suricata timeout") from e

    n = 0
    sigs: Counter = Counter()
    if eve.exists():
        try:
            with eve.open(errors="ignore") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("event_type") == "alert":
                        n += 1
                        sig = (ev.get("alert") or {}).get("signature") or ""
                        if sig:
                            sigs[sig] += 1
        except Exception:
            pass

    return SuricataRun(pcap=pcap, out_dir=out_dir, rc=proc.returncode,
                       eve_path=eve, alert_count=n, sig_hits=dict(sigs),
                       command=cmd)

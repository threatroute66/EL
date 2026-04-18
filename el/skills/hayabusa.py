"""Skill: hayabusa — Sigma-rule-based Windows EVTX threat hunter.

Yamato-Security/hayabusa applies a curated Sigma ruleset to EVTX files
and emits per-rule hits with ATT&CK technique IDs, severity, and
Sigma rule provenance. Drop-in addition to LogAnalyst's basic Event-ID
counting — surfaces named TTPs (e.g. "Suspicious Encoded PowerShell
Command Line", T1059.001) instead of raw counts.
"""
from __future__ import annotations

import csv
import hashlib
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class HayabusaError(RuntimeError):
    pass


@dataclass
class HayabusaRun:
    target: Path
    rc: int
    csv_path: Path
    stderr_path: Path
    command: list[str]
    detection_count: int = 0
    rule_hits: dict[str, int] = field(default_factory=dict)  # rule_name -> hit count
    severity_counts: dict[str, int] = field(default_factory=dict)
    attack_techniques: set[str] = field(default_factory=set)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        sha = "0" * 64
        if self.csv_path.exists():
            sha = hashlib.sha256(self.csv_path.read_bytes()[:4 * 1024 * 1024]).hexdigest()
        merged = {"rc": self.rc, "detection_count": self.detection_count,
                  "severity_counts": self.severity_counts,
                  "attack_techniques": sorted(self.attack_techniques)[:30],
                  "top_rules": sorted(self.rule_hits.items(), key=lambda kv: -kv[1])[:15]}
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool="hayabusa", version=_version(),
            command=" ".join(self.command),
            output_sha256=sha, output_path=str(self.csv_path),
            extracted_facts=merged,
        )


def _bin() -> str:
    p = shutil.which("hayabusa")
    if not p:
        raise HayabusaError("hayabusa not on PATH")
    return p


def _version() -> str:
    try:
        r = subprocess.run([_bin(), "help"], capture_output=True, text=True, timeout=5)
        first = (r.stdout or r.stderr).strip().splitlines()[0]
        return first
    except Exception:
        return "present"


def _rules_dir() -> Path:
    """hayabusa expects --rules <dir>; default ships with /opt/hayabusa/rules/."""
    candidates = [Path("/opt/hayabusa/rules"), Path("/opt/hayabusa/encoded_rules")]
    for c in candidates:
        if c.is_dir():
            return c
    raise HayabusaError("hayabusa rules dir not found at /opt/hayabusa/rules")


def csv_timeline(target: Path, out_dir: Path,
                 timeout: int = 1800) -> HayabusaRun:
    """Run hayabusa csv-timeline on a single .evtx OR a directory of .evtx files.
    Output is a sorted CSV with one row per detection."""
    target = Path(target)
    if not target.exists():
        raise HayabusaError(f"target not found: {target}")
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "hayabusa-detections.csv"
    stderr_path = out_dir / "hayabusa.stderr"

    rules = _rules_dir()
    arg = "-d" if target.is_dir() else "-f"
    cmd = [_bin(), "csv-timeline", arg, str(target),
           "--rules", str(rules),
           "-o", str(csv_path),
           "--no-color", "--no-summary", "--quiet", "-w"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise HayabusaError(f"hayabusa timeout") from e

    stderr_path.write_text(proc.stderr or "")

    rule_hits: Counter = Counter()
    sev_counts: Counter = Counter()
    techniques: set[str] = set()
    n = 0
    if csv_path.exists():
        try:
            with csv_path.open(errors="ignore") as f:
                rd = csv.DictReader(f)
                for row in rd:
                    n += 1
                    rule = row.get("RuleTitle") or row.get("Rule Title") or ""
                    if rule:
                        rule_hits[rule] += 1
                    sev = row.get("Level") or row.get("Severity") or ""
                    if sev:
                        sev_counts[sev] += 1
                    mitre = row.get("MitreTactics") or row.get("MitreTechniques") or ""
                    if mitre:
                        for tok in mitre.replace(",", " ").split():
                            tok = tok.strip()
                            if tok.startswith("T") and tok[1:5].isdigit():
                                techniques.add(tok)
        except Exception:
            pass

    return HayabusaRun(
        target=target, rc=proc.returncode,
        csv_path=csv_path, stderr_path=stderr_path, command=cmd,
        detection_count=n, rule_hits=dict(rule_hits),
        severity_counts=dict(sev_counts),
        attack_techniques=techniques,
    )

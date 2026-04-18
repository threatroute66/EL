"""Skill: capa — capability fingerprinting for malware binaries.

Mandiant's capa identifies capabilities (process injection, persistence,
credential access, etc.) in PE/ELF/shellcode dumps via rule matching.
Maps directly to MITRE ATT&CK technique IDs. Critical for attributing
stripped shellcode dumps that have no textual family markers.

Reads a binary file (.dmp / .exe / .dll / shellcode), produces JSON with:
  - matched rules (with namespaces)
  - ATT&CK techniques + tactics
  - MBC (Malware Behavior Catalog) entries
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class CapaError(RuntimeError):
    pass


@dataclass
class CapaResult:
    target: Path
    rc: int
    rules_matched: list[str] = field(default_factory=list)
    attack_techniques: list[tuple[str, str]] = field(default_factory=list)  # (T-id, name)
    mbc: list[str] = field(default_factory=list)
    json_path: Path | None = None
    command: list[str] = field(default_factory=list)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        sha = "0" * 64
        if self.json_path and self.json_path.exists():
            sha = hashlib.sha256(self.json_path.read_bytes()).hexdigest()
        merged = {"rc": self.rc, "rule_count": len(self.rules_matched),
                  "rules_matched": self.rules_matched[:40],
                  "attack_techniques": [t for t, _ in self.attack_techniques][:30]}
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool="capa", version=_version(),
            command=" ".join(self.command),
            output_sha256=sha,
            output_path=str(self.json_path or self.target),
            extracted_facts=merged,
        )


def _bin() -> str:
    p = shutil.which("capa") or str(Path(sys.executable).parent / "capa")
    if not Path(p).is_file():
        raise CapaError("capa not installed (pip install flare-capa)")
    return p


def _version() -> str:
    try:
        r = subprocess.run([_bin(), "--version"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr).strip().splitlines()[0]
    except Exception:
        return "present"


def analyze(target: Path, out_dir: Path,
            shellcode_arch: str | None = None,
            timeout: int = 600) -> CapaResult:
    """Run capa on target binary. Returns parsed capabilities + ATT&CK.

    For shellcode dumps (vol3 malfind output), set shellcode_arch='32'
    or '64'. capa needs the architecture hint; defaults to PE/ELF parsing
    which fails on raw shellcode.
    """
    target = Path(target)
    if not target.exists():
        raise CapaError(f"target not found: {target}")
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"capa-{target.name}.json"
    stderr_path = out_dir / f"capa-{target.name}.stderr"

    cmd = [_bin(), "--json"]
    if shellcode_arch:
        cmd += ["--format", f"sc{shellcode_arch}"]
    cmd.append(str(target))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise CapaError(f"capa timeout") from e

    stderr_path.write_text(proc.stderr or "")

    rules: list[str] = []
    techniques: list[tuple[str, str]] = []
    mbc: list[str] = []
    if proc.stdout:
        json_path.write_text(proc.stdout)
        try:
            data = json.loads(proc.stdout)
            for rule_name, rule_meta in (data.get("rules") or {}).items():
                rules.append(rule_name)
                meta = rule_meta.get("meta") or {}
                for att in meta.get("attack") or []:
                    tid = att.get("id"); tname = att.get("technique") or ""
                    if tid:
                        techniques.append((tid, tname))
                for m in meta.get("mbc") or []:
                    mid = m.get("id"); mname = m.get("objective") or ""
                    if mid:
                        mbc.append(f"{mid} {mname}")
        except (json.JSONDecodeError, AttributeError):
            pass

    return CapaResult(
        target=target, rc=proc.returncode, rules_matched=sorted(set(rules)),
        attack_techniques=list({(t, n) for t, n in techniques}),
        mbc=sorted(set(mbc)), json_path=json_path, command=cmd,
    )

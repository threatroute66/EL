"""Skill: YARA hunting (per yara-hunting SKILL).

Wraps the system `yara` binary. Pure subprocess — pure Python `yara-python`
intentionally avoided here so we use the same binary the SKILL documents
(consistent flag semantics with operator notes).

YARA-X migration (per docs/enhancement_proposals.md Tier 2.5): the helper
``_yara_bin()`` prefers VirusTotal's Rust rewrite ``yr`` (~10× faster) when
present on PATH, falling back to YARA 4.x. Set ``EL_FORCE_YARA4=1`` to opt
out (useful for rules that target YARA 4 features YARA-X hasn't yet ported).

Provides:
  - scan_paths(): scan files/dirs against a rules file
  - generate_ioc_rules(): emit a YARA file from a per-case IOC catalog,
    so Threat Hunter can sweep evidence with the SAME indicators IOC
    extractor already extracted.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class YaraError(RuntimeError):
    pass


def _is_yara_x(binary_path: str) -> bool:
    """Heuristic: a path containing 'yr' or 'yara-x' is YARA-X; else YARA 4.x.

    YARA-X's CLI uses ``yr scan ...`` rather than ``yara ...`` directly, so
    invoking it differs slightly. Callers query this to decide the argv shape.
    """
    name = Path(binary_path).name
    return name in ("yr", "yara-x") or "yara-x" in name


@dataclass
class YaraScanResult:
    rules_path: Path
    target: Path
    rc: int
    hits_path: Path
    stderr_path: Path
    command: list[str]
    hit_count: int = 0
    rule_to_files: dict[str, list[str]] = field(default_factory=dict)

    def as_evidence(self) -> EvidenceItem:
        sha = hashlib.sha256(self.hits_path.read_bytes()).hexdigest()
        return EvidenceItem(
            tool="yara", version=_yara_version(),
            command=" ".join(self.command),
            output_sha256=sha, output_path=str(self.hits_path),
            extracted_facts={"rc": self.rc, "hit_count": self.hit_count,
                             "rules_with_hits": list(self.rule_to_files.keys())[:50]},
        )


def _yara_bin() -> str:
    """Locate the YARA binary, preferring YARA-X (`yr`) when present.

    Set EL_FORCE_YARA4=1 to skip the YARA-X check and force YARA 4.x.
    """
    if os.environ.get("EL_FORCE_YARA4") != "1":
        yr = shutil.which("yr")
        if yr:
            return yr
    p = shutil.which("yara")
    if p:
        return p
    raise YaraError(
        "neither yr (YARA-X) nor yara (YARA 4) on PATH "
        "(install per yara-hunting SKILL)"
    )


def _yara_version() -> str:
    try:
        binary = _yara_bin()
        # YARA-X: `yr --version` works; YARA 4: `yara --version` works too.
        r = subprocess.run([binary, "--version"],
                            capture_output=True, text=True, timeout=5)
        text = (r.stdout or r.stderr).strip()
        if not text:
            return "present"
        return text.splitlines()[0]
    except Exception:
        return "present"


def scan_paths(rules_path: Path, target: Path, out_dir: Path,
               recursive: bool = True, show_strings: bool = True,
               threads: int = 4, timeout: int = 1800,
               per_file_timeout: int = 30) -> YaraScanResult:
    """SKILL flag set: -r recursive, -s strings, -p N threads, --timeout per file.

    Compatible with both YARA 4.x (``yara``) and YARA-X (``yr scan``):
    YARA-X uses a ``scan`` subcommand and lacks the ``-N`` (no-symlinks)
    flag YARA 4 supports. We adapt the argv per binary; output line shape
    (``rule_name <space> filepath``) is identical between the two so our
    parser doesn't change.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    hits_path = out_dir / f"yara_hits_{target.name}.txt"
    stderr_path = out_dir / f"yara_{target.name}.stderr"

    binary = _yara_bin()
    args: list[str] = [binary]
    if _is_yara_x(binary):
        # YARA-X: argv is `yr scan [opts] <rules> <target>`. No -N flag.
        args.append("scan")
        if recursive and target.is_dir():
            args.append("-r")
        if show_strings:
            args.append("-s")
        args += ["-p", str(threads), "-a", str(per_file_timeout),
                 str(rules_path), str(target)]
    else:
        # YARA 4.x: argv is `yara [opts] <rules> <target>`.
        if recursive and target.is_dir():
            args.append("-r")
        if show_strings:
            args.append("-s")
        args += ["-p", str(threads), "-a", str(per_file_timeout),
                 "-N", str(rules_path), str(target)]

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr_path.write_text(f"TIMEOUT after {timeout}s\n{e}")
        raise YaraError("yara scan timeout") from e

    raw = proc.stdout or ""
    stderr_path.write_text(proc.stderr or "")
    hits_path.write_text(raw)

    rule_to_files: dict[str, list[str]] = {}
    hit_count = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("0x") or line.startswith("$"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            rule_name, filepath = parts
            rule_to_files.setdefault(rule_name, []).append(filepath)
            hit_count += 1

    return YaraScanResult(
        rules_path=rules_path, target=target, rc=proc.returncode,
        hits_path=hits_path, stderr_path=stderr_path, command=args,
        hit_count=hit_count, rule_to_files=rule_to_files,
    )


# Curated family rules appended to every generated rule file so a known
# family is named even when the case IOC catalog doesn't already carry its
# indicators. Keep these high-signal (hallmark UA / build string / specific
# C2 endpoint) to avoid false positives. No regex / external modules so the
# block compiles under both YARA 4.x and YARA-X.
_CURATED_RULES = r'''
rule EL_Lumma_Stealer {
    meta:
        description = "Lumma Stealer (LummaC2) infostealer — C2 / UA markers"
        family = "Lumma Stealer"
        author = "EL"
    strings:
        $ua    = "TeslaBrowser/5.5" ascii wide
        $name  = "LummaC2" ascii wide nocase
        $c2api = "/api/set_agent" ascii wide nocase
        $tok   = "token=" ascii wide nocase
        $log   = "act=log" ascii wide nocase
        $act1  = "act=receive_message" ascii wide nocase
        $act2  = "act=recive_message" ascii wide nocase
        $act3  = "act=life" ascii wide nocase
    condition:
        $ua or $name or $act1 or $act2 or $act3 or
        ($c2api and ($tok or $log))
}
'''


def generate_ioc_rules(iocs: dict[str, list[str]], out_path: Path,
                       case_id: str = "case") -> Path:
    """Emit a YARA file targeting the case's IOC catalog.

    Uses the hash module for SHA-1/256/MD5 IOCs (whole-file hash match) and
    string rules for domains/URLs/IPv4. Each IOC becomes a single rule so
    hits identify the specific indicator that fired.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = ['import "hash"', ""]

    def safe(name: str, ix: int, kind: str) -> str:
        keep = "".join(c if c.isalnum() else "_" for c in name)[:48]
        return f"EL_{case_id.replace('-', '_')}_{kind}_{ix:03d}_{keep}"

    for i, h in enumerate(iocs.get("md5", [])):
        if len(h) == 32:
            rname = safe(h, i, "md5")
            lines += [f"rule {rname} {{", "    meta:",
                      f'        description = "Case {case_id} IOC: MD5 {h}"',
                      "    condition:",
                      f'        hash.md5(0, filesize) == "{h.lower()}"', "}", ""]
    for i, h in enumerate(iocs.get("sha1", [])):
        if len(h) == 40:
            rname = safe(h, i, "sha1")
            lines += [f"rule {rname} {{", "    meta:",
                      f'        description = "Case {case_id} IOC: SHA-1 {h}"',
                      "    condition:",
                      f'        hash.sha1(0, filesize) == "{h.lower()}"', "}", ""]
    for i, h in enumerate(iocs.get("sha256", [])):
        if len(h) == 64:
            rname = safe(h, i, "sha256")
            lines += [f"rule {rname} {{", "    meta:",
                      f'        description = "Case {case_id} IOC: SHA-256 {h}"',
                      "    condition:",
                      f'        hash.sha256(0, filesize) == "{h.lower()}"', "}", ""]

    string_buckets = (
        ("domain", iocs.get("domain", [])),
        ("ipv4", iocs.get("ipv4", [])),
        ("url", iocs.get("url", [])),
        ("email", iocs.get("email", [])),
    )
    for kind, vals in string_buckets:
        for i, v in enumerate(vals):
            if not v or '"' in v or "\\" in v:
                continue
            rname = safe(v, i, kind)
            lines += [f"rule {rname} {{", "    meta:",
                      f'        description = "Case {case_id} IOC: {kind} {v}"',
                      "    strings:",
                      f'        $a = "{v}" ascii nocase wide',
                      "    condition: $a", "}", ""]

    lines.append(_CURATED_RULES)
    out_path.write_text("\n".join(lines))
    return out_path

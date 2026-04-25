"""Skill: wrap chkrootkit / rkhunter / Lynis against a mounted Linux
filesystem.

Closes gap-doc Linux-depth bullet "Rootkit scanners (chkrootkit,
rkhunter, Lynis) over mounted images". The intake pipeline already
mounts evidence read-only at e.g.
``cases/<id>/mnt/<partition>/`` (or accepts a pre-mounted dir);
this skill points each scanner at that root via its
``-r``/``--rootdir`` flag and parses the human-readable output back
into structured findings.

Each scanner has its own quirk:

- **chkrootkit** ``-r <root>`` — single-line per check, the keyword
  "INFECTED" or "Vulnerable" is the smoking gun. We capture every
  line containing those tokens.
- **rkhunter** ``--rootdir <root> --check --skip-keypress
  --report-warnings-only`` — emits ``[Warning]`` lines flat.
- **Lynis** ``audit system --rootdir <root> --no-colors --quiet`` —
  emits ``Warning:`` and ``Suggestion:`` lines at the end of the
  run; we extract those.

All three gracefully degrade when the binary is missing — the
returned ``ScanResult.available`` is False, ``error`` carries the
reason, ``findings`` is empty. ``run_all()`` runs whichever subset
is installed and returns a list of results so the caller doesn't
have to special-case missing tools.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    severity: str = "info"          # "info" | "warning" | "vulnerable"
    message: str = ""               # the exact line from the scanner

    def __str__(self) -> str:
        return f"[{self.severity}] {self.message}"


@dataclass
class ScanResult:
    tool: str = ""
    available: bool = False
    rc: int = -1
    error: str = ""
    rootdir: str = ""
    findings: list[Finding] = field(default_factory=list)
    raw_path: str = ""              # path to saved raw stdout

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "vulnerable")

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warning")


def _which(name: str) -> str | None:
    """Indirected so tests can monkeypatch per-tool independently."""
    return shutil.which(name)


def _chkrootkit_bin() -> str | None:
    return _which("chkrootkit")


def _rkhunter_bin() -> str | None:
    return _which("rkhunter")


def _lynis_bin() -> str | None:
    return _which("lynis")


def _save_raw(out_dir: Path | None, tool: str,
              stdout: str, stderr: str) -> str:
    """Persist raw stdout under <out_dir>/<tool>.stdout for the
    evidence chain. Sibling ``.stderr`` written too."""
    if out_dir is None:
        return ""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = out_dir / f"{tool}.stdout"
    raw.write_text(stdout)
    (out_dir / f"{tool}.stderr").write_text(stderr)
    return str(raw)


# --- chkrootkit ------------------------------------------------------------

# chkrootkit emits "INFECTED" for confirmed hits and "Vulnerable"
# for known-vulnerable conditions. "not infected" is the negative
# case and must be excluded.
_CHKROOTKIT_RE = re.compile(
    r"\b(INFECTED|Vulnerable!?|Possible|Suspicious)\b", re.IGNORECASE)


def run_chkrootkit(rootdir: Path,
                    *, out_dir: Path | None = None,
                    timeout: int = 600) -> ScanResult:
    r = ScanResult(tool="chkrootkit", rootdir=str(rootdir))
    binr = _chkrootkit_bin()
    if binr is None:
        r.error = "chkrootkit binary not available"
        return r
    if not Path(rootdir).is_dir():
        r.error = f"rootdir not found: {rootdir}"
        return r
    cmd = [binr, "-r", str(rootdir), "-q"]    # -q = quiet (only warnings)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        r.error = f"chkrootkit failed: {e}"
        return r
    r.available = True
    r.rc = proc.returncode
    r.raw_path = _save_raw(out_dir, "chkrootkit", proc.stdout, proc.stderr)
    for line in proc.stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        # Hard-skip the explicit-clean lines so "not infected" doesn't
        # match the INFECTED keyword.
        if "not infected" in s.lower() or "not found" in s.lower():
            continue
        m = _CHKROOTKIT_RE.search(s)
        if not m:
            continue
        kw = m.group(1).lower()
        sev = "vulnerable" if kw.startswith(("infected", "vulnerable")) \
              else "warning"
        r.findings.append(Finding(severity=sev, message=s))
    return r


# --- rkhunter --------------------------------------------------------------

# rkhunter uses [Warning] / [Found] / [Possibly] markers. We extract
# every Warning line; Lynis-style severity rollup is enough for the
# downstream Finding emitter.
_RKHUNTER_WARNING_RE = re.compile(r"^\[\s*(Warning|Possibly)\s*\]\s*(.+)$",
                                   re.IGNORECASE)


def run_rkhunter(rootdir: Path,
                  *, out_dir: Path | None = None,
                  timeout: int = 1200) -> ScanResult:
    r = ScanResult(tool="rkhunter", rootdir=str(rootdir))
    binr = _rkhunter_bin()
    if binr is None:
        r.error = "rkhunter binary not available"
        return r
    if not Path(rootdir).is_dir():
        r.error = f"rootdir not found: {rootdir}"
        return r
    cmd = [binr, "--rootdir", str(rootdir),
           "--check", "--skip-keypress", "--no-colors",
           "--report-warnings-only"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        r.error = f"rkhunter failed: {e}"
        return r
    r.available = True
    r.rc = proc.returncode
    r.raw_path = _save_raw(out_dir, "rkhunter", proc.stdout, proc.stderr)
    for line in proc.stdout.splitlines():
        s = line.strip()
        m = _RKHUNTER_WARNING_RE.match(s)
        if not m:
            continue
        kw = m.group(1).lower()
        sev = "vulnerable" if kw == "warning" else "warning"
        r.findings.append(Finding(severity=sev, message=m.group(2).strip()))
    return r


# --- Lynis -----------------------------------------------------------------

# Lynis prints findings as e.g. "Warning: ... [text]" and
# "Suggestion: ... [text]". The bracketed tail is the test ID; we
# keep the full line.
_LYNIS_LINE_RE = re.compile(r"^\s*-?\s*(Warning|Suggestion):\s*(.+?)$",
                             re.IGNORECASE)


def run_lynis(rootdir: Path,
               *, out_dir: Path | None = None,
               timeout: int = 1800) -> ScanResult:
    r = ScanResult(tool="lynis", rootdir=str(rootdir))
    binr = _lynis_bin()
    if binr is None:
        r.error = "lynis binary not available"
        return r
    if not Path(rootdir).is_dir():
        r.error = f"rootdir not found: {rootdir}"
        return r
    cmd = [binr, "audit", "system",
           "--rootdir", str(rootdir),
           "--no-colors", "--quiet"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        r.error = f"lynis failed: {e}"
        return r
    r.available = True
    r.rc = proc.returncode
    r.raw_path = _save_raw(out_dir, "lynis", proc.stdout, proc.stderr)
    for line in proc.stdout.splitlines():
        s = line.strip()
        m = _LYNIS_LINE_RE.match(s)
        if not m:
            continue
        kw = m.group(1).lower()
        sev = "vulnerable" if kw == "warning" else "warning"
        r.findings.append(Finding(severity=sev, message=m.group(2).strip()))
    return r


# --- runner ----------------------------------------------------------------


def run_all(rootdir: Path,
             *, out_dir: Path | None = None) -> list[ScanResult]:
    """Run whichever scanners are installed against ``rootdir``.
    Always returns three ScanResults (one per tool) so the caller can
    surface "scanner not installed" as part of the audit trail rather
    than silently skipping."""
    return [
        run_chkrootkit(rootdir, out_dir=out_dir),
        run_rkhunter(rootdir, out_dir=out_dir),
        run_lynis(rootdir, out_dir=out_dir),
    ]


__all__ = [
    "Finding", "ScanResult",
    "run_chkrootkit", "run_rkhunter", "run_lynis", "run_all",
]

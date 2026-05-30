"""macOS Unified Logs (tracev3) parser — Mandiant Rust port.

Wraps Mandiant's ``unifiedlog_iterator`` (Apache-2.0). Apple's Unified
Logging system on macOS / iOS stores per-process audit + telemetry data
in tracev3 binary files under ``/var/db/diagnostics/`` (Persist) and
``/var/db/uuidtext/`` (UUID-text strings). The native ``log show`` parser
only runs on macOS; Mandiant's Rust port is ~100x faster AND runs on
Linux, which is the SIFT analyst's host.

Two operating modes wired:
  * ``log-archive`` — analyst exports the host's logarchive bundle to a
    forensic directory; parser walks the bundle.
  * ``single-file`` — parse one tracev3 file at a time.

Output is JSONL: one event per line, with subsystem / category / process
name / log type / event message. We aggregate by process and surface
high-signal patterns (TCC consent prompts, AMFI rejections, gatekeeper
denials, sandbox violations).

Project: https://github.com/mandiant/macos-UnifiedLogs
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from el.schemas.finding import EvidenceItem


class MacOSUnifiedLogsError(Exception):
    pass


def _which() -> Path:
    candidates = [
        Path("/opt/macos-unifiedlogs/unifiedlog_iterator"),
        Path("/usr/local/bin/unifiedlog_iterator"),
    ]
    p = shutil.which("unifiedlog_iterator")
    if p:
        candidates.insert(0, Path(p))
    for c in candidates:
        if c.is_file():
            return c
    raise MacOSUnifiedLogsError(
        "unifiedlog_iterator not found — install via "
        "https://github.com/mandiant/macos-UnifiedLogs/releases "
        "(staged at /opt/macos-unifiedlogs/)"
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    if not path.is_file():
        return "0" * 64
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# Subsystem / category prefixes that indicate forensically interesting events.
_HIGH_SIGNAL_SUBSYSTEMS = (
    "com.apple.tcc",                # TCC privacy consent prompts
    "com.apple.amfi",                # Apple Mobile File Integrity
    "com.apple.security.gatekeeper", # Gatekeeper / quarantine
    "com.apple.security.amfi",
    "com.apple.security.sandbox",    # Sandbox violations
    "com.apple.LaunchServices",      # App-bundle execution
    "com.apple.kextd",               # Kext loading
    "com.apple.SIPProtection",       # System Integrity Protection
    "com.apple.xpc.launchd",         # launchd events
    "com.apple.persona",
    "com.apple.spnotificationd",
)

# Severity / type values that are operationally interesting in IR.
_HIGH_SIGNAL_TYPE_PREFIXES = (
    "fault", "error", "alert",
)


@dataclass
class UnifiedLogEvent:
    timestamp: str = ""
    process: str = ""
    subsystem: str = ""
    category: str = ""
    log_type: str = ""
    message: str = ""

    @classmethod
    def from_json(cls, obj: dict) -> "UnifiedLogEvent | None":
        if not isinstance(obj, dict):
            return None
        return cls(
            timestamp=str(obj.get("timestamp")
                           or obj.get("time") or "")[:32],
            process=str(obj.get("process")
                          or obj.get("process_name") or "")[:128],
            subsystem=str(obj.get("subsystem") or "")[:128],
            category=str(obj.get("category") or "")[:64],
            log_type=str(obj.get("log_type") or obj.get("event_type")
                          or "")[:32].lower(),
            message=str(obj.get("message") or obj.get("formatted_message")
                          or "")[:500],
        )

    def is_high_signal(self) -> bool:
        if any(self.subsystem.startswith(p) for p in _HIGH_SIGNAL_SUBSYSTEMS):
            return True
        if any(self.log_type.startswith(p) for p in _HIGH_SIGNAL_TYPE_PREFIXES):
            return True
        return False


@dataclass
class UnifiedLogsRun:
    input_path: Path
    output_path: Path
    mode: str            # "log-archive" / "single-file" / "live"
    rc: int
    duration_seconds: float = 0.0
    event_count: int = 0
    by_subsystem: dict[str, int] = field(default_factory=dict)
    by_log_type: dict[str, int] = field(default_factory=dict)
    distinct_processes: int = 0
    high_signal_count: int = 0
    output_sha256: str = ""
    command: list[str] = field(default_factory=list)
    stderr_path: Path | None = None
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="macos_unifiedlogs",
            version="0.5.1",
            command=" ".join(str(p) for p in self.command),
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path),
            extracted_facts={
                "mode": self.mode,
                "input_path": str(self.input_path),
                "event_count": self.event_count,
                "high_signal_count": self.high_signal_count,
                "distinct_processes": self.distinct_processes,
                "top_subsystems": dict(sorted(
                    self.by_subsystem.items(), key=lambda kv: -kv[1]
                )[:15]),
                "by_log_type": self.by_log_type,
                "rc": self.rc,
                "duration_seconds": round(self.duration_seconds, 2),
                "note": self.note,
                **extra,
            },
        )

    def iter_high_signal(self, *, max_count: int = 200) -> Iterator[UnifiedLogEvent]:
        if not self.output_path.is_file():
            return
        opened = 0
        with self.output_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ev = UnifiedLogEvent.from_json(obj)
                if ev and ev.is_high_signal():
                    yield ev
                    opened += 1
                    if opened >= max_count:
                        return


def _resolve_mode(input_path: Path) -> str:
    """Heuristic: a directory ending in .logarchive is log-archive mode;
    a single file (often .tracev3) is single-file."""
    if input_path.is_dir():
        return "log-archive"
    return "single-file"


def parse(input_path: Path,
           output_dir: Path,
           *, mode: str | None = None,
           timeout_seconds: int = 1800) -> UnifiedLogsRun:
    """Parse macOS unified logs at *input_path*, write JSONL under *output_dir*.

    Args:
        input_path: a .logarchive directory OR a single tracev3 file.
        output_dir: receives ``unified_logs.jsonl`` + stderr.
        mode: explicit mode override; auto-detected if None.
        timeout_seconds: cap on the parse run (large logarchives can be
            multi-GB; default 30 min).
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise MacOSUnifiedLogsError(f"input not found: {input_path}")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    binary = _which()
    chosen_mode = mode or _resolve_mode(input_path)
    if chosen_mode not in ("log-archive", "single-file"):
        raise MacOSUnifiedLogsError(f"unsupported mode {chosen_mode!r}")

    output_path = output_dir / "unified_logs.jsonl"
    stderr_path = output_dir / "unified_logs.stderr"
    cmd = [
        str(binary),
        "--mode", chosen_mode,
        "--input", str(input_path),
        "--output", str(output_path),
        "--format", "jsonl",
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
        return UnifiedLogsRun(
            input_path=input_path, output_path=output_path,
            mode=chosen_mode, rc=124, command=cmd, stderr_path=stderr_path,
            duration_seconds=time.time() - started,
            note=f"unifiedlog_iterator timed out after {timeout_seconds}s",
        )

    duration = time.time() - started

    # Aggregate.
    by_subsystem: dict[str, int] = {}
    by_log_type: dict[str, int] = {}
    distinct_pids: set[str] = set()
    event_count = 0
    high_signal_count = 0
    if output_path.is_file():
        with output_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event_count += 1
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ev = UnifiedLogEvent.from_json(obj)
                if not ev:
                    continue
                if ev.subsystem:
                    by_subsystem[ev.subsystem] = (
                        by_subsystem.get(ev.subsystem, 0) + 1
                    )
                if ev.log_type:
                    by_log_type[ev.log_type] = (
                        by_log_type.get(ev.log_type, 0) + 1
                    )
                if ev.process:
                    distinct_pids.add(ev.process)
                if ev.is_high_signal():
                    high_signal_count += 1

    return UnifiedLogsRun(
        input_path=input_path,
        output_path=output_path,
        mode=chosen_mode,
        rc=rc,
        duration_seconds=duration,
        event_count=event_count,
        by_subsystem=by_subsystem,
        by_log_type=by_log_type,
        distinct_processes=len(distinct_pids),
        high_signal_count=high_signal_count,
        output_sha256=_sha256_file(output_path),
        command=cmd,
        stderr_path=stderr_path,
    )


def find_unified_logs(macos_root: Path) -> Path | None:
    """Locate a .logarchive bundle or /var/db/diagnostics/Persist tracev3
    file inside an extracted macOS filesystem."""
    if not macos_root.is_dir():
        return None
    # 1. .logarchive bundle (analyst typically exports + drops alongside fs)
    for bundle in macos_root.rglob("*.logarchive"):
        if bundle.is_dir():
            return bundle
    # 2. Persist tracev3 files under /var/db/diagnostics/Persist/
    persist_dir = macos_root / "private" / "var" / "db" / "diagnostics"
    if persist_dir.is_dir():
        return persist_dir
    persist_alt = macos_root / "var" / "db" / "diagnostics"
    if persist_alt.is_dir():
        return persist_alt
    # 3. Single tracev3 anywhere
    for f in macos_root.rglob("*.tracev3"):
        if f.is_file():
            return f
    return None


# ---------------------------------------------------------------------------
# logarchive assembly
# ---------------------------------------------------------------------------
#
# A mounted macOS filesystem keeps the two halves of the Unified Logging
# store in *sibling* locations:
#
#   * tracev3 chunks + boot/time mapping  →  /private/var/db/diagnostics/
#       (Persist/, Special/, Signpost/, HighVolume/, timesync/)
#   * the format-string tables (dsc + uuidtext hex dirs) that resolve a
#     chunk's `<private>`/shared-string references into readable messages
#       →  /private/var/db/uuidtext/  (dsc/ + <2-hex>/ dirs)
#
# `unifiedlog_iterator --mode log-archive` expects ALL of these under one
# directory root. Pointing it at `diagnostics/` alone parses the events but
# leaves every message as "Unknown shared string message" because the dsc /
# uuidtext tables aren't found. Assembling a real logarchive (diagnostics
# subdirs + uuidtext children at the root) restores string resolution.
#
# CRITICAL GOTCHA: the parser enumerates the archive root with `read_dir`
# and filters entries by `file_type().is_dir()`, which does NOT follow
# symlinks. A symlink-based archive is therefore silently skipped and yields
# ZERO events. We must materialise REAL directories. To avoid copying GB of
# tracev3 when the case workspace is on the same filesystem as the evidence,
# we hardlink the leaf files (real dirs + hardlinked files are
# indistinguishable from a plain tree to the parser) and fall back to a byte
# copy across filesystem boundaries (EXDEV) — the common SIFT case, where
# evidence lives on /media and the case workspace on /.

_DIAG_SUBDIRS = ("Persist", "Special", "Signpost", "HighVolume", "timesync")


def _first_existing_dir(root: Path, rel_candidates: tuple[tuple[str, ...], ...]
                         ) -> Path | None:
    for rel in rel_candidates:
        p = root.joinpath(*rel)
        if p.is_dir():
            return p
    return None


def _locate_diagnostics(macos_root: Path) -> Path | None:
    found = _first_existing_dir(macos_root, (
        ("private", "var", "db", "diagnostics"),
        ("var", "db", "diagnostics"),
        ("diagnostics",),
    ))
    if found:
        return found
    # macos_root may itself BE a diagnostics dir.
    if (macos_root / "Persist").is_dir() or (macos_root / "Special").is_dir():
        return macos_root
    return None


def _locate_uuidtext(macos_root: Path) -> Path | None:
    return _first_existing_dir(macos_root, (
        ("private", "var", "db", "uuidtext"),
        ("var", "db", "uuidtext"),
        ("uuidtext",),
    ))


def _link_or_copy(src: Path, dst: Path, *, force_copy: bool) -> None:
    """Hardlink *src* → *dst*, falling back to a byte copy on EXDEV /
    permission errors. Idempotent: a pre-existing *dst* is left untouched."""
    if dst.exists():
        return
    if not force_copy:
        try:
            os.link(src, dst)
            return
        except OSError:
            pass  # cross-device (EXDEV), perms, or already-linked → copy
    try:
        shutil.copy2(src, dst)
    except OSError:
        # copy2 can fail setting metadata on some FUSE/exfat mounts.
        shutil.copyfile(src, dst)


def _replicate_tree(src: Path, dst: Path, *, force_copy: bool) -> int:
    """Replicate *src* into *dst* as real directories with hardlinked (or
    copied) files. Returns the number of files materialised. Unreadable
    subtrees are skipped rather than aborting the whole walk."""
    count = 0
    for dirpath, _dirnames, filenames in os.walk(src, onerror=lambda _e: None):
        rel = os.path.relpath(dirpath, src)
        target_dir = dst if rel == "." else dst / rel
        target_dir.mkdir(parents=True, exist_ok=True)
        for fn in filenames:
            try:
                _link_or_copy(Path(dirpath) / fn, target_dir / fn,
                              force_copy=force_copy)
                count += 1
            except OSError:
                continue
    return count


def build_logarchive(macos_root: Path, dest: Path,
                      *, force_copy: bool = False) -> Path | None:
    """Assemble a string-resolvable ``.logarchive``-shaped directory from a
    mounted macOS filesystem *macos_root* into *dest*.

    Returns *dest* on success, or ``None`` when the inputs needed for string
    resolution aren't both present — in which case the caller should fall
    back to :func:`find_unified_logs` (parsing ``diagnostics/`` in place is
    equivalent and avoids a pointless copy when no uuidtext table exists).

    The result contains real directories (never symlinks — see the module
    note) so ``unifiedlog_iterator --mode log-archive`` can enumerate them.
    Idempotent: re-running over an existing *dest* tops up missing files
    without re-copying what's already there.
    """
    macos_root = Path(macos_root)
    dest = Path(dest)

    diagnostics = _locate_diagnostics(macos_root)
    if diagnostics is None:
        return None
    uuidtext = _locate_uuidtext(macos_root)
    if uuidtext is None:
        # No format-string table → assembling buys nothing over parsing the
        # real diagnostics dir directly. Signal the caller to fall back.
        return None

    dest.mkdir(parents=True, exist_ok=True)

    materialised_chunks = False
    for name in _DIAG_SUBDIRS:
        src = diagnostics / name
        if src.is_dir():
            _replicate_tree(src, dest / name, force_copy=force_copy)
            if name in ("Persist", "Special", "HighVolume"):
                materialised_chunks = True
    if not materialised_chunks:
        # diagnostics dir had no tracev3 chunk store — nothing to parse.
        return None

    # uuidtext children (dsc/ + <2-hex>/ dirs) go at the archive ROOT,
    # alongside Persist/ — that is where the parser looks for them.
    for child in uuidtext.iterdir():
        if child.is_dir():
            _replicate_tree(child, dest / child.name, force_copy=force_copy)

    return dest

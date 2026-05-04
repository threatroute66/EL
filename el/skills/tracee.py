"""Tracee eBPF runtime forensics — Linux live-system event capture.

Wraps Aqua Security's Tracee (Apache-2.0). Captures syscall / file / network
behavioural events from a live Linux kernel via eBPF, time-bounded, and
emits JSON for downstream Findings.

Designed to chain off the existing ``LiveResponseCollector`` (UAC) flow —
UAC takes a *snapshot* of state via standard CLI tools; Tracee captures a
*time window* of behaviour the snapshot would miss (in-flight execve,
network connect, file open events).

Requirements:
  * Root privileges (eBPF requires CAP_BPF / CAP_SYS_ADMIN)
  * Linux kernel ≥ 4.18 with BTF / CO-RE support (already present on
    SIFT 22.04+)
  * Tracee binary at /opt/tracee/dist/tracee or /usr/local/bin/tracee

Project: https://github.com/aquasecurity/tracee
"""
from __future__ import annotations

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


class TraceeError(Exception):
    pass


def _which() -> Path:
    candidates = [
        Path("/opt/tracee/dist/tracee"),
        Path("/usr/local/bin/tracee"),
    ]
    p = shutil.which("tracee")
    if p:
        candidates.insert(0, Path(p))
    for c in candidates:
        if c.is_file():
            return c
    raise TraceeError(
        "tracee not found — install via "
        "https://github.com/aquasecurity/tracee/releases (binary at "
        "/opt/tracee/dist/tracee)"
    )


def is_runnable() -> tuple[bool, str]:
    """Whether Tracee can plausibly run on this host.

    Returns (ok, reason) — the reason is operator-readable for inclusion in
    insufficient-finding claims when this returns False.
    """
    try:
        _which()
    except TraceeError as e:
        return False, str(e)
    if os.geteuid() != 0:
        return False, ("tracee requires root for eBPF (CAP_BPF). Re-run "
                        "the live-system collection step with sudo")
    if not Path("/sys/kernel/btf/vmlinux").exists():
        return False, ("/sys/kernel/btf/vmlinux missing — kernel lacks BTF "
                        "info that Tracee CO-RE needs. Most modern kernels "
                        "expose this; check CONFIG_DEBUG_INFO_BTF=y")
    return True, ""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    if not path.is_file():
        return "0" * 64
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class TraceeEvent:
    """A single Tracee JSON event (subset)."""
    timestamp: int
    process_name: str
    pid: int
    event_name: str
    args_summary: str = ""

    @classmethod
    def from_json(cls, obj: dict) -> "TraceeEvent | None":
        try:
            ts = int(obj.get("timestamp") or 0)
            pname = str(obj.get("processName")
                         or obj.get("comm") or "")[:128]
            pid = int(obj.get("processId") or obj.get("pid") or 0)
            ename = str(obj.get("eventName") or obj.get("name") or "")[:64]
            args = obj.get("args") or []
            if isinstance(args, list):
                pieces = []
                for a in args[:5]:
                    if isinstance(a, dict):
                        pieces.append(f"{a.get('name', '?')}={a.get('value', '')}")
                args_summary = " ".join(pieces)[:300]
            else:
                args_summary = str(args)[:300]
            return cls(timestamp=ts, process_name=pname, pid=pid,
                        event_name=ename, args_summary=args_summary)
        except (TypeError, ValueError):
            return None


@dataclass
class TraceeRun:
    output_path: Path
    duration_seconds: float
    requested_seconds: int
    rc: int
    event_count: int = 0
    events_by_type: dict[str, int] = field(default_factory=dict)
    distinct_processes: int = 0
    output_sha256: str = ""
    command: list[str] = field(default_factory=list)
    stderr_path: Path | None = None
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="tracee",
            version="v0.24.1",
            command=" ".join(str(p) for p in self.command),
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path),
            extracted_facts={
                "requested_seconds": self.requested_seconds,
                "duration_seconds": round(self.duration_seconds, 2),
                "event_count": self.event_count,
                "events_by_type": dict(sorted(
                    self.events_by_type.items(), key=lambda kv: -kv[1]
                )[:25]),
                "distinct_processes": self.distinct_processes,
                "rc": self.rc,
                "note": self.note,
                **extra,
            },
        )

    def iter_events(self, *, max_rows: int | None = None) -> Iterator[TraceeEvent]:
        if not self.output_path.is_file():
            return
        with self.output_path.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if max_rows is not None and i >= max_rows:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ev = TraceeEvent.from_json(obj)
                if ev:
                    yield ev


# Default high-signal event set — what an analyst running an IR live capture
# typically wants. Each is an event name Tracee knows; the full list is in
# `tracee list`. Keep this short to bound the JSONL volume.
_DEFAULT_EVENTS = (
    "execve",                   # process execution
    "execveat",
    "openat",                   # file opens (broad — bound by duration)
    "security_file_open",
    "security_socket_connect",  # network connect
    "security_kernel_module_load",
    "ptrace",                   # injection / debugger attach
    "memfd_create",
    "init_module",
    "finit_module",
)


def capture(
    output_dir: Path,
    *,
    duration_seconds: int = 60,
    events: tuple[str, ...] | None = None,
) -> TraceeRun:
    """Run Tracee for *duration_seconds*, capturing JSON events to disk.

    Args:
        output_dir: per-case directory; receives ``tracee.jsonl`` + stderr.
        duration_seconds: how long to capture. Bounded; this is *not* an
            always-on sensor. Default 60s gives meaningful coverage without
            unbounded JSONL growth.
        events: optional tuple of event names overriding the default set.

    Returns a :class:`TraceeRun` with parsed event statistics. Raises
    :class:`TraceeError` only on a precondition failure (binary missing or
    not running as root); other failures are surfaced via ``rc`` + ``note``.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ok, reason = is_runnable()
    if not ok:
        return TraceeRun(
            output_path=output_dir / "tracee.jsonl",
            duration_seconds=0.0,
            requested_seconds=duration_seconds,
            rc=126,
            note=reason,
        )

    binary = _which()
    output_path = output_dir / "tracee.jsonl"
    stderr_path = output_dir / "tracee.stderr"
    cmd = [str(binary), "--output", f"json:{output_path}"]
    for ev in (events or _DEFAULT_EVENTS):
        cmd.extend(["-e", ev])

    started = time.time()
    proc: subprocess.Popen | None = None
    try:
        with stderr_path.open("wb") as ferr:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=ferr,
                start_new_session=True,
            )
        # Bounded capture window.
        try:
            proc.wait(timeout=duration_seconds)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            rc = 0  # graceful termination after the duration window
    except (OSError, subprocess.SubprocessError) as e:
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
        return TraceeRun(
            output_path=output_path, requested_seconds=duration_seconds,
            duration_seconds=time.time() - started, rc=125,
            command=cmd, stderr_path=stderr_path,
            note=f"tracee invocation failed: {e}",
        )

    duration = time.time() - started
    event_count = 0
    by_type: dict[str, int] = {}
    pids: set[int] = set()
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
                name = obj.get("eventName") or obj.get("name")
                if name:
                    by_type[str(name)] = by_type.get(str(name), 0) + 1
                pid = obj.get("processId") or obj.get("pid")
                if isinstance(pid, int):
                    pids.add(pid)

    return TraceeRun(
        output_path=output_path,
        duration_seconds=duration,
        requested_seconds=duration_seconds,
        rc=rc,
        event_count=event_count,
        events_by_type=by_type,
        distinct_processes=len(pids),
        output_sha256=_sha256_file(output_path),
        command=cmd,
        stderr_path=stderr_path,
    )

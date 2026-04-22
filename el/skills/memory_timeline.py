"""Memory-timeline skill — Tier 3 of the Roussev & Quates (2012)
methodology. Diff per-snapshot module inventories against a
baseline + against each other to produce a chronological intrusion
narrative without running any deep parser.

The paper's Case 2 (keylogger on Pat): 18 daily RAM snapshots diffed
against the clean day-1 disk baseline produced the full attacker
timeline (AVG update → XP Advanced Keylogger install → RealVNC
install → keylogger removed) from executable-module deltas alone.

Module set per case is the union of:
  - `pslist` ImageFileName (running processes)
  - `dlllist` Path (loaded DLLs per process; the bulk of the signal)
  - `modules` FullDllName (kernel drivers; optional)

Paths are lowercase-normalised so case-insensitive Windows paths
compare cleanly. Identity is (normalised_path) — sha256 isn't in
the vol3 JSON outputs unless `--dump` ran, so path is what we key on.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


def _norm_path(p: str | None) -> str:
    if not p:
        return ""
    return p.strip().lower().replace("\\", "/")


def _load_json(path: Path) -> list:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    return data if isinstance(data, list) else []


def extract_module_set(case_dir: str | Path) -> dict[str, list[dict]]:
    """Pull every module/DLL/driver path referenced in the case's
    memory_forensicator outputs. Returns
      {normalised_path: [{pid, process, raw_path, source}, ...]}
    so a caller can cite which PIDs / processes a given module is
    tied to in the snapshot.
    """
    root = Path(case_dir) / "analysis" / "memory_forensicator"
    modules: dict[str, list[dict]] = {}
    # pslist → running processes (ImageFileName usually a bare exe name)
    for rec in _load_json(root / "windows_pslist_PsList.json"):
        name = rec.get("ImageFileName") or ""
        key = _norm_path(name)
        if not key:
            continue
        modules.setdefault(key, []).append({
            "pid": rec.get("PID"), "process": name,
            "raw_path": name, "source": "pslist",
        })
    # dlllist → loaded DLLs per process; the bulk of the signal
    for rec in _load_json(root / "windows_dlllist_DllList.json"):
        path = rec.get("Path") or rec.get("Name") or ""
        key = _norm_path(path)
        if not key:
            continue
        modules.setdefault(key, []).append({
            "pid": rec.get("PID"),
            "process": rec.get("Process") or rec.get("Name"),
            "raw_path": path, "source": "dlllist",
        })
    # modules → kernel drivers
    for rec in _load_json(root / "windows_modules_Modules.json"):
        path = rec.get("FullDllName") or rec.get("Path") or ""
        key = _norm_path(path)
        if not key:
            continue
        modules.setdefault(key, []).append({
            "pid": None, "process": rec.get("Name") or "",
            "raw_path": path, "source": "modules",
        })
    return modules


def _case_snapshot_ts(case_dir: Path) -> str | None:
    """Best-effort snapshot timestamp. Prefers manifest.json
    `intake_utc`; falls back to manifest mtime."""
    m = Path(case_dir) / "manifest.json"
    if m.is_file():
        try:
            data = json.loads(m.read_text())
            for k in ("intake_utc", "acquired_utc", "snapshot_utc"):
                v = data.get(k)
                if v:
                    return v
        except Exception:
            pass
        return datetime.fromtimestamp(m.stat().st_mtime).isoformat(
            timespec="seconds")
    return None


@dataclass
class TimelineEntry:
    case_id: str
    case_dir: Path
    snapshot_ts: str | None
    module_count: int
    novel_vs_baseline: list[str] = field(default_factory=list)
    novel_vs_previous: list[str] = field(default_factory=list)
    removed_vs_previous: list[str] = field(default_factory=list)


@dataclass
class Timeline:
    baseline_case_id: str | None
    baseline_count: int
    entries: list[TimelineEntry]


def _sort_key(case_dir: Path) -> tuple:
    ts = _case_snapshot_ts(case_dir) or ""
    return (ts, case_dir.name)


def build_timeline(
    case_dirs: list[str | Path],
    baseline: str | Path | None = None,
) -> Timeline:
    """Chronological diff: for each case, what's novel vs baseline
    (paper's main signal) and what's novel/removed vs the previous
    snapshot (narrative progression).

    baseline: path to a case directory whose module set is the
    "before the incident" reference. If None, the chronologically
    earliest case in `case_dirs` is used as its own baseline and
    every subsequent case is diffed against it.
    """
    cases = [Path(c) for c in case_dirs]
    cases.sort(key=_sort_key)

    if baseline is not None:
        baseline_dir = Path(baseline)
        baseline_modules = set(extract_module_set(baseline_dir))
        baseline_id = baseline_dir.name
    elif cases:
        baseline_dir = cases[0]
        baseline_modules = set(extract_module_set(baseline_dir))
        baseline_id = baseline_dir.name
        cases = cases[1:]        # first becomes the baseline, don't double-count
    else:
        baseline_modules = set()
        baseline_id = None

    prev_modules: set[str] = baseline_modules
    entries: list[TimelineEntry] = []
    for cd in cases:
        current = extract_module_set(cd)
        current_paths = set(current)
        novel_vs_base = sorted(current_paths - baseline_modules)
        novel_vs_prev = sorted(current_paths - prev_modules)
        removed_vs_prev = sorted(prev_modules - current_paths)
        entries.append(TimelineEntry(
            case_id=cd.name,
            case_dir=cd,
            snapshot_ts=_case_snapshot_ts(cd),
            module_count=len(current_paths),
            novel_vs_baseline=novel_vs_base,
            novel_vs_previous=novel_vs_prev,
            removed_vs_previous=removed_vs_prev,
        ))
        prev_modules = current_paths

    return Timeline(
        baseline_case_id=baseline_id,
        baseline_count=len(baseline_modules),
        entries=entries,
    )


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

# Suspicious-path markers reused from other detectors — when a novel
# module lands under one of these, the timeline flags it harder so
# an analyst's eye lands on it.
_SUSPICIOUS_MARKERS = (
    "/temp/", "/tmp/", "/appdata/local/temp/", "/users/public/",
    "/programdata/", "/downloads/", "/desktop/",
)


def _highlight(path: str) -> str:
    """Wrap suspicious paths in markdown bold so the timeline draws
    eyes to the rare execution locations — classic DFIR triage lens."""
    for m in _SUSPICIOUS_MARKERS:
        if m in path:
            return f"**{path}**"
    return f"`{path}`"


def render_markdown(tl: Timeline, top_n: int = 30) -> str:
    """Render a Timeline as a compact Markdown report."""
    lines: list[str] = []
    lines.append(f"# Memory Timeline")
    lines.append("")
    if tl.baseline_case_id:
        lines.append(
            f"Baseline: **{tl.baseline_case_id}** ({tl.baseline_count} "
            f"module paths). Each row below lists modules **novel** in "
            f"that snapshot compared to the baseline, and the incremental "
            f"novelty / removal vs the previous row. Paths under /Temp, "
            f"/AppData, /Downloads, /Users/Public, /ProgramData are "
            f"highlighted in bold — rare-execution locations that the "
            f"paper's M57 Case 2 found telltale of attacker staging.")
    else:
        lines.append("_No baseline set — empty timeline._")
        return "\n".join(lines)
    lines.append("")
    for e in tl.entries:
        ts = e.snapshot_ts or "-"
        lines.append(f"## {e.case_id}  ·  {ts}")
        lines.append("")
        lines.append(f"- module paths in snapshot: **{e.module_count}**")
        lines.append(f"- novel vs baseline: **{len(e.novel_vs_baseline)}**")
        lines.append(f"- novel vs previous snapshot: "
                     f"**{len(e.novel_vs_previous)}**")
        lines.append(f"- removed vs previous snapshot: "
                     f"**{len(e.removed_vs_previous)}**")
        if e.novel_vs_previous:
            lines.append("")
            lines.append("### Novel in this snapshot")
            lines.append("")
            shown = e.novel_vs_previous[:top_n]
            for m in shown:
                lines.append(f"- {_highlight(m)}")
            if len(e.novel_vs_previous) > top_n:
                lines.append(
                    f"- _…+{len(e.novel_vs_previous) - top_n} more, "
                    f"see source JSON for the complete set_")
        if e.removed_vs_previous:
            lines.append("")
            lines.append("### Removed since previous snapshot")
            lines.append("")
            shown = e.removed_vs_previous[:top_n]
            for m in shown:
                lines.append(f"- {_highlight(m)}")
            if len(e.removed_vs_previous) > top_n:
                lines.append(
                    f"- _…+{len(e.removed_vs_previous) - top_n} more_")
        lines.append("")
    return "\n".join(lines)


__all__ = [
    "TimelineEntry", "Timeline",
    "extract_module_set", "build_timeline", "render_markdown",
]

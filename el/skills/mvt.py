"""MVT (Mobile Verification Toolkit) skill — Pegasus / mercenary spyware.

Wraps Amnesty Tech's MVT — the OSS standard for mercenary-spyware (Pegasus,
Predator, Reign, Triangulation, etc.) IOC matching against iOS/Android
forensic collections.

Project: https://mvt.re
Indicators: https://github.com/AmnestyTech/investigations (STIX 2.1 bundles)

MVT outputs per-module JSON files in the output directory. Each module that
has IOC matches writes a ``<module>_detected.json`` file — those are the
high-signal findings we surface as evidence. Modules without matches still
write their parsed-artifact JSON, which is forensic gold even without a hit.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from el.schemas.finding import EvidenceItem


class MVTError(Exception):
    pass


def _which(cmd: str) -> Path:
    """Locate mvt-ios or mvt-android. Prefer the active venv's bin/."""
    import sys
    venv_bin = Path(sys.executable).parent / cmd
    if venv_bin.is_file():
        return venv_bin
    p = shutil.which(cmd)
    if p:
        return Path(p)
    raise MVTError(
        f"{cmd} not found — install with `pip install mvt`"
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_directory(directory: Path, max_files: int = 500) -> str:
    """Stable sha256 of a directory's contents — sample-bounded for speed."""
    if not directory.is_dir():
        return "0" * 64
    h = hashlib.sha256()
    files = sorted(directory.rglob("*"))[:max_files]
    for f in files:
        if f.is_file():
            try:
                h.update(f.name.encode())
                with f.open("rb") as fh:
                    h.update(fh.read(65536))
            except (PermissionError, OSError):
                continue
    return h.hexdigest()


@dataclass
class MVTDetection:
    """A single MVT IOC match — the headline forensic signal."""
    module: str
    indicator_name: str
    indicator_type: str
    matched_value: str
    timestamp: str = ""

    @classmethod
    def from_json_obj(cls, module: str, obj: dict) -> "MVTDetection":
        # MVT detection JSON shape varies slightly per module. Extract
        # robustly with multiple fallbacks.
        ind = (obj.get("matched_indicator") or {}) if isinstance(obj.get("matched_indicator"), dict) else {}
        return cls(
            module=module,
            indicator_name=ind.get("name") or obj.get("indicator_name") or "",
            indicator_type=ind.get("type") or obj.get("indicator_type") or "",
            matched_value=str(obj.get("matched_value")
                              or obj.get("value")
                              or obj.get("url")
                              or obj.get("domain") or "")[:300],
            timestamp=str(obj.get("timestamp") or obj.get("isodate") or "")[:64],
        )


@dataclass
class MVTRun:
    target_path: Path
    output_dir: Path
    platform: str  # "ios" or "android"
    subcommand: str  # e.g. "check-fs", "check-backup", "check-androidqf"
    rc: int
    duration_seconds: float = 0.0
    modules_run: list[str] = field(default_factory=list)
    detections: list[MVTDetection] = field(default_factory=list)
    detected_files: list[Path] = field(default_factory=list)
    output_sha256: str | None = None
    command: list[str] = field(default_factory=list)
    stderr_path: Path | None = None
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        # Group detections by module for the headline summary.
        by_module: dict[str, int] = {}
        for d in self.detections:
            by_module[d.module] = by_module.get(d.module, 0) + 1
        return EvidenceItem(
            tool="mvt",
            version="2026.4.28",
            command=" ".join(str(p) for p in self.command),
            output_sha256=self.output_sha256 or _sha256_directory(self.output_dir),
            output_path=str(self.output_dir),
            extracted_facts={
                "platform": self.platform,
                "subcommand": self.subcommand,
                "target_path": str(self.target_path),
                "modules_run": self.modules_run[:25],
                "detection_count": len(self.detections),
                "detection_modules": dict(sorted(by_module.items(),
                                                  key=lambda kv: -kv[1])[:10]),
                "duration_seconds": round(self.duration_seconds, 2),
                "rc": self.rc,
                "note": self.note,
                **extra,
            },
        )

    def has_hits(self) -> bool:
        return len(self.detections) > 0

    def detection_summary(self) -> str:
        if not self.detections:
            return "no IOC matches"
        by_module: dict[str, int] = {}
        for d in self.detections:
            by_module[d.module] = by_module.get(d.module, 0) + 1
        top = sorted(by_module.items(), key=lambda kv: -kv[1])[:5]
        return ", ".join(f"{m}×{c}" for m, c in top)


def _harvest_detections(output_dir: Path) -> tuple[list[MVTDetection], list[Path]]:
    """Walk *output_dir* for MVT *_detected.json files; parse them."""
    detections: list[MVTDetection] = []
    detected_files: list[Path] = []
    if not output_dir.is_dir():
        return detections, detected_files

    for p in sorted(output_dir.rglob("*_detected.json")):
        if not p.is_file():
            continue
        detected_files.append(p)
        # Module name = file stem minus the "_detected" suffix.
        module = p.stem
        if module.endswith("_detected"):
            module = module[: -len("_detected")]
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
        except (OSError, json.JSONDecodeError):
            continue
        # MVT writes either a list of detection dicts or a single dict.
        if isinstance(data, list):
            for obj in data:
                if isinstance(obj, dict):
                    detections.append(MVTDetection.from_json_obj(module, obj))
        elif isinstance(data, dict):
            detections.append(MVTDetection.from_json_obj(module, data))
    return detections, detected_files


def _harvest_modules_run(output_dir: Path) -> list[str]:
    """Walk *output_dir* for any *.json — module names that ran."""
    if not output_dir.is_dir():
        return []
    seen: set[str] = set()
    for p in output_dir.rglob("*.json"):
        if not p.is_file():
            continue
        stem = p.stem
        if stem.endswith("_detected"):
            stem = stem[: -len("_detected")]
        seen.add(stem)
    return sorted(seen)


def _resolve_iocs_arg(iocs_path: Path | None) -> list[str]:
    """Build the -i flag list. If *iocs_path* is a directory, expand to all
    .stix2 files inside (MVT accepts -i multiple times)."""
    if iocs_path is None:
        return []
    p = Path(iocs_path)
    if p.is_file():
        return ["-i", str(p)]
    if p.is_dir():
        args: list[str] = []
        for stix in sorted(p.rglob("*.stix2")):
            args.extend(["-i", str(stix)])
        return args
    return []


def _run_mvt(
    binary: Path,
    subcommand: str,
    target_path: Path,
    output_dir: Path,
    *,
    iocs_path: Path | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int = 1800,
) -> tuple[int, list[str], float, Path]:
    """Invoke an MVT subcommand; return (rc, full_command, duration, stderr_path)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stderr_path = output_dir / f"{subcommand}.stderr"
    cmd: list[str] = [
        str(binary),
        "--disable-update-check",
        "--disable-indicator-update-check",
        subcommand,
        "-o", str(output_dir),
    ]
    cmd.extend(_resolve_iocs_arg(iocs_path))
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(str(target_path))

    started = time.time()
    try:
        with stderr_path.open("wb") as ferr:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=ferr,
                timeout=timeout_seconds,
            )
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        rc = 124
    return rc, cmd, time.time() - started, stderr_path


def check_ios_fs(target_path: Path, output_dir: Path,
                  *, iocs_path: Path | None = None,
                  fast: bool = False,
                  timeout_seconds: int = 1800) -> MVTRun:
    """Run ``mvt-ios check-fs`` against an extracted iOS filesystem dump."""
    binary = _which("mvt-ios")
    extra = ["--fast"] if fast else []
    rc, cmd, duration, stderr_path = _run_mvt(
        binary, "check-fs", target_path, output_dir,
        iocs_path=iocs_path, extra_args=extra,
        timeout_seconds=timeout_seconds,
    )
    detections, detected_files = _harvest_detections(output_dir)
    return MVTRun(
        target_path=Path(target_path),
        output_dir=Path(output_dir),
        platform="ios", subcommand="check-fs",
        rc=rc, duration_seconds=duration,
        modules_run=_harvest_modules_run(output_dir),
        detections=detections,
        detected_files=detected_files,
        output_sha256=_sha256_directory(output_dir),
        command=cmd, stderr_path=stderr_path,
    )


def check_ios_backup(backup_path: Path, output_dir: Path,
                      *, iocs_path: Path | None = None,
                      timeout_seconds: int = 1800) -> MVTRun:
    """Run ``mvt-ios check-backup`` against an iTunes/Finder backup."""
    binary = _which("mvt-ios")
    rc, cmd, duration, stderr_path = _run_mvt(
        binary, "check-backup", backup_path, output_dir,
        iocs_path=iocs_path, extra_args=["-n"],  # non-interactive
        timeout_seconds=timeout_seconds,
    )
    detections, detected_files = _harvest_detections(output_dir)
    return MVTRun(
        target_path=Path(backup_path),
        output_dir=Path(output_dir),
        platform="ios", subcommand="check-backup",
        rc=rc, duration_seconds=duration,
        modules_run=_harvest_modules_run(output_dir),
        detections=detections,
        detected_files=detected_files,
        output_sha256=_sha256_directory(output_dir),
        command=cmd, stderr_path=stderr_path,
    )


def check_android_backup(backup_path: Path, output_dir: Path,
                          *, iocs_path: Path | None = None,
                          timeout_seconds: int = 1800) -> MVTRun:
    """Run ``mvt-android check-backup`` against an Android adb backup."""
    binary = _which("mvt-android")
    rc, cmd, duration, stderr_path = _run_mvt(
        binary, "check-backup", backup_path, output_dir,
        iocs_path=iocs_path, extra_args=["-n"],  # non-interactive
        timeout_seconds=timeout_seconds,
    )
    detections, detected_files = _harvest_detections(output_dir)
    return MVTRun(
        target_path=Path(backup_path),
        output_dir=Path(output_dir),
        platform="android", subcommand="check-backup",
        rc=rc, duration_seconds=duration,
        modules_run=_harvest_modules_run(output_dir),
        detections=detections,
        detected_files=detected_files,
        output_sha256=_sha256_directory(output_dir),
        command=cmd, stderr_path=stderr_path,
    )


def check_androidqf(target_path: Path, output_dir: Path,
                     *, iocs_path: Path | None = None,
                     timeout_seconds: int = 1800) -> MVTRun:
    """Run ``mvt-android check-androidqf`` against an AndroidQF collection."""
    binary = _which("mvt-android")
    rc, cmd, duration, stderr_path = _run_mvt(
        binary, "check-androidqf", target_path, output_dir,
        iocs_path=iocs_path,
        timeout_seconds=timeout_seconds,
    )
    detections, detected_files = _harvest_detections(output_dir)
    return MVTRun(
        target_path=Path(target_path),
        output_dir=Path(output_dir),
        platform="android", subcommand="check-androidqf",
        rc=rc, duration_seconds=duration,
        modules_run=_harvest_modules_run(output_dir),
        detections=detections,
        detected_files=detected_files,
        output_sha256=_sha256_directory(output_dir),
        command=cmd, stderr_path=stderr_path,
    )

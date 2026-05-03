"""UAC (Unix Artifact Collector) Skill

Subprocess wrapper around UAC for live response collection.
UAC collects comprehensive forensic artifacts from Unix/Linux systems following
forensic best practices (order of volatility, evidence integrity, structured output).

UAC Project: https://github.com/tclahr/uac
Documentation: https://tclahr.github.io/uac-docs/
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

class UACError(Exception):
    pass


def _which(name: str) -> Path:
    """Find UAC executable in expected locations."""
    import shutil
    paths = [
        Path("/opt/uac/uac"),
        Path("/usr/local/bin/uac"),
    ]

    # Check shutil.which first
    which_result = shutil.which(name)
    if which_result:
        paths.insert(0, Path(which_result))

    for path in paths:
        if path.exists() and path.is_file():
            return path

    raise UACError(f"UAC not found. Expected at: {', '.join(str(p) for p in paths)}")


def _hash_directory(directory: Path, max_files: int = 1000) -> str:
    """Generate representative hash of UAC collection directory."""
    if not directory.exists():
        return "directory_missing"

    hasher = hashlib.sha256()
    file_count = 0

    # Hash a sample of files for performance
    for file_path in sorted(directory.rglob("*"))[:max_files]:
        if file_path.is_file() and file_path.stat().st_size < 1024 * 1024:  # < 1MB files only
            try:
                hasher.update(file_path.read_bytes())
                file_count += 1
            except (PermissionError, OSError):
                continue

    hasher.update(f"files_sampled:{file_count}".encode())
    return hasher.hexdigest()[:16] + "..."


def _parse_uac_collection(collection_dir: Path) -> tuple[int, Optional[Path], Optional[Path], Optional[Path]]:
    """Parse UAC collection directory structure and count artifacts."""
    if not collection_dir.exists():
        return 0, None, None, None

    artifact_count = 0
    bodyfile_path = None
    live_response_dir = None
    memory_dump_path = None

    # Count total files as artifacts
    for item in collection_dir.rglob("*"):
        if item.is_file():
            artifact_count += 1

    # Find key UAC output directories
    bodyfile_candidates = list(collection_dir.rglob("bodyfile*.txt"))
    if bodyfile_candidates:
        bodyfile_path = bodyfile_candidates[0]

    live_response_candidates = list(collection_dir.glob("live_response"))
    if live_response_candidates:
        live_response_dir = live_response_candidates[0]

    memory_dump_candidates = list(collection_dir.rglob("*.mem")) + list(collection_dir.rglob("memory_dump"))
    if memory_dump_candidates:
        memory_dump_path = memory_dump_candidates[0]

    return artifact_count, bodyfile_path, live_response_dir, memory_dump_path


@dataclass
class UACCollection:
    """Results from UAC collection run."""
    output_dir: Path
    collection_profile: str
    artifacts_collected: int
    duration_seconds: float
    command: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    bodyfile_path: Optional[Path] = None
    live_response_dir: Optional[Path] = None
    memory_dump_path: Optional[Path] = None

    def as_evidence(self, facts: dict | None = None) -> dict:
        """Convert to EvidenceItem format."""
        facts = facts or {}

        artifacts_desc = f"{self.artifacts_collected} artifacts" if self.artifacts_collected > 0 else "collection completed"

        return {
            "tool": "uac",
            "description": f"UAC {self.collection_profile} collection: {artifacts_desc}",
            "path": str(self.output_dir),
            "command": " ".join(self.command),
            "sha256": _hash_directory(self.output_dir),
            "duration_seconds": self.duration_seconds,
            **facts
        }


def collect_ir_triage(target_dir: Path, output_dir: Path, hostname: str = "target") -> UACCollection:
    """
    Run UAC incident response triage collection.

    Args:
        target_dir: Target directory or system root to collect from
        output_dir: Output directory for collected artifacts
        hostname: Hostname identifier for the collection

    Returns:
        UACCollection with results and metadata
    """
    uac_path = _which("uac")

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build UAC command for IR triage profile
    cmd = [
        str(uac_path),
        "-p", "ir_triage",  # Fast IR collection profile
        "-o", str(output_dir),
        "-s", hostname,  # System identifier
        str(target_dir)
    ]

    start_time = time.time()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(target_dir.parent) if target_dir.parent.exists() else "/",
            timeout=1800  # 30 minute timeout for live collection
        )
    except subprocess.TimeoutExpired:
        raise UACError(f"UAC collection timed out after 30 minutes")
    except Exception as e:
        raise UACError(f"UAC collection failed: {e}")

    duration = time.time() - start_time

    # UAC creates subdirectory with naming pattern: uac-<hostname>-<timestamp>
    collection_dirs = list(output_dir.glob(f"uac-{hostname}-*"))
    if not collection_dirs:
        # Fallback: look for any uac-* directory
        collection_dirs = list(output_dir.glob("uac-*"))

    if not collection_dirs:
        raise UACError(f"UAC collection directory not found in {output_dir}. Command: {' '.join(cmd)}")

    collection_dir = collection_dirs[0]  # Take the first/latest

    # Parse collection results
    artifact_count, bodyfile_path, live_response_dir, memory_dump_path = _parse_uac_collection(collection_dir)

    return UACCollection(
        output_dir=collection_dir,
        collection_profile="ir_triage",
        artifacts_collected=artifact_count,
        duration_seconds=duration,
        command=cmd,
        stdout=result.stdout,
        stderr=result.stderr,
        bodyfile_path=bodyfile_path,
        live_response_dir=live_response_dir,
        memory_dump_path=memory_dump_path
    )


def collect_full_forensics(target_dir: Path, output_dir: Path, hostname: str = "target") -> UACCollection:
    """
    Run comprehensive UAC forensic collection.

    Args:
        target_dir: Target directory or system root to collect from
        output_dir: Output directory for collected artifacts
        hostname: Hostname identifier for the collection

    Returns:
        UACCollection with results and metadata
    """
    uac_path = _which("uac")

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build UAC command for full forensic profile
    cmd = [
        str(uac_path),
        "-p", "full",  # Comprehensive collection profile
        "-o", str(output_dir),
        "-s", hostname,  # System identifier
        str(target_dir)
    ]

    start_time = time.time()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(target_dir.parent) if target_dir.parent.exists() else "/",
            timeout=3600  # 60 minute timeout for full collection
        )
    except subprocess.TimeoutExpired:
        raise UACError(f"UAC full collection timed out after 60 minutes")
    except Exception as e:
        raise UACError(f"UAC collection failed: {e}")

    duration = time.time() - start_time

    # Find UAC output directory
    collection_dirs = list(output_dir.glob(f"uac-{hostname}-*"))
    if not collection_dirs:
        collection_dirs = list(output_dir.glob("uac-*"))

    if not collection_dirs:
        raise UACError(f"UAC collection directory not found in {output_dir}")

    collection_dir = collection_dirs[0]

    # Parse collection results
    artifact_count, bodyfile_path, live_response_dir, memory_dump_path = _parse_uac_collection(collection_dir)

    return UACCollection(
        output_dir=collection_dir,
        collection_profile="full",
        artifacts_collected=artifact_count,
        duration_seconds=duration,
        command=cmd,
        stdout=result.stdout,
        stderr=result.stderr,
        bodyfile_path=bodyfile_path,
        live_response_dir=live_response_dir,
        memory_dump_path=memory_dump_path
    )


def collect_custom_profile(target_dir: Path, output_dir: Path, profile_path: Path, hostname: str = "target") -> UACCollection:
    """
    Run UAC collection with custom profile.

    Args:
        target_dir: Target directory or system root to collect from
        output_dir: Output directory for collected artifacts
        profile_path: Path to custom UAC profile YAML file
        hostname: Hostname identifier for the collection

    Returns:
        UACCollection with results and metadata
    """
    uac_path = _which("uac")

    if not profile_path.exists():
        raise UACError(f"Custom profile not found: {profile_path}")

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build UAC command for custom profile
    cmd = [
        str(uac_path),
        "-p", str(profile_path),  # Custom profile path
        "-o", str(output_dir),
        "-s", hostname,  # System identifier
        str(target_dir)
    ]

    start_time = time.time()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(target_dir.parent) if target_dir.parent.exists() else "/",
            timeout=3600  # 60 minute timeout
        )
    except subprocess.TimeoutExpired:
        raise UACError(f"UAC custom profile collection timed out after 60 minutes")
    except Exception as e:
        raise UACError(f"UAC collection failed: {e}")

    duration = time.time() - start_time

    # Find UAC output directory
    collection_dirs = list(output_dir.glob(f"uac-{hostname}-*"))
    if not collection_dirs:
        collection_dirs = list(output_dir.glob("uac-*"))

    if not collection_dirs:
        raise UACError(f"UAC collection directory not found in {output_dir}")

    collection_dir = collection_dirs[0]

    # Parse collection results
    artifact_count, bodyfile_path, live_response_dir, memory_dump_path = _parse_uac_collection(collection_dir)

    profile_name = profile_path.stem

    return UACCollection(
        output_dir=collection_dir,
        collection_profile=f"custom:{profile_name}",
        artifacts_collected=artifact_count,
        duration_seconds=duration,
        command=cmd,
        stdout=result.stdout,
        stderr=result.stderr,
        bodyfile_path=bodyfile_path,
        live_response_dir=live_response_dir,
        memory_dump_path=memory_dump_path
    )
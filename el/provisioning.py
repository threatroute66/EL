"""Provisioning snapshots — capture host state for chain of custody.

Writes a timestamped bundle into provisioning/snapshots/ documenting
exactly what is on the host at this moment: dpkg state, /opt contents,
pip freeze, EL doctor output. The bundle is cryptographically hashed
(sha256 manifest) so a third party can verify the snapshot wasn't edited.

Useful: before opening a case (snapshot the platform), after install
(prove what changed), in court (cite the manifest hash).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

EL_DIR = Path(__file__).resolve().parent.parent
SNAP_DIR = EL_DIR / "provisioning" / "snapshots"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _capture(cmd: list[str], out_path: Path) -> None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out_path.write_text((r.stdout or "") + (r.stderr or ""))
    except Exception as e:
        out_path.write_text(f"capture failed: {e}\n")


def take_snapshot(label: str = "manual") -> Path:
    """Capture a provisioning snapshot. Returns path to manifest."""
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    ts = _ts()
    bundle = SNAP_DIR / f"snap-{label}-{ts}"
    bundle.mkdir()

    _capture(["uname", "-a"], bundle / "uname.txt")
    if Path("/etc/os-release").exists():
        shutil.copy("/etc/os-release", bundle / "os-release.txt")
    _capture(["dpkg", "-l"], bundle / "dpkg.txt")
    _capture(["ls", "/opt"], bundle / "opt.txt")
    _capture(["ls", "/opt/zimmermantools"], bundle / "zimmermantools.txt")

    venv_pip = EL_DIR / ".venv" / "bin" / "pip"
    if venv_pip.exists():
        _capture([str(venv_pip), "freeze"], bundle / "pip-freeze.txt")

    venv_el = EL_DIR / ".venv" / "bin" / "el"
    if venv_el.exists():
        _capture([str(venv_el), "doctor"], bundle / "doctor.txt")

    git_dir = EL_DIR / ".git"
    if git_dir.exists():
        _capture(["git", "-C", str(EL_DIR), "rev-parse", "HEAD"],
                 bundle / "el-git-head.txt")
        _capture(["git", "-C", str(EL_DIR), "status", "-sb"],
                 bundle / "el-git-status.txt")

    manifest = {
        "label": label,
        "captured_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "el_dir": str(EL_DIR),
        "files": {},
    }
    for p in sorted(bundle.iterdir()):
        if p.is_file() and p.name != "manifest.json":
            sha = hashlib.sha256(p.read_bytes()).hexdigest()
            manifest["files"][p.name] = {"size": p.stat().st_size, "sha256": sha}

    manifest_path = bundle / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return manifest_path

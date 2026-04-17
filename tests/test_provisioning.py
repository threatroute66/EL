"""Provisioning snapshots are evidence-grade artifacts. Tests lock in
that every captured file appears in manifest.json with a sha256 hash,
and that the manifest itself is the only file without a self-hash.
"""
import hashlib
import json
import subprocess
from pathlib import Path

from el import provisioning


def test_snapshot_manifest_hashes_all_files(tmp_path, monkeypatch):
    monkeypatch.setattr(provisioning, "SNAP_DIR", tmp_path)
    manifest_path = provisioning.take_snapshot(label="t")
    bundle = manifest_path.parent

    files_in_bundle = {p.name for p in bundle.iterdir() if p.is_file()}
    manifest = json.loads(manifest_path.read_text())

    assert "manifest.json" in files_in_bundle
    for fname in files_in_bundle:
        if fname == "manifest.json":
            continue
        assert fname in manifest["files"], f"{fname} missing from manifest.json"
        sha_recorded = manifest["files"][fname]["sha256"]
        sha_computed = hashlib.sha256((bundle / fname).read_bytes()).hexdigest()
        assert sha_recorded == sha_computed, f"{fname} hash mismatch"


def test_install_script_passes_bash_syntax_check():
    repo_root = Path(__file__).resolve().parent.parent
    script = repo_root / "install.sh"
    assert script.exists()
    r = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert r.returncode == 0, f"install.sh failed bash -n: {r.stderr}"


def test_apt_packages_list_is_present_and_nonempty():
    repo_root = Path(__file__).resolve().parent.parent
    p = repo_root / "provisioning" / "apt-packages.txt"
    assert p.exists()
    pkgs = [line.strip() for line in p.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]
    assert "yara" in pkgs, "apt-packages.txt must list yara — we installed it via apt at runtime"

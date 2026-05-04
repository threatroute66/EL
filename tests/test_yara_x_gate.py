"""YARA-X feature gate — verifies the auto-prefer logic and EL_FORCE_YARA4 opt-out."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from el.skills import yara_hunt as yh


# --- _is_yara_x detection ----------------------------------------------

def test_is_yara_x_detects_yr():
    assert yh._is_yara_x("/usr/local/bin/yr")
    assert yh._is_yara_x("yr")


def test_is_yara_x_detects_yara_x():
    assert yh._is_yara_x("/opt/yara-x")
    assert yh._is_yara_x("/usr/bin/yara-x-cli")


def test_is_yara_x_rejects_yara_4():
    assert not yh._is_yara_x("/usr/bin/yara")
    assert not yh._is_yara_x("yara")


# --- _yara_bin preference ---------------------------------------------

def test_yara_bin_prefers_yara_x_when_present(monkeypatch):
    monkeypatch.delenv("EL_FORCE_YARA4", raising=False)

    def fake_which(name):
        return "/usr/local/bin/yr" if name == "yr" else "/usr/bin/yara"
    monkeypatch.setattr(yh.shutil, "which", fake_which)
    assert yh._yara_bin().endswith("/yr")


def test_yara_bin_falls_back_to_yara4_when_yr_missing(monkeypatch):
    monkeypatch.delenv("EL_FORCE_YARA4", raising=False)

    def fake_which(name):
        return None if name == "yr" else "/usr/bin/yara"
    monkeypatch.setattr(yh.shutil, "which", fake_which)
    assert yh._yara_bin().endswith("/yara")


def test_yara_bin_force_yara4_skips_yr(monkeypatch):
    monkeypatch.setenv("EL_FORCE_YARA4", "1")

    def fake_which(name):
        return f"/usr/local/bin/{name}"
    monkeypatch.setattr(yh.shutil, "which", fake_which)
    assert yh._yara_bin().endswith("/yara")


def test_yara_bin_raises_when_neither_present(monkeypatch):
    monkeypatch.delenv("EL_FORCE_YARA4", raising=False)
    monkeypatch.setattr(yh.shutil, "which", lambda _: None)
    with pytest.raises(yh.YaraError):
        yh._yara_bin()


# --- scan_paths argv shape per binary ---------------------------------

def test_scan_paths_uses_scan_subcommand_for_yara_x(tmp_path, monkeypatch):
    """When yr is selected, argv must include the 'scan' subcommand and
    must NOT include the YARA-4-only -N flag."""
    yr = tmp_path / "yr"
    yr.write_bytes(b"#!/bin/sh\nexit 0\n")
    yr.chmod(0o755)
    monkeypatch.delenv("EL_FORCE_YARA4", raising=False)
    monkeypatch.setattr(yh.shutil, "which",
                          lambda n: str(yr) if n == "yr" else None)

    captured: dict = {}
    def fake_run(args, **_kw):
        captured["args"] = args
        return subprocess.CompletedProcess(args=args, returncode=0,
                                            stdout="", stderr="")
    monkeypatch.setattr(yh.subprocess, "run", fake_run)

    rules = tmp_path / "r.yar"; rules.write_text("rule x{condition:false}")
    target = tmp_path / "scan_dir"; target.mkdir()
    yh.scan_paths(rules, target, tmp_path / "out")

    assert captured["args"][1] == "scan"
    assert "-N" not in captured["args"]


def test_scan_paths_uses_legacy_argv_for_yara4(tmp_path, monkeypatch):
    """When yara 4 is selected, argv must NOT include 'scan' and MUST
    include -N (do-not-follow-symlinks)."""
    yara = tmp_path / "yara"
    yara.write_bytes(b"#!/bin/sh\nexit 0\n")
    yara.chmod(0o755)
    monkeypatch.setenv("EL_FORCE_YARA4", "1")
    monkeypatch.setattr(yh.shutil, "which",
                          lambda n: str(yara) if n == "yara" else None)

    captured: dict = {}
    def fake_run(args, **_kw):
        captured["args"] = args
        return subprocess.CompletedProcess(args=args, returncode=0,
                                            stdout="", stderr="")
    monkeypatch.setattr(yh.subprocess, "run", fake_run)

    rules = tmp_path / "r.yar"; rules.write_text("rule x{condition:false}")
    target = tmp_path / "scan_dir"; target.mkdir()
    yh.scan_paths(rules, target, tmp_path / "out")

    assert "scan" not in captured["args"]
    assert "-N" in captured["args"]


# --- Real-binary smoke ------------------------------------------------

@pytest.mark.skipif(not shutil.which("yr"), reason="YARA-X (yr) not installed")
def test_real_yara_x_scan(tmp_path):
    """Sanity: invoke the real YARA-X against a tiny sample."""
    rules = tmp_path / "r.yar"
    rules.write_text('rule t { strings: $a = "marker_xyz" condition: $a }')
    target = tmp_path / "f.txt"; target.write_text("contains marker_xyz here")
    out_dir = tmp_path / "out"

    # Force yr regardless of EL_FORCE_YARA4
    os.environ.pop("EL_FORCE_YARA4", None)
    res = yh.scan_paths(rules, target, out_dir, recursive=False)
    assert res.rc == 0
    assert res.hit_count >= 1
    assert "t" in res.rule_to_files

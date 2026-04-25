"""Detect-It-Easy CLI wrapper.

Closes gap-doc Malware-RE bullet "Detect-It-Easy / `diec`"
(line 139). Tests monkeypatch the binary lookup + subprocess so they
don't require diec to be installed.
"""
import json
import subprocess
from pathlib import Path

import pytest

from el.skills import detect_it_easy as die


def test_unavailable_returns_not_available_flag(monkeypatch, tmp_path):
    monkeypatch.setattr(die, "_diec_bin", lambda: None)
    r = die.analyze(tmp_path / "x.exe")
    assert r.available is False
    assert "not on PATH" in r.error


def test_parses_canonical_diec_json(monkeypatch, tmp_path):
    monkeypatch.setattr(die, "_diec_bin", lambda: "/fake/diec")

    payload = {
        "detects": [
            {"type": "Packer", "string": "UPX(3.96)"},
            {"type": "Compiler", "string": "Microsoft Visual C/C++(19.34)"},
        ]
    }

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=json.dumps(payload), stderr="")
    monkeypatch.setattr(die.subprocess, "run", fake_run)

    r = die.analyze(tmp_path / "x.exe")
    assert r.rc == 0
    assert r.has_packed is True
    assert r.packers == ["UPX(3.96)"]
    assert r.compilers == ["Microsoft Visual C/C++(19.34)"]


def test_parses_top_level_list(monkeypatch, tmp_path):
    monkeypatch.setattr(die, "_diec_bin", lambda: "/fake/diec")
    # Some DiE builds emit a flat list rather than the {detects: [...]} shape
    payload = [
        {"type": "Protector", "string": "Themida(2.4.x)"},
        {"type": "Compiler", "string": "GCC 11"},
    ]
    fake = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=json.dumps(payload), stderr="")
    monkeypatch.setattr(die.subprocess, "run", lambda *a, **kw: fake)
    r = die.analyze(tmp_path / "x.exe")
    assert r.protectors == ["Themida(2.4.x)"]
    assert r.has_packed  # protector counts


def test_handles_invalid_json(monkeypatch, tmp_path):
    monkeypatch.setattr(die, "_diec_bin", lambda: "/fake/diec")
    fake = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="not json at all", stderr="")
    monkeypatch.setattr(die.subprocess, "run", lambda *a, **kw: fake)
    r = die.analyze(tmp_path / "x.exe")
    assert r.error == "diec stdout not valid JSON"
    assert r.detects == []


def test_handles_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(die, "_diec_bin", lambda: "/fake/diec")
    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="diec", timeout=1)
    monkeypatch.setattr(die.subprocess, "run", boom)
    r = die.analyze(tmp_path / "x.exe")
    assert r.rc == -1
    assert "timed out" in r.error.lower() or "TimeoutExpired" in r.error

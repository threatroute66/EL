"""Unit tests for el.skills.disk_convert — the qemu-img wrapper that
VMDK / VHD / VHDX inputs get converted through before the Sleuth Kit
pipeline runs against the flat output.

Tests don't require a real qemu-img install; they monkeypatch around
shutil.which and subprocess.run so the wrapper contract is verifiable
on any host.
"""
import subprocess
from pathlib import Path

import pytest

from el.skills import disk_convert
from el.skills.disk_convert import DiskConvertError


def test_qemu_img_available_reports_false_when_missing(monkeypatch):
    monkeypatch.setattr(disk_convert.shutil, "which", lambda _: None)
    ok, version = disk_convert.qemu_img_available()
    assert ok is False
    assert version == ""


def test_qemu_img_available_parses_version_string(monkeypatch):
    monkeypatch.setattr(disk_convert.shutil, "which", lambda _: "/usr/bin/qemu-img")
    fake = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout="qemu-img version 6.2.0 (qemu-6.2.0-debian)\n",
        stderr="",
    )
    monkeypatch.setattr(disk_convert.subprocess, "run", lambda *a, **kw: fake)
    ok, version = disk_convert.qemu_img_available()
    assert ok is True
    assert version == "6.2.0"


def test_convert_to_raw_raises_when_qemu_img_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(disk_convert, "qemu_img_available",
                        lambda: (False, ""))
    with pytest.raises(DiskConvertError, match="qemu-img not available"):
        disk_convert.convert_to_raw(
            tmp_path / "fake.vmdk", "vmdk (sparse)", tmp_path / "raw",
        )


def test_convert_to_raw_happy_path(tmp_path, monkeypatch):
    """qemu-img reports success AND the raw file materialises → we
    return a ConvertResult with useful metadata."""
    monkeypatch.setattr(disk_convert, "qemu_img_available",
                        lambda: (True, "6.2.0"))

    def fake_run(cmd, *args, **kw):
        # Simulate qemu-img actually writing the output file.
        out = Path(cmd[-1])
        out.write_bytes(b"fake raw disk content")
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=b"", stderr=b"",
        )
    monkeypatch.setattr(disk_convert.subprocess, "run", fake_run)

    src = tmp_path / "evidence.vhdx"
    src.write_bytes(b"vhdxfile" + b"\x00" * 128)
    result = disk_convert.convert_to_raw(
        src, source_kind="vhdx", out_dir=tmp_path / "raw",
    )
    assert result.raw_path.exists()
    assert result.raw_path.read_bytes() == b"fake raw disk content"
    assert result.source_kind == "vhdx"
    assert result.qemu_img_version == "6.2.0"
    ev = result.as_evidence({"phase": "test"})
    assert ev.tool == "qemu-img"
    assert ev.extracted_facts["phase"] == "test"
    assert ev.extracted_facts["source_kind"] == "vhdx"


def test_convert_to_raw_nonzero_returncode_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(disk_convert, "qemu_img_available",
                        lambda: (True, "6.2.0"))
    monkeypatch.setattr(disk_convert.subprocess, "run",
                        lambda *a, **kw: subprocess.CompletedProcess(
                            args=a, returncode=1, stdout=b"",
                            stderr=b"qemu-img: Unknown format"))

    with pytest.raises(DiskConvertError, match="rc=1"):
        disk_convert.convert_to_raw(
            tmp_path / "bad.vmdk", "vmdk (sparse)", tmp_path / "raw",
        )


def test_convert_to_raw_timeout_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(disk_convert, "qemu_img_available",
                        lambda: (True, "6.2.0"))
    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="qemu-img", timeout=1)
    monkeypatch.setattr(disk_convert.subprocess, "run", boom)

    with pytest.raises(DiskConvertError, match="timed out"):
        disk_convert.convert_to_raw(
            tmp_path / "slow.vhdx", "vhdx", tmp_path / "raw", timeout=1,
        )


def test_disk_forensicator_insufficient_when_convert_fails(
    tmp_path, monkeypatch,
):
    """End-to-end: if conversion fails, the DiskForensicator emits
    confidence=insufficient with a helpful remediation hint instead
    of blowing up or silently skipping the case."""
    from el.agents.base import AgentContext
    from el.agents.disk_forensicator import DiskForensicatorAgent

    def boom(*a, **kw):
        raise DiskConvertError("qemu-img not available — install qemu-utils")
    monkeypatch.setattr(disk_convert, "convert_to_raw", boom)
    # Also block the fall-through raw walk so the test doesn't run
    # mmls/fls on our fake file.
    monkeypatch.setattr(
        DiskForensicatorAgent, "_raw_disk_walk",
        lambda self, ctx, analysis, path: [],
    )

    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "disk_forensicator").mkdir(parents=True)
    inp = tmp_path / "e.vhdx"
    inp.write_bytes(b"vhdxfile" + b"\x00" * 128)
    ctx = AgentContext(case_id="t", case_dir=case_dir,
                       input_path=inp, manifest={})
    ctx.shared["evidence_kind"] = "vhdx"

    findings = DiskForensicatorAgent().run(ctx)
    assert any(f.confidence == "insufficient"
               and "qemu-img" in f.claim for f in findings)

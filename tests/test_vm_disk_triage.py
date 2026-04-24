"""VM disk triage (VMDK / VHD / VHDX).

Capability-gap-analysis.md listed VMDK, VHD, VHDX as "untested / not
supported" in the disk-format tracker. This test locks in triage's
magic-byte detection for all three so the kind strings land in
`ctx.shared["evidence_kind"]` for the coordinator to dispatch on.

The conversion pipeline itself (qemu-img) is unit-tested separately
in test_disk_convert.py — these tests don't require qemu-img to be
installed.
"""
from pathlib import Path

import pytest

from el.agents.triage import MAGIC_HINTS, TriageAgent, _detect_vhd_footer
from el.agents.base import AgentContext


def _run_triage(tmp_path: Path, content: bytes, *, tail: bytes = b"") -> dict:
    """Drop `content` + optional `tail` into a temp file, run triage,
    return the resulting `ctx.shared` dict for inspection."""
    case_dir = tmp_path / "case"
    (case_dir / "analysis").mkdir(parents=True)
    (case_dir / "reports").mkdir()

    inp = tmp_path / "evidence.bin"
    inp.write_bytes(content + (b"\x00" * max(0, 1024 - len(content))) + tail)

    ctx = AgentContext(
        case_id="test", case_dir=case_dir,
        input_path=inp, manifest={},
    )
    TriageAgent().run(ctx)
    return ctx.shared


# --- VHDX: magic at head ---------------------------------------------------

def test_vhdx_detected_from_head_magic(tmp_path):
    shared = _run_triage(tmp_path, b"vhdxfile\x00\x00\x00\x00")
    assert shared["evidence_kind"] == "vhdx"


# --- VMDK: sparse (KDMV) / COW (COWD) / descriptor ------------------------

def test_vmdk_sparse_kdmv(tmp_path):
    shared = _run_triage(tmp_path, b"KDMV" + b"\x00" * 60)
    assert shared["evidence_kind"] == "vmdk (sparse)"


def test_vmdk_cow_cowd(tmp_path):
    shared = _run_triage(tmp_path, b"COWD" + b"\x00" * 60)
    assert shared["evidence_kind"] == "vmdk (sparse)"


def test_vmdk_descriptor_text(tmp_path):
    shared = _run_triage(
        tmp_path,
        b"# Disk DescriptorFile\nversion=1\nencoding=\"UTF-8\"\n",
    )
    assert shared["evidence_kind"] == "vmdk (descriptor)"


# --- VHD: signature at tail (legacy Connectix cookie) ---------------------

def test_vhd_detected_from_tail_footer(tmp_path):
    # Fixed-VHD: 512-byte raw data stand-in, then 512-byte footer ending
    # with the 'conectix' cookie. In a real VHD the cookie is at the
    # start of the footer; we simulate just the cookie position.
    raw = b"\x00" * 1024
    footer = b"conectix" + (b"\x00" * 504)  # 512-byte footer
    path = tmp_path / "legacy.vhd"
    path.write_bytes(raw + footer)

    kind = _detect_vhd_footer(path)
    assert kind == "vhd"


def test_vhd_without_cookie_not_flagged(tmp_path):
    path = tmp_path / "not-a-vhd.bin"
    path.write_bytes(b"\x00" * 2048)
    assert _detect_vhd_footer(path) is None


def test_vhd_too_small_not_flagged(tmp_path):
    path = tmp_path / "tiny.vhd"
    path.write_bytes(b"\x00" * 256)  # below 512-byte footer size
    assert _detect_vhd_footer(path) is None


def test_vhd_end_to_end_through_triage(tmp_path):
    """Complete triage path: head has no magic, footer check wins."""
    case_dir = tmp_path / "case"
    (case_dir / "analysis").mkdir(parents=True)
    (case_dir / "reports").mkdir()

    inp = tmp_path / "evidence.vhd"
    inp.write_bytes(b"\x00" * 1024 + b"conectix" + b"\x00" * 504)

    ctx = AgentContext(
        case_id="test", case_dir=case_dir,
        input_path=inp, manifest={},
    )
    TriageAgent().run(ctx)
    assert ctx.shared["evidence_kind"] == "vhd"


# --- coordinator dispatch lookup ------------------------------------------

def test_kind_to_agent_routes_vm_disks_to_disk_forensicator():
    """The coordinator must know how to dispatch each triage kind to
    the DiskForensicator — otherwise a correctly-detected VHDX falls
    through to the memory-dump default."""
    from el.agents.disk_forensicator import DiskForensicatorAgent
    from el.orchestrator.coordinator import KIND_TO_AGENT

    for kind in ("vhdx", "vhd", "vmdk (sparse)", "vmdk (descriptor)"):
        assert KIND_TO_AGENT.get(kind) is DiskForensicatorAgent, (
            f"kind {kind!r} must route to DiskForensicatorAgent"
        )


def test_magic_hints_cover_all_vm_disk_kinds():
    # Head-magic hints cover VHDX and all VMDK variants.
    kinds_from_head = set(MAGIC_HINTS.values())
    assert "vhdx" in kinds_from_head
    assert "vmdk (sparse)" in kinds_from_head
    assert "vmdk (descriptor)" in kinds_from_head

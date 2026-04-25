"""Triage detection of mounted Linux filesystems + QNAP NAS volumes.

Driver: QNAP case 21APR_245 (Geneva-airport seizure 2021). After
manually assembling the 3-disk RAID5 + locating DataVol1 via ext4
superblock scan, EL was given the mounted /mnt/qnap-data — but
triage routed it to `directory-unclassified` and fell through to
MemoryForensicatorAgent. These tests lock in:

- `linux-fs-dir` evidence_kind on a directory with ≥4 of
  {etc, var/log, home, root, usr, bin, boot}
- `qnap-nas-dir` on a directory with ≥3 of {homes, .qpkg, .system,
  .samba, .@station_config}
- KIND_TO_AGENT routes both to LinuxForensicatorAgent
- LinuxForensicatorAgent uses ctx.input_path as the artifacts root
  when triage set one of the new kinds (no DiskForensicator chain
  available)
"""
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.linux_forensicator import LinuxForensicatorAgent
from el.agents.triage import TriageAgent
from el.orchestrator.coordinator import KIND_TO_AGENT


def _new_ctx(tmp_path: Path) -> AgentContext:
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True, exist_ok=True)
    return AgentContext(
        case_id="t", case_dir=case_dir,
        input_path=tmp_path / "fs-root", manifest={},
    )


# --- linux-fs-dir detection -----------------------------------------------

def test_classic_linux_rootfs_triages_to_linux_fs_dir(tmp_path):
    root = tmp_path / "fs-root"
    for sub in ("etc", "var/log", "home", "root", "usr/bin", "boot"):
        (root / sub).mkdir(parents=True)
    ctx = _new_ctx(tmp_path)
    TriageAgent().run(ctx)
    assert ctx.shared["evidence_kind"] == "linux-fs-dir"


def test_partial_linux_layout_does_not_misfire(tmp_path):
    """Only 2 markers — must NOT trigger linux-fs-dir; falls through
    to directory-unclassified."""
    root = tmp_path / "fs-root"
    (root / "etc").mkdir(parents=True)
    (root / "var").mkdir()
    ctx = _new_ctx(tmp_path)
    TriageAgent().run(ctx)
    assert ctx.shared["evidence_kind"] != "linux-fs-dir"


# --- qnap-nas-dir detection -----------------------------------------------

def test_qnap_datavol_triages_to_qnap_nas_dir(tmp_path):
    """Real QNAP DataVol1 layout — homes/ + .qpkg/ + .system/ +
    .samba/ + .@station_config/ all present."""
    root = tmp_path / "fs-root"
    for sub in ("homes", ".qpkg", ".system", ".samba",
                ".@station_config"):
        (root / sub).mkdir(parents=True)
    ctx = _new_ctx(tmp_path)
    TriageAgent().run(ctx)
    assert ctx.shared["evidence_kind"] == "qnap-nas-dir"


def test_qnap_with_three_markers_still_qualifies(tmp_path):
    """≥3 of 5 is the threshold — covers older QTS builds that
    didn't ship .@station_config."""
    root = tmp_path / "fs-root"
    for sub in ("homes", ".qpkg", ".system"):
        (root / sub).mkdir(parents=True)
    ctx = _new_ctx(tmp_path)
    TriageAgent().run(ctx)
    assert ctx.shared["evidence_kind"] == "qnap-nas-dir"


def test_qnap_takes_precedence_over_linux(tmp_path):
    """A QNAP volume happens to also have homes/ and a few Linux-ish
    dirs — qnap-nas-dir must win (more specific)."""
    root = tmp_path / "fs-root"
    for sub in ("homes", ".qpkg", ".system", ".samba",
                "etc", "var/log", "usr"):
        (root / sub).mkdir(parents=True)
    ctx = _new_ctx(tmp_path)
    TriageAgent().run(ctx)
    assert ctx.shared["evidence_kind"] == "qnap-nas-dir"


# --- KIND_TO_AGENT routing ------------------------------------------------

def test_linux_fs_dir_routes_to_linux_forensicator():
    assert KIND_TO_AGENT.get("linux-fs-dir") is LinuxForensicatorAgent


def test_qnap_nas_dir_routes_to_linux_forensicator():
    assert KIND_TO_AGENT.get("qnap-nas-dir") is LinuxForensicatorAgent


# --- LinuxForensicatorAgent direct-mode ----------------------------------

def test_agent_uses_input_path_when_kind_is_linux_fs_dir(tmp_path):
    """When triage sets evidence_kind=linux-fs-dir, the agent must
    treat ctx.input_path as the artifacts root rather than failing
    with 'no extracted artifacts'."""
    root = tmp_path / "linux"
    for sub in ("etc", "var/log", "home/alice"):
        (root / sub).mkdir(parents=True)
    # Drop a benign auth.log so a detector has something to chew on
    (root / "var/log/auth.log").write_text("")
    ctx = AgentContext(
        case_id="t", case_dir=tmp_path / "case",
        input_path=root, manifest={},
    )
    (ctx.case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    ctx.shared["evidence_kind"] = "linux-fs-dir"

    findings = LinuxForensicatorAgent().run(ctx)
    # Must NOT emit the "no Linux artifacts directory" insufficient
    # finding — that's the failure mode this test exists to prevent.
    insufficient = [f for f in findings
                    if f.confidence == "insufficient"
                    and "no Linux artifacts directory" in f.claim]
    assert insufficient == [], (
        "agent fell through to 'no artifacts' branch despite "
        "triage routing the directory directly"
    )


def test_agent_uses_input_path_when_kind_is_qnap_nas_dir(tmp_path):
    root = tmp_path / "qnap"
    for sub in ("homes", ".qpkg", ".system"):
        (root / sub).mkdir(parents=True)
    ctx = AgentContext(
        case_id="t", case_dir=tmp_path / "case",
        input_path=root, manifest={},
    )
    (ctx.case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    ctx.shared["evidence_kind"] = "qnap-nas-dir"

    findings = LinuxForensicatorAgent().run(ctx)
    insufficient = [f for f in findings
                    if f.confidence == "insufficient"
                    and "no Linux artifacts directory" in f.claim]
    assert insufficient == []

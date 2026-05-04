"""Regression: MemProcFS corroboration must not crash MemoryForensicator.

Tier 1.1 introduced ``_run_memprocfs_corroboration`` to MemoryForensicator.
The original integration only caught ``mpfs.MemProcFSError`` — but in the
field (SRL-2018 APT 22-host bundle, 2026-05-04) a stalled or partially-
initialised forensic scan surfaced as ``OSError: [Errno 5] Input/output
error`` when the agent tried to read ``findevil.csv`` from the FUSE mount.
That OSError escaped, killing the entire MemoryForensicator agent and
losing all the vol3 plugin findings that had already run successfully.

Fix: catch ``(mpfs.MemProcFSError, OSError, TypeError, ValueError)`` —
emit an insufficient finding for MemProcFS, but never abort the host
agent. The vol3 plugin findings (the primary evidence) are unaffected.

This test locks the contract.
"""
from pathlib import Path
from unittest.mock import patch

import pytest

from el.agents.memory_forensicator import MemoryForensicatorAgent
from el.agents.base import AgentContext
from el.skills import memprocfs as mpfs


@pytest.fixture
def fake_ctx(tmp_path, monkeypatch):
    """Synthetic AgentContext anchored at a per-test workspace."""
    case_dir = tmp_path / "cases" / "t-memprocfs-fail"
    case_dir.mkdir(parents=True)
    (case_dir / "analysis").mkdir()
    img = tmp_path / "memory.img"
    img.write_bytes(b"PMEM" * 1024)  # plausible-shaped fake image
    return AgentContext(
        case_id="t-memprocfs-fail", case_dir=case_dir, input_path=img,
        manifest={}, shared={"mem_os": "windows"},
    )


def test_memprocfs_oserror_is_caught(fake_ctx):
    """The IO-error from the FUSE mount must NOT escape — Tier 1.1 contract."""
    agent = MemoryForensicatorAgent()
    with patch.object(mpfs, "run_forensic_scan",
                       side_effect=OSError(5,
                           "Input/output error",
                           "memprocfs_mount/forensic/findevil/findevil.csv")):
        # Must not raise.
        findings = agent._run_memprocfs_corroboration(fake_ctx)
    assert findings, "expected at least one insufficient finding"
    assert any(f.confidence == "insufficient" for f in findings)
    assert any("MemProcFS corroboration unavailable" in f.claim
               for f in findings)


def test_memprocfs_memprocfs_error_is_still_caught(fake_ctx):
    """The original MemProcFSError path must keep working."""
    agent = MemoryForensicatorAgent()
    with patch.object(mpfs, "run_forensic_scan",
                       side_effect=mpfs.MemProcFSError("binary missing")):
        findings = agent._run_memprocfs_corroboration(fake_ctx)
    assert any(f.confidence == "insufficient" for f in findings)
    assert any("binary missing" in f.claim for f in findings)


def test_memprocfs_typeerror_is_caught(fake_ctx):
    """A test-fixture monkeypatching subprocess.run with an incompatible
    signature surfaces as TypeError — must not break the host agent."""
    agent = MemoryForensicatorAgent()
    with patch.object(mpfs, "run_forensic_scan",
                       side_effect=TypeError(
                           "fake subprocess.run got unexpected kwarg")):
        findings = agent._run_memprocfs_corroboration(fake_ctx)
    assert any(f.confidence == "insufficient" for f in findings)


def test_memprocfs_valueerror_is_caught(fake_ctx):
    """ValueError from CSV / JSON parsing under the mount."""
    agent = MemoryForensicatorAgent()
    with patch.object(mpfs, "run_forensic_scan",
                       side_effect=ValueError("malformed findevil.csv")):
        findings = agent._run_memprocfs_corroboration(fake_ctx)
    assert any(f.confidence == "insufficient" for f in findings)


def test_memprocfs_unrelated_exception_still_propagates(fake_ctx):
    """Don't catch *every* exception — only the four we know correspond to
    transient FUSE / fixture / parse issues. A genuine bug should still
    surface."""
    agent = MemoryForensicatorAgent()
    with patch.object(mpfs, "run_forensic_scan",
                       side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            agent._run_memprocfs_corroboration(fake_ctx)


def test_memprocfs_failure_attempts_unmount(fake_ctx, monkeypatch):
    """When the scan fails, the agent must best-effort unmount the FUSE
    mount it (or memprocfs itself) may have left behind, so the case dir
    isn't stuck unwriteable for the next run."""
    import subprocess as _sp
    seen_calls = []

    def fake_run(args, **kwargs):
        seen_calls.append(args)
        return _sp.CompletedProcess(args=args, returncode=0,
                                     stdout=b"", stderr=b"")

    with patch.object(mpfs, "run_forensic_scan",
                       side_effect=OSError(5, "I/O error", "x")), \
            patch("subprocess.run", side_effect=fake_run):
        MemoryForensicatorAgent()._run_memprocfs_corroboration(fake_ctx)
    # At least one fusermount -u call should have been attempted.
    fuser = [c for c in seen_calls
             if c and any("fusermount" in str(p) for p in c)]
    assert fuser, "expected a best-effort fusermount -u call after failure"

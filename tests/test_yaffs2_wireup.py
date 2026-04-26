"""Integration tests for the YAFFS2 wire-up: triage routing for
MTD bundle directories + AndroidForensicator's
_run_yaffs2_bundle dispatch path.
"""
import subprocess
from pathlib import Path

import pytest

from el.agents.android_forensicator import AndroidForensicatorAgent
from el.agents.base import AgentContext
from el.agents.triage import TriageAgent
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger
from el.skills import yaffs2 as y_skill


def _make_case(tmp_path, monkeypatch, cid: str):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "trigger.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=cid)
    with open_ledger(m.case_dir):
        pass
    return src, m


def _build_synthetic_yaffs2_chunk(name: str = "system") -> bytes:
    obj_type = b"\x03\x00\x00\x00"             # DIRECTORY
    parent_id = b"\x01\x00\x00\x00"
    sum_unused = b"\x00\x00"
    name_b = name.encode("ascii").ljust(256, b"\x00")
    pad = b"\x00" * (2048 - 4 - 4 - 2 - 256)
    return obj_type + parent_id + sum_unused + name_b + pad


def _make_mtd_bundle(d: Path, with_yaffs: bool = True):
    """Build a fake mtd*.dd bundle directory.
    mtd0/1/2 = bootloader / kernel / random (NON-YAFFS2)
    mtd3 = synthetic YAFFS2 (4 directory chunks) when with_yaffs=True
    """
    d.mkdir(parents=True, exist_ok=True)
    (d / "mtd0.dd").write_bytes(b"\x00\x10\xa0\xe3" * 1024)
    (d / "mtd1.dd").write_bytes(b"ANDROID!" * 200)
    (d / "mtd2.dd").write_bytes(b"\xff" * 4096)
    if with_yaffs:
        (d / "mtd3.dd").write_bytes(b"".join(
            _build_synthetic_yaffs2_chunk(n)
            for n in ("system", "etc", "data", "lib", "bin")))
    else:
        (d / "mtd3.dd").write_bytes(b"\x00" * 4096)


# --- Triage routing -----------------------------------------------------

def test_triage_routes_mtd_bundle(tmp_path, monkeypatch):
    src, m = _make_case(tmp_path, monkeypatch, "t-tri-mtd")
    bundle = tmp_path / "phone_dump"
    _make_mtd_bundle(bundle, with_yaffs=True)
    ctx = AgentContext(
        case_id="t-tri-mtd", case_dir=Path(m.case_dir),
        input_path=bundle, manifest=m.__dict__)
    findings = TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") == "android-mtd-bundle"
    routed = [f for f in findings
               if "MTD/YAFFS2 phone dump" in f.claim]
    assert routed and routed[0].confidence == "high"


def test_triage_does_not_route_arbitrary_dir(tmp_path, monkeypatch):
    """A random directory with no mtd*.dd files should NOT trip the
    MTD-bundle detector."""
    src, m = _make_case(tmp_path, monkeypatch, "t-tri-no-mtd")
    bundle = tmp_path / "random"; bundle.mkdir()
    (bundle / "readme.txt").write_text("not a dump")
    (bundle / "image.dd").write_bytes(b"x")
    ctx = AgentContext(
        case_id="t-tri-no-mtd", case_dir=Path(m.case_dir),
        input_path=bundle, manifest=m.__dict__)
    findings = TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") != "android-mtd-bundle"


def test_triage_requires_minimum_partitions(tmp_path, monkeypatch):
    """A directory with only 2 mtd*.dd files (below the default
    min_partitions=3) should NOT route to android-mtd-bundle."""
    src, m = _make_case(tmp_path, monkeypatch, "t-tri-mtd-low")
    bundle = tmp_path / "bundle"; bundle.mkdir()
    (bundle / "mtd0.dd").write_bytes(b"x")
    (bundle / "mtd1.dd").write_bytes(b"x")
    ctx = AgentContext(
        case_id="t-tri-mtd-low", case_dir=Path(m.case_dir),
        input_path=bundle, manifest=m.__dict__)
    findings = TriageAgent().run(ctx)
    assert ctx.shared.get("evidence_kind") != "android-mtd-bundle"


# --- Android agent: YAFFS2 wire-up --------------------------------------

def test_android_agent_unyaffs_missing_emits_per_partition_blockers(
        tmp_path, monkeypatch):
    """When unyaffs is missing entirely, each YAFFS2 partition the
    detector flags should produce one insufficient Finding pointing
    at the install path."""
    src, m = _make_case(tmp_path, monkeypatch, "t-andr-mtd-noun")
    bundle = tmp_path / "bundle"
    _make_mtd_bundle(bundle, with_yaffs=True)
    monkeypatch.setattr(y_skill, "_unyaffs_bin", lambda: None)
    ctx = AgentContext(
        case_id="t-andr-mtd-noun", case_dir=Path(m.case_dir),
        input_path=bundle, manifest=m.__dict__,
        shared={"evidence_kind": "android-mtd-bundle"})
    findings = AndroidForensicatorAgent().run(ctx)
    blockers = [f for f in findings
                 if f.confidence == "insufficient"
                 and "extract failed" in f.claim
                 and "unyaffs not installed" in f.claim]
    assert blockers


def test_android_agent_no_yaffs_partitions_emits_blocker(
        tmp_path, monkeypatch):
    """When the bundle has no YAFFS2-shaped partitions at all, the
    agent emits a single insufficient Finding explaining what
    happened and bails."""
    src, m = _make_case(tmp_path, monkeypatch, "t-andr-mtd-noyaffs")
    bundle = tmp_path / "bundle"
    _make_mtd_bundle(bundle, with_yaffs=False)
    ctx = AgentContext(
        case_id="t-andr-mtd-noyaffs", case_dir=Path(m.case_dir),
        input_path=bundle, manifest=m.__dict__,
        shared={"evidence_kind": "android-mtd-bundle"})
    findings = AndroidForensicatorAgent().run(ctx)
    msgs = [f for f in findings
             if "no YAFFS2-shaped partitions" in f.claim]
    assert msgs


def test_android_agent_extracts_and_chains_to_artifacts_walker(
        tmp_path, monkeypatch):
    """When unyaffs IS available and extraction succeeds, the agent
    emits one extraction Finding per partition + chains the
    standard android-artifacts walker against the merged extract."""
    src, m = _make_case(tmp_path, monkeypatch,
                         "t-andr-mtd-success")
    bundle = tmp_path / "bundle"
    _make_mtd_bundle(bundle, with_yaffs=True)
    monkeypatch.setattr(y_skill, "_unyaffs_bin",
                         lambda: "/fake/unyaffs")

    def fake_unyaffs(cmd, capture_output, text, timeout):
        # Simulate unyaffs creating an Android-shaped extraction:
        # data/system/packages.xml + data/data/<pkg>/databases/
        out_dir = Path(cmd[2])
        (out_dir / "data" / "system").mkdir(parents=True)
        (out_dir / "data" / "system" / "packages.xml").write_text(
            "<packages/>")
        (out_dir / "data" / "data" / "com.example").mkdir(
            parents=True)
        (out_dir / "data" / "data" / "com.example"
         / "shared_prefs").mkdir()
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(y_skill.subprocess, "run", fake_unyaffs)
    ctx = AgentContext(
        case_id="t-andr-mtd-success", case_dir=Path(m.case_dir),
        input_path=bundle, manifest=m.__dict__,
        shared={"evidence_kind": "android-mtd-bundle"})
    findings = AndroidForensicatorAgent().run(ctx)
    extracted = [f for f in findings
                  if "extracted via unyaffs" in f.claim]
    assert extracted and extracted[0].confidence == "high"
    # Merged FS path must exist + the standard android-artifacts
    # extractor should have run on it (look for the
    # "Android artifacts extracted" Finding).
    artifacts = [f for f in findings
                  if "Android artifacts extracted" in f.claim]
    assert artifacts, ("expected the standard android-artifacts "
                        "walker to fire on the YAFFS2 merged extract")

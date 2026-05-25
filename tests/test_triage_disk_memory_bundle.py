"""Contract tests for the disk+memory bundle triage rule.

The SANS LoneWolf evidence shape is a single directory containing
multi-segment .E01 files plus a standalone memory dump (memdump.mem)
plus optionally pagefile.sys and an FTK Imager log. The original
``directory-unclassified`` fallback dropped this on the floor; both
DiskForensicator and MemoryForensicator ended up looking at the raw
directory and emitted ``insufficient``.

Locks in:
  * A directory with ≥1 .E01 and a memory-image-shaped file is
    detected, evidence_kind becomes "EWF (E01)" (the existing kind that
    routes to DiskForensicator).
  * ctx.input_path is rewritten to the .E01 segment so DiskForensicator
    sees a single image as input.
  * ctx.shared['paired_memory_image'] points at the memory dump so the
    coordinator can chain MemoryForensicator after disk extraction.
  * pagefile.sys, when present, is recorded but never mistaken for the
    memory image.
  * A directory with .E01 but no memory image does NOT trigger this
    rule (the single .E01 file flow handles that case via magic bytes
    on the file at intake time).
  * A directory with a memory dump but no .E01 does NOT trigger.
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import AgentContext
from el.agents.triage import TriageAgent


# EWF (E01) magic bytes — written into the test fixtures so any
# accidental magic-byte probe of the rewritten input_path still
# resolves to the correct kind even outside the directory probe.
_E01_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"


def _ctx(case_dir: Path, input_path: Path) -> AgentContext:
    (case_dir / "analysis" / "triage").mkdir(parents=True, exist_ok=True)
    return AgentContext(
        case_id="lonewolf-test", case_dir=case_dir,
        input_path=input_path, manifest={"input_path": str(input_path)},
    )


def _make_bundle(tmp_path: Path, *, segments: int = 9,
                  memdump_name: str = "memdump.mem",
                  with_pagefile: bool = True) -> Path:
    d = tmp_path / "LoneWolf_Image_Files"
    d.mkdir()
    for i in range(1, segments + 1):
        (d / f"LoneWolf.E{i:02d}").write_bytes(_E01_MAGIC + b"\x00" * 64)
    (d / memdump_name).write_bytes(b"\x00" * 1024)
    if with_pagefile:
        (d / "pagefile.sys").write_bytes(b"\x00" * 512)
    (d / "FTK Imager Log.txt").write_text("ftk imager log")
    return d


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_lonewolf_shape_detected(tmp_path):
    """The canonical LoneWolf layout (9 .E01 segments + memdump.mem +
    pagefile.sys + FTK Imager log) must be recognised as a bundle
    and not fall through to directory-unclassified."""
    bundle = _make_bundle(tmp_path)
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, bundle)

    findings = TriageAgent().run(ctx)

    assert ctx.shared.get("evidence_kind") == "EWF (E01)"
    assert ctx.shared.get("paired_memory_image", "").endswith("memdump.mem")
    assert ctx.shared.get("paired_pagefile", "").endswith("pagefile.sys")
    assert any(
        f.confidence == "high"
        and "disk+memory" in (f.claim or "")
        for f in findings
    )


def test_input_path_rewritten_to_e01_segment(tmp_path):
    """After detection DiskForensicator must see a single .E01 file
    as ctx.input_path, not the bundle directory — EWF tooling auto-
    walks the .E0N siblings from there."""
    bundle = _make_bundle(tmp_path)
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, bundle)

    TriageAgent().run(ctx)

    assert ctx.input_path != bundle
    assert ctx.input_path.is_file()
    assert ctx.input_path.suffix == ".E01"
    # Deterministic — the lowest-numbered segment wins
    assert ctx.input_path.name == "LoneWolf.E01"


def test_paired_memory_image_recorded_in_shared(tmp_path):
    """The coordinator's paired-memory pass keys off
    ctx.shared['paired_memory_image']."""
    bundle = _make_bundle(tmp_path)
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, bundle)

    TriageAgent().run(ctx)

    mem_path = Path(ctx.shared["paired_memory_image"])
    assert mem_path.is_file()
    assert mem_path.name == "memdump.mem"
    assert mem_path.parent == bundle


def test_pagefile_recorded_but_not_treated_as_memory(tmp_path):
    """pagefile.sys is the swap, not a vol3-compatible memory image —
    it must never be selected as paired_memory_image even when it sits
    alongside a real memdump.mem."""
    bundle = _make_bundle(tmp_path)
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, bundle)

    TriageAgent().run(ctx)

    assert ctx.shared["paired_memory_image"].endswith("memdump.mem")
    assert "pagefile.sys" not in ctx.shared["paired_memory_image"]
    assert ctx.shared.get("paired_pagefile", "").endswith("pagefile.sys")


def test_bundle_without_pagefile_still_detected(tmp_path):
    """pagefile.sys is optional — the bundle detector should fire on
    just .E01 + memory image."""
    bundle = _make_bundle(tmp_path, with_pagefile=False)
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, bundle)

    TriageAgent().run(ctx)

    assert ctx.shared.get("evidence_kind") == "EWF (E01)"
    assert ctx.shared.get("paired_memory_image", "").endswith("memdump.mem")
    assert "paired_pagefile" not in ctx.shared


def test_img_extension_recognised_as_memory_when_e01_siblings_present(tmp_path):
    """SRL-2018 corpus shape: memory dumps are named `base-<host>-
    memory.img` — `.img` is generic enough to also mean a raw disk
    image, but a `.img` sitting next to E01 segments is almost
    certainly the paired memory dump (you wouldn't ship two copies
    of the same disk). The gate is the E01 neighbour requirement
    that the bundle detector already enforces."""
    bundle = _make_bundle(tmp_path, memdump_name="base-dc-memory.img",
                            with_pagefile=False)
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, bundle)

    TriageAgent().run(ctx)

    assert ctx.shared.get("evidence_kind") == "EWF (E01)"
    assert ctx.shared.get(
        "paired_memory_image", "").endswith("base-dc-memory.img")


def test_substring_stem_matches_hostname_prefixed_memory(tmp_path):
    """The SRL-2018 stems are always hostname-prefixed
    (`base-dc-memory`, `wkstn05-memdump`, …). The original exact-
    match rule (`stem in {memdump, memory, memcap, ram}`) missed
    them all. Substring match keeps the same vocabulary but works
    when the name carries a hostname prefix."""
    for stem in ("base-dc-memory", "wkstn05-memdump",
                  "host-RAM-capture", "srl-memcap-2018"):
        slot = tmp_path / stem
        slot.mkdir()
        bundle = _make_bundle(slot, memdump_name=f"{stem}.bin",
                                with_pagefile=False)
        ctx = _ctx(slot / "case", bundle)

        TriageAgent().run(ctx)

        assert ctx.shared.get("evidence_kind") == "EWF (E01)", stem
        assert ctx.shared.get(
            "paired_memory_image", "").endswith(f"{stem}.bin"), stem


def test_alternative_memory_extensions_recognised(tmp_path):
    """vol3 reads .mem, .vmem, .raw, .dmp, .bin, .lime — the detector
    must accept any of those as the memory image, not only memdump.mem."""
    for ext in (".vmem", ".raw", ".dmp"):
        slot = tmp_path / f"case-{ext.lstrip('.')}"
        slot.mkdir()
        bundle = _make_bundle(
            slot, memdump_name=f"capture{ext}", with_pagefile=False)
        ctx = _ctx(slot / "case", bundle)

        TriageAgent().run(ctx)

        assert ctx.shared.get("evidence_kind") == "EWF (E01)"
        assert ctx.shared.get(
            "paired_memory_image", "").endswith(f"capture{ext}")


def test_e01_only_does_not_trigger_bundle(tmp_path):
    """A directory holding only .E01 segments (no memory dump) must
    NOT be classified as a disk+memory bundle. Without a memory image
    we have nothing for MemoryForensicator to chain on — the .E01
    should be picked up via its own single-file intake path."""
    d = tmp_path / "disk-only"
    d.mkdir()
    for i in range(1, 4):
        (d / f"disk.E{i:02d}").write_bytes(_E01_MAGIC + b"\x00" * 64)
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, d)

    TriageAgent().run(ctx)

    # Triage may still classify as directory-unclassified; the key
    # assertion is that paired_memory_image is NOT set — there was no
    # memory image to pair.
    assert "paired_memory_image" not in ctx.shared


def test_memory_only_does_not_trigger_bundle(tmp_path):
    """A directory holding only a memory dump (no .E01) must NOT
    be classified as the bundle either — single memory images flow
    through the file-shape detector."""
    d = tmp_path / "mem-only"
    d.mkdir()
    (d / "memdump.mem").write_bytes(b"\x00" * 1024)
    (d / "pagefile.sys").write_bytes(b"\x00" * 512)
    case_dir = tmp_path / "case"
    ctx = _ctx(case_dir, d)

    TriageAgent().run(ctx)

    assert ctx.shared.get("evidence_kind") != "EWF (E01)"
    assert "paired_memory_image" not in ctx.shared


# ---------------------------------------------------------------------------
# Routing — the existing EWF (E01) kind already maps to DiskForensicator;
# this test guards against an accidental re-map.
# ---------------------------------------------------------------------------

def test_kind_to_agent_routes_e01_to_disk_forensicator():
    from el.orchestrator.coordinator import KIND_TO_AGENT
    from el.agents.disk_forensicator import DiskForensicatorAgent
    assert KIND_TO_AGENT.get("EWF (E01)") is DiskForensicatorAgent

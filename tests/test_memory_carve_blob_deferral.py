"""Contract tests for memory-image vs carve-only disambiguation.

A raw Windows memory image caches enormous volumes of filesystem metadata —
MFT records (FILE0), registry hives (regf), event logs, prefetch — so it trips
``_detect_carvable_blob`` exactly like an exported unallocated-space blob.
(Measured on the 19 GiB SRL "Rocba" capture: FILE0 in 9 of 12 sample windows.)
That false positive routed the whole memory capture to the carving pipeline and
``MemoryForensicator`` (plus the chained UserActivity / RDPBruteForce agents)
never ran — even though Volatility reads the image fine.

Fix: when the carve-blob heuristic fires but the input *names itself* a memory
capture (conventional extension / name token, or the bundle device label in
case_id "<bundle>:<device>"), defer the verdict to a vol3 kernel probe. Kernel
found → memory path; no kernel → fall back to carving (no regression for the
Ashemery "Unallocated01" blob, which carries no memory name).

Locks in:
  * the name heuristic (`_looks_like_memory_input`) — tokens, strong/weak
    extensions, and the bundle device label;
  * a memory-named carve-blob hit defers to vol3 and routes to the memory
    path when a kernel is found;
  * the same input falls back to carve-only when vol3 finds no kernel;
  * a carve-blob with NO memory name still carves immediately and never pays
    the vol3 probe.
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import AgentContext
from el.agents.triage import TriageAgent, _looks_like_memory_input


# 300 MiB clears the 256 MiB carve-blob floor while staying sparse on disk.
SZ = 300 * 1024 * 1024


def _blob(path: Path, *, sigs=(b"FILE0", b"regf"), size: int = SZ) -> Path:
    """Sparse file with each signature placed at offsets the carve-blob
    detector definitely samples (it reads 1 MiB windows at fixed fractions)."""
    path.write_bytes(b"")
    with path.open("wb") as f:
        f.truncate(size)
        for sig in sigs:
            for frac in (0.2, 0.5, 0.7):
                f.seek(int(size * frac))
                f.write(sig)
    return path


def _ctx(tmp_path: Path, input_path: Path, *, case_id: str = "c") -> AgentContext:
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "triage").mkdir(parents=True, exist_ok=True)
    return AgentContext(
        case_id=case_id, case_dir=case_dir, input_path=input_path,
        manifest={"input_path": str(input_path)},
    )


# ---------------------------------------------------------------------------
# _looks_like_memory_input — name heuristic
# ---------------------------------------------------------------------------

def test_name_token_memory_recognised(tmp_path):
    assert _looks_like_memory_input(tmp_path / "Rocba-Memory.raw", None)
    assert _looks_like_memory_input(tmp_path / "wkstn05-memdump.bin", None)
    assert _looks_like_memory_input(tmp_path / "host-winpmem.raw", None)


def test_strong_extension_recognised(tmp_path):
    for ext in (".lime", ".vmem", ".vmss", ".vmsn", ".pmem", ".dmp", ".mem"):
        assert _looks_like_memory_input(tmp_path / f"capture{ext}", None), ext


def test_bundle_device_label_recognised(tmp_path):
    # investigate-bundle sub-case ids look like "<bundle>:<device>".
    assert _looks_like_memory_input(tmp_path / "evidence.raw", "rocba:memory")
    assert _looks_like_memory_input(tmp_path / "evidence.001", "case:ram")
    assert _looks_like_memory_input(tmp_path / "evidence.bin", "x:memdump")


def test_weak_extension_alone_is_not_a_memory_hint(tmp_path):
    # .raw/.img/.bin are also disk extensions — they only count alongside a
    # name token or device label, never on their own.
    assert not _looks_like_memory_input(tmp_path / "unalloc.raw", None)
    assert not _looks_like_memory_input(tmp_path / "export.bin", "case:disk")
    assert not _looks_like_memory_input(tmp_path / "image.img", None)


# ---------------------------------------------------------------------------
# Deferral behaviour in TriageAgent.run
# ---------------------------------------------------------------------------

def test_memory_named_carve_blob_defers_and_routes_to_memory(tmp_path, monkeypatch):
    """A memory-named blob that trips the carve heuristic must NOT be
    committed to carve-only; it defers to vol3, and when a kernel is found
    the memory path owns it."""
    img = _blob(tmp_path / "Rocba-Memory.raw")
    ctx = _ctx(tmp_path, img, case_id="rocba:memory")

    def fake_vol3(self, ctx, analysis):
        ctx.shared["mem_os"] = "windows"   # vol3 found a Windows kernel
        return []

    monkeypatch.setattr(TriageAgent, "_maybe_run_vol3", fake_vol3)
    TriageAgent().run(ctx)

    assert ctx.shared.get("mem_os") == "windows"
    assert ctx.shared.get("evidence_kind") != "unallocated (carve-only)"


def test_memory_named_carve_blob_falls_back_to_carve_when_no_kernel(tmp_path, monkeypatch):
    """If the input is named like memory but vol3 finds no kernel, it is a
    headerless blob after all — route it to carving, don't drop it."""
    img = _blob(tmp_path / "host-memdump.raw")
    ctx = _ctx(tmp_path, img, case_id="case:memory")

    def fake_vol3(self, ctx, analysis):
        return []   # no kernel; mem_os stays unset

    monkeypatch.setattr(TriageAgent, "_maybe_run_vol3", fake_vol3)
    TriageAgent().run(ctx)

    assert "mem_os" not in ctx.shared
    assert ctx.shared.get("evidence_kind") == "unallocated (carve-only)"


def test_unnamed_carve_blob_carves_immediately_without_vol3(tmp_path, monkeypatch):
    """Regression guard for the Ashemery 'Unallocated01' shape: a carve-blob
    with no memory name must classify carve-only up front and never pay the
    vol3 probe."""
    img = _blob(tmp_path / "unalloc.bin")
    ctx = _ctx(tmp_path, img, case_id="ashemery:disk")

    called = {"vol3": False}

    def fake_vol3(self, ctx, analysis):
        called["vol3"] = True
        return []

    monkeypatch.setattr(TriageAgent, "_maybe_run_vol3", fake_vol3)
    TriageAgent().run(ctx)

    assert ctx.shared.get("evidence_kind") == "unallocated (carve-only)"
    assert called["vol3"] is False

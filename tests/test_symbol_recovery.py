"""Contract for the Windows symbol-mismatch recovery path.

Pure helpers (windows_symbol_degraded, parse_pdbscan_guid) are tested directly;
the agent's heal-and-retry vs degraded-flag branches are tested with vol3 fully
mocked (no memory image, no vol3 binary).
"""
from __future__ import annotations

from pathlib import Path

from el.skills.vol3 import (
    windows_symbol_degraded, parse_windows_info, SymbolRecovery,
)
from el.agents.memory_forensicator import MemoryForensicatorAgent
from el.agents.base import AgentContext


# --- pure helpers ----------------------------------------------------------

def test_symbol_degraded_signature():
    # psscan found procs, pslist didn't → degraded
    assert windows_symbol_degraded(0, 97) is True
    # both populated → fine
    assert windows_symbol_degraded(85, 97) is False
    # both empty → not the symbol signature (could be empty image / non-windows)
    assert windows_symbol_degraded(0, 0) is False


def test_parse_windows_info_extracts_kernel_and_guid():
    # real shape of windows.info.Info rows (the Symbols row carries the ISF path)
    rows = [
        {"Variable": "Kernel Base", "Value": "0xf80038e1b000"},
        {"Variable": "Symbols", "Value":
            "file:///x/symbols/windows/ntkrnlmp.pdb/DA4A2FB4BAD84D0F95A1A5B0FDE4F155-1.json.xz"},
    ]
    kb, guid = parse_windows_info(rows)
    assert kb == "0xf80038e1b000"
    assert guid == "DA4A2FB4BAD84D0F95A1A5B0FDE4F155"
    # no kernel base → smear shape
    assert parse_windows_info([{"Variable": "x", "Value": "y"}]) == (None, None)


# --- agent recovery branches -----------------------------------------------

class _Run:
    """Minimal PluginRun stand-in."""
    def __init__(self, row_count, rc=0):
        self.row_count = row_count
        self.rc = rc
    def as_evidence(self, facts=None):
        from el.schemas.finding import EvidenceItem
        return EvidenceItem(tool="vol3", version="t", command="vol",
                            output_sha256="0" * 64, output_path="/x")


def _ctx(tmp_path):
    return AgentContext(case_id="c", case_dir=tmp_path, input_path=tmp_path / "mem.img",
                        manifest={}, shared={})


def test_not_degraded_is_noop(tmp_path):
    runs = {"windows.pslist.PsList": _Run(85), "windows.psscan.PsScan": _Run(97)}
    out = MemoryForensicatorAgent()._recover_symbols_if_degraded(_ctx(tmp_path), tmp_path, runs)
    assert out == []


def test_heal_success_reenables_plugins(tmp_path, monkeypatch):
    import el.agents.memory_forensicator as mod
    healed = _Run(85)
    monkeypatch.setattr(mod.vol3, "recover_windows_symbols",
                        lambda *a, **k: (SymbolRecovery("healed", True, None, "ok"), healed))
    reran = []
    def fake_run_plugin(image, plugin, out, extra_args=None, timeout=900, streaming=False):
        reran.append(plugin)
        return _Run(12)
    monkeypatch.setattr(mod.vol3, "run_plugin", fake_run_plugin)

    runs = {"windows.pslist.PsList": _Run(0), "windows.psscan.PsScan": _Run(97)}
    ctx = _ctx(tmp_path)
    out = MemoryForensicatorAgent()._recover_symbols_if_degraded(ctx, tmp_path, runs)

    claims = " ".join(f.claim for f in out)
    assert "process list RECOVERED" in claims
    assert runs["windows.pslist.PsList"] is healed          # swapped in
    assert "windows.cmdline.CmdLine" in reran               # process-context re-run
    assert "windows.malfind.Malfind" in reran
    assert "mem_degraded" not in ctx.shared


def test_scanner_fallback_recovers_process_source(tmp_path, monkeypatch):
    """The real elf/sp/dc case: symbols loaded, list-walk empty → psscan is the
    source, flagged honestly (not a silent 0-rows)."""
    import el.agents.memory_forensicator as mod
    monkeypatch.setattr(mod.vol3, "recover_windows_symbols",
                        lambda *a, **k: (SymbolRecovery("scanner_fallback", True, "KGUID",
                                                        "list-walk empty"), None))
    runs = {"windows.pslist.PsList": _Run(0), "windows.psscan.PsScan": _Run(97)}
    ctx = _ctx(tmp_path)
    out = MemoryForensicatorAgent()._recover_symbols_if_degraded(ctx, tmp_path, runs)

    assert ctx.shared.get("mem_degraded") == "scanner_fallback"
    assert ctx.shared.get("process_source") == "psscan"
    claim = " ".join(f.claim for f in out)
    assert "KGUID" in claim and "psscan recovered 97" in claim
    assert "not missing symbols" in claim


def test_smear_flags_degraded(tmp_path, monkeypatch):
    import el.agents.memory_forensicator as mod
    monkeypatch.setattr(mod.vol3, "recover_windows_symbols",
                        lambda *a, **k: (SymbolRecovery("smear", False, None, "smear"), None))
    runs = {"windows.pslist.PsList": _Run(0), "windows.psscan.PsScan": _Run(97)}
    ctx = _ctx(tmp_path)
    out = MemoryForensicatorAgent()._recover_symbols_if_degraded(ctx, tmp_path, runs)

    assert ctx.shared.get("mem_degraded") == "smear"
    assert any(f.confidence == "insufficient" and "smeared acquisition" in f.claim for f in out)
    assert all(f.confidence != "high" for f in out)


def test_symbols_missing_flags_degraded_with_fix(tmp_path, monkeypatch):
    import el.agents.memory_forensicator as mod
    monkeypatch.setattr(mod.vol3, "recover_windows_symbols",
                        lambda *a, **k: (SymbolRecovery("symbols_missing", True, "KGUID", "no isf"), None))
    runs = {"windows.pslist.PsList": _Run(0), "windows.psscan.PsScan": _Run(50)}
    ctx = _ctx(tmp_path)
    out = MemoryForensicatorAgent()._recover_symbols_if_degraded(ctx, tmp_path, runs)

    assert ctx.shared.get("mem_degraded") == "symbols_missing"
    claim = " ".join(f.claim for f in out)
    assert "KGUID" in claim and ("pre-seed" in claim.lower() or "EL_VOL_SYMBOLS" in claim)

"""Tests for FinFisher/FinSpy attribution + carved-binary scanning.

Grounded in Ashemery's Unallocated01 case: EL carved 264 EXE / 224 DLL
fragments from unallocated space, one of which is a FinSpy implant. The
distinctive markers (msnetobj.dll, the MSI kernel-driver custom actions, the
id-keyed HTTP C2 beacon) live only in the binary BODY, not in bulk_extractor's
feature files — so malware_triage must scan the carved binaries, and the
family library must carry a FinFisher fingerprint.
"""
from __future__ import annotations

from el.intel.malware_families import detect, FAMILIES
from el.intel.attack_tactics import tactic_for
from el.intel.attack_capacities import capacity_for


# Markers observed in the carved FinSpy binary (and corroborated by public
# FinSpy reporting).
_FINSPY_STRINGS = {
    r"C:\WINDOWS\system32\msnetobj.dll",
    "ERROR: Invalid CustomActionData for VMInstallKernelDriver",
    "KernelDriverUninstall",
    "http://%s.com/info?id=%u",
    "LicenseVersion, LicenseType, LicenseEdition, Epoch",
}


def test_finfisher_detects_observed_markers():
    fams = [m.family for m in detect(_FINSPY_STRINGS, context="memory")]
    assert "finfisher" in fams


def test_finfisher_code_markers_are_high_signal():
    """Each distinctive CODE marker alone attributes FinFisher — they are
    near-unique to the implant."""
    for s in (r"...\msnetobj.dll", "VMInstallKernelDriver", "VMUninstallKernelDriver"):
        fams = [m.family for m in detect({s}, context="memory")]
        assert "finfisher" in fams, f"{s!r} should attribute finfisher"


def test_finfisher_does_not_match_benign_strings():
    benign = {"C:\\Windows\\System32\\kernel32.dll", "GetProcAddress",
              "https://www.microsoft.com/", "Mozilla/5.0", "advapi32.dll"}
    fams = [m.family for m in detect(benign, context="memory")]
    assert "finfisher" not in fams


def test_finfisher_c2_beacon_matches_in_network_context():
    """The id-keyed beacon is a URL pattern — it must also fire on
    network-context text (bulk_extractor url.txt)."""
    fams = [m.family for m in detect({"http://%s.com/info?id=%u"},
                                     context="network")]
    assert "finfisher" in fams


def test_finfisher_attack_techniques_have_full_coverage():
    """Every ATT&CK technique the family emits must map to a tactic AND a
    capacity (the heatmap + coverage guarantees). T1014 was newly added."""
    for tid, _ in FAMILIES["finfisher"]["attack"]:
        assert tactic_for(tid) is not None, f"{tid} has no tactic"
        assert capacity_for(tid) is not None, f"{tid} has no capacity"
    assert tactic_for("T1014") == "Defense Evasion"


def test_malware_triage_attributes_carved_binary(tmp_path, monkeypatch):
    """End-to-end through MalwareTriageAgent: a carved binary in
    ctx.shared['carved_files_dir'] is strings-scanned and attributed, emitting
    a medium-confidence finding WITH tags. Regression: this emission path uses
    EvidenceItem and previously UnboundLocalError'd because of a redundant
    in-function import — the unit detect() tests didn't exercise it; the live
    Unallocated01 run did."""
    from pathlib import Path
    from el.agents.base import AgentContext
    from el.agents.malware_triage import MalwareTriageAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"
    src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="finfisher-carve")
    with open_ledger(m.case_dir):
        pass
    # synthetic carved PE body carrying the distinctive FinSpy markers
    carved = Path(m.case_dir) / "exports" / "carved"
    (carved / "exe").mkdir(parents=True)
    (carved / "exe" / "00001234.exe").write_bytes(
        b"MZ\x90\x00" + b"\x00" * 64
        + b"C:\\WINDOWS\\system32\\msnetobj.dll\x00"
        + b"ERROR: Invalid CustomActionData for VMInstallKernelDriver\x00"
        + b"http://%s.com/info?id=%u\x00" + b"\x00" * 4096)
    ctx = AgentContext(case_id="finfisher-carve", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"carved_files_dir": str(carved)})
    findings = MalwareTriageAgent().run(ctx)
    carved_hits = [f for f in findings
                   if "Carved-binary attribution" in f.claim
                   and "finfisher" in f.claim]
    assert carved_hits, "expected a carved-binary finfisher attribution finding"
    f = carved_hits[0]
    assert f.confidence == "medium"
    assert "H_C2_OR_REVERSE_SHELL" in f.hypotheses_supported

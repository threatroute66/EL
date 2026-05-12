"""Regression tests for the three deep-memory detectors added after charlie-02:
 - PE-header detection in malfind Hexdumps ("4d 5a" = MZ = hollowed PE)
 - Orphaned processes (PPID not in pslist)
 - Very short-lived processes (<5s exit)

Plus T1055.012 mapping for H_PROCESS_HOLLOWING."""
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.memory_forensicator import MemoryForensicatorAgent
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger
from el.intel.attack_map import map_finding
from el.schemas.finding import EvidenceItem, Finding
from el.skills.vol3 import PluginRun


def _ctx(tmp_path, monkeypatch, case_id="t-deep"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


def _run(plugin: str, rows: list, tmp_path: Path) -> PluginRun:
    p = tmp_path / f"{plugin.replace('.', '_')}.json"
    p.write_text("[]")
    return PluginRun(plugin=plugin, image=tmp_path / "img", rc=0,
                     stdout_path=p, stderr_path=tmp_path / f"{plugin}.stderr",
                     rows=rows, command=["vol", "..."], version="2.27.0")


def test_mz_hexdump_emits_hollowing_finding(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [
        {"PID": 1234, "Process": "explorer.exe",
         "Hexdump": "4d 5a 90 00 03 00 00 00", "Start VPN": "0x12340000"},
        {"PID": 5678, "Process": "svchost.exe",
         "Hexdump": "90 90 90 90 cc cc cc cc", "Start VPN": "0x56780000"},  # not MZ
    ]
    findings = MemoryForensicatorAgent()._flag_pe_headers(
        ctx, _run("windows.malfind.Malfind", rows, tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert "MZ header" in f.claim
    assert "explorer.exe" in f.claim
    assert "H_PROCESS_HOLLOWING" in f.hypotheses_supported


def test_no_mz_rows_no_finding(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    rows = [{"PID": 1, "Process": "x", "Hexdump": "cc cc cc cc cc cc cc cc"}]
    findings = MemoryForensicatorAgent()._flag_pe_headers(
        ctx, _run("windows.malfind.Malfind", rows, tmp_path))
    assert findings == []


def test_hollowing_maps_to_t1055_012():
    f = Finding(case_id="c", agent="memory_forensicator", confidence="high",
                claim="Reflectively-loaded PE image(s) detected in explorer.exe",
                evidence=[EvidenceItem(tool="t", version="0", command="x",
                                        output_sha256="0"*64, output_path="/tmp/x")],
                hypotheses_supported=["H_PROCESS_HOLLOWING", "H_PROCESS_INJECTION"])
    pairs = map_finding(f)
    tids = {tid for tid, _ in pairs}
    assert "T1055" in tids
    assert "T1055.012" in tids


def test_orphaned_process_detected(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, case_id="t-orphan")
    rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 400, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 666, "PPID": 99999, "ImageFileName": "suspicious.exe"},  # parent PID absent
    ]
    findings = MemoryForensicatorAgent()._process_anomalies(
        ctx, _run("windows.pslist.PsList", rows, tmp_path))
    orphan = [f for f in findings if "Orphaned" in f.claim]
    assert len(orphan) == 1
    assert "suspicious.exe" in orphan[0].claim


def test_malfind_all_jit_processes_downgraded_to_medium(tmp_path, monkeypatch):
    """Rocba carve-out: when every malfind hit lands in a known JIT-heavy
    UWP / .NET / Electron component, the RWX VAD pattern is almost
    certainly the JIT compiler's emitted code, not an implant. The
    finding is still emitted (so the analyst sees it) but downgraded to
    `medium` with a caveat naming the FP class."""
    ctx = _ctx(tmp_path, monkeypatch, case_id="t-malfind-jit")
    rows = [
        {"PID": 4864, "Process": "MsMpEng.exe", "Hexdump": "cc cc cc cc"},
        {"PID": 8312, "Process": "SearchApp.exe", "Hexdump": "cc cc cc cc"},
        {"PID": 9788, "Process": "LockApp.exe", "Hexdump": "00 00 00 00"},
        {"PID": 15636, "Process": "Teams.exe", "Hexdump": "cc cc cc cc"},
    ]
    findings = MemoryForensicatorAgent()._flag_malfind(
        ctx, _run("windows.malfind.Malfind", rows, tmp_path))
    main = [f for f in findings if "malfind flagged" in f.claim]
    assert len(main) == 1
    assert main[0].confidence == "medium"
    assert "JIT-heavy" in main[0].claim
    assert "elevation suppressed" in main[0].claim.lower()


def test_malfind_mixed_processes_keep_high_confidence(tmp_path, monkeypatch):
    """When at least ONE non-JIT process is flagged (e.g. an attacker
    injected into notepad.exe alongside Teams), the JIT-FP carve-out
    must NOT fire — keep the elevation."""
    ctx = _ctx(tmp_path, monkeypatch, case_id="t-malfind-mixed")
    rows = [
        {"PID": 100, "Process": "Teams.exe", "Hexdump": "cc cc"},
        {"PID": 200, "Process": "notepad.exe", "Hexdump": "cc cc"},
    ]
    findings = MemoryForensicatorAgent()._flag_malfind(
        ctx, _run("windows.malfind.Malfind", rows, tmp_path))
    main = [f for f in findings if "malfind flagged" in f.claim]
    assert len(main) == 1
    assert main[0].confidence == "high"


def test_driverirp_wdf01000_ndis_dxgkrnl_not_flagged(tmp_path, monkeypatch):
    """Rocba carve-out: DriverIrp owners Wdf01000.sys (KMDF framework),
    ndis.sys (NDIS networking), dxgkrnl.sys (DirectX kernel), ACPI.sys,
    partmgr.sys are in-box Windows drivers that legitimately own
    thousands of IRP entries on every Win10 install. Flagging them as
    rootkit hooks was the largest single source of false H_ROOTKIT /
    H_APT_ESPIONAGE elevation in the Rocba memory ledger."""
    ctx = _ctx(tmp_path, monkeypatch, case_id="t-driverirp-wdf")
    rows = [
        {"Driver": "\\Driver\\Wdf01000", "Address": 0x123, "Module": "Wdf01000.sys"},
        {"Driver": "\\Driver\\Ndis",     "Address": 0x456, "Module": "ndis.sys"},
        {"Driver": "\\Driver\\dxgkrnl",  "Address": 0x789, "Module": "dxgkrnl.sys"},
        {"Driver": "\\Driver\\ACPI",     "Address": 0xabc, "Module": "ACPI.sys"},
        {"Driver": "\\Driver\\partmgr",  "Address": 0xdef, "Module": "partmgr.sys"},
    ]
    findings = MemoryForensicatorAgent()._flag_kernel_hooks(
        ctx, "windows.driverirp.DriverIrp",
        _run("windows.driverirp.DriverIrp", rows, tmp_path))
    assert findings == [], (
        f"in-box Win10 drivers should not be flagged as kernel hooks, "
        f"got: {[f.claim[:120] for f in findings]}"
    )


def test_driverirp_unknown_module_still_flagged(tmp_path, monkeypatch):
    """The detector must STILL fire on a genuinely-unknown / non-MS
    module owning an IRP entry (a real rootkit primitive)."""
    ctx = _ctx(tmp_path, monkeypatch, case_id="t-driverirp-real")
    rows = [
        {"Driver": "\\Driver\\evil",  "Address": 0x111, "Module": "evil_rk.sys"},
        {"Driver": "\\Driver\\Unknown", "Address": 0x222, "Module": "UNKNOWN"},
        # Mixed with legit driver — must still fire on the bad one
        {"Driver": "\\Driver\\Wdf01000", "Address": 0x333, "Module": "Wdf01000.sys"},
    ]
    findings = MemoryForensicatorAgent()._flag_kernel_hooks(
        ctx, "windows.driverirp.DriverIrp",
        _run("windows.driverirp.DriverIrp", rows, tmp_path))
    assert len(findings) == 1
    assert "2 entry(ies)" in findings[0].claim or "2 entr" in findings[0].claim
    assert "H_ROOTKIT" in findings[0].hypotheses_supported


def test_ldrmodules_host_wide_unlinked_downgraded(tmp_path, monkeypatch):
    """Rocba carve-out: 203 unlinked DLLs across 198 processes is the
    shape of Win10's ApiSet contract behaviour, not reflective injection.
    With >15 processes flagged the detector must downgrade and clear
    its hypothesis_supported list."""
    ctx = _ctx(tmp_path, monkeypatch, case_id="t-ldr-hostwide")
    # Build rows for 20 processes each with one InLoad=False/InMem=True DLL
    rows = [
        {"Pid": 100 + i, "Process": f"proc{i}.exe", "MappedPath": "x.dll",
         "InLoad": False, "InInit": True, "InMem": True}
        for i in range(20)
    ]
    findings = MemoryForensicatorAgent()._flag_unlinked_dlls(
        ctx, _run("windows.ldrmodules.LdrModules", rows, tmp_path))
    assert len(findings) == 1
    assert findings[0].confidence == "medium"
    assert findings[0].hypotheses_supported == []
    assert "host-wide" in findings[0].claim.lower() or "ApiSet" in findings[0].claim


def test_ldrmodules_concentrated_injection_still_high(tmp_path, monkeypatch):
    """Concentrated unlinked-DLL signature in ≤15 processes is the real
    reflective-injection pattern and must STILL elevate to high."""
    ctx = _ctx(tmp_path, monkeypatch, case_id="t-ldr-real")
    rows = [
        {"Pid": 100, "Process": "victim.exe", "MappedPath": f"reflective{i}.dll",
         "InLoad": False, "InInit": False, "InMem": True}
        for i in range(8)
    ] + [
        {"Pid": 200, "Process": "other.exe", "MappedPath": "rk.dll",
         "InLoad": False, "InInit": False, "InMem": True}
    ]
    findings = MemoryForensicatorAgent()._flag_unlinked_dlls(
        ctx, _run("windows.ldrmodules.LdrModules", rows, tmp_path))
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert "H_PROCESS_INJECTION" in findings[0].hypotheses_supported
    assert "H_APT_ESPIONAGE" in findings[0].hypotheses_supported


def test_ldrmodules_apiset_partial_mismatch_no_fire(tmp_path, monkeypatch):
    """A DLL in InLoad+InMem but not InInit is NOT reflective injection
    — that's the Win10 ApiSet forwarder shape. Detector must skip it."""
    ctx = _ctx(tmp_path, monkeypatch, case_id="t-ldr-apiset")
    rows = [
        {"Pid": 100, "Process": "x.exe", "MappedPath": "api-ms-win-core.dll",
         "InLoad": True, "InInit": False, "InMem": True},
    ]
    findings = MemoryForensicatorAgent()._flag_unlinked_dlls(
        ctx, _run("windows.ldrmodules.LdrModules", rows, tmp_path))
    assert findings == []


def test_malfind_lsass_keeps_credential_access_high(tmp_path, monkeypatch):
    """Credential-access carve-out (the pre-existing one) must still
    fire on lsass.exe regardless of the new JIT-FP path."""
    ctx = _ctx(tmp_path, monkeypatch, case_id="t-malfind-lsass")
    rows = [{"PID": 600, "Process": "lsass.exe", "Hexdump": "cc cc"}]
    findings = MemoryForensicatorAgent()._flag_malfind(
        ctx, _run("windows.malfind.Malfind", rows, tmp_path))
    cred = [f for f in findings if "credential-access" in f.claim]
    assert len(cred) == 1
    assert cred[0].confidence == "high"


def test_short_lived_process_detected_but_noisy_filtered(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, case_id="t-short")
    rows = [
        # conhost.exe routinely short-lived — filtered
        {"PID": 100, "PPID": 1, "ImageFileName": "conhost.exe",
         "CreateTime": "2026-04-17T10:00:00+00:00",
         "ExitTime": "2026-04-17T10:00:01+00:00"},
        # suspicious: rundll32 exited in 2 seconds
        {"PID": 200, "PPID": 1, "ImageFileName": "rundll32.exe",
         "CreateTime": "2026-04-17T10:00:00+00:00",
         "ExitTime": "2026-04-17T10:00:02+00:00"},
    ]
    findings = MemoryForensicatorAgent()._process_anomalies(
        ctx, _run("windows.pslist.PsList", rows, tmp_path))
    short = [f for f in findings if "short-lived" in f.claim]
    assert len(short) == 1
    assert "rundll32.exe" in short[0].claim
    assert "conhost.exe" not in short[0].claim

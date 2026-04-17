"""Disk-side anomaly pattern tests, captured from the Stark Research Labs
nrom-disk-01 case which had no disk-side scoring before this commit."""
from el.skills.disk_anomaly import scan_text


def test_psexec_service_artifact_detected():
    text = "0|/Windows/PSEXESVC.EXE|123|...\n0|/some/other/file.txt|...\n"
    hits = scan_text(text)
    by_id = {h.pattern_id: h for h in hits}
    assert "PSEXEC_SERVICE_ARTIFACT" in by_id
    h = by_id["PSEXEC_SERVICE_ARTIFACT"]
    assert "H_LATERAL_MOVEMENT" in h.hypotheses
    assert any(tid == "T1021.002" for tid, _ in h.attack_techniques)


def test_pyinstaller_temp_dir_detected():
    text = ("0|/Users/Bob/AppData/Local/Temp/_MEI29562/python25.dll|...\n"
            "0|/Users/Bob/AppData/Local/Temp/_MEI29562/_ctypes.pyd|...\n")
    hits = scan_text(text)
    assert any(h.pattern_id == "PYINSTALLER_TEMP_DIR" for h in hits)


def test_svchost_outside_system32_detected():
    text = "0|/Windows/System32/dllhost/svchost.exe|...\n"
    hits = scan_text(text)
    assert any(h.pattern_id == "SVCHOST_OUTSIDE_SYSTEM32" for h in hits)


def test_legitimate_svchost_not_flagged():
    text = "0|/Windows/System32/svchost.exe|...\n"
    hits = scan_text(text)
    pids = {h.pattern_id for h in hits}
    assert "SVCHOST_OUTSIDE_SYSTEM32" not in pids


def test_exe_in_temp_detected():
    text = "0|/Users/foo/AppData/Local/Temp/dropper.exe|...\n"
    hits = scan_text(text)
    assert any(h.pattern_id == "EXE_IN_TEMP" for h in hits)


def test_mimikatz_named_binary_detected():
    text = "0|/Tools/mimikatz.exe|...\n0|/Loot/sekurlsa-dump.kirbi|...\n"
    hits = scan_text(text)
    assert any(h.pattern_id == "MIMIKATZ_NAMED_BINARY" for h in hits)


def test_vssadmin_delete_shadows_detected():
    text = "0|/Windows/System32/vssadmin.exe|...\nlog: vssadmin delete shadows /all /quiet\n"
    hits = scan_text(text)
    assert any(h.pattern_id == "VSSADMIN_DELETE_SHADOWS_TRACE" for h in hits)


def test_no_match_returns_empty():
    text = "0|/Windows/System32/notepad.exe|...\n0|/Users/foo/document.docx|...\n"
    hits = scan_text(text)
    assert hits == []

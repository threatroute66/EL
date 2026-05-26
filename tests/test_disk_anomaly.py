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


# ---------------------------------------------------------------------------
# FOR508 cheatsheet: NTFS Alternate Data Streams (`fls -r -p | grep ':.*:'`)
# ---------------------------------------------------------------------------

def test_ntfs_ads_on_executable_detected():
    """The smoking-gun case: a .exe with a non-Zone.Identifier ADS.
    Body-file format puts the path in field 2 between pipes."""
    text = "0|/Users/Bob/Downloads/installer.exe:malicious_payload|123|...\n"
    hits = scan_text(text)
    by_id = {h.pattern_id: h for h in hits}
    assert "NTFS_ALTERNATE_DATA_STREAM" in by_id
    h = by_id["NTFS_ALTERNATE_DATA_STREAM"]
    assert "H_NTFS_ADS_PRESENT" in h.hypotheses
    assert "H_DEFENSE_EVASION" in h.hypotheses
    assert any(tid == "T1564.004" for tid, _ in h.attack_techniques)


def test_ntfs_ads_on_document_detected():
    """ADS attached to Office documents (a real macro-dropper hiding
    place) must fire, not just executables."""
    text = "0|/Users/alice/Reports/Q4.docx:hidden_payload|456|...\n"
    hits = scan_text(text)
    assert any(h.pattern_id == "NTFS_ALTERNATE_DATA_STREAM" for h in hits)


def test_zone_identifier_ads_not_flagged():
    """Mark-of-the-Web Zone.Identifier ADS is on EVERY downloaded file —
    flagging it would flood the ledger with thousands of benign hits.
    The negative-lookahead must exclude it cleanly."""
    text = ("0|/Users/Bob/Downloads/installer.exe:Zone.Identifier|123|...\n"
            "0|/Users/Bob/Downloads/setup.msi:Zone.Identifier|124|...\n")
    hits = scan_text(text)
    ads = [h for h in hits if h.pattern_id == "NTFS_ALTERNATE_DATA_STREAM"]
    assert ads == [], "Zone.Identifier must be excluded from ADS detection"


def test_non_executable_ads_not_flagged():
    """ADS on text/log/data files isn't in the high-risk extension list —
    the pattern only fires on executable / script / Office-doc shapes
    so we don't drown in noise from system-managed ADSes on data files."""
    text = "0|/var/log/normal.log:metadata|123|...\n"
    hits = scan_text(text)
    ads = [h for h in hits if h.pattern_id == "NTFS_ALTERNATE_DATA_STREAM"]
    assert ads == []


def test_multiple_ads_grouped_into_one_hit():
    """When several files have suspicious ADSes, the scanner emits one
    PathHit per pattern with all matches grouped — caller decides how
    to render (existing convention; no per-match finding)."""
    text = ("0|/A/payload.exe:s1|1|...\n"
            "0|/B/script.ps1:s2|2|...\n"
            "0|/C/loader.dll:s3|3|...\n")
    hits = scan_text(text)
    ads = [h for h in hits if h.pattern_id == "NTFS_ALTERNATE_DATA_STREAM"]
    assert len(ads) == 1
    assert len(ads[0].matches) >= 3


def test_h_ntfs_ads_lifts_hypothesis_in_ach():
    """The H_NTFS_ADS_PRESENT tag scores +2 — but as a contextual
    anti-forensic MODIFIER (concealment technique, not a competing
    motive), so it's read from the modifier breakdown and is absent
    from the ranked leader list."""
    from el.intel.ach import anti_forensic_context, score_findings
    from el.schemas.finding import EvidenceItem, Finding
    ev = EvidenceItem(tool="el.disk_anomaly", version="0", command="x",
                      output_sha256="0"*64, output_path="/x")
    f = Finding(case_id="c", agent="disk_forensicator", confidence="high",
                claim="Disk anomaly [NTFS_ALTERNATE_DATA_STREAM]: 3 match(es)",
                evidence=[ev],
                hypotheses_supported=["H_NTFS_ADS_PRESENT",
                                       "H_DEFENSE_EVASION"])
    ctx = anti_forensic_context([f])
    assert ctx is not None
    ads = next(i for i in ctx["indicators"]
               if i["hyp_id"] == "H_NTFS_ADS_PRESENT")
    assert ads["score"] == 2
    # …and NOT in the competing ranked list
    ranked, _ = score_findings([f])
    assert all(r.hyp_id != "H_NTFS_ADS_PRESENT" for r in ranked)

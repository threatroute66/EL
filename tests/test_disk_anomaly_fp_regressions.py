"""Regression tests for disk_anomaly false positives caught by the
M57-Jean blind run.

Four FP classes on a clean Windows XP image:

 1. LSASS_OUTSIDE_SYSTEM32 / SVCHOST_OUTSIDE_SYSTEM32 firing on
    $NtServicePackUninstall$ (SP rollback backup), ServicePackFiles/i386,
    dllcache (Windows File Protection), winsxs, $hf_mig$, and on
    Prefetch/LSASS.EXE-<hash>.pf filenames — the \\b boundary in the
    regex ended the match at `.exe` even inside a `.pf` filename.
 2. EXE_IN_TEMP firing on MSI installer unpack dirs (Temp/00006b1c/…)
    and on VMware Tools installer layouts (Temp/<hex>/program files/…).

Fix:
  - Replaced \\b anchor with end-of-path lookahead (?=[|\\s]|$)
  - Direct-parent + ancestor-fragment filters in _post_filter for
    LSASS/SVCHOST
  - Installer-temp-shape regex filter for EXE_IN_TEMP
"""
from el.skills.disk_anomaly import scan_text


# ---------------------------------------------------------------------------
# LSASS / SVCHOST — legitimate Windows backup / cache locations
# ---------------------------------------------------------------------------

def test_nt_service_pack_uninstall_lsass_not_flagged():
    text = "0|/WINDOWS/$NtServicePackUninstall$/lsass.exe|13023-128-3|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "LSASS_OUTSIDE_SYSTEM32" for h in hits)


def test_service_pack_files_i386_lsass_not_flagged():
    text = "0|/WINDOWS/ServicePackFiles/i386/lsass.exe|20704-128-3|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "LSASS_OUTSIDE_SYSTEM32" for h in hits)


def test_service_pack_files_i386_svchost_not_flagged():
    text = "0|/WINDOWS/ServicePackFiles/i386/svchost.exe|21016-128-3|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "SVCHOST_OUTSIDE_SYSTEM32" for h in hits)


def test_dllcache_lsass_not_flagged():
    text = "0|/WINDOWS/system32/dllcache/lsass.exe (deleted-realloc)|8767-128-1|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "LSASS_OUTSIDE_SYSTEM32" for h in hits)


def test_winsxs_svchost_not_flagged():
    text = "0|/Windows/winsxs/x86_microsoft-windows-s..vchost_.../svchost.exe|1|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "SVCHOST_OUTSIDE_SYSTEM32" for h in hits)


def test_hf_mig_svchost_not_flagged():
    text = "0|/WINDOWS/$hf_mig$/KB898461/svchost.exe|1|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "SVCHOST_OUTSIDE_SYSTEM32" for h in hits)


def test_prefetch_svchost_pf_filename_not_flagged():
    """The exact M57-Jean FP: `LSASS.EXE-3530F672.pf` in the Prefetch dir
    matched the regex because \\b lets the match end at `.exe` inside a
    `.pf` filename. Fix: anchor to end-of-path."""
    text = ("0|/WINDOWS/Prefetch/SVCHOST.EXE-3530F672.pf|17641-128-4|...|0\n"
            "0|/WINDOWS/Prefetch/LSASS.EXE-3530F673.pf|17642-128-4|...|0\n")
    hits = scan_text(text)
    pids = {h.pattern_id for h in hits}
    assert "SVCHOST_OUTSIDE_SYSTEM32" not in pids
    assert "LSASS_OUTSIDE_SYSTEM32" not in pids


def test_syswow64_svchost_not_flagged():
    text = "0|/Windows/SysWOW64/svchost.exe|1|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "SVCHOST_OUTSIDE_SYSTEM32" for h in hits)


# ---------------------------------------------------------------------------
# LSASS / SVCHOST — genuine anomalies must STILL fire
# ---------------------------------------------------------------------------

def test_masqueraded_svchost_in_temp_still_flagged():
    """Real masquerade: svchost.exe somewhere truly unusual."""
    text = "0|/Users/alice/AppData/Local/Temp/svchost.exe|1|...|0\n"
    hits = scan_text(text)
    assert any(h.pattern_id == "SVCHOST_OUTSIDE_SYSTEM32" for h in hits)


def test_masqueraded_lsass_in_programdata_still_flagged():
    text = "0|/ProgramData/attacker/lsass.exe|1|...|0\n"
    hits = scan_text(text)
    assert any(h.pattern_id == "LSASS_OUTSIDE_SYSTEM32" for h in hits)


def test_svchost_in_weird_system32_subdir_still_flagged():
    """System32/<something>/svchost.exe — direct parent isn't System32, so
    it's still a masquerade even though the ancestor tree touches System32."""
    text = "0|/Windows/System32/dllhost/svchost.exe|1|...|0\n"
    hits = scan_text(text)
    assert any(h.pattern_id == "SVCHOST_OUTSIDE_SYSTEM32" for h in hits)


# ---------------------------------------------------------------------------
# EXE_IN_TEMP — MSI / InstallShield / VMware installer unpack paths
# ---------------------------------------------------------------------------

def test_msi_installer_hex_dir_not_flagged():
    text = ("0|/Documents and Settings/Administrator/Local Settings/Temp/"
            "00006b1c/msi/InstMsi.exe|1|...|0\n")
    hits = scan_text(text)
    assert not any(h.pattern_id == "EXE_IN_TEMP" for h in hits)


def test_vmware_installer_nested_path_not_flagged():
    text = ("0|/Documents and Settings/Administrator/Local Settings/Temp/"
            "00006b1c/program files/VMware/VMware Tools/9x Files/"
            "VMwareService.exe|1|...|0\n")
    hits = scan_text(text)
    assert not any(h.pattern_id == "EXE_IN_TEMP" for h in hits)


def test_installshield_is_dir_not_flagged():
    text = "0|/Users/foo/AppData/Local/Temp/_ISE12A3/setup.exe|1|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "EXE_IN_TEMP" for h in hits)


def test_guid_installer_dir_not_flagged():
    text = "0|/Users/foo/AppData/Local/Temp/{a1b2c3d4-e5f6-7890-1234-56789abcdef0}/payload.exe|1|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "EXE_IN_TEMP" for h in hits)


# ---------------------------------------------------------------------------
# EXE_IN_TEMP — real droppers still fire
# ---------------------------------------------------------------------------

def test_exe_directly_in_temp_still_flagged():
    text = "0|/Users/foo/AppData/Local/Temp/dropper.exe|1|...|0\n"
    hits = scan_text(text)
    assert any(h.pattern_id == "EXE_IN_TEMP" for h in hits)


# ---------------------------------------------------------------------------
# SCHEDULED_TASK_NONMS — stock Windows files in Tasks/
# ---------------------------------------------------------------------------

def test_scheduled_task_desktop_ini_not_flagged():
    """Every Windows install has Windows/Tasks/desktop.ini."""
    text = "0|/WINDOWS/Tasks/desktop.ini|5808-128-1|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "SCHEDULED_TASK_NONMS" for h in hits)


def test_scheduled_task_sa_dat_not_flagged():
    """SA.DAT is the task scheduler service's own state file."""
    text = "0|/WINDOWS/Tasks/SA.DAT|10202-48-2|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "SCHEDULED_TASK_NONMS" for h in hits)


def test_scheduled_task_at_job_still_flagged():
    """Actual at-job files are still a persistence signal."""
    text = "0|/WINDOWS/Tasks/At1.job|12345|...|0\n"
    hits = scan_text(text)
    assert any(h.pattern_id == "SCHEDULED_TASK_NONMS" for h in hits)


# ---------------------------------------------------------------------------
# VSSADMIN — mere existence of binary was firing on every Windows host
# ---------------------------------------------------------------------------

def test_vssadmin_binary_existence_alone_not_flagged():
    """The binary ships with every Windows — its presence on disk is
    not an anomaly."""
    text = "0|/WINDOWS/system32/vssadmin.exe|1552-48-4|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "VSSADMIN_DELETE_SHADOWS_TRACE" for h in hits)


def test_vssadmin_in_dllcache_not_flagged():
    text = "0|/WINDOWS/system32/dllcache/vssadmin.exe|9711-48-4|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "VSSADMIN_DELETE_SHADOWS_TRACE" for h in hits)


def test_wbadmin_binary_existence_alone_not_flagged():
    text = "0|/WINDOWS/system32/wbadmin.exe|1|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "VSSADMIN_DELETE_SHADOWS_TRACE" for h in hits)


def test_vssadmin_delete_shadows_command_still_flagged():
    """Command-shaped trace is the real signal."""
    text = ('cmdline: vssadmin delete shadows /all /quiet\n'
            '2023-09-12: vssadmin.exe delete shadows /quiet\n')
    hits = scan_text(text)
    assert any(h.pattern_id == "VSSADMIN_DELETE_SHADOWS_TRACE" for h in hits)


def test_wbadmin_delete_catalog_still_flagged():
    text = 'process: wbadmin.exe delete catalog -quiet\n'
    hits = scan_text(text)
    assert any(h.pattern_id == "VSSADMIN_DELETE_SHADOWS_TRACE" for h in hits)


def test_inline_shadowcopy_delete_still_flagged():
    """The shadowcopy+delete shape matches when both terms appear close."""
    text = 'cmd: ShadowCopy and delete within 20 chars'
    hits = scan_text(text)
    assert any(h.pattern_id == "VSSADMIN_DELETE_SHADOWS_TRACE" for h in hits)


# ---------------------------------------------------------------------------
# Rocba case carve-outs (added after RE of the Rocba memory + disk evidence)
# ---------------------------------------------------------------------------


def test_pyinstaller_google_drive_not_flagged():
    """Rocba: PYINSTALLER_TEMP_DIR fired on Google Drive Backup&Sync's
    normal runtime unpack. A `_MEI<digits>/` dir that also contains
    `drive.v2internal.rest.json` is the Drive client, not a dropper."""
    text = (
        "0|/Users/fredr/AppData/Local/Temp/_MEI118162/bz2.pyd|1|...|0\n"
        "0|/Users/fredr/AppData/Local/Temp/_MEI118162/cello.pyd|1|...|0\n"
        "0|/Users/fredr/AppData/Local/Temp/_MEI118162/drive.v2internal.rest.json|1|...|0\n"
        "0|/Users/fredr/AppData/Local/Temp/_MEI118162/main.exe.manifest|1|...|0\n"
    )
    hits = scan_text(text)
    assert not any(h.pattern_id == "PYINSTALLER_TEMP_DIR" for h in hits), (
        "Google Drive's _MEI dir should be excluded by the marker-file "
        "allowlist"
    )


def test_pyinstaller_google_drive_marker_in_subdir_not_flagged():
    """Regression: real Rocba bodyfile puts the marker at
    `_MEI<digits>/resources/drive_api/drive.v2internal.rest.json` —
    several subdirs deep. The pre-scan must classify the parent
    `_MEI<digits>` as benign even when markers aren't direct children."""
    text = (
        "0|/Users/fredr/AppData/Local/Temp/_MEI118162/bz2.pyd|1|...|0\n"
        "0|/Users/fredr/AppData/Local/Temp/_MEI118162/resources/"
        "drive_api/drive.v2internal.rest.json|2|...|0\n"
    )
    hits = scan_text(text)
    assert not any(h.pattern_id == "PYINSTALLER_TEMP_DIR" for h in hits)


def test_pyinstaller_anaconda_not_flagged():
    """anaconda-navigator inside _MEI marks it as Anaconda; not a dropper."""
    text = (
        "0|/Users/x/AppData/Local/Temp/_MEI98765/anaconda-navigator.pyc|1|...|0\n"
        "0|/Users/x/AppData/Local/Temp/_MEI98765/Lib/site.pyc|1|...|0\n"
    )
    hits = scan_text(text)
    assert not any(h.pattern_id == "PYINSTALLER_TEMP_DIR" for h in hits)


def test_pyinstaller_unknown_bundle_still_flagged():
    """A _MEI dir with NO legitimate-marker files is still suspect."""
    text = (
        "0|/Users/victim/AppData/Local/Temp/_MEI66666/python27.dll|1|...|0\n"
        "0|/Users/victim/AppData/Local/Temp/_MEI66666/payload.pyc|1|...|0\n"
    )
    hits = scan_text(text)
    assert any(h.pattern_id == "PYINSTALLER_TEMP_DIR" for h in hits)


def test_winsxs_hashed_component_dir_svchost_not_flagged():
    """Rocba: SVCHOST_OUTSIDE_SYSTEM32 fired on Win10+ WinSxS hashed
    component-cache dirs whose snippet didn't include the literal
    `winsxs` string. The hashed dir shape is enough to exclude."""
    text = (
        "0|/Windows/WinSxS/amd64_microsoft-windows-s..svchost-minimal_"
        "31bf3856ad364e35_10.0.19041.546_none_9e094af3987dca57/svchost.exe|1|...|0\n"
        # Snippet-clipping case: just the hash dir, no `winsxs` substring
        "0|.19041.546_none_9e094af3987dca57/f/svchost.exe|1|...|0\n"
    )
    hits = scan_text(text)
    assert not any(h.pattern_id == "SVCHOST_OUTSIDE_SYSTEM32" for h in hits)


def test_winsxs_hashed_component_dir_lsass_not_flagged():
    text = "0|.19041.546_none_1b64e89df11db196/r/lsass.exe|1|...|0\n"
    hits = scan_text(text)
    assert not any(h.pattern_id == "LSASS_OUTSIDE_SYSTEM32" for h in hits)


def test_shadercache_timestomp_skew_not_flagged():
    """Rocba: MACB_TIMESTOMP_SKEW fired on Intel GPU shader cache where
    B-time is set at first compile and M-time updates on every reuse —
    the skew is a documented driver behaviour, not timestomping."""
    # B-time 2020-11-10 (1604966400), M-time 2020-12-01 (1606780800)
    # = 21 day skew, far above the 7-day floor
    text = (
        "0|/ProgramData/Intel/ShaderCache/dwm_1|1-128-1|r/r|0|0|1024"
        "|1606780800|1606780800|1606780800|1604966400\n"
        "0|/ProgramData/Intel/ShaderCache/EXCEL_1|2-128-1|r/r|0|0|1024"
        "|1606780800|1606780800|1606780800|1604966400\n"
        "0|/ProgramData/Intel/ShaderCache/GoogleDriveFS_0|3-128-1|r/r|0|0|1024"
        "|1606780800|1606780800|1606780800|1604966400\n"
    )
    hits = scan_text(text)
    assert not any(h.pattern_id == "MACB_TIMESTOMP_SKEW" for h in hits), (
        "ShaderCache entries should be excluded — GPU drivers legitimately"
        " produce large B→M skew"
    )


def test_pnf_driver_setup_timestomp_skew_not_flagged():
    """Driver setup .pnf files inside Windows/INF/ are precompiled INF
    blobs whose B/M skew is normal Windows behaviour."""
    text = (
        "0|/Windows/INF/usbstor.pnf|1-128-1|r/r|0|0|2048"
        "|1606780800|1606780800|1606780800|1604966400\n"
    )
    hits = scan_text(text)
    assert not any(h.pattern_id == "MACB_TIMESTOMP_SKEW" for h in hits)


def test_office_clicktorun_timestomp_skew_not_flagged():
    """Rocba round-2: MACB_TIMESTOMP_SKEW fired on Office Click-to-Run
    config + per-package catalog files under ProgramData/Microsoft/
    ClickToRun/. C2R rewrites these in place on every channel update,
    legitimately producing 18+ day skew."""
    text = (
        "0|/ProgramData/Microsoft/ClickToRun/DeploymentConfig.2.xml"
        "|51671-128-4|r/r|0|0|1382|1605363458|1605363458|1605363458"
        "|1603767977\n"
        "0|/ProgramData/Microsoft/ClickToRun/MachineData/Catalog/"
        "Packages/{9AC08E99-230B-47E8-9721-4577B7F124EA}/Manifest.xml"
        "|99-128-1|r/r|0|0|2048|1605363458|1605363458|1605363458"
        "|1603767977\n"
    )
    hits = scan_text(text)
    assert not any(h.pattern_id == "MACB_TIMESTOMP_SKEW" for h in hits)


def test_software_distribution_timestomp_skew_not_flagged():
    """Windows Update download cache rewrites file timestamps on every
    update cycle; legitimately produces skew."""
    text = (
        "0|/Windows/SoftwareDistribution/Download/Install/AM_Delta.exe"
        "|1-128-1|r/r|0|0|2048|1606780800|1606780800|1606780800"
        "|1604966400\n"
    )
    hits = scan_text(text)
    assert not any(h.pattern_id == "MACB_TIMESTOMP_SKEW" for h in hits)


def test_uwp_package_state_timestomp_skew_not_flagged():
    """UWP / Modern app package state under AppData/Local/Packages/
    legitimately produces large skew (package state updates in place)."""
    text = (
        "0|/Users/fredr/AppData/Local/Packages/Microsoft.WindowsStore_"
        "8wekyb3d8bbwe/LocalCache/local-0.dat|1-128-1|r/r|0|0|4096"
        "|1606780800|1606780800|1606780800|1604966400\n"
    )
    hits = scan_text(text)
    assert not any(h.pattern_id == "MACB_TIMESTOMP_SKEW" for h in hits)


def test_user_temp_timestomp_skew_still_flagged():
    """The skew detector must STILL fire on user-Temp files with the
    same skew — that's the real timestomp pattern."""
    text = (
        "0|/Users/fredr/AppData/Local/Temp/dropped.exe|1-128-1|r/r|0|0|2048"
        "|1606780800|1606780800|1606780800|1604966400\n"
    )
    hits = scan_text(text)
    assert any(h.pattern_id == "MACB_TIMESTOMP_SKEW" for h in hits)


def test_windows_old_zero_size_dll_not_flagged():
    """Rocba: SYSTEM_BINARY_ZERO_SIZE fired on `Windows.old/System32/*.dll`
    placeholders left by a Win10 feature-update cleanup pass. Normal."""
    text = (
        "0|/Windows.old/WINDOWS/System32/LAPRXY.DLL (deleted)|1-128-1|r/r|0|0|0"
        "|1604000000|1604000000|1604000000|1604000000\n"
        "0|/Windows.old/WINDOWS/System32/vcamp140.dll|2-128-1|r/r|0|0|0"
        "|1604000000|1604000000|1604000000|1604000000\n"
    )
    hits = scan_text(text)
    pids = {h.pattern_id for h in hits}
    assert "SYSTEM_BINARY_ZERO_SIZE" not in pids
    assert "SYSTEM_BINARY_ZERO_TIMESTAMPS" not in pids


def test_live_system_zero_size_dll_still_flagged():
    """The wipe detector must STILL fire on a zero-byte system DLL in
    the LIVE System32 (jynxora M57-Jean signature)."""
    text = (
        "0|/WINDOWS/system32/debug.exe|1-128-1|r/r|0|0|0"
        "|1604000000|1604000000|1604000000|1604000000\n"
    )
    hits = scan_text(text)
    assert any(h.pattern_id == "SYSTEM_BINARY_ZERO_SIZE" for h in hits)

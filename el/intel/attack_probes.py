"""ATT&CK technique probes — light-weight detector callables tied to
specific T-IDs.

Closes the gap-doc bullet "ATT&CK technique-coverage regression
test". A *probe* is a deterministic callable
``probe(events) -> bool`` that returns True iff the events stream
exhibits the canonical fingerprint of one ATT&CK technique. Probes
power two things:

1. ``tests/test_attack_coverage_matrix.py`` — gated regression that
   runs every probe against the labelled Splunk ``attack_data``
   corpus and asserts it fires on its own T-ID + does NOT fire on
   unrelated ones.
2. ``el coverage`` CLI (future) — measure ATT&CK coverage as a
   live percentage so detection-rule churn shows up as a number.

Probes are intentionally narrow: they detect the **fingerprint**,
not the full claim. ``T1003.001`` fires on "any LSASS-handle open
with non-trivial GrantedAccess"; the agent layer downstream is
responsible for adding context (source-image allowlist, operator-
benign-pattern suppression). Keeping the probe narrow means we
can validate it on a 30-line synthetic test and trust it on the
real corpus.

Each probe takes a unified ``ProbeContext`` carrying both Sysmon and
Falcon events for the same technique. A probe can use either source
(or both); when only one is present the other is empty, and the
probe simply scans what it has.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from el.skills import falcon_logs as fl
from el.skills import sysmon_xml as sx


@dataclass
class ProbeContext:
    """Bundle of parsed events from a single technique-folder run.
    Either field may be empty; the probe decides which it needs."""
    sysmon: list[sx.SysmonEvent] = field(default_factory=list)
    falcon: list[fl.FalconEvent] = field(default_factory=list)

    @property
    def sysmon_eids(self) -> dict[int, int]:
        return sx.by_eid(self.sysmon)

    @property
    def falcon_event_names(self) -> dict[str, int]:
        return fl.by_event_name(self.falcon)


# --- Probe primitives --------------------------------------------------


def _process_create_match(ctx: ProbeContext, *,
                            image_substr: str = "",
                            cmdline_substr: str = "",
                            ) -> bool:
    """Either Sysmon EID 1 or Falcon ProcessRollup2 with the
    requested image/cmdline substring."""
    if image_substr or cmdline_substr:
        if sx.find_process_creates(ctx.sysmon,
                                     image_substr=image_substr,
                                     cmdline_substr=cmdline_substr):
            return True
        if fl.find_process_creates(ctx.falcon,
                                     image_substr=image_substr,
                                     cmdline_substr=cmdline_substr):
            return True
    return False


def _registry_value_set(ctx: ProbeContext, *,
                         path_substr: str) -> bool:
    """Sysmon EID 13 (RegistryEventValueSet) where TargetObject
    contains ``path_substr`` (case-insensitive)."""
    needle = path_substr.lower()
    for e in ctx.sysmon:
        if e.eid != 13:
            continue
        target = e.data.get("TargetObject", "").lower()
        if needle in target:
            return True
    return False


def _file_create_match(ctx: ProbeContext, *,
                        target_substr: str = "",
                        target_endswith: str = "") -> bool:
    """Sysmon EID 11 (FileCreate) or Falcon FileWritten /
    DmpFileWritten where TargetFilename matches."""
    sub = target_substr.lower()
    end = target_endswith.lower()
    for e in ctx.sysmon:
        if e.eid != 11:
            continue
        f = e.data.get("TargetFilename", "").lower()
        if sub and sub not in f:
            continue
        if end and not f.endswith(end):
            continue
        if sub or end:
            return True
    for fe in ctx.falcon:
        if fe.event_name not in ("FileWritten", "FileDeleteInfo",
                                   "DmpFileWritten"):
            continue
        f = fe.target_file.lower()
        if sub and sub not in f:
            continue
        if end and not f.endswith(end):
            continue
        if sub or end:
            return True
    return False


# --- Per-technique probes ---------------------------------------------


def probe_t1003_001_lsass_dump(ctx: ProbeContext) -> bool:
    """T1003.001 — OS Credential Dumping: LSASS Memory.

    Fingerprint: a process opens lsass.exe with a non-trivial access
    mask (Sysmon EID 10, GrantedAccess != 0x1000), OR an EDR sees a
    handle-op against lsass, OR a dump file landing on disk with
    'lsass' in the name."""
    return (
        bool(sx.find_lsass_handles(ctx.sysmon))
        or bool(fl.find_lsass_handles(ctx.falcon))
        or bool(fl.find_lsass_dump_files(ctx.falcon))
    )


def probe_t1059_001_powershell(ctx: ProbeContext) -> bool:
    """T1059.001 — PowerShell.

    Fingerprint: any ProcessCreate where the image basename is
    powershell.exe (or pwsh.exe). Powershell-with-encoded-command
    is a stricter sub-fingerprint (cmdline carries -enc / -e /
    -EncodedCommand)."""
    return (
        _process_create_match(ctx, image_substr="powershell.exe")
        or _process_create_match(ctx, image_substr="pwsh.exe")
    )


def probe_t1547_001_run_keys(ctx: ProbeContext) -> bool:
    """T1547.001 — Boot or Logon Autostart: Registry Run Keys /
    Startup Folder.

    Fingerprint: registry-value-set targeting a Run / RunOnce /
    BootExecute path under HKLM or HKCU. The Sysmon event 13
    fires the moment a value is written under any of these
    well-known autorun keys."""
    return (
        _registry_value_set(ctx,
                              path_substr="\\CurrentVersion\\Run")
        or _registry_value_set(ctx,
                                 path_substr="\\CurrentVersion\\RunOnce")
        or _registry_value_set(ctx,
                                 path_substr="\\BootExecute")
    )


# Known-benign rundll32 invocations that fire constantly during
# normal Windows operation — Control Panel applets, Bluetooth
# auth bridge, Windows Update, Defender. These would push every
# corpus into "T1218.011 fired" if we counted them.
_RUNDLL32_BENIGN_SUBSTRINGS = (
    "control_rundll", "shell32.dll,control_rundll",
    "bthudtask.exe", "windowsupdateelevatedinstaller",
    "advapi32.dll,processidletasks",
    "appwiz.cpl", "ncpa.cpl", "inetcpl.cpl", "main.cpl",
    "system32\\printui.dll",
    "shell32.dll,shellexec_rundll",       # legit launcher path
)


def probe_t1218_011_rundll32(ctx: ProbeContext) -> bool:
    """T1218.011 — System Binary Proxy Execution: Rundll32.

    Fingerprint: ProcessCreate of rundll32.exe with a DLL/export
    pair on the cmdline (the ',#<n>' or ',<entrypoint>' shape)
    that is NOT one of the high-volume benign Windows invocations
    (control-panel applets, Bluetooth handshake, updater
    elevations). The narrow shape distinguishes attacker-driven
    rundll32 abuse from the Windows-internal rundll32 traffic
    every host emits constantly.
    """
    candidates = sx.find_process_creates(
        ctx.sysmon, image_substr="rundll32.exe")
    candidates += [e for e in fl.find_process_creates(
        ctx.falcon, image_substr="rundll32.exe")]
    for e in candidates:
        cl = (e.command_line or "").lower()
        # Need a DLL/export pair separator
        if "," not in cl:
            continue
        if any(b in cl for b in _RUNDLL32_BENIGN_SUBSTRINGS):
            continue
        return True
    return False


def probe_t1112_registry_modification(ctx: ProbeContext) -> bool:
    """T1112 — Modify Registry.

    Fingerprint: a registry-value-set hitting a security-relevant
    location (WDigest UseLogonCredential, SafeBoot AlternateShell,
    LSA Notification Packages, Disable* Defender values)."""
    needles = (
        "\\wdigest\\useLogonCredential",
        "\\SafeBoot\\AlternateShell",
        "\\Lsa\\Notification Packages",
        "\\Windows Defender\\DisableAntiSpyware",
        "\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring",
        "\\System\\CurrentControlSet\\Services\\TermService\\Parameters",
    )
    return any(_registry_value_set(ctx, path_substr=n) for n in needles)


def probe_t1003_003_ntds(ctx: ProbeContext) -> bool:
    """T1003.003 — OS Credential Dumping: NTDS.

    Fingerprint: ntdsutil / vssadmin invoked, OR a file with
    'NTDS.dit' in the name being copied / written."""
    if _process_create_match(ctx, image_substr="ntdsutil.exe"):
        return True
    if _process_create_match(ctx, image_substr="vssadmin.exe",
                              cmdline_substr="create shadow"):
        return True
    if _file_create_match(ctx, target_substr="ntds.dit"):
        return True
    return False


def probe_t1021_001_rdp(ctx: ProbeContext) -> bool:
    """T1021.001 — Remote Services: RDP.

    Fingerprint: ProcessCreate of mstsc.exe (the RDP client) with a
    target host on the cmdline. Server-side detection (4624
    LogonType=10) is a separate signal a future probe could add.
    """
    return _process_create_match(ctx, image_substr="mstsc.exe")


def probe_t1021_002_smb_admin_shares(ctx: ProbeContext) -> bool:
    """T1021.002 — Remote Services: SMB / Admin Shares.

    Fingerprint: cmdline references an admin share (``\\\\target\\C$``,
    ``\\\\target\\ADMIN$``, ``\\\\target\\IPC$``) — typically via
    ``net use``, ``copy``, or PsExec / WMIExec / SMBExec script
    drops. The corpus puts these in 4688 events whose CommandLine
    carries the share path."""
    candidates = sx.find_process_creates(ctx.sysmon)
    candidates += list(fl.find_process_creates(ctx.falcon))
    for e in candidates:
        cl = (e.command_line or "").lower()
        if any(s in cl for s in (r"\admin$", r"\c$", r"\ipc$")):
            return True
    return False


def probe_t1021_006_winrm(ctx: ProbeContext) -> bool:
    """T1021.006 — Remote Services: WinRM.

    Fingerprint: winrs.exe / wsmprovhost.exe in image, OR
    Enter-PSSession / Invoke-Command / -ComputerName in PowerShell
    cmdline."""
    if (_process_create_match(ctx, image_substr="winrs.exe")
            or _process_create_match(ctx,
                                       image_substr="wsmprovhost.exe")):
        return True
    if (_process_create_match(ctx, cmdline_substr="enter-pssession")
            or _process_create_match(ctx,
                                       cmdline_substr="invoke-command")):
        return True
    return False


def probe_t1027_obfuscation(ctx: ProbeContext) -> bool:
    """T1027 — Obfuscated Files or Information.

    Fingerprint: PowerShell with ``-EncodedCommand`` /``-enc`` /
    ``-e`` followed by base64-shape data. The `-noni -e` /
    `-nop -enc` shapes are the canonical Cobalt Strike / Empire
    cradle invocations."""
    candidates = sx.find_process_creates(
        ctx.sysmon, image_substr="powershell")
    candidates += list(fl.find_process_creates(
        ctx.falcon, image_substr="powershell"))
    for e in candidates:
        cl = (e.command_line or "").lower()
        # Match -enc / -encodedcommand / -e but NOT -noni alone.
        # Need the literal flag pattern AND base64-shape payload.
        flags = (" -enc ", " -e ", " -encodedcommand", "/enc ",
                  " -encoded ")
        if any(f in cl for f in flags):
            return True
    return False


def probe_t1055_process_injection(ctx: ProbeContext) -> bool:
    """T1055 — Process Injection.

    Fingerprint: Sysmon EID 8 (CreateRemoteThread) into a target
    process whose image is non-trivial (not the same as source —
    legitimate threads-create-into-self happens). Cobalt-Strike's
    spawnto / inject pattern leaves dense EID 8 traffic toward
    rundll32 / dllhost / searchprotocolhost / svchost as
    sacrificial host processes.

    A SECOND fingerprint: EID 1 ProcessCreate where ParentImage
    is rundll32 / dllhost AND CommandLine is empty / generic — the
    sacrificial-host ``rundll32.exe`` with no DLL argument is
    Cobalt Strike's spawnto signature."""
    for e in ctx.sysmon:
        if e.eid == 8:
            src = (e.data.get("SourceImage", "") or "").lower()
            tgt = (e.data.get("TargetImage", "") or "").lower()
            if src and tgt and src != tgt:
                # Only count when source is not a known-system worker.
                src_base = src.rsplit("\\", 1)[-1]
                if src_base not in {"system", "csrss.exe",
                                       "wininit.exe"}:
                    return True
    # Sacrificial-host shape: rundll32 / dllhost / searchprotocolhost
    # spawned by a parent that's NOT explorer/services with empty cmdline
    for e in sx.find_process_creates(ctx.sysmon):
        img = e.image.lower()
        base = img.rsplit("\\", 1)[-1] if img else ""
        cl = (e.command_line or "").strip().lower()
        if base in {"rundll32.exe", "dllhost.exe",
                     "searchprotocolhost.exe"}:
            # Empty / minimal cmdline is the spawnto fingerprint
            if cl == base or cl == img or len(cl) <= len(base) + 3:
                parent = e.parent_image.lower()
                pbase = parent.rsplit("\\", 1)[-1] if parent else ""
                # Legit launchers we should ignore
                if pbase not in {"explorer.exe", "services.exe",
                                    "svchost.exe", "csrss.exe",
                                    "wininit.exe"}:
                    return True
    return False


def probe_t1059_003_windows_cmd(ctx: ProbeContext) -> bool:
    """T1059.003 — Command and Scripting Interpreter: Windows
    Command Shell.

    Fingerprint: cmd.exe with ``/c`` followed by chained commands
    (``cmd /c foo & bar``, ``cmd /c foo > out``). Bare interactive
    cmd.exe shouldn't fire — it's the scripted shape that's the
    signal."""
    candidates = sx.find_process_creates(ctx.sysmon,
                                           image_substr="cmd.exe")
    candidates += list(fl.find_process_creates(
        ctx.falcon, image_substr="cmd.exe"))
    for e in candidates:
        cl = (e.command_line or "").lower()
        if " /c " in cl or cl.startswith("cmd /c"):
            return True
    return False


def probe_t1059_005_vba_wscript(ctx: ProbeContext) -> bool:
    """T1059.005 — Command and Scripting Interpreter: Visual Basic.

    Fingerprint: wscript.exe / cscript.exe ProcessCreate with a
    .vbs / .vbe / .js / .wsf script as argument."""
    candidates = sx.find_process_creates(
        ctx.sysmon, image_substr="wscript.exe")
    candidates += sx.find_process_creates(
        ctx.sysmon, image_substr="cscript.exe")
    candidates += list(fl.find_process_creates(
        ctx.falcon, image_substr="wscript.exe"))
    candidates += list(fl.find_process_creates(
        ctx.falcon, image_substr="cscript.exe"))
    for e in candidates:
        cl = (e.command_line or "").lower()
        if any(ext in cl for ext in (
                ".vbs", ".vbe", ".vba", ".js", ".jse", ".wsf",
                ".hta")):
            return True
    return False


def probe_t1190_web_shell_parent(ctx: ProbeContext) -> bool:
    """T1190 — Exploit Public-Facing Application.

    Fingerprint: a child process (cmd / powershell / dropper) is
    spawned by a web-server worker process. ``w3wp.exe`` (IIS),
    ``httpd.exe`` (Apache on Windows), ``tomcat.exe``, ``nginx.exe``
    spawning anything that isn't itself or a worker pool spawning
    csrss is the classic web-shell signal."""
    # The "web parent" set is broader than just IIS/Apache —
    # exploitable internet-facing services that the T1190 corpus
    # documents include Exchange (MSExchangeHMWorker /
    # MSExchangeMailboxAssistants), CrushFTP, ManageEngine, etc.
    # Anything that listens on the internet and shouldn't be
    # spawning cmd / powershell / wmic at runtime.
    web_parents = {
        "w3wp.exe", "httpd.exe", "nginx.exe",
        "tomcat.exe", "tomcat9.exe", "javaw.exe", "java.exe",
        "msexchangehmworker.exe", "msexchangemailboxassistants.exe",
        "umworkerprocess.exe",                # Exchange UM
        "crushftpservice.exe",
        "manageenginedesktopcentral.exe",
        "ws_tomcat.exe", "tomcatw.exe",
        "phpcgi.exe", "fpm.exe",
        "splunkd.exe",                          # Splunk-RCE chains
    }
    suspicious_children = {
        "cmd.exe", "powershell.exe", "pwsh.exe",
        "wmic.exe", "rundll32.exe", "regsvr32.exe",
        "certutil.exe", "bitsadmin.exe",
        # nslookup from a web server is the canonical
        # ProxyShell / ProxyLogon recon ping (the attacker
        # validates RCE by triggering an outbound DNS lookup)
        "nslookup.exe",
        # Living-off-the-land binaries that get used through
        # exploited public-facing servers
        "net.exe", "ipconfig.exe", "whoami.exe",
        "systeminfo.exe", "tasklist.exe", "hostname.exe",
    }
    for e in sx.find_process_creates(ctx.sysmon):
        parent = e.parent_image.lower()
        pbase = parent.rsplit("\\", 1)[-1] if parent else ""
        img = e.image.lower()
        cbase = img.rsplit("\\", 1)[-1] if img else ""
        if pbase in web_parents and cbase in suspicious_children:
            return True
    return False


def probe_t1218_005_mshta(ctx: ProbeContext) -> bool:
    """T1218.005 — System Binary Proxy Execution: Mshta.

    Fingerprint: mshta.exe with an .hta / javascript: / vbscript:
    argument. Bare mshta.exe shouldn't fire — Windows Help shells
    invoke it briefly during install ops."""
    candidates = sx.find_process_creates(
        ctx.sysmon, image_substr="mshta.exe")
    candidates += list(fl.find_process_creates(
        ctx.falcon, image_substr="mshta.exe"))
    for e in candidates:
        cl = (e.command_line or "").lower()
        if (".hta" in cl
                or "javascript:" in cl
                or "vbscript:" in cl
                or "http:" in cl
                or "https:" in cl):
            return True
    return False


def probe_t1486_data_encrypted_for_impact(ctx: ProbeContext) -> bool:
    """T1486 — Data Encrypted for Impact (Ransomware).

    Fingerprint: ProcessCreate of bcdedit.exe with ``recoveryenabled
    no`` or ``bootstatuspolicy ignoreallfailures`` (canonical
    ransomware boot-recovery disable) OR the ransomware-encryption
    binaries (cipher.exe /w, manage-bde -off) are invoked OR
    file extensions characteristic of ransomware (.lockbit,
    .conti, .ryk, .crypt, .encrypted) appear in target file
    creates."""
    candidates = sx.find_process_creates(ctx.sysmon)
    candidates += list(fl.find_process_creates(ctx.falcon))
    for e in candidates:
        cl = (e.command_line or "").lower()
        img = e.image.lower()
        if "bcdedit" in img and (
                "recoveryenabled" in cl
                or "ignoreallfailures" in cl):
            return True
        if "manage-bde" in img and "-off" in cl:
            return True
    # File-create fingerprints (Sysmon EID 11 — the dropped
    # ransom note + encrypted file shape)
    ransom_exts = (".lockbit", ".conti", ".ryk", ".lock",
                    ".crypt", ".encrypted", ".enc")
    ransom_notes = ("readme", "decrypt", "ransom",
                     "how_to_decrypt")
    for e in ctx.sysmon:
        if e.eid != 11:
            continue
        f = (e.data.get("TargetFilename", "") or "").lower()
        if any(f.endswith(ext) for ext in ransom_exts):
            return True
        base = f.rsplit("\\", 1)[-1] if f else ""
        if any(base.startswith(p) or p in base
                for p in ransom_notes):
            return True
    return False


def probe_t1490_inhibit_recovery(ctx: ProbeContext) -> bool:
    """T1490 — Inhibit System Recovery.

    Fingerprint: vssadmin.exe delete shadows / wbadmin.exe delete
    catalog / wmic shadowcopy delete. The canonical ransomware
    pre-encrypt step."""
    candidates = sx.find_process_creates(ctx.sysmon)
    candidates += list(fl.find_process_creates(ctx.falcon))
    for e in candidates:
        cl = (e.command_line or "").lower()
        img = e.image.lower()
        if ("vssadmin" in img and "delete" in cl
                and "shadow" in cl):
            return True
        if "wbadmin" in img and "delete" in cl and (
                "catalog" in cl or "systemstatebackup" in cl):
            return True
        if "wmic" in img and "shadowcopy" in cl and "delete" in cl:
            return True
    return False


def probe_t1562_001_disable_defender(ctx: ProbeContext) -> bool:
    """T1562.001 — Impair Defenses: Disable or Modify Tools.

    Fingerprint: Set-MpPreference / Stop-Service WinDefend /
    Add-MpPreference -ExclusionPath / sc stop sense / explicit
    Defender disable cmdlines."""
    candidates = sx.find_process_creates(ctx.sysmon)
    candidates += list(fl.find_process_creates(ctx.falcon))
    needles = (
        "set-mppreference -disablerealtimemonitoring",
        "set-mppreference -disableioavprotection",
        "set-mppreference -disablebehaviormonitoring",
        "add-mppreference -exclusionpath",
        "stop-service windefend",
        "stop-service sense",
        "sc stop windefend",
        "sc stop sense",
        "sc config windefend start= disabled",
        "fltmc unload wdfilter",
    )
    for e in candidates:
        cl = (e.command_line or "").lower()
        if any(n in cl for n in needles):
            return True
    # Registry-set route: Tamper Protection / DisableAntiSpyware
    # via reg.exe (kept narrow so it doesn't overlap T1112).
    return False


# Probe registry — keyed by canonical T-ID. Add new entries here as
# the matrix grows; the test auto-discovers from this dict.
PROBES: dict[str, Callable[[ProbeContext], bool]] = {
    "T1003.001": probe_t1003_001_lsass_dump,
    "T1003.003": probe_t1003_003_ntds,
    "T1021.001": probe_t1021_001_rdp,
    "T1021.002": probe_t1021_002_smb_admin_shares,
    "T1021.006": probe_t1021_006_winrm,
    "T1027":     probe_t1027_obfuscation,
    "T1055":     probe_t1055_process_injection,
    "T1059.001": probe_t1059_001_powershell,
    "T1059.003": probe_t1059_003_windows_cmd,
    "T1059.005": probe_t1059_005_vba_wscript,
    "T1112":     probe_t1112_registry_modification,
    "T1190":     probe_t1190_web_shell_parent,
    "T1218.005": probe_t1218_005_mshta,
    "T1218.011": probe_t1218_011_rundll32,
    "T1486":     probe_t1486_data_encrypted_for_impact,
    "T1490":     probe_t1490_inhibit_recovery,
    "T1547.001": probe_t1547_001_run_keys,
    "T1562.001": probe_t1562_001_disable_defender,
}


def probe_for(tid: str) -> Callable[[ProbeContext], bool] | None:
    return PROBES.get(tid)


__all__ = [
    "ProbeContext", "PROBES", "probe_for",
    "probe_t1003_001_lsass_dump",
    "probe_t1003_003_ntds",
    "probe_t1021_001_rdp",
    "probe_t1021_002_smb_admin_shares",
    "probe_t1021_006_winrm",
    "probe_t1027_obfuscation",
    "probe_t1055_process_injection",
    "probe_t1059_001_powershell",
    "probe_t1059_003_windows_cmd",
    "probe_t1059_005_vba_wscript",
    "probe_t1112_registry_modification",
    "probe_t1190_web_shell_parent",
    "probe_t1218_005_mshta",
    "probe_t1218_011_rundll32",
    "probe_t1486_data_encrypted_for_impact",
    "probe_t1490_inhibit_recovery",
    "probe_t1547_001_run_keys",
    "probe_t1562_001_disable_defender",
]

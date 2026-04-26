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


# Probe registry — keyed by canonical T-ID. Add new entries here as
# the matrix grows; the test auto-discovers from this dict.
PROBES: dict[str, Callable[[ProbeContext], bool]] = {
    "T1003.001": probe_t1003_001_lsass_dump,
    "T1003.003": probe_t1003_003_ntds,
    "T1059.001": probe_t1059_001_powershell,
    "T1112":     probe_t1112_registry_modification,
    "T1218.011": probe_t1218_011_rundll32,
    "T1547.001": probe_t1547_001_run_keys,
}


def probe_for(tid: str) -> Callable[[ProbeContext], bool] | None:
    return PROBES.get(tid)


__all__ = [
    "ProbeContext", "PROBES", "probe_for",
    "probe_t1003_001_lsass_dump",
    "probe_t1003_003_ntds",
    "probe_t1059_001_powershell",
    "probe_t1112_registry_modification",
    "probe_t1218_011_rundll32",
    "probe_t1547_001_run_keys",
]

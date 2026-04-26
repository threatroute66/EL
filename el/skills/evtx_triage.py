"""Skill: EvtxECmd CSV triage.

Reads the normalized CSV that EvtxECmd emits (one row per event across
every EVTX channel in the case) and provides (a) filtering helpers to
pull events by channel/provider/EventId, and (b) Hunt-Evil lateral-
movement detector functions that return per-technique hit summaries.

The CSV schema EvtxECmd produces (all parseable via csv.DictReader):

    RecordNumber, EventRecordId, TimeCreated, EventId, Level, Provider,
    Channel, ProcessId, ThreadId, Computer, ChunkNumber, UserId,
    MapDescription, UserName, RemoteHost, PayloadData1-6, ExecutableInfo,
    HiddenRecord, SourceFile, Keywords, ExtraDataOffset, Payload

No I/O outside the given CSV path. No network. Pure functions — callers
get back dataclasses describing what was seen, so findings can be
constructed with sha256-verified provenance at the agent layer.
"""
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# --- CSV iteration --------------------------------------------------------

_REQUIRED_COLS = (
    "TimeCreated", "EventId", "Channel", "Provider",
    "Computer", "UserName", "MapDescription",
    "PayloadData1", "PayloadData2", "PayloadData3",
    "PayloadData4", "PayloadData5", "PayloadData6",
)


class EvtxTriageError(RuntimeError):
    pass


@dataclass
class EvtxEvent:
    time_created: str                 # raw ISO-ish string as EvtxECmd emits
    event_id: int
    channel: str
    provider: str
    computer: str
    user_name: str
    map_description: str
    payload: dict                     # PayloadData1..6 concatenated + parsed
    source_file: str = ""             # which .evtx the row came from

    @property
    def dt(self) -> datetime | None:
        """Parse the EvtxECmd time format. Falls back to None on error."""
        t = self.time_created.strip()
        if not t:
            return None
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
        ):
            try:
                return datetime.strptime(t.split("+", 1)[0], fmt)
            except ValueError:
                continue
        return None


def stream_events(csv_path: Path):
    """Generator — yield one EvtxEvent per row. Use this on DC-class
    EVTX CSVs (multi-GB / 5 M+ rows) instead of `iter_events`, which
    materializes the whole file. Skips rows with non-integer EventId
    or missing columns the same way `iter_events` does."""
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        raise EvtxTriageError(f"EvtxECmd CSV not found: {csv_path}")
    with csv_path.open(newline="", errors="ignore") as f:
        reader = csv.DictReader(f)
        missing = [c for c in _REQUIRED_COLS if c not in (reader.fieldnames or ())]
        if missing:
            raise EvtxTriageError(
                f"CSV missing required columns {missing}; got {reader.fieldnames}")
        for row in reader:
            try:
                eid = int(row.get("EventId", "").strip())
            except (TypeError, ValueError):
                continue
            payload = {
                f"PayloadData{i}": (row.get(f"PayloadData{i}") or "").strip()
                for i in range(1, 7)
            }
            yield EvtxEvent(
                time_created=row.get("TimeCreated", ""),
                event_id=eid,
                channel=row.get("Channel", "").strip(),
                provider=row.get("Provider", "").strip(),
                computer=row.get("Computer", "").strip(),
                user_name=row.get("UserName", "").strip(),
                map_description=row.get("MapDescription", "").strip(),
                payload=payload,
                source_file=row.get("SourceFile", "").strip(),
            )


def iter_events(csv_path: Path) -> list[EvtxEvent]:
    """Eager wrapper around `stream_events`. Avoid on DC-class CSVs —
    `run_all` uses `stream_events` directly via `_build_index_streaming`
    so the eager path is for tests + small-fixture callers only."""
    return list(stream_events(csv_path))


def _logon_type10(ev: EvtxEvent) -> bool:
    """Security 4624 only matters to detectors when LogonType=10
    (RDP). On a DC, 4624 fires ~800 K times per case (every Kerberos
    auth); only a tiny fraction are RDP. Push the filter to stream-
    time so the rest never enter memory."""
    blob = (ev.map_description.lower() + " "
            + " ".join(ev.payload.values()).lower())
    return ("logontype = 10" in blob
            or "logontype=10" in blob
            or "logontype: 10" in blob)


def _ticket_rc4(ev: EvtxEvent) -> bool:
    """Security 4769 only matters to credential_triage when the
    TicketEncryptionType is RC4-HMAC (kerberoast precondition).
    On a DC, 4769 fires ~2.2 M times per case (every TGS request);
    only a tiny fraction are RC4 in modern AES-by-default AD."""
    blob = (ev.map_description.lower() + " "
            + " ".join(ev.payload.values()).lower())
    return "rc4" in blob or "0x17" in blob


# (channel_substring, eid_set, row_predicate_or_None) — the union of
# every detector's interest. Streaming index drops events outside
# this set so the in-memory footprint is bounded by the relevant
# subset, not by the full DC event volume (which is 90%+ login
# churn 4634/4672 we never read, plus 2.2 M+ default-AES Kerberos
# tickets the kerberoast detector throws away anyway). Add a row
# here when adding a new detector.
_RELEVANT_PREDICATES = (
    # Lateral-movement detectors (this module)
    ("system", {7045}, None),                                        # service install
    ("security", {4697, 4698, 1102}, None),                          # service install (audit), sched-task, log-clear
    ("security", {4624}, _logon_type10),                             # RDP-only — drop bulk logon traffic
    ("taskscheduler", {106}, None),                                  # task-create
    ("wmi-activity", {5857, 5860, 5861}, None),                      # WMI provider load + event consumer
    ("powershell/operational", {4103, 4104}, None),                  # PS script-block + module-log
    ("winrm", {91}, None),                                           # WinRM session start
    ("remoteconnectionmanager", {1149}, None),                       # RDP inbound
    ("microsoft-windows-eventlog", {104}, None),                     # log-clear (legacy)
    # Credential-triage detectors (el/skills/credential_triage.py)
    ("security", {4625, 4768, 4771, 4776}, None),                    # password-burst, Kerberos AS-REQ, NTLM
    ("security", {4769}, _ticket_rc4),                               # RC4-only — drop bulk Kerberos TGS
)


def _is_relevant(ev: EvtxEvent) -> bool:
    """Predicate: should this event be retained by the streaming
    index? Combines (channel, eid) match with per-row payload
    filters. Anything the detector layer reads via `idx.get(...)`
    or `for (ch, e), evs in idx.items()`."""
    ch = ev.channel.lower()
    for sub, eids, pred in _RELEVANT_PREDICATES:
        if ev.event_id in eids and sub in ch:
            if pred is None or pred(ev):
                return True
    return False


def _build_index_streaming(
    csv_path: Path,
) -> dict[tuple[str, int], list[EvtxEvent]]:
    """Single-pass stream + filtered index build. Drops events outside
    the detector-relevance set (incl. payload-level filters) during
    streaming so memory stays bounded by the matched subset, not the
    full event volume.

    Pre-fix: DC images OOM at ~5 M rows × 2-5 KB each = 10-25 GB,
    even after the (channel, eid) filter because (security, 4769)
    had 2.2 M default-AES Kerberos tickets and (security, 4624) had
    800 K logon events of which 99% aren't RDP.
    Post-fix: DC index is ~10-50 K events × 2 KB = ~20-100 MB —
    sized by detector signal, not source volume."""
    idx: dict[tuple[str, int], list[EvtxEvent]] = defaultdict(list)
    for e in stream_events(csv_path):
        if _is_relevant(e):
            idx[(e.channel.lower(), e.event_id)].append(e)
    return idx


def by_channel_eid(events: list[EvtxEvent]) -> dict[tuple[str, int], list[EvtxEvent]]:
    """Index events by (channel_lc, event_id) for quick lookup."""
    idx: dict[tuple[str, int], list[EvtxEvent]] = defaultdict(list)
    for e in events:
        idx[(e.channel.lower(), e.event_id)].append(e)
    return idx


# --- Lateral-movement detectors -------------------------------------------

@dataclass
class LMHit:
    """One hit of a lateral-movement technique."""
    technique: str                    # e.g. "psexec", "sched_task_remote"
    subtechnique: str = ""
    description: str = ""
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    sample_events: list[EvtxEvent] = field(default_factory=list)
    source_ip: str = ""               # when extractable (RDP / WinRM)
    source_user: str = ""
    target_host: str = ""
    attack: list[tuple[str, str]] = field(default_factory=list)


def _summary(events: list[EvtxEvent]) -> tuple[str, str]:
    """Earliest / latest TimeCreated across `events`."""
    if not events:
        return "", ""
    stamps = [e.time_created for e in events if e.time_created]
    if not stamps:
        return "", ""
    return min(stamps), max(stamps)


def detect_psexec_destination(
    events: list[EvtxEvent],
    idx: dict[tuple[str, int], list[EvtxEvent]],
) -> list[LMHit]:
    """PsExec installs the PSEXESVC service on the destination. Look for
    System channel EID 7045 whose payload mentions PSEXESVC."""
    out: list[LMHit] = []
    # system.evtx = "System" channel; provider = Service Control Manager
    candidates = idx.get(("system", 7045), [])
    hits = [e for e in candidates
            if "psexesvc" in (
                e.map_description.lower()
                + " ".join(e.payload.values()).lower())
            or "psexec" in " ".join(e.payload.values()).lower()]
    if hits:
        first, last = _summary(hits)
        out.append(LMHit(
            technique="psexec",
            subtechnique="service_install",
            description=(f"PsExec service (PSEXESVC) installed on destination — "
                         f"system.evtx EID 7045 fired {len(hits)} time(s); "
                         f"first={first}, last={last}."),
            event_count=len(hits), first_seen=first, last_seen=last,
            sample_events=hits[:3],
            attack=[("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
                    ("T1569.002", "System Services: Service Execution")],
        ))
    return out


def detect_scheduled_task_creation(
    events: list[EvtxEvent],
    idx: dict[tuple[str, int], list[EvtxEvent]],
) -> list[LMHit]:
    """Scheduled-task creation via schtasks/at — security 4698 OR the
    TaskScheduler operational channel EID 106."""
    out: list[LMHit] = []
    s4698 = idx.get(("security", 4698), [])
    ts106: list[EvtxEvent] = []
    for (channel, eid), evs in idx.items():
        if eid == 106 and "taskscheduler" in channel:
            ts106.extend(evs)
    hits = s4698 + ts106
    if hits:
        first, last = _summary(hits)
        by_ch: Counter = Counter((e.channel.lower(), e.event_id) for e in hits)
        out.append(LMHit(
            technique="scheduled_task",
            subtechnique="task_created",
            description=(f"Scheduled-task creation observed: {len(hits)} event(s) "
                         f"across {dict(by_ch)}; first={first}, last={last}."),
            event_count=len(hits), first_seen=first, last_seen=last,
            sample_events=hits[:3],
            attack=[("T1053.005", "Scheduled Task/Job: Scheduled Task")],
        ))
    return out


def detect_service_install_remote(
    events: list[EvtxEvent],
    idx: dict[tuple[str, int], list[EvtxEvent]],
) -> list[LMHit]:
    """Non-PsExec service install on destination — system 7045 excluding
    known-benign Windows service names and PSEXESVC (covered separately)."""
    out: list[LMHit] = []
    benign_services = {"sc manager", "service control manager",
                        "windows modules installer", "microsoft policy platform",
                        "intel", "nvidia", "dell", "hp ", "vmware tools"}
    hits = []
    for e in idx.get(("system", 7045), []):
        payload = " ".join(e.payload.values()).lower()
        if "psexesvc" in payload:
            continue
        if any(b in payload for b in benign_services):
            continue
        hits.append(e)
    # Security 4697 is a stronger signal when subscription is enabled
    sec = idx.get(("security", 4697), [])
    hits = hits + sec
    if hits:
        first, last = _summary(hits)
        out.append(LMHit(
            technique="service_install",
            subtechnique="remote_service_creation",
            description=(f"Service installed on destination (non-PSEXESVC): "
                         f"{len(hits)} event(s); first={first}, last={last}. "
                         f"Inspect PayloadData for service name + ImagePath."),
            event_count=len(hits), first_seen=first, last_seen=last,
            sample_events=hits[:3],
            attack=[("T1543.003", "Create or Modify System Process: Windows Service"),
                    ("T1569.002", "System Services: Service Execution")],
        ))
    return out


def detect_wmi_persistence(
    events: list[EvtxEvent],
    idx: dict[tuple[str, int], list[EvtxEvent]],
) -> list[LMHit]:
    """WMI-Activity 5860/5861 = EventFilter/EventConsumer registration —
    classic WMI persistence + remote-exec trigger."""
    out: list[LMHit] = []
    hits: list[EvtxEvent] = []
    for (channel, eid), evs in idx.items():
        if "wmi-activity" in channel and eid in (5860, 5861):
            hits.extend(evs)
    if hits:
        first, last = _summary(hits)
        out.append(LMHit(
            technique="wmi",
            subtechnique="event_consumer_registration",
            description=(f"WMI EventFilter/EventConsumer registration: "
                         f"{len(hits)} event(s) on WMI-Activity channel "
                         f"(EID 5860/5861); classic remote-exec persistence. "
                         f"first={first}, last={last}."),
            event_count=len(hits), first_seen=first, last_seen=last,
            sample_events=hits[:3],
            attack=[("T1546.003",
                     "Event Triggered Execution: WMI Event Subscription"),
                    ("T1047", "Windows Management Instrumentation")],
        ))
    # Transient WMI activity (provider load) — 5857 is noisy; surface at
    # lower confidence ONLY when the provider matches known-abusable paths.
    noise_providers = ("wbem", "msiserver", "defrag", "wmsrv")
    suspicious_5857: list[EvtxEvent] = []
    wmi_5857: list[EvtxEvent] = []
    for (channel, eid), evs in idx.items():
        if "wmi-activity" in channel and eid == 5857:
            wmi_5857.extend(evs)
    for e in wmi_5857:
        payload = " ".join(e.payload.values()).lower()
        if any(n in payload for n in noise_providers):
            continue
        if "\\temp\\" in payload or "\\appdata\\" in payload or "\\programdata\\" in payload:
            suspicious_5857.append(e)
    if suspicious_5857:
        first, last = _summary(suspicious_5857)
        out.append(LMHit(
            technique="wmi",
            subtechnique="provider_load_from_user_writable_path",
            description=(f"WMI provider loaded from user-writable path "
                         f"(Temp/AppData/ProgramData): {len(suspicious_5857)} "
                         f"event(s). Rare — investigate PayloadData for "
                         f"ProviderPath. first={first}, last={last}."),
            event_count=len(suspicious_5857), first_seen=first, last_seen=last,
            sample_events=suspicious_5857[:3],
            attack=[("T1047", "Windows Management Instrumentation")],
        ))
    return out


def detect_powershell_remoting_inbound(
    events: list[EvtxEvent],
    idx: dict[tuple[str, int], list[EvtxEvent]],
) -> list[LMHit]:
    """Inbound PowerShell Remoting lands on WinRM%4Operational (EID 91 =
    user authenticated for WinRM) and produces PowerShell/Operational
    4103/4104 records on the destination."""
    out: list[LMHit] = []
    winrm91: list[EvtxEvent] = []
    ps4104: list[EvtxEvent] = []
    for (channel, eid), evs in idx.items():
        if eid == 91 and "winrm" in channel:
            winrm91.extend(evs)
        if eid == 4104 and "powershell/operational" in channel:
            ps4104.extend(evs)
    if not (winrm91 or ps4104):
        return out
    hits = winrm91 + ps4104
    first, last = _summary(hits)
    out.append(LMHit(
        technique="ps_remoting",
        subtechnique="inbound_pssession",
        description=(f"Inbound PowerShell Remoting: "
                     f"WinRM EID 91 ×{len(winrm91)}, "
                     f"PowerShell/Operational EID 4104 script-block ×{len(ps4104)}. "
                     f"first={first}, last={last}."),
        event_count=len(hits), first_seen=first, last_seen=last,
        sample_events=(winrm91[:2] + ps4104[:2])[:3],
        attack=[("T1021.006", "Remote Services: Windows Remote Management"),
                ("T1059.001", "Command and Scripting Interpreter: PowerShell")],
    ))
    return out


def detect_rdp_destination(
    events: list[EvtxEvent],
    idx: dict[tuple[str, int], list[EvtxEvent]],
) -> list[LMHit]:
    """Inbound RDP: security 4624 Type 10 + TerminalServices 1149 (with
    source IP in PayloadData1)."""
    out: list[LMHit] = []
    ts1149: list[EvtxEvent] = []
    for (channel, eid), evs in idx.items():
        if eid == 1149 and "remoteconnectionmanager" in channel:
            ts1149.extend(evs)
    # Security 4624 with LogonType=10 — EvtxECmd typically maps LogonType
    # into PayloadData. Look for "LogonType = 10" or "%%2311" string.
    rdp_4624 = []
    for e in idx.get(("security", 4624), []):
        blob = (e.map_description.lower() + " "
                + " ".join(e.payload.values()).lower())
        if "logontype = 10" in blob or "logontype=10" in blob or "logontype: 10" in blob:
            rdp_4624.append(e)
    if not (ts1149 or rdp_4624):
        return out
    hits = ts1149 + rdp_4624
    first, last = _summary(hits)
    # Source IP mining from 1149 PayloadData
    src_ips: Counter = Counter()
    for e in ts1149:
        for v in e.payload.values():
            # 1149 PayloadData looks like "User: ... Domain: ... Source Network Address: 1.2.3.4"
            import re
            m = re.search(r"\b(?:Source Network Address|Source IP):?\s*([0-9a-fA-F:.]+)", v)
            if m:
                src_ips[m.group(1)] += 1
    src_list = ", ".join(f"{ip} (×{n})" for ip, n in src_ips.most_common(5))
    out.append(LMHit(
        technique="rdp",
        subtechnique="inbound_session",
        description=(f"Inbound RDP activity: TerminalServices "
                     f"RemoteConnectionManager 1149 ×{len(ts1149)}, "
                     f"security 4624 Type 10 ×{len(rdp_4624)}. "
                     + (f"Source IPs: {src_list}. " if src_list else "")
                     + f"first={first}, last={last}."),
        event_count=len(hits), first_seen=first, last_seen=last,
        sample_events=(ts1149[:2] + rdp_4624[:2])[:3],
        source_ip=next(iter(src_ips), ""),
        attack=[("T1021.001", "Remote Services: Remote Desktop Protocol")],
    ))
    return out


def detect_log_clearing(
    events: list[EvtxEvent],
    idx: dict[tuple[str, int], list[EvtxEvent]],
) -> list[LMHit]:
    """security 1102 = audit log cleared. Classic anti-forensic step
    after lateral movement — surface any occurrence loudly."""
    hits = idx.get(("security", 1102), [])
    if not hits:
        return []
    first, last = _summary(hits)
    return [LMHit(
        technique="anti_forensic",
        subtechnique="security_log_cleared",
        description=(f"Security audit log CLEARED (EID 1102) ×{len(hits)}. "
                     f"Strong anti-forensic indicator — correlate with "
                     f"other LM detectors for timeline. first={first}, "
                     f"last={last}."),
        event_count=len(hits), first_seen=first, last_seen=last,
        sample_events=hits[:3],
        attack=[("T1070.001", "Indicator Removal: Clear Windows Event Logs")],
    )]


ALL_DETECTORS = (
    detect_psexec_destination,
    detect_scheduled_task_creation,
    detect_service_install_remote,
    detect_wmi_persistence,
    detect_powershell_remoting_inbound,
    detect_rdp_destination,
    detect_log_clearing,
)


def run_all(csv_path: Path) -> list[LMHit]:
    """One-shot: stream CSV, build (channel, EventId) index, run every
    detector. Avoids materializing the full event list — see
    `_build_index_streaming` for the OOM rationale on DC images."""
    idx = _build_index_streaming(csv_path)
    hits: list[LMHit] = []
    # Detectors retain the (events, idx) signature for back-compat
    # with tests that pass synthesized event lists. When called via
    # this path `events` is unused — every detector now reads from
    # `idx` exclusively. Pass an empty list as the events placeholder.
    for fn in ALL_DETECTORS:
        hits.extend(fn([], idx))
    return hits

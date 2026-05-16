"""Read the system's time-configuration baseline from a SYSTEM hive.

Two keys answer "what did this machine think the time was, and how
sure can we be?":

  HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation
    Bias, StandardBias, DaylightBias, ActiveTimeBias
    StandardName, DaylightName  (e.g. "GMT Standard Time")

  HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters
    NtpServer, Type ("NTP" / "NoSync" / "NT5DS" / ...)

  HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config
    (last-write timestamp = approx last time the sync state changed)

CurrentControlSet is a runtime alias — on a dead hive we resolve via
HKLM\\SYSTEM\\Select.Current to the actual ControlSet001 / 002 / etc.

The forensic value is calibration, not correction:
  - TZ name + active bias → interpret FAT / EXIF / Office-metadata
    timestamps stored in local time with no TZ record.
  - W32Time Type → drift is bounded (NTP / domain time sync) vs.
    unbounded (NoSync = orphan clock, drift accumulates).
  - W32Time Config last-write → an approximation of when sync state
    last changed (install, manual change, last NTP touch — not
    surgical, but it's a free signal).

We deliberately do NOT modify any artifact times. The baseline is a
single Finding the analyst can refer to when reading any other time
value in the case.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass
class TimeBaseline:
    # TimeZoneInformation
    tz_standard_name: str = ""
    tz_daylight_name: str = ""
    tz_bias_minutes: int | None = None          # base offset from UTC
    tz_standard_bias_minutes: int | None = None
    tz_daylight_bias_minutes: int | None = None
    tz_active_bias_minutes: int | None = None   # active right now

    # W32Time
    w32time_type: str = ""             # "NTP" / "NoSync" / "NT5DS" / ""
    w32time_ntp_server: str = ""       # e.g. "time.windows.com,0x1"
    w32time_config_last_write_utc: str = ""    # ISO-8601, or ""

    # Diagnostics
    control_set: str = ""              # e.g. "ControlSet001"
    notes: list[str] = field(default_factory=list)

    @property
    def have_anything(self) -> bool:
        return bool(self.tz_standard_name or self.w32time_type
                    or self.tz_bias_minutes is not None)

    @property
    def sync_state_label(self) -> str:
        """Plain-English summary the analyst can drop into the
        narrative. Tells you whether to trust the clock or not."""
        t = (self.w32time_type or "").upper()
        if t == "NTP":
            return f"NTP-synced to {self.w32time_ntp_server or '<unspecified>'}"
        if t == "NT5DS":
            return "domain-time-sync (NT5DS — synced to domain controller)"
        if t == "NOSYNC":
            return "NoSync — orphan clock, drift accumulates"
        if t == "ALLSYNC":
            return "AllSync — accepts time from any source"
        return f"unknown sync mode ({self.w32time_type or 'absent'})"


def _filetime_to_iso(filetime_100ns: int) -> str:
    """Convert a Windows FILETIME (100-ns ticks since 1601-01-01 UTC)
    to an ISO-8601 UTC string. Returns '' on overflow / zero."""
    if not filetime_100ns or filetime_100ns < 0:
        return ""
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=filetime_100ns // 10)
    except (OverflowError, ValueError):
        return ""
    return dt.isoformat()


def _dword_as_signed_minutes(raw: int | None) -> int | None:
    """ActiveTimeBias / Bias are stored as REG_DWORD but represent a
    signed minute-offset where the SIGN is reversed by Windows
    convention: positive bias means clock is BEHIND UTC. Some
    extractors hand back the raw unsigned form (e.g. 4294967236 for
    -60); fold both shapes into a single signed integer."""
    if raw is None:
        return None
    # REG_DWORD is 32-bit. Values above 2^31 = negative two's complement.
    if raw >= 0x80000000:
        return raw - 0x100000000
    return raw


def _resolve_current_control_set(hive) -> str:
    """Dead hive — \\Select\\Current names the ControlSet number to
    read from. Defaults to ControlSet001 when Select is unreadable."""
    try:
        k = hive.get_key("\\Select")
        for v in k.iter_values():
            if v.name == "Current":
                return f"ControlSet{int(v.value):03d}"
    except Exception:
        pass
    return "ControlSet001"


def _read_values(hive, path: str) -> dict[str, object]:
    try:
        k = hive.get_key(path)
    except Exception:
        return {}
    out: dict[str, object] = {}
    try:
        for v in k.iter_values():
            out[v.name] = v.value
    except Exception:
        pass
    # The key's own last-modified timestamp is forensically interesting
    # for W32Time\\Config (approximates when sync state last changed).
    try:
        out["__last_modified_filetime"] = k.header.last_modified
    except Exception:
        pass
    return out


def parse_system_hive(system_hive: Path) -> TimeBaseline:
    """Read TimeZoneInformation + W32Time/Parameters + W32Time/Config
    from a SYSTEM hive file. Returns an empty TimeBaseline (with
    `have_anything == False`) when the hive can't be opened or the
    keys are absent — caller decides whether to emit an `insufficient`
    finding or stay silent."""
    out = TimeBaseline()
    try:
        from regipy.registry import RegistryHive
    except ImportError:
        out.notes.append("regipy unavailable — cannot read SYSTEM hive")
        return out
    p = Path(system_hive)
    if not p.is_file():
        out.notes.append(f"SYSTEM hive not found: {p}")
        return out
    try:
        hive = RegistryHive(str(p))
    except Exception as e:
        out.notes.append(f"regipy failed to open hive: {type(e).__name__}")
        return out

    out.control_set = _resolve_current_control_set(hive)

    tz = _read_values(hive,
                      f"\\{out.control_set}\\Control\\TimeZoneInformation")
    if tz:
        out.tz_standard_name = str(tz.get("StandardName") or "")
        out.tz_daylight_name = str(tz.get("DaylightName") or "")
        out.tz_bias_minutes = _dword_as_signed_minutes(
            tz.get("Bias") if isinstance(tz.get("Bias"), int) else None)
        out.tz_standard_bias_minutes = _dword_as_signed_minutes(
            tz.get("StandardBias")
            if isinstance(tz.get("StandardBias"), int) else None)
        out.tz_daylight_bias_minutes = _dword_as_signed_minutes(
            tz.get("DaylightBias")
            if isinstance(tz.get("DaylightBias"), int) else None)
        out.tz_active_bias_minutes = _dword_as_signed_minutes(
            tz.get("ActiveTimeBias")
            if isinstance(tz.get("ActiveTimeBias"), int) else None)

    params = _read_values(
        hive, f"\\{out.control_set}\\Services\\W32Time\\Parameters")
    if params:
        out.w32time_type = str(params.get("Type") or "")
        out.w32time_ntp_server = str(params.get("NtpServer") or "")

    config = _read_values(
        hive, f"\\{out.control_set}\\Services\\W32Time\\Config")
    if config:
        lm = config.get("__last_modified_filetime")
        if isinstance(lm, int):
            out.w32time_config_last_write_utc = _filetime_to_iso(lm)

    return out


__all__ = ["TimeBaseline", "parse_system_hive"]

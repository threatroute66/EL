"""Skill: parse the Windows CapabilityAccessManager `ConsentStore`.

Lives in the SOFTWARE registry hive at
``\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\``
plus a per-user mirror under NTUSER.DAT. Each capability (microphone,
camera, location, contacts, …) is a top-level subkey; under it sit
per-app entries with `LastUsedTimeStart` / `LastUsedTimeStop`
FILETIMEs recording the last invocation.

Forensic value:
- Records what apps used sensitive capabilities AND when.
- Surfaces capability use by sandboxed UWP / packaged apps that don't
  show up in Prefetch.
- The `LastUsedTimeStop=0` case = currently in use at acquisition time
  (or the app crashed without releasing the capability).

Pure-Python via `regipy`.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


# Capabilities the analyst typically pivots on first. Other subkeys
# (gazeInput, broadFileSystemAccess, etc.) get the same parser, but
# these are the headline rows in a forensic report.
HIGH_INTEREST_CAPABILITIES = {
    "webcam", "microphone", "location", "contacts",
    "documentslibrary", "videoslibrary", "musiclibrary",
    "picturesLibrary", "broadFileSystemAccess",
    "humanInterfaceDevice", "phoneCall", "userAccountInformation",
}


@dataclass
class CapabilityUse:
    capability: str                    # e.g. "webcam"
    app: str                           # subkey name; package family or NonPackaged path
    last_used_start_utc: str = ""      # FILETIME → ISO 8601 UTC
    last_used_stop_utc: str = ""       # "" if 0 (still in use)
    in_use_at_acquisition: bool = False


def _filetime_to_utc(value: int | bytes | None) -> str:
    """Decode an NT FILETIME (100-ns ticks since 1601-01-01 UTC) into
    an ISO 8601 string. Returns "" for 0 / None / unparseable."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        if len(value) < 8:
            return ""
        try:
            value = struct.unpack("<Q", bytes(value)[:8])[0]
        except struct.error:
            return ""
    if not isinstance(value, int) or value <= 0:
        return ""
    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return (epoch + timedelta(microseconds=value // 10)
                ).isoformat(timespec="seconds")
    except (OverflowError, ValueError):
        return ""


def parse_software_hive(software_hive_path: str | Path) -> list[CapabilityUse]:
    """Walk SOFTWARE\\...\\ConsentStore\\ and return a CapabilityUse
    per (capability, app) pair. Empty list on any parse error so the
    caller never crashes — regipy's CLI form is permissive."""
    try:
        from regipy.registry import RegistryHive
    except Exception:
        return []
    p = Path(software_hive_path)
    if not p.is_file():
        return []
    try:
        hive = RegistryHive(str(p))
    except Exception:
        return []

    out: list[CapabilityUse] = []
    consent_path = (r"\Microsoft\Windows\CurrentVersion"
                    r"\CapabilityAccessManager\ConsentStore")
    try:
        consent = hive.get_key(consent_path)
    except Exception:
        return []
    if consent is None:
        return []

    for cap_subkey in consent.iter_subkeys():
        cap_name = cap_subkey.name
        for app_subkey in cap_subkey.iter_subkeys():
            start = stop = None
            for v in app_subkey.iter_values():
                if v.name == "LastUsedTimeStart":
                    start = v.value
                elif v.name == "LastUsedTimeStop":
                    stop = v.value
            start_iso = _filetime_to_utc(start)
            stop_iso = _filetime_to_utc(stop)
            in_use = bool(start_iso) and not stop_iso
            out.append(CapabilityUse(
                capability=cap_name, app=app_subkey.name,
                last_used_start_utc=start_iso,
                last_used_stop_utc=stop_iso,
                in_use_at_acquisition=in_use,
            ))
            # Some Windows builds nest a per-user mirror one level deeper
            try:
                for nested in app_subkey.iter_subkeys():
                    n_start = n_stop = None
                    for v in nested.iter_values():
                        if v.name == "LastUsedTimeStart":
                            n_start = v.value
                        elif v.name == "LastUsedTimeStop":
                            n_stop = v.value
                    if n_start is None and n_stop is None:
                        continue
                    s = _filetime_to_utc(n_start)
                    p_ = _filetime_to_utc(n_stop)
                    out.append(CapabilityUse(
                        capability=cap_name,
                        app=f"{app_subkey.name}\\{nested.name}",
                        last_used_start_utc=s,
                        last_used_stop_utc=p_,
                        in_use_at_acquisition=bool(s) and not p_,
                    ))
            except Exception:
                pass
    out.sort(key=lambda r: (r.capability, r.last_used_start_utc),
             reverse=False)
    return out


__all__ = [
    "CapabilityUse", "HIGH_INTEREST_CAPABILITIES", "parse_software_hive",
]

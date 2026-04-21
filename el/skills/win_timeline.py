"""Skill: Windows Timeline (ActivitiesCache.db) parser.

Every Windows 10/11 user profile has `ActivitiesCache.db` at
`%LOCALAPPDATA%\\ConnectedDevicesPlatform\\L.<username>\\`. It's the
SQLite store behind the Win+Tab timeline UI and records every
foreground app launch plus every file / URI the user touched inside
those apps. Persistent across reboots; survives app-level clearing
because Windows caches the data before the app even writes to it.

Schema (pragmatic; actual tables include more columns but these are
what DFIR uses):

  Activity
    - Id                       (activity GUID)
    - AppId                    (JSON; identifies the owning app)
    - ActivityType             (5 = app-in-use, 6 = clipboard-copy,
                                 10 = user-engaged, 11 = notification, …)
    - Payload                  (JSON; display name, URI, file path)
    - StartTime, EndTime       (Unix epoch, UTC)
    - LastModifiedTime
    - PackageIdHash, ParentActivityId, Tag, Group

We return `Activity` rows normalised into `TimelineEntry` objects
with the most useful subset extracted. Raw JSON stays accessible via
the `raw_payload` field for deeper drilldown.

Pure-function skill. sqlite3 only (stdlib), no external deps.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ActivityType enum from MS docs + reverse-engineering by Eric
# Zimmerman's WxTCmd / Ryan Benson's CCL work.
_ACTIVITY_TYPE_NAMES: dict[int, str] = {
    2:  "notification",
    3:  "mobile_shift",
    5:  "app_in_use",
    6:  "clipboard",
    10: "user_engaged",
    11: "system",
    12: "cortana_query",
    16: "application_launch",
}


@dataclass
class TimelineEntry:
    activity_id: str = ""
    activity_type: int = 0
    activity_type_name: str = ""
    app_id: str = ""                 # extracted application key
    app_path: str = ""               # Win32/packaged path if present in AppId
    display_text: str = ""           # Payload.displayText
    description: str = ""            # Payload.description
    target_uri: str = ""             # Payload.activationUri or contentUri
    file_path: str = ""              # Payload "appPath" / "path" if present
    start_time_utc: str = ""
    end_time_utc: str = ""
    last_modified_utc: str = ""
    source_db: str = ""
    raw_payload: dict = field(default_factory=dict)


def _unix_to_iso(secs: Any) -> str:
    try:
        s = int(secs or 0)
    except (TypeError, ValueError):
        return ""
    if s <= 0:
        return ""
    try:
        return datetime.fromtimestamp(s, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def _parse_appid(raw: Any) -> tuple[str, str]:
    """AppId is a JSON array of {application, platform} pairs. Return
    (human_app, concrete_path_if_any). Packaged apps carry PFN; Win32
    apps carry a full path — both useful, so we prefer the non-empty
    one with a path-shaped value and fall back to the packaged name."""
    if not raw:
        return "", ""
    try:
        parsed = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (ValueError, TypeError):
        return "", ""
    if not isinstance(parsed, list):
        return "", ""

    win32_path = ""
    packaged_name = ""
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        app = str(entry.get("application") or "")
        platform = str(entry.get("platform") or "").lower()
        if not app:
            continue
        if platform == "packagedapplication":
            packaged_name = packaged_name or app
        elif platform in ("windows_win32", "x_exe_path"):
            if ":" in app or "\\" in app or "/" in app:
                win32_path = win32_path or app
        elif "\\" in app or ":" in app:
            win32_path = win32_path or app
        else:
            packaged_name = packaged_name or app
    return packaged_name, win32_path


def _parse_payload(raw: Any) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def parse_activities_cache(db_path: Path) -> list[TimelineEntry]:
    """Stream ActivitiesCache.db's Activity table into TimelineEntry
    objects. Opens the DB read-only in URI mode to avoid
    accidentally writing to evidence (SQLite normally touches the
    WAL on open)."""
    p = Path(db_path)
    if not p.is_file():
        return []

    uri = f"file:{p.resolve()}?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return []

    rows: list[TimelineEntry] = []
    try:
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute("""
                SELECT Id, AppId, ActivityType, Payload,
                       StartTime, EndTime, LastModifiedTime
                FROM Activity
            """)
        except sqlite3.Error:
            return []
        for r in cur:
            entry = _row_to_entry(r, source_db=str(p))
            if entry:
                rows.append(entry)
    finally:
        conn.close()
    return rows


def _row_to_entry(row: sqlite3.Row, source_db: str) -> TimelineEntry | None:
    try:
        activity_type = int(row["ActivityType"] or 0)
    except (TypeError, ValueError):
        activity_type = 0

    activity_id = row["Id"]
    if isinstance(activity_id, (bytes, bytearray)):
        activity_id = activity_id.hex()
    else:
        activity_id = str(activity_id or "")

    app_id_raw = row["AppId"]
    if isinstance(app_id_raw, (bytes, bytearray)):
        app_id_raw = app_id_raw.decode("utf-8", errors="ignore")
    app_name, app_path = _parse_appid(app_id_raw)

    payload_raw = row["Payload"]
    if isinstance(payload_raw, (bytes, bytearray)):
        payload_raw = payload_raw.decode("utf-8", errors="ignore")
    payload = _parse_payload(payload_raw)

    entry = TimelineEntry(
        activity_id=activity_id,
        activity_type=activity_type,
        activity_type_name=_ACTIVITY_TYPE_NAMES.get(activity_type,
                                                     f"type_{activity_type}"),
        app_id=app_name,
        app_path=app_path,
        display_text=str(payload.get("displayText") or ""),
        description=str(payload.get("description") or ""),
        target_uri=str(payload.get("activationUri")
                        or payload.get("contentUri")
                        or payload.get("dynamicBackgroundUri") or ""),
        file_path=str(payload.get("appPath")
                       or payload.get("path")
                       or payload.get("fileShellLink") or ""),
        start_time_utc=_unix_to_iso(row["StartTime"]),
        end_time_utc=_unix_to_iso(row["EndTime"]),
        last_modified_utc=_unix_to_iso(row["LastModifiedTime"]),
        source_db=source_db,
        raw_payload=payload,
    )
    return entry


# --- Suspicion overlay ---------------------------------------------------

_USER_WRITABLE_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\temp\\",
    "\\downloads\\",
    "\\recycle.bin\\",
    "/appdata/local/temp/",
    "/appdata/roaming/",
    "/programdata/",
    "/users/public/",
    "/temp/",
    "/downloads/",
    "/recycle.bin/",
)


def has_suspicious_path(entry: TimelineEntry) -> bool:
    """Flag entries whose app path, file path, or target URI sits in
    a user-writable marker directory. Matches the shape used by
    execution_corroboration and bam_dam for cross-surface consistency."""
    for hay in (entry.app_path, entry.file_path, entry.target_uri):
        lp = (hay or "").lower()
        if any(m in lp for m in _USER_WRITABLE_MARKERS):
            return True
    return False


def suspicious_entries(entries: list[TimelineEntry]) -> list[TimelineEntry]:
    return [e for e in entries if has_suspicious_path(e)]


def summarise_apps(entries: list[TimelineEntry],
                    top_n: int = 20) -> list[tuple[str, int]]:
    from collections import Counter
    c: Counter = Counter()
    for e in entries:
        key = e.app_path or e.app_id or "(unknown)"
        c[key] += 1
    return c.most_common(top_n)


__all__ = [
    "TimelineEntry",
    "parse_activities_cache",
    "has_suspicious_path", "suspicious_entries", "summarise_apps",
]

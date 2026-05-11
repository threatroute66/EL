"""Skill: User-activity reconstruction from a Windows memory image.

Where ``recent_docs.py`` parses a hive *file* with regipy, this skill
operates on the **memory image itself** via vol3. It is the load-bearing
piece of the memory-only project-access-timeline pivot — the one
described in /opt/EL/cases/rocba-memory/analysis/timeline_pivot/.

The novel decoders here, not covered by any other EL skill:

  * **Office MRU FILETIME**. The values under
    ``Software\\Microsoft\\Office\\<ver>\\<App>\\User MRU\\<acct>\\
    File MRU\\Item N`` are REG_SZ strings shaped like
    ``[F<flags>][T<filetime>][O<options>]*<full path>``. Every
    file opened in Word/Excel/PowerPoint while signed in to a given
    Microsoft account is captured here with a per-file FILETIME
    last-open. This is the single highest-fidelity per-file user-
    activity timestamp in Windows outside Plaso + $UsnJrnl.

  * **Drive-letter ↔ USB-serial correlation**. ``MountedDevices``
    holds ``\\DosDevices\\<X>: -> <REG_BINARY device-path>`` for every
    drive letter present at acquisition. Decoding the device path
    pins each letter to either an on-system volume or a specific
    USBSTOR serial number. Without this join, "F:\\Files of
    interest\\..." in an MRU value is just a string — with it, F:
    becomes "Lexar USB Flash Drive AAZ62W7KENRSJLHY", a piece of
    physical evidence the analyst can correlate against the actual
    device.

The skill returns dataclasses with ``as_evidence()``; the
``UserActivityAgent`` does the rule-based scoring + Finding emission.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from el.schemas.finding import EvidenceItem
from el.skills import vol3


# --------------------------------------------------------------------------
# Office MRU value decoding
# --------------------------------------------------------------------------

# Office MRU REG_SZ value format. Both File MRU and Place MRU items use
# this shape — the FILETIME inside is the last-open time of the path.
_MRU_VALUE_RE = re.compile(
    r'^"?\[F[0-9A-F]+\]\[T([0-9A-F]+)\]\[O[0-9A-F]+\]\*(.+?)"?\s*$',
    re.IGNORECASE,
)


def _filetime_to_iso(ft: int) -> str:
    """Decode a Windows FILETIME (100-ns ticks since 1601-01-01 UTC)."""
    if ft <= 0:
        return ""
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=ft / 10
        )
        return dt.isoformat()
    except (OverflowError, ValueError):
        return ""


def parse_office_mru_value(data: str) -> tuple[str, str] | None:
    """Decode ``[F…][T<filetime>][O…]*<path>`` → (iso_utc, path).

    Returns None for any string that isn't a recognised Office MRU
    item value. Callers should rely on the non-None return to filter
    real items from the surrounding folder-id stubs (``FOLDERID_*``)
    that appear as siblings in the same key.
    """
    if not isinstance(data, str) or not data:
        return None
    m = _MRU_VALUE_RE.match(data.strip())
    if not m:
        return None
    try:
        ft = int(m.group(1), 16)
    except ValueError:
        return None
    iso = _filetime_to_iso(ft)
    if not iso:
        return None
    return iso, m.group(2).rstrip('"').strip()


@dataclass
class OfficeMRUEntry:
    """One Office MRU item with its per-file last-open time."""

    app: str               # "Word", "Excel", "PowerPoint", or "?"
    account: str           # "ADAL", "LiveId", "noprofile"
    account_id: str        # raw subkey name (or "" if no profile)
    kind: str              # "File" or "Place"
    path: str
    opened_utc: str        # ISO-8601 UTC
    key_last_write_utc: str = ""


# App-name + account discriminators in the Office MRU registry path.
_OFFICE_APP_RE = re.compile(r"\\Office\\\d+\.\d+\\(Word|Excel|PowerPoint)\\",
                             re.IGNORECASE)


def _office_account_label(key: str) -> tuple[str, str]:
    """Identify the Office account-profile subkey embedded in *key*.

    Returns (label, raw_id):
      ``ADAL`` = corporate Azure-AD-bound identity (work / school)
      ``LiveId`` = personal Microsoft account
      ``noprofile`` = the parent File/Place MRU before any profile
                      subkey (only the folder-id stubs live here)
    """
    m = re.search(r"\\(ADAL_[0-9A-F]+|LiveId_[0-9A-F]+)\\", key, re.IGNORECASE)
    if not m:
        return "noprofile", ""
    raw = m.group(1)
    label = "ADAL" if raw.upper().startswith("ADAL_") else "LiveId"
    return label, raw


def walk_office_mru(printkey_rows: list[dict]) -> list[OfficeMRUEntry]:
    """Walk a recursive ``printkey`` JSON tree rooted at
    ``Software\\Microsoft\\Office`` and yield decoded MRU entries.

    Tolerant of partial trees (memory carving frequently breaks deep
    subkeys). Skips children whose ``Type`` isn't ``REG_SZ`` and whose
    decoded data isn't a recognised MRU value.
    """
    entries: list[OfficeMRUEntry] = []

    def _visit(node: dict) -> None:
        key = node.get("Key") or ""
        name = node.get("Name") or ""
        data = node.get("Data") or ""
        typ = node.get("Type") or ""
        lwt = node.get("Last Write Time") or ""
        if typ == "REG_SZ" and ("File MRU" in key or "Place MRU" in key):
            decoded = parse_office_mru_value(data)
            if decoded:
                iso, path = decoded
                app_m = _OFFICE_APP_RE.search(key)
                app = app_m.group(1) if app_m else "?"
                acct, acct_id = _office_account_label(key)
                kind = "File" if "File MRU" in key else "Place"
                entries.append(OfficeMRUEntry(
                    app=app, account=acct, account_id=acct_id,
                    kind=kind, path=path, opened_utc=iso,
                    key_last_write_utc=str(lwt) if lwt else "",
                ))
        for child in node.get("__children") or []:
            _visit(child)

    for top in printkey_rows:
        _visit(top)
    entries.sort(key=lambda e: e.opened_utc)
    return entries


# --------------------------------------------------------------------------
# MountedDevices ↔ USBSTOR correlation
# --------------------------------------------------------------------------

_DOSDEV_RE = re.compile(r"^\\DosDevices\\([A-Z]):$")
# Match a USBSTOR device-path embedded in the printkey hex+ASCII column.
# The vol3 binary-pretty-print column collapses NUL bytes to '.', so a
# UTF-16LE string like "_??_USBSTOR#Disk&Ven_Lexar..." comes through as
# "_??_USBSTOR#Disk&Ven_Lexar..." after we strip dots. We capture the
# vendor + product + serial discriminators.
_USB_SIG_RE = re.compile(
    r"USBSTOR#Disk&Ven_([^&#]*)&Prod_([^&#]*)&Rev_[^#]+#([A-Z0-9]+)&",
    re.IGNORECASE,
)


@dataclass
class DriveLetterMapping:
    letter: str                  # "C", "D", "F", ...
    backing: str                 # short label for tables
    usb_vendor: str = ""         # populated only when backing is USBSTOR
    usb_product: str = ""
    usb_serial: str = ""
    raw_ascii: str = ""          # debug payload — useful when our regex misses


def _extract_ascii_column(printkey_data_field: str) -> str:
    """Re-assemble the ASCII column from vol3's hex+ASCII REG_BINARY dump.

    vol3 emits REG_BINARY values as multi-line strings shaped::

        '"\\n5f 00 3f 00 ... _.?.? ...\\n..."'

    16 hex pairs followed by their ASCII annotation, with NUL bytes
    drawn as ``.``. We pull each ASCII annotation column, strip the
    dots (NULs), and return the concatenated text.
    """
    if not isinstance(printkey_data_field, str):
        return ""
    rebuilt: list[str] = []
    for raw_line in printkey_data_field.split("\n"):
        line = raw_line.strip()
        # 16 pairs of hex digits followed by whitespace and the ASCII column.
        m = re.match(r"^((?:[0-9a-fA-F]{2} ){15}[0-9a-fA-F]{2})\s+(.+)$", line)
        if m:
            rebuilt.append(re.sub(r'"\s*$', "", m.group(2)))
    return re.sub(r"\.", "", "".join(rebuilt))


def parse_mounted_devices(printkey_rows: list[dict]) -> list[DriveLetterMapping]:
    """Decode ``MountedDevices`` → ordered list of letter → backing-device.

    Only ``\\DosDevices\\<letter>:`` values are kept. The Volume-GUID
    entries (``\\??\\Volume{…}``) are dropped here — they're useful
    for the disk-image pivot but noisy in the memory-only table.
    """
    out: list[DriveLetterMapping] = []

    def _visit(node: dict) -> None:
        name = node.get("Name") or ""
        m = _DOSDEV_RE.match(name)
        if m:
            letter = m.group(1)
            asc = _extract_ascii_column(node.get("Data") or "")
            usb = _USB_SIG_RE.search(asc)
            if usb:
                vendor = usb.group(1) or "(generic)"
                product = usb.group(2)
                serial = usb.group(3)
                backing = (
                    f"USB {vendor.strip() or '(generic)'} "
                    f"{product.strip()} [{serial}]"
                )
                out.append(DriveLetterMapping(
                    letter=letter, backing=backing,
                    usb_vendor=vendor.strip(),
                    usb_product=product.strip(),
                    usb_serial=serial,
                    raw_ascii=asc[:200],
                ))
            elif asc:
                # Non-USB backing — local HDD, optical, network share.
                # We don't try to identify it further; the analyst only
                # needs to know "this letter is internal" vs "this letter
                # is removable USB". Anything not USBSTOR is "internal".
                out.append(DriveLetterMapping(
                    letter=letter, backing="internal / non-USB",
                    raw_ascii=asc[:200],
                ))
            else:
                out.append(DriveLetterMapping(
                    letter=letter, backing="(empty / no signature)",
                ))
        for child in node.get("__children") or []:
            _visit(child)

    for top in printkey_rows:
        _visit(top)
    out.sort(key=lambda d: d.letter)
    return out


def removable_drive_letters(
    mappings: list[DriveLetterMapping],
) -> dict[str, DriveLetterMapping]:
    """Subset of *mappings* whose backing is USBSTOR (i.e. removable)."""
    return {m.letter: m for m in mappings if m.usb_serial}


# --------------------------------------------------------------------------
# Insider-staging detector
# --------------------------------------------------------------------------

# Word fragments treated as evidence of "corporate / project" content.
# Intentionally narrow: matches the path style produced by SRL-style
# project folder naming. Each match is a substring test against the
# Office MRU path's basename + parents, case-insensitive. Add patterns
# here as we encounter more corpora; do NOT broaden these to generic
# words ("file", "data") — that'd false-positive on every Office MRU.
_CORPORATE_PROJECT_FRAGMENTS: tuple[str, ...] = (
    "srl-projects",
    "stark-research-labs",
    "stark research labs",
    "\\research\\",
    " - kitt", "\\kitt",
    " - gunstar", "\\gunstar",
    " - megaforce", "\\megaforce",
    " - airwolf", "\\airwolf",
    " - blue thunder",
    "vibrainium", "adamantium",
    "files from srl",
    "files of interest",
    "recovered documents",
)


@dataclass
class StagingSignal:
    """One Office MRU entry that looks like project IP on removable media."""

    entry: OfficeMRUEntry
    letter: str
    usb_serial: str
    matched_fragment: str


def detect_removable_staging(
    mru_entries: list[OfficeMRUEntry],
    removable: dict[str, DriveLetterMapping],
) -> list[StagingSignal]:
    """Pair Office MRU entries against the removable-drive letter set.

    A *staging signal* is an MRU entry whose path starts with a drive
    letter currently backed by a USBSTOR device, AND whose path
    contains a corporate-project fragment. The bar is intentionally
    high — neither condition alone is enough.
    """
    signals: list[StagingSignal] = []
    for e in mru_entries:
        if len(e.path) < 3 or e.path[1:3] != ":\\":
            continue
        letter = e.path[0].upper()
        if letter not in removable:
            continue
        lp = e.path.lower()
        matched = next(
            (frag for frag in _CORPORATE_PROJECT_FRAGMENTS if frag in lp),
            None,
        )
        if not matched:
            continue
        signals.append(StagingSignal(
            entry=e, letter=letter,
            usb_serial=removable[letter].usb_serial,
            matched_fragment=matched,
        ))
    return signals


# --------------------------------------------------------------------------
# Vol3 driver: dump hives + recursive printkey, package as EvidenceItems
# --------------------------------------------------------------------------

@dataclass
class HiveSummary:
    file_full_path: str        # e.g. "\\??\\C:\\Users\\fredr\\ntuser.dat"
    offset: int                # numeric hive offset (for printkey --offset)
    user: str = ""             # parsed username from path; "" if not a per-user hive


_USER_HIVE_RE = re.compile(r"\\Users\\([^\\]+)\\(ntuser\.dat|"
                             r"AppData\\Local\\Microsoft\\Windows\\UsrClass\.dat)",
                             re.IGNORECASE)


def find_user_hives(hivelist_rows: list[dict]) -> list[HiveSummary]:
    """Filter ``windows.registry.hivelist`` JSON rows to per-user hives."""
    out: list[HiveSummary] = []
    for r in hivelist_rows:
        fp = r.get("FileFullPath") or r.get("Path") or r.get("Name") or ""
        off = r.get("Offset") or 0
        m = _USER_HIVE_RE.search(str(fp))
        if not m:
            continue
        out.append(HiveSummary(
            file_full_path=str(fp), offset=int(off), user=m.group(1),
        ))
    return out


@dataclass
class UserActivityRun:
    """Full result of one user's activity pass — every file path is
    relative to ``out_dir`` and lives on disk so each EvidenceItem can
    SHA-256-anchor."""

    user: str
    ntuser_offset: int
    out_dir: Path
    office_mru_path: Path
    typedpaths_path: Path
    mounted_devices_path: Path
    office_mru: list[OfficeMRUEntry] = field(default_factory=list)
    typedpaths: list[str] = field(default_factory=list)
    drive_map: list[DriveLetterMapping] = field(default_factory=list)
    staging_signals: list[StagingSignal] = field(default_factory=list)

    def as_evidence(self, source_path: Path,
                    facts: dict | None = None) -> EvidenceItem:
        """Generic provenance wrapper — *source_path* names the JSON
        file the caller is anchoring this Finding to."""
        try:
            sha = hashlib.sha256(source_path.read_bytes()).hexdigest()
        except OSError:
            sha = ""
        merged = {"user": self.user, "ntuser_offset_hex": hex(self.ntuser_offset)}
        if facts:
            merged.update(facts)
        return EvidenceItem(
            tool="volatility3+user_activity_memory",
            version=vol3._vol_version(),
            command=f"vol --offset {hex(self.ntuser_offset)} (printkey + MountedDevices)",
            output_sha256=sha,
            output_path=str(source_path),
            extracted_facts=merged,
        )


_OFFICE_KEY = r"Software\Microsoft\Office"
_TYPEDPATHS_KEY = (
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
)


def run_for_user(
    image: str | Path,
    out_dir: str | Path,
    hive: HiveSummary,
    *,
    timeout: int = 600,
) -> UserActivityRun:
    """Run the per-user Office-MRU + TypedPaths + MountedDevices passes.

    Writes one JSON file per query under *out_dir*. Caller hands us the
    output of ``find_user_hives()`` so we don't re-run hivelist per user.

    Per-key vol3 printkey calls are scoped via ``--offset`` so they read
    *only* the target hive rather than walking every hive in memory —
    the unscoped path emits one row per hive (most of them empty) and
    blows up the JSON for no benefit.
    """
    image = Path(image)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", hive.user)
    user_out = out_dir / f"user_{safe_user}"
    user_out.mkdir(parents=True, exist_ok=True)

    # 1. Office MRU recursive (per-user)
    office_run = vol3.run_plugin(
        image, "windows.registry.printkey", user_out,
        extra_args=["--offset", str(hive.offset),
                     "--key", _OFFICE_KEY, "--recurse"],
        timeout=timeout,
    )
    office_mru = walk_office_mru(office_run.rows)

    # 2. TypedPaths (per-user)
    typed_run = vol3.run_plugin(
        image, "windows.registry.printkey", user_out,
        extra_args=["--offset", str(hive.offset),
                     "--key", _TYPEDPATHS_KEY],
        timeout=timeout,
    )
    typed_paths: list[str] = []

    def _collect_typed(rows: list[dict]) -> None:
        for r in rows:
            if (r.get("Type") == "REG_SZ"
                    and (r.get("Name") or "").lower().startswith("url")):
                raw = (r.get("Data") or "").strip().strip('"')
                if raw:
                    typed_paths.append(raw)
            for child in r.get("__children") or []:
                _collect_typed([child])

    _collect_typed(typed_run.rows)

    # 3. MountedDevices — system-scoped, not per-user. We still write
    # it per-user-dir so the EvidenceItem chain stays one-finding-per-
    # JSON-file. If multiple users on the same image both call this,
    # they each get their own MountedDevices copy — cheap, identical.
    md_run = vol3.run_plugin(
        image, "windows.registry.printkey", user_out,
        extra_args=["--key", "MountedDevices"],
        timeout=timeout,
    )
    drive_map = parse_mounted_devices(md_run.rows)
    removable = removable_drive_letters(drive_map)
    staging = detect_removable_staging(office_mru, removable)

    return UserActivityRun(
        user=hive.user, ntuser_offset=hive.offset, out_dir=user_out,
        office_mru_path=office_run.stdout_path,
        typedpaths_path=typed_run.stdout_path,
        mounted_devices_path=md_run.stdout_path,
        office_mru=office_mru,
        typedpaths=typed_paths,
        drive_map=drive_map,
        staging_signals=staging,
    )


__all__ = [
    "DriveLetterMapping", "HiveSummary", "OfficeMRUEntry",
    "StagingSignal", "UserActivityRun",
    "detect_removable_staging", "find_user_hives",
    "parse_mounted_devices", "parse_office_mru_value",
    "removable_drive_letters", "run_for_user", "walk_office_mru",
]

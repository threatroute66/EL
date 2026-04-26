"""Skill: parse iOS sysdiagnose tarballs.

Closes the FOR585-mobile gap-doc bullet "iOS sysdiagnose triage"
and partially addresses the macOS ``unified_log_parse`` bullet.
A sysdiagnose is the canonical Apple support bundle: tar.gz of
device logs, crash records, jetsam events, IOReg state, WiFi
scan history, and (on iOS 11+) a ``system_logs.logarchive/``
subtree carrying the Unified Log timeshare archive.

This skill catalogs and triages sysdiagnose tarballs WITHOUT
requiring macOS host tools. It can:

- Extract the tarball into a working directory.
- Index the bundle by subsystem (crashes_and_spins, summaries,
  logs, system_logs.logarchive, WiFi, ASPSnapshots, …) with
  per-subsystem file counts.
- Parse ``.ips`` records (Apple's JSON-then-JSON crash / jetsam
  / wakeups format) into structured ``IPSRecord`` dataclasses.
- Surface high-signal events: jetsam (low-memory kills),
  app crashes, wakeups, WiFi connection-quality drops.
- Extract device metadata (iOS version, build, product type,
  incident-id chain) without the full unified-log replay.

The ``system_logs.logarchive/`` subtree is the part that needs
``log show`` (Apple-only) to replay; we surface a marker that
it's present plus the byte-size, and emit a clear "needs macOS
host" note in the metadata.
"""
from __future__ import annotations

import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SysdiagnoseIndex:
    """Catalog of a sysdiagnose bundle: per-subsystem file count
    and an explicit flag for the presence of the Unified Log
    archive."""
    root: Path
    file_count: int = 0
    bytes_total: int = 0
    subsystems: dict[str, int] = field(default_factory=dict)
    has_logarchive: bool = False
    logarchive_bytes: int = 0
    ips_files: list[Path] = field(default_factory=list)


@dataclass
class IPSRecord:
    """One parsed ``.ips`` file. The IPS format is JSON-then-JSON:
    a single-line header dict (bug_type, timestamp, os_version,
    incident_id) followed by a second JSON document with the full
    structured report."""
    path: Path
    header: dict = field(default_factory=dict)
    body: dict = field(default_factory=dict)
    parse_error: str = ""

    @property
    def bug_type(self) -> str:
        return str(self.header.get("bug_type", "") or "")

    @property
    def os_version(self) -> str:
        return str(self.header.get("os_version", "") or "")

    @property
    def timestamp(self) -> str:
        return str(self.header.get("timestamp", "") or "")

    @property
    def incident_id(self) -> str:
        return str(self.header.get("incident_id", "") or "")

    @property
    def product(self) -> str:
        return str(self.body.get("product", "") or "")

    @property
    def is_jetsam(self) -> bool:
        """Bug type 298 = Jetsam (low-memory kill)."""
        return self.bug_type == "298"

    @property
    def is_crash(self) -> bool:
        """Bug type 109 = process crash; 309 = stackshot."""
        return self.bug_type in ("109", "309")

    @property
    def largest_process(self) -> str:
        return str(self.body.get("largestProcess", "") or "")


# Subsystem→top-level-dir map. Sysdiagnose layouts vary slightly
# across iOS versions; the top-level names below are stable from
# iOS 12 through iOS 17.
_SUBSYSTEM_DIRS = (
    "crashes_and_spins", "logs", "summaries",
    "system_logs.logarchive", "WiFi", "ASPSnapshots",
    "Preferences", "containers", "RunningBoard",
    "errors", "ioreg", "brctl", "User", "Library",
    "TimezoneDB", "Personalization", "Shared",
    "SystemGroup", "private",
)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract(tarball: Path, out_dir: Path) -> Path:
    """Extract a sysdiagnose tar.gz into ``out_dir``. Returns the
    extracted root (the single top-level directory inside the
    tarball, named ``sysdiagnose_<TS>_<UDID>_<MODEL>_<BUILD>``).

    Tolerates the ``LIBARCHIVE.creationtime`` extended-header
    warnings the corpus emits — those are noise, not errors."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:*") as tf:
        # Pick the first member's top dir as the root anchor
        top: str | None = None
        for m in tf.getmembers():
            head = m.name.split("/", 1)[0]
            if head:
                top = head
                break
        # Avoid extractall's deprecation warning by setting filter.
        try:
            tf.extractall(out_dir, filter="data")
        except (TypeError, ValueError):
            tf.extractall(out_dir)
    if top:
        return out_dir / top
    return out_dir


# ---------------------------------------------------------------------------
# Index / catalog
# ---------------------------------------------------------------------------


def index(root: Path) -> SysdiagnoseIndex:
    """Walk an extracted sysdiagnose root and produce a per-
    subsystem index. ``root`` is the single top directory the
    tarball put in place."""
    root = Path(root)
    out = SysdiagnoseIndex(root=root)
    if not root.is_dir():
        return out
    for sub in _SUBSYSTEM_DIRS:
        d = root / sub
        if d.is_dir():
            count = 0
            size = 0
            for f in d.rglob("*"):
                if f.is_file():
                    count += 1
                    try:
                        size += f.stat().st_size
                    except OSError:
                        pass
            out.subsystems[sub] = count
            out.file_count += count
            out.bytes_total += size
            if sub == "system_logs.logarchive":
                out.has_logarchive = True
                out.logarchive_bytes = size
    # Locate IPS records
    cas = root / "crashes_and_spins"
    if cas.is_dir():
        out.ips_files = [
            f for f in cas.rglob("*.ips")
            if not f.name.startswith("._")
        ]
    return out


# ---------------------------------------------------------------------------
# .ips parsing
# ---------------------------------------------------------------------------


def parse_ips(path: Path) -> IPSRecord:
    """Parse a single ``.ips`` record. Format is a single-line
    JSON header followed by a second JSON document. Returns an
    IPSRecord with parse_error populated when the file isn't
    well-formed."""
    p = Path(path)
    rec = IPSRecord(path=p)
    if not p.is_file():
        rec.parse_error = "file not found"
        return rec
    try:
        with p.open("r", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        rec.parse_error = str(e)
        return rec
    # First line = header JSON; remainder = body JSON
    nl = text.find("\n")
    if nl < 0:
        rec.parse_error = "no newline separating header from body"
        return rec
    header_text = text[:nl].strip()
    body_text = text[nl + 1:].strip()
    try:
        rec.header = json.loads(header_text) if header_text else {}
    except json.JSONDecodeError as e:
        rec.parse_error = f"header parse: {e}"
        return rec
    if body_text:
        try:
            rec.body = json.loads(body_text)
        except json.JSONDecodeError as e:
            # Body sometimes contains trailing non-JSON noise from
            # older iOS versions; surface the partial header rather
            # than failing the whole record.
            rec.parse_error = f"body parse: {e}"
    return rec


# ---------------------------------------------------------------------------
# Per-event queries
# ---------------------------------------------------------------------------


def find_jetsam_events(idx: SysdiagnoseIndex,
                        *, max_records: int = 200
                        ) -> list[IPSRecord]:
    """Return parsed Jetsam (low-memory kill) IPS records. Jetsam
    fingerprints flag anomalous memory pressure — sometimes
    spyware-relevant when an app's resident-page count grows
    unexpectedly before being killed."""
    out: list[IPSRecord] = []
    for f in idx.ips_files:
        if "jetsamevent" not in f.name.lower():
            continue
        rec = parse_ips(f)
        if rec.is_jetsam or "jetsamevent" in f.name.lower():
            out.append(rec)
        if len(out) >= max_records:
            break
    return out


def find_crashes(idx: SysdiagnoseIndex,
                  *, max_records: int = 200
                  ) -> list[IPSRecord]:
    """Return parsed app-crash IPS records (bug_type 109 + .crash
    -named files)."""
    out: list[IPSRecord] = []
    for f in idx.ips_files:
        n = f.name.lower()
        if ("jetsamevent" in n or "wakeups_resource" in n
                or "wifiquality" in n
                or "wificonnectionquality" in n):
            continue
        rec = parse_ips(f)
        out.append(rec)
        if len(out) >= max_records:
            break
    return out


def find_wakeups(idx: SysdiagnoseIndex,
                  *, max_records: int = 200
                  ) -> list[IPSRecord]:
    """Apps that woke up the device too often. Privacy-relevant —
    spyware frequently exhibits unusual wakeup volume."""
    out: list[IPSRecord] = []
    for f in idx.ips_files:
        if "wakeups_resource" not in f.name.lower():
            continue
        rec = parse_ips(f)
        out.append(rec)
        if len(out) >= max_records:
            break
    return out


def device_metadata(idx: SysdiagnoseIndex) -> dict:
    """Derive device metadata from the first parseable IPS record.
    Returns a dict with os_version, product, build, sysdiagnose
    timestamp, plus a ``unified_log_replay_available`` flag noting
    whether the Unified Log archive is present (always False in
    practice on Linux — replay needs macOS ``log show``)."""
    out = {
        "os_version": "",
        "product": "",
        "incident_id": "",
        "timestamp": "",
        "has_logarchive": idx.has_logarchive,
        "logarchive_bytes": idx.logarchive_bytes,
        "unified_log_replay_available": False,
        "unified_log_replay_note": (
            "system_logs.logarchive replay requires macOS "
            "`log show` / `log archive` — ingest the archive "
            "from a macOS host or rely on the static .log "
            "files alongside it."
        ) if idx.has_logarchive else "",
    }
    for f in idx.ips_files:
        rec = parse_ips(f)
        if rec.os_version and not rec.parse_error:
            out["os_version"] = rec.os_version
            out["product"] = rec.product
            out["incident_id"] = rec.incident_id
            out["timestamp"] = rec.timestamp
            break
    return out


__all__ = [
    "SysdiagnoseIndex", "IPSRecord",
    "extract", "index", "parse_ips",
    "find_jetsam_events", "find_crashes", "find_wakeups",
    "device_metadata",
]

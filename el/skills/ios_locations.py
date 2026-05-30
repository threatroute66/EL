"""iOS location-cache parser — cell / Wi-Fi harvested locations.

``/private/var/root/Library/Caches/locationd/cache_encryptedB.db`` is the
locationd harvest cache: rows of cell towers (``CellLocation`` /
``LteCellLocation`` / ``CdmaCellLocation``) and Wi-Fi APs
(``WifiLocation``) the device observed, each with a lat/lon, accuracy and a
Mac-absolute timestamp. It places the device in space and time independently
of any app — e.g. which cell tower it pinged at a given instant.

Read-only via :mod:`el.skills._sqlite` (WAL-applied copy). Native parser —
no SIFT CLI reads this store.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from el.schemas.finding import EvidenceItem
from el.skills._sqlite import EvidenceDBError, open_evidence_db

_MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

# Harvest tables that carry Timestamp + Latitude + Longitude.
_LOCATION_TABLES = (
    "CellLocation", "LteCellLocation", "CdmaCellLocation",
    "WifiLocation", "CellLocationLocal", "LteCellLocationLocal",
)


class IOSLocationsError(Exception):
    pass


def _abs_to_utc(value) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        return (_MAC_EPOCH + timedelta(seconds=v)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class LocationPoint:
    source: str = ""            # the table the row came from
    timestamp_utc: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    horizontal_accuracy: float = 0.0
    altitude: float = 0.0
    cell: str = ""              # MCC-MNC-LAC-CI (cell rows) or BSSID (wifi)

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class LocationsRun:
    db_path: Path
    points: list[LocationPoint] = field(default_factory=list)
    tables_read: list[str] = field(default_factory=list)
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return len(self.points)

    def date_range(self) -> tuple[str, str]:
        ds = [p.timestamp_utc for p in self.points if p.timestamp_utc]
        return (min(ds), max(ds)) if ds else ("", "")

    def near_time(self, utc: str, *, window_s: int = 60) -> list[LocationPoint]:
        """Points whose timestamp is within ±*window_s* of *utc*
        ('YYYY-MM-DD HH:MM:SS'). Answers 'where was the device at T'."""
        try:
            t0 = datetime.strptime(utc, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
        except ValueError:
            return []
        out = []
        for p in self.points:
            if not p.timestamp_utc:
                continue
            try:
                t = datetime.strptime(p.timestamp_utc, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc)
            except ValueError:
                continue
            if abs((t - t0).total_seconds()) <= window_s:
                out.append(p)
        return sorted(out, key=lambda p: p.timestamp_utc)

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        lo, hi = self.date_range()
        return EvidenceItem(
            tool="el.ios_locations", version="0.1.0",
            command=f"parse cache_encryptedB.db -- {self.db_path}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.db_path),
            extracted_facts={
                "db_path": str(self.db_path),
                "point_count": self.total,
                "tables_read": self.tables_read,
                "first_fix_utc": lo,
                "last_fix_utc": hi,
                **extra,
            },
        )


def find_location_cache(fs_root: Path) -> Path | None:
    fs_root = Path(fs_root)
    for rel in (("private", "var", "root", "Library", "Caches", "locationd",
                 "cache_encryptedB.db"),
                ("var", "root", "Library", "Caches", "locationd",
                 "cache_encryptedB.db")):
        p = fs_root.joinpath(*rel)
        if p.is_file():
            return p
    if fs_root.name == "cache_encryptedB.db" and fs_root.is_file():
        return fs_root
    direct = fs_root / "cache_encryptedB.db"
    return direct if direct.is_file() else None


def parse(db_path: Path, output_dir: Path | None = None) -> LocationsRun:
    db_path = Path(db_path)
    if not db_path.is_file():
        raise IOSLocationsError(f"cache_encryptedB.db not found: {db_path}")

    run = LocationsRun(db_path=db_path)
    workdir = Path(output_dir) / "_dbcopy" if output_dir else None
    try:
        with open_evidence_db(db_path, workdir=workdir,
                              row_factory=sqlite3.Row) as conn:
            present = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            for table in _LOCATION_TABLES:
                if table not in present:
                    continue
                cols = {r[1] for r in conn.execute(f"PRAGMA table_info('{table}')")}
                if not ({"Timestamp", "Latitude", "Longitude"} <= cols):
                    continue
                run.tables_read.append(table)
                is_wifi = "MAC" in cols or "BSSID" in cols
                for r in conn.execute(f"SELECT * FROM '{table}'"):
                    d = dict(r)
                    if is_wifi:
                        cell = str(d.get("MAC") or d.get("BSSID") or "")
                    else:
                        cell = "-".join(str(d.get(k, "")) for k in
                                        ("MCC", "MNC", "LAC", "CI"))
                    run.points.append(LocationPoint(
                        source=table,
                        timestamp_utc=_abs_to_utc(d.get("Timestamp")),
                        latitude=float(d.get("Latitude") or 0.0),
                        longitude=float(d.get("Longitude") or 0.0),
                        horizontal_accuracy=float(d.get("HorizontalAccuracy") or 0.0),
                        altitude=float(d.get("Altitude") or 0.0),
                        cell=cell,
                    ))
    except EvidenceDBError as e:
        raise IOSLocationsError(str(e)) from e
    except sqlite3.DatabaseError as e:
        raise IOSLocationsError(f"cannot read {db_path}: {e}") from e

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "ios_locations.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for p in run.points:
                f.write(json.dumps(p.as_dict(), ensure_ascii=False) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run

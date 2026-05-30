"""Untappd (iOS) parser — cached beer check-ins with venue + comment + coords.

The Untappd app (``com.untappdllc.com``) caches API responses under
``Library/Caches/com.untappdllc.com/`` — the response bodies land in
``fsCachedData/`` (NSURLCache external data files) as JSON. Each
``response.checkins.items[]`` entry is a beer check-in: the beer, the venue
(with ``location.lat`` / ``location.lng``), the user's rating, and their
free-text ``checkin_comment``.

NOTE on coordinates: the cache also contains a Cloudflare geo-IP block
(``response.data`` with ``latitude``/``longitude`` = the network's city
centroid). That is NOT a venue location — this parser reads venue locations
from ``checkins.items[].venue.location`` only, so the geo-IP centroid is never
mistaken for a check-in place.

No SIFT CLI parses Untappd's cache, so this is a native parser. Read-only.
"""
from __future__ import annotations

import glob
import hashlib
import json
import plistlib
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class UntappdError(Exception):
    pass


@dataclass
class CheckIn:
    beer: str = ""
    brewery: str = ""
    venue: str = ""
    latitude: float | None = None
    longitude: float | None = None
    rating: float | None = None
    comment: str = ""
    created: str = ""

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class UntappdRun:
    cache_dir: Path
    checkins: list[CheckIn] = field(default_factory=list)
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return len(self.checkins)

    def with_comments(self) -> list[CheckIn]:
        return [c for c in self.checkins if c.comment.strip()]

    def with_coords(self) -> list[CheckIn]:
        return [c for c in self.checkins
                if c.latitude is not None and c.longitude is not None]

    def venues(self) -> list[str]:
        return sorted({c.venue for c in self.checkins if c.venue})

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="el.untappd_ios", version="0.1.0",
            command=f"parse Untappd fsCachedData check-ins -- {self.cache_dir}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.cache_dir),
            extracted_facts={
                "cache_dir": str(self.cache_dir),
                "checkin_count": self.total,
                "with_comments": len(self.with_comments()),
                "distinct_venues": len(self.venues()),
                **extra,
            },
        )


def find_untappd_cache(fs_root: Path) -> Path | None:
    """Locate the Untappd cache dir under an extracted iOS filesystem by
    resolving the app container whose bundle id is com.untappdllc.com."""
    fs_root = Path(fs_root)
    appbase = fs_root / "private" / "var" / "mobile" / "Containers" / "Data" / "Application"
    if not appbase.is_dir():
        appbase = fs_root / "var" / "mobile" / "Containers" / "Data" / "Application"
    if appbase.is_dir():
        for meta in appbase.glob(
                "*/.com.apple.mobile_container_manager.metadata.plist"):
            try:
                d = plistlib.load(open(meta, "rb"))
            except Exception:
                continue
            if d.get("MCMMetadataIdentifier") == "com.untappdllc.com":
                cache = (meta.parent / "Library" / "Caches"
                         / "com.untappdllc.com")
                if cache.is_dir():
                    return cache
    # fs_root may itself be the cache dir.
    if (fs_root / "fsCachedData").is_dir() or (fs_root / "Cache.db").is_file():
        return fs_root
    return None


def _iter_checkins(obj):
    """Yield raw check-in dicts from a parsed Untappd API response, whatever
    the wrapping (user feed, single checkin, venue feed)."""
    if not isinstance(obj, dict):
        return
    resp = obj.get("response")
    if not isinstance(resp, dict):
        return
    ci = resp.get("checkins")
    if isinstance(ci, dict) and isinstance(ci.get("items"), list):
        yield from ci["items"]
    if isinstance(resp.get("checkin"), dict):
        yield resp["checkin"]


def _to_checkin(it: dict) -> CheckIn:
    beer = it.get("beer") or {}
    brew = it.get("brewery") or {}
    ven = it.get("venue") or {}
    loc = (ven.get("location") or {}) if isinstance(ven, dict) else {}
    rating = it.get("rating_score")
    return CheckIn(
        beer=str((beer.get("beer_name") if isinstance(beer, dict) else "") or ""),
        brewery=str((brew.get("brewery_name") if isinstance(brew, dict) else "") or ""),
        venue=str((ven.get("venue_name") if isinstance(ven, dict) else "") or ""),
        latitude=loc.get("lat") if isinstance(loc, dict) else None,
        longitude=loc.get("lng") if isinstance(loc, dict) else None,
        rating=float(rating) if isinstance(rating, (int, float)) else None,
        comment=str(it.get("checkin_comment") or ""),
        created=str(it.get("created_at") or ""),
    )


def parse(cache_dir: Path, output_dir: Path | None = None) -> UntappdRun:
    cache_dir = Path(cache_dir)
    if not cache_dir.is_dir():
        raise UntappdError(f"Untappd cache dir not found: {cache_dir}")

    run = UntappdRun(cache_dir=cache_dir)
    seen: set[tuple] = set()
    blob_dir = cache_dir / "fsCachedData"
    files = sorted(glob.glob(str(blob_dir / "*"))) if blob_dir.is_dir() else []
    for f in files:
        try:
            raw = Path(f).read_bytes()
        except OSError:
            continue
        if b"checkin" not in raw:
            continue
        txt = raw.decode("utf-8", "replace")
        i = txt.find("{")
        if i < 0:
            continue
        try:
            obj = json.loads(txt[i:])
        except (json.JSONDecodeError, ValueError):
            continue
        for it in _iter_checkins(obj):
            if not isinstance(it, dict):
                continue
            c = _to_checkin(it)
            key = (c.beer, c.venue, c.comment, c.created, c.latitude)
            if key in seen:
                continue
            seen.add(key)
            run.checkins.append(c)

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "untappd_checkins.jsonl"
        with out.open("w", encoding="utf-8") as fh:
            for c in run.checkins:
                fh.write(json.dumps(c.as_dict(), ensure_ascii=False) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run

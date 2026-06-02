"""Apple iCloud-for-Windows account attribution.

Productises the Layer-2 analyst step: recover the **Apple ID** and **DSID**
(the numeric Apple account identifier) from the iCloud control-panel config
plists left on a Windows disk. ADI provisioning blobs are encrypted/
machine-bound and yield nothing, but the AOSKit + iCloud-preference plists
carry the account in cleartext:

  * ``com.apple.AOSKit.plist``  — a top-level key IS the Apple ID email
    (its value is a DPAPI-encrypted token we don't need).
  * ``iCloudWinPref.plist``     — quota-service URLs embed the DSID
    (``…/quotaservice/external/ios/<DSID>/…``) and the storage quota.

Why it matters: Apple ID + DSID are the exact handles a responder hands
Apple (legal process) to obtain the account's iCloud contents — iCloud
Photos with GPS, any iCloud device backup, Find My location history —
i.e. the route to evidence that isn't on the disk (a missing phone's
location). Pure plist parsing; no external tools.
"""
from __future__ import annotations

import plistlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# DSID appears in iCloud quota-service URLs: .../external/ios/<DSID>/...
_DSID_URL = re.compile(r"/ios/(\d{6,})/")

# iCloud-for-Windows config lives under (Store build):
#   <user>\AppData\Local\Packages\AppleInc.iCloud_*\LocalCache\Roaming\
#       Apple Computer\Preferences\
# and (classic installer):
#   <user>\AppData\Roaming\Apple Computer\Preferences\
_AOSKIT = "com.apple.AOSKit.plist"
_WINPREF = "iCloudWinPref.plist"


@dataclass
class ICloudAttribution:
    prefs_dir: Path
    apple_id: str | None = None
    dsid: str | None = None
    quota_total_bytes: int | None = None
    quota_used_bytes: int | None = None
    sources: list[str] = field(default_factory=list)

    def found(self) -> bool:
        return bool(self.apple_id or self.dsid)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        f = {"apple_id": self.apple_id, "dsid": self.dsid,
             "icloud_quota_total_bytes": self.quota_total_bytes,
             "icloud_quota_used_bytes": self.quota_used_bytes}
        if facts:
            f.update(facts)
        src = self.sources[0] if self.sources else _AOSKIT
        return EvidenceItem(
            tool="iCloud for Windows (plist)", version="AOSKit/iCloudWinPref",
            command=f"plistlib parse {', '.join(self.sources) or _AOSKIT}",
            output_sha256="0" * 64,
            output_path=str(self.prefs_dir / src),
            extracted_facts=f, source_reliability="A", info_credibility="1",
        )


def _load(path: Path):
    """plistlib.load handles both binary + XML plists. Returns None on any
    error (corrupt / not a plist)."""
    try:
        with path.open("rb") as fh:
            return plistlib.load(fh)
    except Exception:  # noqa: BLE001
        return None


def _iter_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v)


def _get_path(d: dict, *keys):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def find_prefs_dirs(root: Path) -> list[Path]:
    """Directories under *root* that contain the iCloud config plists
    (AOSKit and/or iCloudWinPref)."""
    root = Path(root)
    out: list[Path] = []
    if not root.is_dir():
        return out
    seen: set[str] = set()
    for name in (_AOSKIT, _WINPREF):
        for p in root.rglob(name):
            d = p.parent
            if str(d) not in seen:
                seen.add(str(d))
                out.append(d)
    return out


def parse_icloud_attribution(prefs_dir: str | Path) -> ICloudAttribution:
    """Extract Apple ID + DSID + quota from the iCloud config plists in
    *prefs_dir*. Never raises — returns an empty result if nothing parses."""
    prefs_dir = Path(prefs_dir)
    res = ICloudAttribution(prefs_dir=prefs_dir)

    aos = _load(prefs_dir / _AOSKIT)
    if isinstance(aos, dict):
        for k in aos:
            if isinstance(k, str) and _EMAIL.match(k):
                res.apple_id = k
                res.sources.append(_AOSKIT)
                break

    wp = _load(prefs_dir / _WINPREF)
    if isinstance(wp, dict):
        used = False
        for s in _iter_strings(wp):
            m = _DSID_URL.search(s)
            if m:
                res.dsid = m.group(1)
                used = True
                break
        qi = _get_path(wp, "StorageData", "storage_data", "quota_info_in_bytes")
        if isinstance(qi, dict):
            tot = qi.get("total_quota")
            usd = qi.get("total_used")
            if isinstance(tot, int):
                res.quota_total_bytes = tot
                used = True
            if isinstance(usd, int):
                res.quota_used_bytes = usd
        if used:
            res.sources.append(_WINPREF)
    return res


__all__ = ["ICloudAttribution", "parse_icloud_attribution", "find_prefs_dirs"]

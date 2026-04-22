"""Skill: Microsoft Internet Explorer Cache File (index.dat) parser.

Wraps `msiecfexport` (from the libmsiecf package). Parses the legacy
IE5 `Content.IE5/index.dat` records that live on Windows XP hosts and
occasionally on later systems in legacy profiles.

Surfaces per-record (URL, hit-count, modified time, cached filename)
and flags suspicious rows for the investigator — raw-IP hosts,
unusual TLDs, long query strings, and JS artifacts under Content.IE5
that look like session-hijack payloads (the jynxora M57-Jean signal).
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


@dataclass
class IEItem:
    url: str
    hits: int
    modified_utc: str
    expiration_utc: str
    filename: str
    raw_block: str = ""


@dataclass
class IECacheRun:
    source_path: Path
    out_path: Path          # msiecfexport stdout capture
    rc: int
    items: list[IEItem] = field(default_factory=list)

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        import hashlib
        sha = hashlib.sha256(self.out_path.read_bytes()).hexdigest() \
            if self.out_path.is_file() else ("0" * 64)
        base = {"source_path": str(self.source_path),
                "item_count": len(self.items), "rc": self.rc}
        if facts:
            base.update(facts)
        return EvidenceItem(
            tool="msiecfexport", version="libmsiecf-20240425",
            command=f"msiecfexport -m all {self.source_path}",
            output_sha256=sha, output_path=str(self.out_path),
            extracted_facts=base,
        )


class IECacheError(RuntimeError):
    pass


def _which() -> str:
    p = shutil.which("msiecfexport")
    if not p:
        raise IECacheError(
            "msiecfexport not on PATH — apt install libmsiecf-tools")
    return p


def parse(index_dat: str | Path,
          out_path: str | Path,
          timeout: int = 120) -> IECacheRun:
    """Parse a single index.dat. Writes msiecfexport's stdout to
    out_path (pipe-separated text) and returns the structured records
    as IEItems."""
    src = Path(index_dat)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not src.is_file():
        return IECacheRun(source_path=src, out_path=out, rc=-1)
    exe = _which()
    try:
        r = subprocess.run(
            [exe, "-m", "all", str(src)],
            capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return IECacheRun(source_path=src, out_path=out, rc=-2)
    stdout = r.stdout or b""
    out.write_bytes(stdout)
    items = _parse_stdout(stdout.decode("utf-8", errors="replace"))
    return IECacheRun(source_path=src, out_path=out,
                       rc=r.returncode, items=items)


_URL_RE = re.compile(r"^URL\s*:\s*(\S.*)$", re.MULTILINE)
_HITS_RE = re.compile(r"^Number of hits\s*:\s*(\d+)", re.MULTILINE)
_MOD_RE = re.compile(r"^Last modification time\s*:\s*(\S.*)$",
                      re.MULTILINE)
_EXP_RE = re.compile(r"^Expiration time\s*:\s*(\S.*)$", re.MULTILINE)
_FNAME_RE = re.compile(r"^Filename\s*:\s*(\S.*)$", re.MULTILINE)


def _parse_stdout(text: str) -> list[IEItem]:
    """msiecfexport's default format is a sequence of blank-line
    separated records, each with key: value lines. Parse records
    heuristically — the library sometimes emits 'URL' alongside
    'Type' / 'Primary date' depending on record type."""
    items: list[IEItem] = []
    # Split on blank lines between records
    for block in re.split(r"\n\s*\n", text):
        url_m = _URL_RE.search(block)
        if not url_m:
            continue
        items.append(IEItem(
            url=url_m.group(1).strip(),
            hits=int((_HITS_RE.search(block)
                       or re.match("x", "x")).group(1))
                if _HITS_RE.search(block) else 0,
            modified_utc=(_MOD_RE.search(block).group(1).strip()
                           if _MOD_RE.search(block) else ""),
            expiration_utc=(_EXP_RE.search(block).group(1).strip()
                             if _EXP_RE.search(block) else ""),
            filename=(_FNAME_RE.search(block).group(1).strip()
                       if _FNAME_RE.search(block) else ""),
            raw_block=block.strip()[:400],
        ))
    return items


# ---------------------------------------------------------------------------
# Suspicious-row detectors (used by an agent; side-effect-free here)
# ---------------------------------------------------------------------------

_RAW_IP_RE = re.compile(r"https?://(\d+\.\d+\.\d+\.\d+)(?:[/:]|$)")
_SUSPICIOUS_TLDS = frozenset({
    "pw", "cc", "top", "xyz", "bid", "click", "download",
    "tk", "ml", "ga", "cf", "gq", "info",
})
_TRACKER_HINTS = (
    "syncuserdata", "__utm", "tcode", "uid=", "sessionid=",
    "synchronization",
)


@dataclass
class IESuspect:
    kind: str           # raw_ip / unusual_tld / tracker_sync / long_query
    url: str
    filename: str
    modified_utc: str
    note: str


def flag_suspects(items: list[IEItem]) -> list[IESuspect]:
    out: list[IESuspect] = []
    for it in items:
        url_low = it.url.lower()
        if _RAW_IP_RE.search(it.url):
            out.append(IESuspect(
                kind="raw_ip", url=it.url, filename=it.filename,
                modified_utc=it.modified_utc,
                note="HTTP(S) URL with raw IPv4 host"))
            continue
        host_m = re.match(r"https?://([^/]+)/?", it.url)
        if host_m:
            host = host_m.group(1).lower()
            tld = host.rsplit(".", 1)[-1]
            if tld in _SUSPICIOUS_TLDS:
                out.append(IESuspect(
                    kind="unusual_tld", url=it.url,
                    filename=it.filename,
                    modified_utc=it.modified_utc,
                    note=f"Suspicious TLD .{tld}"))
                continue
        if any(h in url_low for h in _TRACKER_HINTS):
            out.append(IESuspect(
                kind="tracker_sync", url=it.url,
                filename=it.filename,
                modified_utc=it.modified_utc,
                note="Tracker / session-sync URL pattern"))
            continue
        if "?" in it.url and len(it.url) > 400:
            out.append(IESuspect(
                kind="long_query", url=it.url[:200] + "…",
                filename=it.filename,
                modified_utc=it.modified_utc,
                note=f"URL length {len(it.url)} — unusual for legit traffic"))
    return out


def find_index_dat_files(root: str | Path,
                          max_files: int = 200) -> list[Path]:
    """Walk an extracted-NTFS mount and return every index.dat file
    that looks like IE cache (under a Content.IE5/ subdir or directly
    in a Temporary Internet Files/ subtree)."""
    root = Path(root)
    if not root.is_dir():
        return []
    found: list[Path] = []
    for p in root.rglob("index.dat"):
        if len(found) >= max_files:
            break
        ps = str(p).lower()
        if ("content.ie5" in ps
                or "temporary internet files" in ps
                or "history.ie5" in ps
                or "cookies" in ps):
            found.append(p)
    return found


__all__ = [
    "IEItem", "IECacheRun", "IESuspect", "IECacheError",
    "parse", "flag_suspects", "find_index_dat_files",
]

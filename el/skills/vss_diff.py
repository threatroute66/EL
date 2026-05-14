"""Volume Shadow Copy cross-snapshot artifact diff (FOR508 ex 3.1b).

Windows VSS keeps point-in-time snapshots of the live filesystem. When
an attacker deletes a forensically critical file (`RecentFileCache.bcf`,
`Amcache.hve`, `Security.evtx`, scheduled-task `.job`s) the live copy
disappears — but the shadow-copy version usually survives because the
attacker rarely thinks to clean shadows. Comparing live to shadow on a
small fixed list of artefacts surfaces the deletion as a load-bearing
finding (rather than a silent gap).

Wraps three libvshadow + sleuthkit primitives:

* ``vshadowinfo``  — enumerate snapshots on a raw NTFS image
* ``vshadowmount`` — expose each snapshot as a vss<N> raw device
* ``mount -o ro,loop`` — loop-mount a snapshot's NTFS volume RO

Hashing + size comparison is pure-Python so callers can unit-test the
diff logic against tmp_path fixtures without any of the FUSE / sudo
plumbing. The subprocess wrappers are only invoked at the agent layer.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


class VssError(RuntimeError):
    """Any failure in the libvshadow toolchain. Caller is expected to
    treat this as 'VSS unavailable on this image' and emit a single
    insufficient-evidence Finding rather than raising."""


# Forensic-critical artefacts compared snapshot-vs-live. Picked to be
# (a) small enough that hashing is cheap on a per-snapshot basis,
# (b) always present in a Windows install so absence-from-live is a
# meaningful signal, and (c) high-signal — each one lands directly in
# the FOR508 anti-forensics section (RecentFileCache + Amcache for
# program-execution erasure, Security.evtx for log clearing,
# Tasks/.job for persistence-removal).
#
# Path is relative to the NTFS root mount point. Globs are resolved
# at compare-time via Path.glob() so per-host variations in directory
# population don't cause sub-glob false-fires.
DEFAULT_TARGETS: tuple[str, ...] = (
    "Windows/AppCompat/Programs/RecentFileCache.bcf",
    "Windows/AppCompat/Programs/Amcache.hve",
    "Windows/System32/winevt/Logs/Security.evtx",
    "Windows/System32/winevt/Logs/System.evtx",
    "Windows/System32/winevt/Logs/Application.evtx",
    "Windows/Tasks/At*.job",
    "Windows/System32/Tasks/*",
)


@dataclass
class VssSnapshot:
    """One snapshot row from ``vshadowinfo`` output."""
    number: int
    identifier: str
    creation_utc: str          # ISO-8601 (best-effort parse from vshadowinfo)
    volume_size_bytes: int


@dataclass
class ArtifactState:
    """Per-side fingerprint of one artefact path. ``size`` and ``sha256``
    are None when the artefact is absent on that side."""
    relpath: str
    side: str                  # "live" or "snapshot:<N>"
    size: int | None
    sha256: str | None


@dataclass
class ArtifactDiff:
    """Diff result for one artefact across a (live, snapshot) pair.

    ``severity`` values:

    - ``"deleted_in_live"``  — present in snapshot, absent in live
                               (anti-forensic erasure)
    - ``"shrunk_in_live"``   — present in both, live size < snapshot
                               (truncation / log clear)
    - ``"changed"``           — present in both, sizes equal but sha
                               differs (timestomp / content rewrite)
    - ``"identical"``         — same bytes; not interesting
    - ``"absent_both"``       — never existed on this host; not
                               interesting (artefact list is generic)
    """
    relpath: str
    snapshot_number: int
    severity: str
    live: ArtifactState
    snapshot: ArtifactState
    delta_bytes: int = 0       # snapshot.size - live.size (positive = live shrunk)


# ---------------------------------------------------------------------------
# Pure helpers — unit-testable without any subprocess or filesystem mount
# ---------------------------------------------------------------------------

# libvshadow's CLI calls each snapshot a "Store" in its output —
# checked against vshadowinfo 20240504 directly. Older docs and SANS
# slides occasionally say "Snapshot" for the same concept; accept
# both as section headers so future libvshadow renames don't break
# the parser silently (which is exactly what happened on the SRL-2015
# r2 run — every disk reported 0 shadows because the section header
# was Store:, not Snapshot:).
_SNAPSHOT_HEADER_RE = re.compile(r"^(?:Store|Snapshot):\s*(\d+)\s*$", re.M)
_FIELD_RE = re.compile(r"^\s+(?P<k>[A-Za-z0-9 _-]+?)\s*:\s*(?P<v>.*?)\s*$")
_SIZE_BYTES_RE = re.compile(r"\((\d+)\s*bytes\)")


def parse_vshadowinfo(stdout: str) -> list[VssSnapshot]:
    """Parse ``vshadowinfo`` text output into VssSnapshot records.

    Format (libvshadow 20240504):

        Store: 1
            Identifier        : aaaa-bbbb-cccc-dddd
            Creation time     : Apr 04, 2012 17:30:11.000000000 UTC
            Volume size       : 64 GiB (68719476736 bytes)

    Robust to extra/missing fields — only ``number`` is required to
    construct a record. Unknown fields (e.g. set identifier, attribute
    flags) are ignored. Both ``Store:`` (current libvshadow) and the
    legacy ``Snapshot:`` header keyword are accepted.
    """
    out: list[VssSnapshot] = []
    # Walk the text snapshot-block by snapshot-block.
    for m in _SNAPSHOT_HEADER_RE.finditer(stdout):
        number = int(m.group(1))
        # Block ends at the next "Snapshot:" line or end-of-string.
        next_m = _SNAPSHOT_HEADER_RE.search(stdout, pos=m.end())
        block_end = next_m.start() if next_m else len(stdout)
        block = stdout[m.end():block_end]

        ident = ""
        ctime = ""
        size = 0
        for line in block.splitlines():
            fm = _FIELD_RE.match(line)
            if not fm:
                continue
            k = fm.group("k").strip().lower()
            v = fm.group("v").strip()
            if k == "identifier":
                ident = v
            elif k == "creation time":
                ctime = v   # raw vshadowinfo string; caller can normalise
            elif k == "volume size":
                sm = _SIZE_BYTES_RE.search(v)
                if sm:
                    size = int(sm.group(1))
        out.append(VssSnapshot(number=number, identifier=ident,
                                creation_utc=ctime, volume_size_bytes=size))
    return out


def _hash_file(p: Path, chunk: int = 1 << 20) -> tuple[int, str] | None:
    """SHA-256 a file, returning (size, sha) — or None when the path
    doesn't exist / isn't a file. Reads in 1 MiB chunks so the wrapper
    stays bounded on multi-GB EVTX files."""
    if not p.is_file():
        return None
    h = hashlib.sha256()
    size = 0
    with p.open("rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf)
            size += len(buf)
    return size, h.hexdigest()


def _expand_target(mount_root: Path, target: str) -> list[Path]:
    """Expand a target spec (literal path or ``Path.glob`` pattern)
    relative to the mount root. Returns absolute paths that exist;
    empty list when nothing matches."""
    if any(c in target for c in "*?["):
        return [p for p in mount_root.glob(target) if p.is_file()]
    p = mount_root / target
    return [p] if p.is_file() else []


def fingerprint(mount_root: Path, side: str,
                 targets: tuple[str, ...] = DEFAULT_TARGETS) -> dict[str, ArtifactState]:
    """Walk the target list, hash every match. Result keyed on the
    relative path from mount_root so the diff function can join
    live and snapshot fingerprints by path.
    """
    out: dict[str, ArtifactState] = {}
    for target in targets:
        matches = _expand_target(mount_root, target)
        if not matches:
            # Record an absent-on-this-side state for the canonical
            # target so downstream diff sees "absent" rather than
            # silently dropping the entry.
            out[target] = ArtifactState(
                relpath=target, side=side, size=None, sha256=None)
            continue
        for m in matches:
            rel = str(m.relative_to(mount_root))
            res = _hash_file(m)
            if res is None:
                out[rel] = ArtifactState(
                    relpath=rel, side=side, size=None, sha256=None)
            else:
                size, sha = res
                out[rel] = ArtifactState(
                    relpath=rel, side=side, size=size, sha256=sha)
    return out


def diff_fingerprints(
    live: dict[str, ArtifactState],
    snapshot: dict[str, ArtifactState],
    snapshot_number: int,
) -> list[ArtifactDiff]:
    """Compute per-artefact diff between two fingerprint dicts.

    Returns one ``ArtifactDiff`` per path that exists on either side.
    Drops the boring categories (``identical`` and ``absent_both``)
    so callers only see actionable rows.
    """
    out: list[ArtifactDiff] = []
    for path in sorted(set(live) | set(snapshot)):
        l = live.get(path, ArtifactState(path, "live", None, None))
        s = snapshot.get(path, ArtifactState(
            path, f"snapshot:{snapshot_number}", None, None))
        # Classify
        if l.sha256 is None and s.sha256 is None:
            sev = "absent_both"
        elif l.sha256 is None and s.sha256 is not None:
            sev = "deleted_in_live"
        elif l.sha256 is not None and s.sha256 is None:
            sev = "absent_in_snapshot"   # rarely interesting; surfaced for completeness
        elif l.sha256 == s.sha256:
            sev = "identical"
        elif l.size is not None and s.size is not None and l.size < s.size:
            sev = "shrunk_in_live"
        else:
            sev = "changed"
        if sev in ("identical", "absent_both", "absent_in_snapshot"):
            continue
        delta = 0
        if l.size is not None and s.size is not None:
            delta = s.size - l.size
        out.append(ArtifactDiff(
            relpath=path,
            snapshot_number=snapshot_number,
            severity=sev,
            live=l,
            snapshot=s,
            delta_bytes=delta,
        ))
    return out


# ---------------------------------------------------------------------------
# Subprocess wrappers — only at the agent layer. Each raises VssError on
# failure so the agent emits an insufficient-evidence Finding rather than
# crashing.
# ---------------------------------------------------------------------------

def vshadowinfo(raw_image: Path, offset_bytes: int = 0,
                 timeout: int = 60) -> list[VssSnapshot]:
    """Enumerate snapshots on a raw NTFS image. ``offset_bytes`` is
    the byte offset of the partition start (= start_sector × sector_size)
    when ``raw_image`` is a whole-disk stream; pass 0 when the image
    is already a single partition. Returns [] when the volume has no
    shadow copies (the common case on a clean workstation). Raises
    VssError on tool failure."""
    cmd = ["vshadowinfo"]
    if offset_bytes:
        cmd += ["-o", str(offset_bytes)]
    cmd.append(str(raw_image))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        raise VssError(f"vshadowinfo not found on PATH: {e}") from e
    except subprocess.TimeoutExpired as e:
        raise VssError(f"vshadowinfo timeout: {e}") from e
    # rc=0 with "Number of snapshots: 0" → empty result, NOT an error
    if proc.returncode != 0:
        # Some images emit "no shadow copies" as rc!=0 with a
        # specific message — treat as empty rather than error.
        # The check is case-INSENSITIVE because libvshadow 20240504
        # emits "No Volume Shadow Snapshots found." with capital N;
        # earlier tooling docs reference lowercase variants. We saw
        # the tdungan-disk case raise a VssError on the SRL-2015 r2
        # run because the substring match was case-sensitive.
        msg_lower = (proc.stderr or proc.stdout).strip().lower()
        if "no volume shadow" in msg_lower or "no shadow" in msg_lower:
            return []
        raise VssError(
            f"vshadowinfo failed (rc={proc.returncode}): "
            f"{(proc.stderr or proc.stdout).strip()[:300]}")
    return parse_vshadowinfo(proc.stdout)


def vshadowmount(raw_image: Path, mount_dir: Path,
                  offset_bytes: int = 0, timeout: int = 60) -> Path:
    """Expose every snapshot under mount_dir as vss1, vss2, … raw
    devices. ``offset_bytes`` mirrors :func:`vshadowinfo`. Returns
    the mount_dir Path. Caller unmounts via ``fusermount -u``
    (libvshadow uses FUSE)."""
    mount_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["sudo", "vshadowmount", "-X", "allow_other"]
    if offset_bytes:
        cmd += ["-o", str(offset_bytes)]
    cmd += [str(raw_image), str(mount_dir)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        raise VssError(f"vshadowmount not found: {e}") from e
    except subprocess.TimeoutExpired as e:
        raise VssError(f"vshadowmount timeout: {e}") from e
    if proc.returncode != 0:
        raise VssError(
            f"vshadowmount failed (rc={proc.returncode}): "
            f"{(proc.stderr or proc.stdout).strip()[:300]}")
    return mount_dir


def fusermount_unmount(mount_dir: Path, timeout: int = 30) -> None:
    """Best-effort FUSE unmount; idempotent (silent on already-unmounted)."""
    try:
        subprocess.run(["fusermount", "-u", str(mount_dir)],
                       capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


# ---------------------------------------------------------------------------
# Evidence helper
# ---------------------------------------------------------------------------

def diff_as_evidence(diff: ArtifactDiff, raw_image: Path) -> EvidenceItem:
    """Build an EvidenceItem for one ArtifactDiff so the agent can emit
    a grounded Finding. Sha256 is the snapshot-side hash (when present)
    so the analyst can re-verify against the actual shadow content."""
    sha = (diff.snapshot.sha256 or diff.live.sha256
           or hashlib.sha256(diff.relpath.encode()).hexdigest())
    return EvidenceItem(
        tool="libvshadow+sleuthkit",
        version="vshadowinfo 20240504",
        command=(f"vshadowinfo {raw_image} | "
                 f"vshadowmount; sha256(snapshot:{diff.snapshot_number}/{diff.relpath})"),
        output_sha256=sha,
        output_path=str(raw_image),
        extracted_facts={
            "relpath": diff.relpath,
            "snapshot": diff.snapshot_number,
            "severity": diff.severity,
            "live_size": diff.live.size,
            "live_sha256": diff.live.sha256,
            "snapshot_size": diff.snapshot.size,
            "snapshot_sha256": diff.snapshot.sha256,
            "delta_bytes": diff.delta_bytes,
        },
    )


__all__ = [
    "VssError",
    "VssSnapshot",
    "ArtifactState",
    "ArtifactDiff",
    "DEFAULT_TARGETS",
    "parse_vshadowinfo",
    "fingerprint",
    "diff_fingerprints",
    "vshadowinfo",
    "vshadowmount",
    "fusermount_unmount",
    "diff_as_evidence",
]

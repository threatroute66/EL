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
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem
from el.skills.ntfs_vbr import is_ntfs_vbr


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
                 timeout: int = 60, sudo: bool = False) -> list[VssSnapshot]:
    """Enumerate snapshots on a raw NTFS image. ``offset_bytes`` is
    the byte offset of the partition start (= start_sector × sector_size)
    when ``raw_image`` is a whole-disk stream; pass 0 when the image
    is already a single partition. ``sudo`` is required when ``raw_image``
    is a root-owned block device (e.g. the device-mapper overlay built by
    :func:`vss_open`); a user-readable fuse/file path does not need it.
    Returns [] when the volume has no shadow copies (the common case on a
    clean workstation). Raises VssError on tool failure."""
    cmd = (["sudo", "vshadowinfo"] if sudo else ["vshadowinfo"])
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
# vss_open — make a truncated / partition-short NTFS image libvshadow-openable
# ---------------------------------------------------------------------------
#
# libvshadow validates the NTFS *backup* VBR, which lives in the volume's
# LAST sector (byte offset = total_sectors × bytes_per_sector, read from the
# primary VBR's BPB). E01 acquisitions of a single partition routinely end a
# few sectors short of that declared size, so vshadowinfo fails with
# "unable to read backup NTFS volume header" — NOT because shadows are
# absent, but because the sector it wants to read is past EOF. (Seen on the
# rocba-cdrive image: 7 sectors short → all 5 snapshots invisible until
# repaired.)
#
# The fix is the read-only analogue of `dd if=primary of=backup`: present a
# block device that is the original image followed by a zero pad whose final
# region carries a copy of the primary VBR at the backup offset. We do this
# with a device-mapper *linear* overlay (loop(image) + loop(pad)) so no
# multi-GB copy of the evidence is made and the original stays byte-for-byte
# intact. The arithmetic below is pure + unit-tested; only vss_open/vss_close
# touch losetup/dmsetup.

# vshadowinfo error fragments that mean "backup VBR unreadable / wrong size",
# as opposed to a genuine "no shadow copies" or a real corruption. Matched
# case-insensitively against the VssError text.
_BACKUP_HEADER_ERRORS: tuple[str, ...] = (
    "backup ntfs volume header",
    "unable to read ntfs volume header",
    "invalid volume system signature",
)

# NTFS BPB field offsets within the 512-byte VBR.
_BPB_BYTES_PER_SECTOR = 0x0B   # 2 bytes LE
_BPB_TOTAL_SECTORS = 0x28      # 8 bytes LE (volume sectors-1; backup VBR sector)


@dataclass
class VssRepairPlan:
    """Pure geometry for the backup-VBR overlay. All byte/sector values are
    derived from the primary VBR's BPB + the image size — no I/O."""
    needs_repair: bool
    bytes_per_sector: int
    total_sectors: int
    image_size: int
    backup_vbr_abs_offset: int     # where libvshadow expects the backup VBR
    device_bytes_needed: int       # min device length to read that sector
    pad_bytes: int                 # zero pad to append (0 when no repair)
    backup_vbr_pad_offset: int     # offset of the VBR copy *within* the pad
    image_sectors_512: int         # dm works in 512-byte sectors
    pad_sectors_512: int


def plan_vss_repair(image_size: int, vbr: bytes, offset_bytes: int = 0,
                    slack_sectors: int = 8) -> VssRepairPlan:
    """Compute the overlay geometry needed for libvshadow to read the backup
    VBR of an NTFS volume whose image is shorter than the volume's declared
    size. ``vbr`` is the 512-byte primary boot sector at ``offset_bytes``.

    Raises VssError when ``vbr`` is not a valid NTFS VBR (so the caller does
    not silently build a bogus device)."""
    if not is_ntfs_vbr(vbr):
        raise VssError("primary VBR is not a valid NTFS boot sector — "
                       "cannot compute backup-VBR geometry")
    bps = int.from_bytes(vbr[_BPB_BYTES_PER_SECTOR:_BPB_BYTES_PER_SECTOR + 2],
                         "little")
    total = int.from_bytes(vbr[_BPB_TOTAL_SECTORS:_BPB_TOTAL_SECTORS + 8],
                           "little")
    if bps not in (256, 512, 1024, 2048, 4096) or total <= 0:
        raise VssError(f"implausible NTFS BPB (bytes/sector={bps}, "
                       f"total_sectors={total})")
    backup_abs = offset_bytes + total * bps
    device_needed = backup_abs + bps            # must be able to read that sector
    if image_size >= device_needed:
        # Image already covers the backup VBR — vshadow's failure (if any)
        # was for some other reason; padding won't help.
        return VssRepairPlan(
            needs_repair=False, bytes_per_sector=bps, total_sectors=total,
            image_size=image_size, backup_vbr_abs_offset=backup_abs,
            device_bytes_needed=device_needed, pad_bytes=0,
            backup_vbr_pad_offset=-1,
            image_sectors_512=image_size // 512, pad_sectors_512=0)
    pad_bytes = (device_needed - image_size) + slack_sectors * bps
    return VssRepairPlan(
        needs_repair=True, bytes_per_sector=bps, total_sectors=total,
        image_size=image_size, backup_vbr_abs_offset=backup_abs,
        device_bytes_needed=device_needed, pad_bytes=pad_bytes,
        backup_vbr_pad_offset=backup_abs - image_size,
        image_sectors_512=image_size // 512,
        pad_sectors_512=(pad_bytes + 511) // 512)


@dataclass
class VssVolume:
    """A libvshadow-openable block device for a raw NTFS volume, plus the
    teardown state needed to release it. Pass ``device`` to vshadowinfo /
    vshadowmount. ``repaired`` is True when the backup-VBR overlay was built
    (vs the image opening directly)."""
    device: Path
    repaired: bool
    snapshots: list[VssSnapshot] = field(default_factory=list)
    _loops: list[str] = field(default_factory=list)
    _dm_name: str | None = None
    _pad_path: Path | None = None


# Monotonic per-process counter so concurrent / sequential vss_open() calls in
# one process each get a unique dm device + pad file. Using only os.getpid()
# collided when an agent recovered several wiped artifacts in a row ("Device or
# resource busy" on the 2nd+ create, even after vss_close).
_VSS_SEQ = 0


def _next_vss_tag() -> str:
    global _VSS_SEQ
    _VSS_SEQ += 1
    return f"{os.getpid()}_{_VSS_SEQ}"


def _is_backup_header_error(msg: str) -> bool:
    m = msg.lower()
    return any(frag in m for frag in _BACKUP_HEADER_ERRORS)


def _run_priv(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        raise VssError(f"{cmd[0]} not found on PATH: {e}") from e
    except subprocess.TimeoutExpired as e:
        raise VssError(f"{' '.join(cmd[:2])} timeout: {e}") from e


def _losetup_ro(path: Path, timeout: int = 30) -> str:
    r = _run_priv(["sudo", "losetup", "-r", "-f", "--show", str(path)], timeout)
    if r.returncode != 0 or not r.stdout.strip():
        raise VssError(f"losetup failed for {path}: {(r.stderr or r.stdout).strip()[:200]}")
    return r.stdout.strip()


def vss_open(raw_image: Path, work_dir: Path, offset_bytes: int = 0,
             timeout: int = 60) -> VssVolume:
    """Return a :class:`VssVolume` whose ``device`` libvshadow can enumerate.

    Fast path: try ``vshadowinfo`` on the image directly. Only when it fails
    with a *backup-VBR* error (truncated/partition-short image) do we build
    the read-only device-mapper overlay that splices a copy of the primary
    VBR to the backup offset. Any other VssError (genuine corruption, no
    tooling) propagates unchanged — we don't paper over real failures.

    The caller MUST call :func:`vss_close` on the result to release the loop
    + dm devices and the scratch pad file.
    """
    raw_image = Path(raw_image)
    try:
        snaps = vshadowinfo(raw_image, offset_bytes, timeout)
        return VssVolume(device=raw_image, repaired=False, snapshots=snaps)
    except VssError as e:
        if not _is_backup_header_error(str(e)):
            raise

    # --- backup-VBR overlay repair ----------------------------------------
    with raw_image.open("rb") as f:
        f.seek(offset_bytes)
        vbr = f.read(512)
    image_size = raw_image.stat().st_size
    plan = plan_vss_repair(image_size, vbr, offset_bytes)
    if not plan.needs_repair:
        # Image already covers the backup VBR; the failure was something else.
        raise VssError("vshadowinfo failed but image already spans the backup "
                       "VBR offset — not a truncation; not repairing")

    work_dir.mkdir(parents=True, exist_ok=True)
    tag = _next_vss_tag()
    pad_path = work_dir / f"vss_pad_{tag}.img"
    # zero pad with a copy of the primary VBR at the backup offset
    with pad_path.open("wb") as p:
        p.truncate(plan.pad_sectors_512 * 512)
        p.seek(plan.backup_vbr_pad_offset)
        p.write(vbr)

    loops: list[str] = []
    dm_name = f"elvss_{tag}"
    try:
        loop_main = _losetup_ro(raw_image, timeout)
        loops.append(loop_main)
        loop_pad = _losetup_ro(pad_path, timeout)
        loops.append(loop_pad)
        table = (f"0 {plan.image_sectors_512} linear {loop_main} 0\n"
                 f"{plan.image_sectors_512} {plan.pad_sectors_512} linear {loop_pad} 0\n")
        r = _run_priv(["sudo", "dmsetup", "create", dm_name, "--table", table.strip()],
                      timeout)
        if r.returncode != 0:
            raise VssError(f"dmsetup create failed: {(r.stderr or r.stdout).strip()[:200]}")
        device = Path(f"/dev/mapper/{dm_name}")
        # the dm node is root-owned → vshadowinfo needs sudo here (unlike the
        # user-readable fuse file the fast path enumerates).
        snaps = vshadowinfo(device, offset_bytes, timeout, sudo=True)
        return VssVolume(device=device, repaired=True, snapshots=snaps,
                         _loops=loops, _dm_name=dm_name, _pad_path=pad_path)
    except Exception:
        # roll back any partial scaffolding before propagating
        vss_close(VssVolume(device=Path("/dev/null"), repaired=True,
                            _loops=loops, _dm_name=dm_name, _pad_path=pad_path))
        raise


def vss_close(vol: VssVolume) -> None:
    """Release the overlay scaffolding built by :func:`vss_open`. Idempotent
    and best-effort: a direct-opened volume (``repaired=False``) is a no-op.
    Order matters — remove the dm device before detaching its loop backers."""
    if not vol.repaired:
        return
    if vol._dm_name:
        _run_priv(["sudo", "dmsetup", "remove", vol._dm_name], 30)
    for loop in vol._loops:
        _run_priv(["sudo", "losetup", "-d", loop], 30)
    if vol._pad_path:
        try:
            vol._pad_path.unlink()
        except OSError:
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
    "VssRepairPlan",
    "VssVolume",
    "plan_vss_repair",
    "vss_open",
    "vss_close",
]

"""Skill: extract YAFFS2 filesystem images via the SIFT-bundled
``unyaffs`` CLI.

Closes the corpus-gated gap-doc bullet "MTD/YAFFS2-formatted older
Android phone dumps". Pre-Android-4 phones used MTD partitions with
the YAFFS2 (Yet Another Flash File System v2) filesystem on
/system, /data, and /cache. The 2011-vintage Android dump at
``/mnt/hgfs/hackathon/Case2/`` is the canonical example: 10
``mtdN.dd`` raw partition images plus an ``sdcard.dd`` FAT image.

EL philosophy (CLAUDE.md Step 0): we wrap the SIFT-bundled
``unyaffs`` (Debian/Ubuntu package ``unyaffs`` — added to
``provisioning/apt-packages.txt``) rather than reimplementing the
parser. The SIFT default is the Whitechapel ``unyaffs 0.9.7``
binary which handles the canonical 2 KB page + 64 B OOB layout
common on Android 2.x / 3.x phones.

Detection: YAFFS2 has no single magic-byte header — object-header
records are scattered. We use a structural heuristic that scans
the first ~256 KB looking for the YAFFS2 object-header pattern
(``0x0001`` or ``0x0002`` type-tag followed by null-padded name +
plausible mode/uid/gid). Combined with the operator's MTD-bundle
folder shape (multiple ``mtdN.dd`` files), this is sufficient
triage.

Two entry points:

- ``is_yaffs2(path)`` — heuristic detector for a single .dd file.
- ``extract(image, out_dir)`` — subprocess wrap of ``unyaffs``.
  Tolerates failure gracefully; the wrapper records stdout/stderr
  and returns a structured ``Yaffs2ExtractResult`` so the agent
  layer can emit a clean Finding regardless of outcome.
- ``walk_bundle(bundle_dir, out_root)`` — convenience driver:
  walk a directory of ``mtd*.dd`` files, try extraction on each,
  return per-partition results.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


# YAFFS2 object-header structural fingerprint. The on-NAND struct:
#   u32 type         offset 0   (1=FILE, 2=SYMLINK, 3=DIR, 4=HARDLINK,
#                                 5=SPECIAL, 6=UNKNOWN)
#   u32 parent_id    offset 4
#   u16 sum_unused   offset 8   (high bytes 0xFFFF on modern YAFFS2)
#   char name[256]   offset 10  (null-padded ASCII)
#
# Detector requires:
#   1. At least 3 candidate headers in the scan window
#   2. Each candidate carries a plausible name (3+ ASCII chars
#      followed by null padding at offset+10)
#   3. parent_id ≤ 1,000,000 (real filesystems don't have IDs
#      in the billions; random kernel bytes do)
#   4. Headers at stride-aligned offsets (page boundaries —
#      typically 2 KB but we try 512 / 1024 / 2048 / 4096)
#
# Tighter than a single regex match because kernel images
# (Android boot.img with `ANDROID!` magic) carry random byte
# sequences that lookalike-match individual headers.
_VALID_TYPES = (1, 2, 3, 4, 5, 6)
_STRIDES = (512, 1024, 2048, 4096)
_MAX_PARENT_ID = 1_000_000


@dataclass
class Yaffs2DetectResult:
    path: Path
    is_yaffs2: bool = False
    candidate_headers: int = 0
    sample_names: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class Yaffs2ExtractResult:
    image_path: Path
    out_dir: Path
    success: bool = False
    rc: int = -1
    file_count: int = 0
    bytes_extracted: int = 0
    error: str = ""
    stdout_path: Path | None = None
    stderr_path: Path | None = None


def _unyaffs_bin() -> str | None:
    """Indirected for monkeypatching in tests."""
    return shutil.which("unyaffs")


def _unyaffs2_bin() -> str | None:
    """Locate the yaffs2utils ``unyaffs2`` binary (separate
    project from `unyaffs` — built from source per
    ``install.sh``'s yaffs2utils stage). Tries:
      1. PATH lookup
      2. /opt/yaffs2utils/unyaffs2 (canonical install location)
      3. EL_YAFFS2UTILS_DIR/unyaffs2 (operator override)
    Returns None when not found — the wrapper degrades to
    unyaffs-only mode."""
    p = shutil.which("unyaffs2")
    if p:
        return p
    canonical = Path("/opt/yaffs2utils/unyaffs2")
    if canonical.is_file():
        return str(canonical)
    import os
    env = os.environ.get("EL_YAFFS2UTILS_DIR")
    if env:
        cand = Path(env) / "unyaffs2"
        if cand.is_file():
            return str(cand)
    return None


def _looks_like_header(blob: bytes, off: int) -> str | None:
    """Return the decoded name iff blob[off..off+266] looks like a
    YAFFS2 object header. None when any structural check fails.

    Layout (little-endian on ARM and x86 alike — YAFFS2 is host-
    byte-order, but the image is captured on the device, so for
    Android phones this is LE):
        offset 0  u32 type           (1..6)
        offset 4  u32 parent_id      (1..1,000,000)
        offset 8  u16 sum_unused
        offset 10 char name[256]     (NUL-padded ASCII)
    """
    if off + 266 > len(blob):
        return None
    type_val = int.from_bytes(blob[off:off + 4], "little")
    if type_val not in _VALID_TYPES:
        return None
    parent_id = int.from_bytes(blob[off + 4:off + 8], "little")
    if parent_id < 1 or parent_id > _MAX_PARENT_ID:
        return None
    name_field = blob[off + 10:off + 10 + 256]
    # Find first NUL terminator
    end = name_field.find(b"\x00")
    if end < 3:
        return None
    name_bytes = name_field[:end]
    # All bytes printable ASCII (no control chars, no high bytes)
    if not all(32 <= b < 127 for b in name_bytes):
        return None
    # Bytes after the NUL must continue to be NUL-padded — name
    # field is fixed 256 bytes; anything else means we're inside
    # arbitrary binary data, not a real header.
    if name_field[end:end + 4] != b"\x00\x00\x00\x00":
        return None
    try:
        return name_bytes.decode("ascii")
    except UnicodeDecodeError:
        return None


def is_yaffs2(path: Path,
               *, scan_bytes: int = 1024 * 1024,
               min_headers: int = 2,
               ) -> Yaffs2DetectResult:
    """Heuristic detector — scan up to ``scan_bytes`` of the head
    of the image, walking each canonical YAFFS2 chunk stride
    (512 / 1024 / 2048 / 4096 B) and counting structurally-valid
    object headers at stride-aligned offsets. Returns
    ``is_yaffs2=True`` when ≥``min_headers`` valid headers land on
    a single consistent stride.

    Stride-aligned check is the discriminator that tells real
    YAFFS2 partitions apart from kernel images carrying
    coincidental byte patterns: only a real YAFFS2 image has
    headers at consistent page-aligned positions. Threshold
    defaults to 2 because real partitions can have sparse
    early directory trees (validated against Case2's mtd6.dd
    which carries only 2 valid headers — ``linker`` and
    ``printenv`` — in the first 1 MB)."""
    p = Path(path)
    out = Yaffs2DetectResult(path=p)
    if not p.is_file():
        out.note = "not a file"
        return out
    try:
        with p.open("rb") as f:
            head = f.read(scan_bytes)
    except OSError as e:
        out.note = f"read failed: {e}"
        return out
    best_count = 0
    best_names: list[str] = []
    best_stride = 0
    for stride in _STRIDES:
        names: list[str] = []
        for off in range(0, len(head) - 266, stride):
            n = _looks_like_header(head, off)
            if n is not None:
                names.append(n)
                if len(names) >= 64:
                    break
        if len(names) > best_count:
            best_count = len(names)
            best_names = names
            best_stride = stride
    out.candidate_headers = best_count
    out.sample_names = best_names[:10]
    out.is_yaffs2 = best_count >= min_headers
    if not out.is_yaffs2:
        out.note = (
            f"{best_count} stride-aligned header(s) at best "
            f"stride={best_stride} — below YAFFS2 detection "
            f"threshold ({min_headers})")
    else:
        out.note = (f"detected {best_count} headers at stride "
                    f"{best_stride} B")
    return out


# Canonical YAFFS2 NAND geometries the wrapper tries when
# ``unyaffs -d`` autodetect fails. Order matters — most common
# Android phone geometries first. The list is conservative
# (avoids exotic 4K-page configurations) so the worst-case
# extract attempt count stays bounded.
_FALLBACK_GEOMETRIES = (
    ("-b", "-c", "2", "-s", "64"),    # 2K page + 64B OOB + bad-block (most Android NAND)
    ("-c", "2", "-s", "64"),           # 2K page + 64B OOB, no bad-block
    ("-c", "2", "-s", "32"),           # 2K page + 32B OOB
    ("-c", "2", "-s", "16"),           # 2K page + 16B OOB (older NAND)
    ("-c", "4", "-s", "128"),          # 4K page + 128B OOB (newer NAND)
    (),                                 # autodetect (default)
)


def _detect_layout(binr: str, image: Path,
                    timeout: int) -> tuple[str, ...] | None:
    """Run ``unyaffs -d <image>`` to ask the binary for its
    autodetected layout. Returns the flag tuple to use for
    extraction (e.g. ``("-b", "-c", "2", "-s", "64")``) or None
    when no layout is recognised."""
    try:
        proc = subprocess.run(
            [binr, "-d", str(image)],
            capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    # Output shape:
    #   Detected flash layout(s):
    #   -b -c 2  -s 64  : chunk size =  2K, spare size =  64, ...
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("-"):
            # Take the prefix before the colon — that's the flags
            head = line.split(":", 1)[0].strip()
            if head:
                return tuple(head.split())
    return None


def _count_files(d: Path) -> tuple[int, int]:
    file_count = 0
    bytes_extracted = 0
    for f in d.rglob("*"):
        if f.is_file():
            file_count += 1
            try:
                bytes_extracted += f.stat().st_size
            except OSError:
                pass
    return file_count, bytes_extracted


# yaffs2utils unyaffs2 page+spare combos, ordered by frequency
# in real Android NAND dumps. unyaffs2 takes ``-p <pagesize>
# -s <sparesize>`` rather than unyaffs's ``-c <KB> -s <bytes>``.
_UNYAFFS2_GEOMETRIES = (
    ("-p", "2048", "-s", "64"),     # 2K page + 64B OOB (most common)
    ("-p", "2048", "-s", "32"),     # 2K page + 32B OOB
    ("-p", "2048", "-s", "16"),     # 2K page + 16B OOB
    ("-p", "4096", "-s", "128"),    # 4K page + 128B OOB
    ("-p", "512", "-s", "16"),      # 512B page (yaffs1 / oldest NAND)
    (),                              # autodetect
)


def _try_extractor(binr: str, image: Path, out: Path,
                    geometries: tuple[tuple[str, ...], ...],
                    timeout: int,
                    pre_invocation_clear: bool = True,
                    ) -> tuple[bool, int, int, int,
                                tuple[str, ...] | None,
                                subprocess.CompletedProcess | None,
                                str]:
    """Run a YAFFS2 extractor across ``geometries`` until one
    produces files-on-disk. Returns
    ``(success, rc, file_count, bytes, used_geometry, last_proc,
    error)``.

    Generic so we use the same retry loop for both the
    Whitechapel ``unyaffs`` (apt) and yaffs2utils ``unyaffs2``
    (built from source). Caller passes the right geometry tuple
    list per binary."""
    last_proc: subprocess.CompletedProcess | None = None
    used: tuple[str, ...] | None = None
    error = ""
    for g in geometries:
        if pre_invocation_clear:
            try:
                for child in out.iterdir():
                    if child.is_dir():
                        import shutil as _sh
                        _sh.rmtree(child, ignore_errors=True)
                    else:
                        child.unlink(missing_ok=True)
            except OSError:
                pass
        cmd = [binr, *g, str(image), str(out)]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout)
        except subprocess.TimeoutExpired:
            error = (f"timed out after {timeout}s on geometry "
                     f"{' '.join(g) or '<auto>'}")
            return False, -1, 0, 0, None, None, error
        except OSError as e:
            error = f"invocation failed: {e}"
            return False, -1, 0, 0, None, None, error
        last_proc = proc
        file_count, bytes_extracted = _count_files(out)
        if file_count > 0:
            return (True, proc.returncode, file_count,
                    bytes_extracted, g, proc, "")
    return (False,
            last_proc.returncode if last_proc else -1,
            0, 0, None, last_proc,
            f"failed across {len(geometries)} geometry attempt(s)")


def extract(image: Path, out_dir: Path,
             *, timeout: int = 600) -> Yaffs2ExtractResult:
    """Extract a YAFFS2 image into ``out_dir``.

    Two-stage workflow:
      1. ``unyaffs`` (Whitechapel, apt). Try ``unyaffs -d``
         autodetect; on failure walk 5 canonical Android NAND
         geometries.
      2. ``unyaffs2`` (yaffs2utils, source-built). Triggers
         when stage 1 produced 0 files. Walks 6 page/spare
         combos (2K/64, 2K/32, 2K/16, 4K/128, 512/16, auto).

    The two-stage chain handles the real-world split observed
    on Case2: ``unyaffs 0.9.7`` extracts the system partition
    (mtd6) cleanly but fails on the userdata partition (mtd8)
    with "Can't determine flash layout"; ``unyaffs2`` from
    yaffs2utils handles mtd8 (1,997 files / 181 MB).

    Always returns a result (no raise) so the agent's _safe
    wrapper can write a clean Finding regardless of outcome.
    Real-world extractors often emit non-zero rc on partition
    tail bad blocks even when the bulk extracted successfully
    — we count files-on-disk, not rc, as the success signal."""
    img = Path(image)
    out = Path(out_dir)
    res = Yaffs2ExtractResult(image_path=img, out_dir=out)
    if not img.is_file():
        res.error = f"image not found: {img}"
        return res
    out.mkdir(parents=True, exist_ok=True)
    res.stdout_path = out.parent / f"{out.name}.unyaffs.stdout"
    res.stderr_path = out.parent / f"{out.name}.unyaffs.stderr"

    binr = _unyaffs_bin()
    binr2 = _unyaffs2_bin()
    if binr is None and binr2 is None:
        res.error = (
            "neither unyaffs (apt) nor unyaffs2 (yaffs2utils, "
            "source-built) is installed. Install via "
            "`apt-get install unyaffs` AND/OR run install.sh "
            "yaffs2utils stage to build /opt/yaffs2utils/.")
        return res

    last_proc: subprocess.CompletedProcess | None = None
    used_geometry: tuple[str, ...] | None = None
    used_tool = ""

    # --- Stage 1: unyaffs (apt) --------------------------------
    if binr is not None:
        detected = _detect_layout(binr, img, timeout=60)
        geometries: list[tuple[str, ...]] = []
        if detected is not None:
            geometries.append(detected)
        for g in _FALLBACK_GEOMETRIES:
            if g not in geometries:
                geometries.append(g)
        ok, rc, fc, bx, geo, proc, err = _try_extractor(
            binr, img, out, tuple(geometries), timeout)
        last_proc = proc
        if ok:
            res.success = True
            res.rc = rc
            res.file_count = fc
            res.bytes_extracted = bx
            used_geometry = geo
            used_tool = "unyaffs"

    # --- Stage 2: unyaffs2 (yaffs2utils) -----------------------
    # Only fires when stage 1 produced no files. Catches the
    # Case2 mtd8 shape — userdata partitions whose layout
    # unyaffs 0.9.7 doesn't recognise but unyaffs2 does.
    if not res.success and binr2 is not None:
        ok, rc, fc, bx, geo, proc, err = _try_extractor(
            binr2, img, out, _UNYAFFS2_GEOMETRIES, timeout)
        last_proc = proc
        if ok:
            res.success = True
            res.rc = rc
            res.file_count = fc
            res.bytes_extracted = bx
            used_geometry = geo
            used_tool = "unyaffs2"

    if res.stdout_path and last_proc is not None:
        res.stdout_path.write_text(last_proc.stdout or "")
    if res.stderr_path and last_proc is not None:
        res.stderr_path.write_text(last_proc.stderr or "")

    if not res.success:
        tools_tried = []
        if binr:
            tools_tried.append("unyaffs")
        if binr2:
            tools_tried.append("unyaffs2")
        res.rc = last_proc.returncode if last_proc else -1
        res.error = (
            f"all tools ({', '.join(tools_tried)}) failed across "
            f"all geometries; last stderr: "
            f"{(last_proc.stderr if last_proc else '').strip()[:300]}")
    elif used_geometry is not None:
        res.error = (
            f"extracted via {used_tool} "
            f"({' '.join(used_geometry) or 'autodetect'})")
    return res


@dataclass
class Yaffs2BundleResult:
    bundle_dir: Path
    extractions: list[Yaffs2ExtractResult] = field(default_factory=list)
    successful_count: int = 0
    failed_count: int = 0


def walk_bundle(bundle_dir: Path, out_root: Path,
                 *, mtd_glob: str = "mtd*.dd"
                 ) -> Yaffs2BundleResult:
    """Walk ``bundle_dir`` for ``mtd*.dd`` files, run is_yaffs2 +
    extract on each, return aggregated results. ``out_root`` is
    the destination root; per-partition output goes under
    ``<out_root>/<image_basename>/``.

    Skips files where the YAFFS2 detector says no — saves the
    operator from waiting on unyaffs trying to make sense of a
    bootloader image.
    """
    bundle = Path(bundle_dir)
    res = Yaffs2BundleResult(bundle_dir=bundle)
    if not bundle.is_dir():
        return res
    for img in sorted(bundle.glob(mtd_glob)):
        det = is_yaffs2(img)
        if not det.is_yaffs2:
            continue
        out_dir = Path(out_root) / img.stem
        ex = extract(img, out_dir)
        res.extractions.append(ex)
        if ex.success:
            res.successful_count += 1
        else:
            res.failed_count += 1
    return res


def is_mtd_bundle_dir(d: Path,
                       *, min_partitions: int = 3) -> bool:
    """Return True iff ``d`` contains at least ``min_partitions``
    files matching ``mtd*.dd``. The triage detector for old
    Android phone dumps (Case2-style)."""
    return sum(1 for _ in Path(d).glob("mtd*.dd")) >= min_partitions


__all__ = [
    "Yaffs2DetectResult", "Yaffs2ExtractResult",
    "Yaffs2BundleResult",
    "is_yaffs2", "extract", "walk_bundle",
    "is_mtd_bundle_dir",
]

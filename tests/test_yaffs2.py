"""YAFFS2 wrapper around the SIFT-bundled unyaffs CLI.

Synthetic tests cover detection heuristic + subprocess wrapper
behaviour; a corpus-gated smoke test runs the real unyaffs binary
against the Case2 mtd*.dd images when present.
"""
import os
import subprocess
from pathlib import Path

import pytest

from el.skills import yaffs2 as y


# --- is_mtd_bundle_dir -------------------------------------------------

def test_is_mtd_bundle_dir_threshold(tmp_path):
    assert y.is_mtd_bundle_dir(tmp_path) is False
    for i in range(2):
        (tmp_path / f"mtd{i}.dd").write_bytes(b"x")
    assert y.is_mtd_bundle_dir(tmp_path) is False     # below default min=3
    (tmp_path / "mtd2.dd").write_bytes(b"x")
    assert y.is_mtd_bundle_dir(tmp_path) is True
    # Lower threshold also works
    assert y.is_mtd_bundle_dir(tmp_path, min_partitions=2) is True


def test_is_mtd_bundle_dir_ignores_non_mtd_files(tmp_path):
    for n in ("readme.txt", "image.dd", "sdcard.dd"):
        (tmp_path / n).write_bytes(b"x")
    assert y.is_mtd_bundle_dir(tmp_path) is False


# --- is_yaffs2 detection heuristic -------------------------------------

def _build_synthetic_yaffs2_chunk(name: str = "system",
                                    chunk_size: int = 2048,
                                    parent_id: int = 1) -> bytes:
    """A minimal YAFFS2-shaped chunk for the 2 KB-stride canonical
    layout. Real YAFFS2 chunks include further fields after the
    name (st_mode / uid / gid / atime etc.); for detection
    purposes only the prefix matters."""
    obj_type = b"\x03\x00\x00\x00"             # DIRECTORY (3)
    parent_b = parent_id.to_bytes(4, "little")
    sum_unused = b"\x00\x00"                    # u16 at offset 8
    name_b = name.encode("ascii").ljust(256, b"\x00")
    header_size = 4 + 4 + 2 + 256              # 266 bytes
    pad = b"\x00" * (chunk_size - header_size)
    return obj_type + parent_b + sum_unused + name_b + pad


def test_is_yaffs2_detects_synthetic_chunks(tmp_path):
    p = tmp_path / "fake.dd"
    chunks = b"".join(
        _build_synthetic_yaffs2_chunk(n)
        for n in ("system", "etc", "data", "lib", "bin"))
    p.write_bytes(chunks + b"\xff" * 1024)
    det = y.is_yaffs2(p)
    assert det.is_yaffs2 is True
    assert det.candidate_headers >= 3
    assert "system" in det.sample_names or "data" in det.sample_names


def test_is_yaffs2_rejects_random_bytes(tmp_path):
    """Bootloader / kernel images don't match the heuristic."""
    p = tmp_path / "random.dd"
    p.write_bytes(b"\xff" * 4096 + b"\x00\x10\xa0\xe3" * 200)
    det = y.is_yaffs2(p)
    assert det.is_yaffs2 is False


def test_is_yaffs2_rejects_erased_pages(tmp_path):
    p = tmp_path / "blank.dd"
    p.write_bytes(b"\xff" * 65536)
    det = y.is_yaffs2(p)
    assert det.is_yaffs2 is False


def test_is_yaffs2_missing_file(tmp_path):
    det = y.is_yaffs2(tmp_path / "absent.dd")
    assert det.is_yaffs2 is False
    assert det.note == "not a file"


# --- extract -----------------------------------------------------------

def test_extract_unavailable_when_binary_missing(tmp_path,
                                                   monkeypatch):
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: None)
    img = tmp_path / "x.dd"; img.write_bytes(b"x")
    r = y.extract(img, tmp_path / "out")
    assert r.success is False
    assert "unyaffs not installed" in r.error


def test_extract_missing_image(tmp_path, monkeypatch):
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    r = y.extract(tmp_path / "absent.dd", tmp_path / "out")
    assert r.success is False
    assert "image not found" in r.error


def test_extract_subprocess_success(tmp_path, monkeypatch):
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    img = tmp_path / "x.dd"; img.write_bytes(b"x" * 1024)

    def fake_run(cmd, capture_output, text, timeout):
        # Simulate unyaffs creating files in the output dir
        out_dir = Path(cmd[2])
        (out_dir / "etc").mkdir()
        (out_dir / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
        (out_dir / "system.txt").write_text("system file\n")
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(y.subprocess, "run", fake_run)
    r = y.extract(img, tmp_path / "out")
    assert r.success is True
    assert r.rc == 0
    assert r.file_count == 2
    assert r.bytes_extracted > 0


def test_extract_subprocess_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    img = tmp_path / "x.dd"; img.write_bytes(b"x")
    monkeypatch.setattr(
        y.subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            args=[], returncode=1, stdout="",
            stderr="unyaffs: bad header"))
    r = y.extract(img, tmp_path / "out")
    assert r.success is False
    assert "rc=1" in r.error
    assert "bad header" in r.error


def test_extract_returns_zero_but_no_files(tmp_path, monkeypatch):
    """unyaffs sometimes returns 0 even when it produced nothing
    (page-geometry mismatch). The wrapper flags this clearly."""
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    img = tmp_path / "x.dd"; img.write_bytes(b"x")
    monkeypatch.setattr(
        y.subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""))
    r = y.extract(img, tmp_path / "out")
    assert r.success is False
    assert "produced no files" in r.error


def test_extract_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    img = tmp_path / "x.dd"; img.write_bytes(b"x")

    def raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="unyaffs", timeout=1)

    monkeypatch.setattr(y.subprocess, "run", raise_timeout)
    r = y.extract(img, tmp_path / "out", timeout=1)
    assert r.success is False
    assert "timed out" in r.error


# --- walk_bundle -------------------------------------------------------

def test_walk_bundle_skips_non_yaffs2_partitions(tmp_path,
                                                   monkeypatch):
    """Bundle has 3 .dd files: 1 YAFFS2-shaped + 2 random.
    walk_bundle should only invoke extract() on the YAFFS2 one."""
    bundle = tmp_path / "bundle"; bundle.mkdir()
    (bundle / "mtd0.dd").write_bytes(b"\x00\x10\xa0\xe3" * 1024)
    (bundle / "mtd1.dd").write_bytes(b"ANDROID!" * 100)
    (bundle / "mtd2.dd").write_bytes(b"".join(
        _build_synthetic_yaffs2_chunk(n)
        for n in ("system", "etc", "data", "lib")))

    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    extracted_paths: list[Path] = []

    def fake_run(cmd, capture_output, text, timeout):
        extracted_paths.append(Path(cmd[1]))
        out_dir = Path(cmd[2])
        (out_dir / "marker").write_text("ok")
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(y.subprocess, "run", fake_run)
    res = y.walk_bundle(bundle, tmp_path / "out")
    assert len(res.extractions) == 1                    # only mtd2 fired
    assert res.successful_count == 1
    assert res.failed_count == 0
    assert extracted_paths[0].name == "mtd2.dd"


def test_walk_bundle_missing_dir(tmp_path):
    res = y.walk_bundle(tmp_path / "absent", tmp_path / "out")
    assert res.extractions == []


# --- corpus smoke ------------------------------------------------------

_REAL_BUNDLE = "/mnt/hgfs/hackathon/Case2"


@pytest.mark.skipif(not Path(_REAL_BUNDLE).is_dir(),
                     reason="Case2 corpus not staged")
def test_real_case2_detection_finds_yaffs2_partitions(tmp_path):
    """Run the heuristic detector against the real Case2 mtd*.dd
    images. Bootloader / kernel partitions should NOT detect as
    YAFFS2; system / userdata partitions SHOULD."""
    bundle = Path(_REAL_BUNDLE)
    detected: dict[str, bool] = {}
    for img in sorted(bundle.glob("mtd*.dd")):
        det = y.is_yaffs2(img)
        detected[img.name] = det.is_yaffs2
    # At least some YAFFS2 partitions must be detected
    yaffs_count = sum(1 for v in detected.values() if v)
    assert yaffs_count >= 1, (
        f"expected ≥1 YAFFS2 partition in Case2; "
        f"detection map: {detected}")
    # The 405 KB Android-boot image (`ANDROID!` magic) must NOT
    # be detected as YAFFS2 — it's a kernel boot.img.
    # In Case2, mtd4 + mtd5 carry the ANDROID! signature.
    for kernel in ("mtd4.dd", "mtd5.dd"):
        if kernel in detected:
            assert detected[kernel] is False, (
                f"{kernel} (Android kernel boot.img) "
                f"misclassified as YAFFS2")


@pytest.mark.skipif(
    not Path(_REAL_BUNDLE).is_dir() or not y._unyaffs_bin(),
    reason="Case2 corpus not staged or unyaffs binary missing",
)
@pytest.mark.skipif(
    os.environ.get("EL_RUN_YAFFS2_E2E") != "1",
    reason="set EL_RUN_YAFFS2_E2E=1 to run the slow real extract",
)
def test_real_case2_extraction_succeeds_on_at_least_one(tmp_path):
    bundle = Path(_REAL_BUNDLE)
    res = y.walk_bundle(bundle, tmp_path / "out")
    assert res.successful_count >= 1, (
        f"unyaffs failed on every YAFFS2 partition in Case2 — "
        f"page geometry mismatch? "
        f"errors: {[e.error for e in res.extractions]}")

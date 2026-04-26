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

def test_extract_unavailable_when_both_binaries_missing(
        tmp_path, monkeypatch):
    """Neither unyaffs nor unyaffs2 installed → install hint."""
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: None)
    monkeypatch.setattr(y, "_unyaffs2_bin", lambda: None)
    img = tmp_path / "x.dd"; img.write_bytes(b"x")
    r = y.extract(img, tmp_path / "out")
    assert r.success is False
    assert "unyaffs" in r.error
    assert "unyaffs2" in r.error
    assert "install.sh" in r.error or "apt-get" in r.error


def test_extract_missing_image(tmp_path, monkeypatch):
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    monkeypatch.setattr(y, "_unyaffs2_bin", lambda: None)
    r = y.extract(tmp_path / "absent.dd", tmp_path / "out")
    assert r.success is False
    assert "image not found" in r.error


def _make_fake_run(extract_action=None,
                    extract_rc: int = 0,
                    extract_stderr: str = ""):
    """Helper to build a fake subprocess.run that handles both
    the autodetect probe (``unyaffs -d``) and the real extract.
    ``extract_action`` is called on the extract invocation with
    the cmd list — typically writes synthetic files into out_dir."""

    def fake_run(cmd, capture_output, text, timeout):
        # Detect the autodetect probe vs the real extract:
        # ``-d`` is the only flag the probe carries.
        if "-d" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0,
                # No layout detected — falls through to fallbacks.
                stdout="Detected flash layout(s):\n-- none --\n",
                stderr="")
        if extract_action is not None:
            extract_action(cmd)
        return subprocess.CompletedProcess(
            args=cmd, returncode=extract_rc,
            stdout="", stderr=extract_stderr)
    return fake_run


def test_extract_subprocess_success(tmp_path, monkeypatch):
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    monkeypatch.setattr(y, "_unyaffs2_bin", lambda: None)
    img = tmp_path / "x.dd"; img.write_bytes(b"x" * 1024)

    def make_files(cmd):
        out_dir = Path(cmd[-1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "etc").mkdir(exist_ok=True)
        (out_dir / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
        (out_dir / "system.txt").write_text("system file\n")

    monkeypatch.setattr(y.subprocess, "run",
                         _make_fake_run(extract_action=make_files,
                                          extract_rc=0))
    r = y.extract(img, tmp_path / "out")
    assert r.success is True
    assert r.rc == 0
    assert r.file_count == 2
    assert r.bytes_extracted > 0
    assert "unyaffs" in r.error                # success note carries tool name


def test_extract_falls_through_to_unyaffs2_when_unyaffs_fails(
        tmp_path, monkeypatch):
    """When unyaffs produces 0 files across all geometries, the
    wrapper falls through to unyaffs2 (yaffs2utils) — the
    Case2-mtd8-style scenario where userdata has a layout
    unyaffs 0.9.7 doesn't recognise but unyaffs2 does."""
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    monkeypatch.setattr(y, "_unyaffs2_bin",
                         lambda: "/fake/unyaffs2")
    img = tmp_path / "x.dd"; img.write_bytes(b"x" * 1024)

    def fake_run(cmd, capture_output, text, timeout):
        # unyaffs -d probe → no layout
        if "-d" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0,
                stdout="-- none --", stderr="")
        # unyaffs invocations: 0 files (every geometry fails)
        if cmd[0] == "/fake/unyaffs":
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr="")
        # unyaffs2 invocation: extract files into out_dir
        if cmd[0] == "/fake/unyaffs2":
            out_dir = Path(cmd[-1])
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "data").mkdir(exist_ok=True)
            (out_dir / "data" / "x.txt").write_text("ok")
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr="")
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr="")

    monkeypatch.setattr(y.subprocess, "run", fake_run)
    r = y.extract(img, tmp_path / "out")
    assert r.success is True
    assert r.file_count == 1
    assert "unyaffs2" in r.error                # success note records tool


def test_extract_subprocess_failure(tmp_path, monkeypatch):
    """Both extractors fail → "all tools failed" diagnostic."""
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    monkeypatch.setattr(y, "_unyaffs2_bin",
                         lambda: "/fake/unyaffs2")
    img = tmp_path / "x.dd"; img.write_bytes(b"x")
    monkeypatch.setattr(y.subprocess, "run",
                         _make_fake_run(extract_action=None,
                                          extract_rc=1,
                                          extract_stderr=(
                                              "bad header")))
    r = y.extract(img, tmp_path / "out")
    assert r.success is False
    assert "all tools" in r.error.lower()
    assert "unyaffs" in r.error and "unyaffs2" in r.error


def test_extract_returns_zero_but_no_files(tmp_path, monkeypatch):
    """Both extractors return rc=0 but produce no files —
    wrapper reports "all tools failed"."""
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    monkeypatch.setattr(y, "_unyaffs2_bin",
                         lambda: "/fake/unyaffs2")
    img = tmp_path / "x.dd"; img.write_bytes(b"x")
    monkeypatch.setattr(y.subprocess, "run",
                         _make_fake_run(extract_action=None,
                                          extract_rc=0))
    r = y.extract(img, tmp_path / "out")
    assert r.success is False
    assert "all tools" in r.error.lower()


def test_extract_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(y, "_unyaffs_bin", lambda: "/fake/unyaffs")
    monkeypatch.setattr(y, "_unyaffs2_bin", lambda: None)
    img = tmp_path / "x.dd"; img.write_bytes(b"x")

    def raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="unyaffs", timeout=1)

    monkeypatch.setattr(y.subprocess, "run", raise_timeout)
    r = y.extract(img, tmp_path / "out", timeout=1)
    assert r.success is False
    # Timeout from stage 1 short-circuits — the message either
    # carries "timed out" (stage 1 returned the error directly)
    # or "all tools failed" (stage 2 wasn't installed so we
    # fall through). Either way, success is False.
    assert ("timed out" in r.error
             or "all tools" in r.error.lower())


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
        if "-d" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0,
                stdout="Detected flash layout(s):\n-- none --\n",
                stderr="")
        # Real extract: image path is the second-to-last arg
        extracted_paths.append(Path(cmd[-2]))
        out_dir = Path(cmd[-1])
        out_dir.mkdir(parents=True, exist_ok=True)
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

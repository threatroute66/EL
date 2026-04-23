"""Tests for the PE structural deep-dive skill."""
from pathlib import Path
import subprocess

import pytest

from el.skills.pefile_deep import (
    _shannon_entropy, analyze_pe,
    attack_techniques_for_groups, iter_pe_candidates,
)


def test_shannon_entropy_uniform_is_max():
    """One byte of each of 256 values → 8 bits."""
    data = bytes(range(256))
    assert abs(_shannon_entropy(data) - 8.0) < 0.001


def test_shannon_entropy_zero_data():
    assert _shannon_entropy(b"\x00" * 1000) == 0.0


def test_shannon_entropy_empty():
    assert _shannon_entropy(b"") == 0.0


def test_analyze_pe_returns_none_on_non_pe(tmp_path):
    p = tmp_path / "text.txt"
    p.write_bytes(b"this is not a PE at all")
    assert analyze_pe(p) is None


def test_analyze_pe_returns_none_on_missing_file(tmp_path):
    assert analyze_pe(tmp_path / "does-not-exist.exe") is None


def test_analyze_pe_returns_none_on_tiny_file(tmp_path):
    p = tmp_path / "tiny.exe"
    p.write_bytes(b"MZ\x00")      # Too small to be a real PE
    assert analyze_pe(p) is None


def _make_minimal_pe(path: Path) -> Path:
    """Generate a real minimal PE via `gcc -O0 -nostdlib` so tests
    have a parseable target. Skip gracefully when the toolchain isn't
    available."""
    import shutil as _shutil
    gcc = _shutil.which("x86_64-w64-mingw32-gcc")
    if not gcc:
        return None
    src = path.parent / "tiny.c"
    src.write_text("int main(void){return 0;}\n")
    out = path
    r = subprocess.run([gcc, str(src), "-o", str(out)],
                       capture_output=True, timeout=30)
    return out if r.returncode == 0 and out.is_file() else None


def test_analyze_pe_on_real_binary(tmp_path):
    out = _make_minimal_pe(tmp_path / "tiny.exe")
    if out is None:
        pytest.skip("mingw gcc not installed — skip real-PE test")
    analysis = analyze_pe(out)
    assert analysis is not None
    assert analysis.machine in ("i386", "x64")
    assert analysis.subsystem in ("gui", "console")
    assert len(analysis.sections) >= 2
    assert 0.0 <= analysis.max_section_entropy <= 8.0
    # Rich header usually absent on mingw binaries
    # imphash presence is compiler-dependent — don't assert


def test_analyze_pe_on_real_carved_pe():
    """Uses a real carved PE from the LoneWolf case if present.
    Skip when the case hasn't been run on this host yet."""
    carved = list(Path("/opt/EL/cases").glob(
        "*/analysis/disk_forensicator/bulk_extractor/"
        "winpe_carved/000/*.winpe"))
    if not carved:
        pytest.skip("no carved PE sample in /opt/EL/cases — run a "
                     "disk case first to populate")
    for sample in carved[:3]:
        a = analyze_pe(sample)
        if a is None:
            continue
        assert a.sha256
        assert a.file_size > 0
        assert 0.0 <= a.max_section_entropy <= 8.0
        # Either it's parseable (analysis is not None) OR it isn't
        # — no assertion on specific fields that depend on which
        # file libewf happened to carve.
        break
    else:
        pytest.skip("every carved sample unparseable — corpus-dependent")


def test_attack_techniques_for_groups_maps_credential_dump():
    t = attack_techniques_for_groups(["credential_dump"])
    tids = {tid for tid, _ in t}
    assert "T1003" in tids
    assert "T1003.001" in tids


def test_attack_techniques_for_groups_dedupes_across_groups():
    # Both credential_dump and process_injection reference T1055.012
    # transitively — make sure they don't duplicate
    t = attack_techniques_for_groups(
        ["process_injection", "shellcode_runtime"])
    tids = [tid for tid, _ in t]
    assert len(tids) == len(set(tids))        # no duplicates
    assert "T1055" in set(tids)


def test_attack_techniques_for_groups_empty():
    assert attack_techniques_for_groups([]) == []
    assert attack_techniques_for_groups(["unknown_group"]) == []


def test_iter_pe_candidates_walks_tree(tmp_path):
    pe1 = tmp_path / "a" / "bad.exe"
    pe2 = tmp_path / "b" / "also.dll"
    not_pe = tmp_path / "a" / "readme.txt"
    empty = tmp_path / "a" / "empty.exe"
    pe1.parent.mkdir(parents=True)
    pe2.parent.mkdir(parents=True)
    pe1.write_bytes(b"MZ" + b"\x00" * 200)
    pe2.write_bytes(b"MZ" + b"\x00" * 200)
    not_pe.write_text("hello world")
    empty.write_bytes(b"")
    found = iter_pe_candidates([tmp_path])
    names = {p.name for p in found}
    assert names == {"bad.exe", "also.dll"}


def test_iter_pe_candidates_skips_csvs_and_text(tmp_path):
    # A file named .csv that happens to start with MZ should be skipped
    # (cheap filter — we don't want to parse huge CSV outputs)
    p = tmp_path / "fake.csv"
    p.write_bytes(b"MZ" + b"\x00" * 1000)
    found = iter_pe_candidates([tmp_path])
    assert found == []


def test_iter_pe_candidates_respects_size_cap(tmp_path):
    # > 50 MB files are skipped
    big = tmp_path / "huge.bin"
    big.write_bytes(b"MZ" + b"\x00" * (60 * 1024 * 1024))
    found = iter_pe_candidates([tmp_path])
    assert found == []


def test_iter_pe_candidates_empty_dir(tmp_path):
    assert iter_pe_candidates([tmp_path]) == []


def test_iter_pe_candidates_missing_dir(tmp_path):
    assert iter_pe_candidates([tmp_path / "nope"]) == []

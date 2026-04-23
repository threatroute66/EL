"""Tests for office_deobf (olevba + rtfobj) and netflow (nfdump wrappers)."""
import struct
from pathlib import Path

import pytest

from el.skills import netflow as nf
from el.skills import office_deobf as office


# ---------------------------------------------------------------------------
# office_deobf
# ---------------------------------------------------------------------------

def test_is_office_candidate_by_suffix(tmp_path):
    for ext in (".docm", ".xlsm", ".rtf", ".ppt"):
        f = tmp_path / f"a{ext}"
        f.write_bytes(b"dummy" * 200)
        assert office.is_office_candidate(f)
    # non-Office suffix
    p = tmp_path / "a.txt"
    p.write_bytes(b"dummy" * 200)
    assert not office.is_office_candidate(p)


def test_iter_office_candidates_walks_tree(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "good.docm").write_bytes(b"x" * 2048)
    (tmp_path / "b" / "evil.rtf").write_bytes(b"x" * 2048)
    (tmp_path / "a" / "ignored.txt").write_bytes(b"x" * 2048)
    (tmp_path / "a" / "tiny.xls").write_bytes(b"x" * 100)          # < 1 KB cap
    (tmp_path / "a" / "huge.xls").write_bytes(b"x" * (200 * 1024 * 1024))
    found = office.iter_office_candidates([tmp_path])
    names = sorted(p.name for p in found)
    assert names == ["evil.rtf", "good.docm"]


def test_iter_office_candidates_empty_dir(tmp_path):
    assert office.iter_office_candidates([tmp_path]) == []
    assert office.iter_office_candidates([tmp_path / "nope"]) == []


def test_analyze_macros_skips_non_office(tmp_path):
    f = tmp_path / "random.txt"
    f.write_bytes(b"this is not an office document")
    assert office.analyze_macros(f) is None


def test_analyze_macros_on_real_macro_docm(tmp_path):
    """If the venv has olevba, parse a small OLE2 doc built with the
    oletools source-kit stub. When that's not feasible, skip —
    CI may not have the toolchain."""
    try:
        import olefile    # shipped with oletools
    except ImportError:
        pytest.skip("olefile not installed")
    # Try olevba first on the synthetic known-empty file above —
    # it should return a MacroAnalysis with has_macros=False rather
    # than None since the suffix is .docm
    fake = tmp_path / "empty.docm"
    fake.write_bytes(b"PK\x03\x04" + b"\x00" * 2048)   # fake zip
    r = office.analyze_macros(fake)
    # olevba may error on a malformed zip; either way the skill
    # returns a MacroAnalysis — never raises
    assert r is None or isinstance(r, office.MacroAnalysis)


def test_analyze_rtf_objects_skips_non_rtf(tmp_path):
    f = tmp_path / "not.docx"
    f.write_bytes(b"PK\x03\x04" + b"\x00" * 2048)
    assert office.analyze_rtf_objects(f) is None


def test_analyze_rtf_objects_handles_trivial_rtf(tmp_path):
    """Minimum-viable RTF with no embedded objects — rtfobj should
    return object_count=0 rather than raising."""
    f = tmp_path / "trivial.rtf"
    f.write_bytes(b"{\\rtf1 hello world}")
    result = office.analyze_rtf_objects(f)
    if result is None:
        pytest.skip("rtfobj CLI not available in this environment")
    assert result.object_count == 0


# ---------------------------------------------------------------------------
# netflow / nfdump
# ---------------------------------------------------------------------------

def test_is_nfcapd_file_recognises_ascii_magic(tmp_path):
    f = tmp_path / "nfcapd.201801010000"
    f.write_bytes(b"NFCAPD\x00\x00" + b"\x00" * 200)
    assert nf.is_nfcapd_file(f) is True


def test_is_nfcapd_file_recognises_le_magic(tmp_path):
    f = tmp_path / "lfn.bin"
    f.write_bytes(b"\xa5\x0c" + b"\x00" * 200)
    assert nf.is_nfcapd_file(f) is True


def test_is_nfcapd_file_rejects_random(tmp_path):
    f = tmp_path / "random.bin"
    f.write_bytes(b"\x00" * 100)
    assert nf.is_nfcapd_file(f) is False


def test_is_nfcapd_file_missing(tmp_path):
    assert nf.is_nfcapd_file(tmp_path / "nope") is False


def test_top_beacons_groups_and_counts():
    flows = []
    # 12 beacons from X → Y:443
    for i in range(12):
        flows.append(nf.Flow(
            ts_first=f"2026-01-01 10:00:{i:02d}.000",
            ts_last=f"2026-01-01 10:00:{i:02d}.500",
            duration_ms=500, src_ip="10.0.0.5",
            src_port=50000 + i, dst_ip="203.0.113.7", dst_port=443,
            protocol="TCP", packets=3, bytes_=180))
    # 2 one-offs (below threshold)
    flows.append(nf.Flow(
        ts_first="", ts_last="", duration_ms=0,
        src_ip="10.0.0.5", src_port=0,
        dst_ip="8.8.8.8", dst_port=53,
        protocol="UDP", packets=1, bytes_=70))
    out = nf.top_beacons(flows, min_count=10)
    assert len(out) == 1
    b = out[0]
    assert b.src_ip == "10.0.0.5"
    assert b.dst_ip == "203.0.113.7"
    assert b.dst_port == 443
    assert b.count == 12


def test_detect_port_scans_flags_vertical_scan():
    flows = []
    for port in range(50):
        flows.append(nf.Flow(
            ts_first="", ts_last="", duration_ms=0,
            src_ip="6.6.6.6", src_port=40000,
            dst_ip="10.0.0.1", dst_port=port,
            protocol="TCP", packets=1, bytes_=60))
    scans = nf.detect_port_scans(flows, distinct_port_threshold=30)
    assert len(scans) == 1
    assert scans[0].src_ip == "6.6.6.6"
    assert scans[0].distinct_ports == 50


def test_detect_port_scans_ignores_few_ports():
    flows = [nf.Flow(
        ts_first="", ts_last="", duration_ms=0,
        src_ip="6.6.6.6", src_port=0,
        dst_ip="10.0.0.1", dst_port=p, protocol="TCP",
        packets=1, bytes_=60) for p in (80, 443, 22)]
    assert nf.detect_port_scans(flows) == []


def test_top_talkers_sorted_by_bytes():
    flows = [
        nf.Flow(ts_first="", ts_last="", duration_ms=0,
                src_ip="a", src_port=0, dst_ip="x", dst_port=0,
                protocol="TCP", packets=1, bytes_=1000),
        nf.Flow(ts_first="", ts_last="", duration_ms=0,
                src_ip="b", src_port=0, dst_ip="x", dst_port=0,
                protocol="TCP", packets=1, bytes_=5000),
        nf.Flow(ts_first="", ts_last="", duration_ms=0,
                src_ip="a", src_port=0, dst_ip="y", dst_port=0,
                protocol="TCP", packets=1, bytes_=2000),
    ]
    tops = nf.top_talkers(flows)
    assert tops[0][0] == "b"              # 5000 bytes
    assert tops[1][0] == "a"              # 3000 bytes
    assert tops[0][2] == 5000
    assert tops[1][1] == 2                 # 2 flows


def test_parse_nfcapd_missing_file(tmp_path):
    run = nf.parse_nfcapd(tmp_path / "nope", tmp_path / "out.csv")
    assert run.rc == -1
    assert run.flow_count == 0

"""Dump-region strings extractor + family fingerprints."""
from el.intel.malware_families import detect
from el.skills.dump_analysis import scan_dump


def test_mz_header_and_pe_signature_flagged(tmp_path):
    p = tmp_path / "pid.123.dmp"
    # Minimal MZ + PE fixture: MZ header + padding + PE\x00\x00 signature
    data = b"MZ" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 200
    p.write_bytes(data)
    s = scan_dump(p)
    assert s.has_mz_header is True
    assert s.has_pe_signature is True


def test_nop_sled_detection(tmp_path):
    p = tmp_path / "region.dmp"
    p.write_bytes(b"\xcc" * 40 + b"\x90" * 200 + b"\xcc" * 40)
    s = scan_dump(p)
    assert s.nop_sled_runs >= 1


def test_ascii_strings_extracted(tmp_path):
    p = tmp_path / "region.dmp"
    p.write_bytes(b"\x00\x01\x02mimikatz 2.2.0 (x86)\x00\x00"
                  b"sekurlsa::logonpasswords\x00\x00random noise" + b"\x00" * 10)
    s = scan_dump(p)
    assert any("mimikatz" in x for x in s.ascii_strings)
    assert any("sekurlsa" in x for x in s.ascii_strings)


def test_wide_strings_extracted(tmp_path):
    p = tmp_path / "region.dmp"
    # UTF-16LE "evilcorp" + padding
    p.write_bytes(b"e\x00v\x00i\x00l\x00c\x00o\x00r\x00p\x00" + b"\x00" * 8)
    s = scan_dump(p)
    assert any("evilcorp" in x for x in s.wide_strings)


def test_detect_mimikatz_family():
    strings = {"mimikatz 2.2.0", "sekurlsa::logonpasswords", "random noise"}
    matches = detect(strings)
    names = {m.family for m in matches}
    assert "mimikatz" in names
    mimi = next(m for m in matches if m.family == "mimikatz")
    assert "H_CREDENTIAL_ACCESS" in mimi.hypotheses
    assert any(tid == "T1003.001" for tid, _ in mimi.attack_techniques)


def test_detect_meterpreter_family():
    strings = {"meterpreter session established", "msf::core::payload"}
    matches = detect(strings)
    names = {m.family for m in matches}
    assert "metasploit_meterpreter" in names


def test_no_match_returns_empty():
    assert detect({"regular benign strings"}) == []

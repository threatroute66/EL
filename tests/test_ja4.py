"""JA4+ skill — unit tests.

Real ja4.py runs require tshark + a pcap; tests focus on parsing, dataclass
behaviour, and resilience when input is missing or malformed.
"""
import json
from pathlib import Path

import pytest

from el.skills import ja4 as ja4_skill


# --- _which discovery ---------------------------------------------------

def test_which_finds_installed_script():
    try:
        p = ja4_skill._which()
    except ja4_skill.JA4Error:
        pytest.skip("FoxIO ja4.py not installed")
    assert p.is_file()
    assert p.name == "ja4.py"


def test_which_raises_when_missing(monkeypatch):
    fake_path_class = type("FakePath", (), {
        "is_file": lambda self: False,
    })
    monkeypatch.setattr(ja4_skill, "Path", lambda *a, **kw: fake_path_class())
    with pytest.raises(ja4_skill.JA4Error):
        ja4_skill._which()


# --- JA4Flow parsing ---------------------------------------------------

def test_flow_from_record_full():
    rec = {
        "src": "10.0.0.1", "dst": "1.2.3.4",
        "src_port": "443", "dst_port": "12345",
        "protocol": "tcp",
        "JA4": "t13d1516h2_8daaf6152771_b186095e22b6",
        "JA4S": "t130200_1303_a56c5b993250",
        "JA4H": "ge11nn05enus_0a92cda06d50_000000000000_000000000000",
        "server_name": "evil.example.com",
        "user_agent": "Mozilla/5.0 ...",
    }
    f = ja4_skill.JA4Flow.from_record(rec)
    assert f.src == "10.0.0.1"
    assert f.ja4 == "t13d1516h2_8daaf6152771_b186095e22b6"
    assert f.ja4h.startswith("ge11nn05enus")
    assert f.sni == "evil.example.com"
    assert f.has_any_fingerprint()


def test_flow_from_record_lowercase_keys():
    """FoxIO output sometimes uses lowercase ja4 keys; tolerate both."""
    rec = {"ja4": "t13d_x_y", "ja4s": "t12_a_b"}
    f = ja4_skill.JA4Flow.from_record(rec)
    assert f.ja4 == "t13d_x_y"
    assert f.ja4s == "t12_a_b"


def test_flow_from_record_truncates_user_agent():
    f = ja4_skill.JA4Flow.from_record({"user_agent": "X" * 1000})
    assert len(f.user_agent) <= 300


def test_flow_has_any_fingerprint_false_for_empty():
    f = ja4_skill.JA4Flow()
    assert not f.has_any_fingerprint()


# --- _parse_ja4_output -------------------------------------------------

def test_parse_returns_zero_for_missing_file(tmp_path):
    count, flows = ja4_skill._parse_ja4_output(tmp_path / "missing.json")
    assert count == 0 and flows == []


def test_parse_returns_zero_for_empty_file(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("")
    count, flows = ja4_skill._parse_ja4_output(p)
    assert count == 0 and flows == []


def test_parse_handles_array_form(tmp_path):
    p = tmp_path / "out.json"
    p.write_text(json.dumps([
        {"src": "10.0.0.1", "dst": "1.2.3.4", "JA4": "abc"},
        {"src": "10.0.0.2", "dst": "5.6.7.8", "JA4": "def"},
    ]))
    count, flows = ja4_skill._parse_ja4_output(p)
    assert count == 2
    assert flows[0].ja4 == "abc"
    assert flows[1].src == "10.0.0.2"


def test_parse_handles_jsonl_form(tmp_path):
    p = tmp_path / "out.jsonl"
    p.write_text(
        json.dumps({"src": "10.0.0.1", "JA4": "x"}) + "\n"
        + json.dumps({"src": "10.0.0.2", "JA4": "y"}) + "\n"
    )
    count, flows = ja4_skill._parse_ja4_output(p)
    assert count == 2
    assert flows[1].ja4 == "y"


def test_parse_handles_single_object_form(tmp_path):
    p = tmp_path / "single.json"
    p.write_text(json.dumps({"src": "10.0.0.1", "JA4": "z"}))
    count, flows = ja4_skill._parse_ja4_output(p)
    assert count == 1
    assert flows[0].ja4 == "z"


# --- _distinct deduplication -------------------------------------------

def test_distinct_dedupes_and_preserves_order():
    out = ja4_skill._distinct(["a", "b", "a", "c", "", "b"])
    assert out == ["a", "b", "c"]


def test_distinct_caps_at_limit():
    out = ja4_skill._distinct((str(i) for i in range(1000)), cap=5)
    assert len(out) == 5


# --- JA4ScanResult shape -----------------------------------------------

def test_scan_result_as_evidence(tmp_path):
    out = tmp_path / "ja4.json"
    out.write_text("[]")
    r = ja4_skill.JA4ScanResult(
        pcap_path=tmp_path / "x.pcap",
        output_path=out,
        rc=0, flow_count=42,
        distinct_ja4=["a", "b"],
        distinct_ja4h=["h1"],
        output_sha256="d" * 64,
        command=["python3", "ja4.py", "-J", str(tmp_path / "x.pcap")],
    )
    ev = r.as_evidence()
    assert ev.tool == "ja4"
    assert ev.output_sha256 == "d" * 64
    assert ev.extracted_facts["flow_count"] == 42
    assert ev.extracted_facts["distinct_ja4_count"] == 2


def test_scan_result_zero_pads_when_no_sha():
    r = ja4_skill.JA4ScanResult(
        pcap_path=Path("/x"), output_path=Path("/y"), rc=2,
    )
    ev = r.as_evidence()
    assert ev.output_sha256 == "0" * 64


def test_all_distinct_fingerprints_unions():
    r = ja4_skill.JA4ScanResult(
        pcap_path=Path("/x"), output_path=Path("/y"), rc=0,
        distinct_ja4=["a"], distinct_ja4s=["b"],
        distinct_ja4h=["c"], distinct_ja4ssh=["d"],
    )
    out = r.all_distinct_fingerprints()
    assert out == ["a", "b", "c", "d"]


# --- KNOWN_BAD_JA4 lookup ---------------------------------------------

def test_lookup_returns_none_for_empty_input():
    assert ja4_skill.lookup_ja4("") is None
    assert ja4_skill.lookup_ja4("   ") is None or \
        ja4_skill.lookup_ja4("   ") is None  # whitespace-only


def test_lookup_returns_none_for_unknown_fingerprint():
    assert ja4_skill.lookup_ja4("nonsense_fingerprint") is None


def test_lookup_returns_match_when_in_table(monkeypatch):
    monkeypatch.setitem(ja4_skill.KNOWN_BAD_JA4,
                          "test_fp_123",
                          ("Test Family", "test source 2025"))
    result = ja4_skill.lookup_ja4("test_fp_123")
    assert result == ("Test Family", "test source 2025")


# --- Smoke (real binary) ----------------------------------------------

@pytest.mark.skipif(
    not Path("/opt/ja4-tools/python/ja4.py").is_file(),
    reason="FoxIO ja4.py not installed",
)
def test_real_ja4_help_smoke():
    import subprocess
    p = subprocess.run(
        ["python3", "/opt/ja4-tools/python/ja4.py", "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert "JA4" in (p.stdout + p.stderr)

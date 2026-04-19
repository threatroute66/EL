"""Regression tests for the extract_from_paths feedback-loop guard.

Pre-fix: a 560 KB Cool EK pcap produced a 229 MB iocs.json because
extract_from_paths re-scanned its own downstream outputs — knowledge.sqlite
(98 MB, binary!), ach_matrix.json (12 MB), the case's own iocs.json from
the previous pass, and threat_hunter's auto-generated case_iocs.yar
(32 MB of rules). Each pass concatenated URL fragments across file
boundaries, producing tens of thousands of hallucinated "URLs" that
looked like real-URL + caseid-suffix garbage.

Fix: _should_skip_path() filters by filename allowlist, parent-dir
skip-list, binary-magic sniff, and a 10 MB size cap. Downstream outputs
never become inputs.
"""
from pathlib import Path

import pytest

from el.skills.ioc_extract import (
    _MAX_EVIDENCE_BYTES, _should_skip_path, extract_from_paths,
)


# ---------------------------------------------------------------------------
# _should_skip_path — every category
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "ach_matrix.json", "knowledge.sqlite", "stix-bundle.json", "report.md",
    "transitions.json", "manifest.json", "seal.json", "iocs.json",
    "CLAUDE.md", "case_iocs.yar",
])
def test_downstream_output_filenames_skipped(tmp_path, name):
    p = tmp_path / name
    p.write_text("http://evil.example.com/payload")
    skip, reason = _should_skip_path(p)
    assert skip
    assert "downstream" in reason or "output" in reason


def test_reports_subdirectory_skipped(tmp_path):
    """Anything under case/reports/ is downstream, regardless of filename."""
    d = tmp_path / "reports"
    d.mkdir()
    p = d / "anything.txt"
    p.write_text("x")
    skip, _ = _should_skip_path(p)
    assert skip


def test_archives_subdirectory_skipped(tmp_path):
    d = tmp_path / "_archives"
    d.mkdir()
    p = d / "some-case.tar.gz"
    p.write_bytes(b"PK\x03\x04" + b"x" * 100)
    skip, _ = _should_skip_path(p)
    assert skip


def test_sqlite_magic_skipped_regardless_of_name(tmp_path):
    """Even if someone renames a sqlite file, the magic sniff catches it."""
    p = tmp_path / "innocent-looking.txt"
    p.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
    skip, reason = _should_skip_path(p)
    assert skip
    assert "binary" in reason.lower()


def test_gzip_binary_skipped(tmp_path):
    p = tmp_path / "archive.bin"
    p.write_bytes(b"\x1f\x8b" + b"data")
    skip, _ = _should_skip_path(p)
    assert skip


def test_size_cap_skips_oversized(tmp_path):
    """Files > _MAX_EVIDENCE_BYTES are skipped to bound the pass."""
    p = tmp_path / "huge.json"
    p.write_bytes(b"a" * (_MAX_EVIDENCE_BYTES + 1))
    skip, reason = _should_skip_path(p)
    assert skip
    assert "size" in reason


def test_empty_file_skipped(tmp_path):
    p = tmp_path / "empty.txt"
    p.write_bytes(b"")
    skip, _ = _should_skip_path(p)
    assert skip


def test_normal_text_evidence_not_skipped(tmp_path):
    """Real analysis outputs (small, text, not named as a downstream file)
    must pass through unchanged."""
    p = tmp_path / "tshark-http-tls.json"
    p.write_text('{"http.host": ["evil.example.com"]}')
    skip, _ = _should_skip_path(p)
    assert not skip


# ---------------------------------------------------------------------------
# End-to-end: extract_from_paths refuses to feedback-loop
# ---------------------------------------------------------------------------

def test_knowledge_sqlite_input_yields_empty_iocs(tmp_path):
    """The exact bug: pointing extract_from_paths at a 'knowledge.sqlite'
    must not produce 40k hallucinated URLs — should produce zero."""
    fake_kb = tmp_path / "knowledge.sqlite"
    # Realistic sqlite-like content: header + some text that contains URL
    # fragments (URLs ARE in the real knowledge DB as IOC values).
    fake_kb.write_bytes(
        b"SQLite format 3\x00" + b"\x00" * 100
        + b"http://evil.example.com/a " * 50
    )
    out = extract_from_paths([fake_kb])
    # All classes empty — the file was skipped at magic-sniff
    assert all(not v for v in out.values())


def test_ach_matrix_json_input_yields_empty_iocs(tmp_path):
    """Re-scanning the ACH matrix amplifies hallucinations. Must be skipped."""
    matrix = tmp_path / "ach_matrix.json"
    matrix.write_text('{"findings": ["http://evil.example.com/a"]}' * 10)
    out = extract_from_paths([matrix])
    assert all(not v for v in out.values())


def test_previous_iocs_json_not_re_ingested(tmp_path):
    """The case's iocs.json from a previous pass IS listed as evidence in
    some agents' findings. Reading it back is the root of the feedback
    amplification — must be skipped."""
    prev = tmp_path / "iocs.json"
    prev.write_text('{"url": ["http://evil.example.com/a",'
                    '"http://evil.example.com/b"]}')
    out = extract_from_paths([prev])
    assert all(not v for v in out.values())


def test_yara_rules_file_not_re_ingested(tmp_path):
    """threat_hunter's case_iocs.yar is its OWN output; re-reading it
    produces quoted URL strings inside rule bodies, many of which the
    regex accepts as new 'URLs'."""
    yar = tmp_path / "case_iocs.yar"
    yar.write_text('rule ioc_url_0 { strings: $s = "http://evil.example.com/a" '
                   'condition: $s }')
    out = extract_from_paths([yar])
    assert all(not v for v in out.values())


def test_normal_evidence_still_extracted(tmp_path):
    """Regression guard: small, real-looking evidence JSON still produces
    IOCs. If the skip logic is too aggressive we'd lose everything."""
    ev = tmp_path / "tshark-http-tls.json"
    ev.write_text('{"http.host": ["evil.example.com", "203.0.113.7"]}')
    out = extract_from_paths([ev])
    assert "evil.example.com" in out.get("domain", set())
    assert "203.0.113.7" in out.get("ipv4", set())

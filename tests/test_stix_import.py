"""T4-2 tests: STIX 2.1 bundle import — pattern parsing, bundle
formats, knowledge-DB integration."""
import json
import sqlite3
from pathlib import Path

import pytest

from el.skills import stix_import as si


# ---------------------------------------------------------------------------
# Pattern extraction
# ---------------------------------------------------------------------------

def test_pattern_extracts_ipv4():
    pairs = si._extract_iocs_from_pattern(
        "[ipv4-addr:value = '203.0.113.10']")
    assert pairs == [("ipv4", "203.0.113.10")]


def test_pattern_extracts_domain():
    pairs = si._extract_iocs_from_pattern(
        "[domain-name:value = 'evil.example.com']")
    assert pairs == [("domain", "evil.example.com")]


def test_pattern_extracts_sha256_with_quoted_hash_key():
    pairs = si._extract_iocs_from_pattern(
        "[file:hashes.'SHA-256' = 'deadbeef" + "a" * 58 + "']")
    assert pairs == [("sha256", "deadbeef" + "a" * 58)]


def test_pattern_extracts_md5_unquoted_form():
    pairs = si._extract_iocs_from_pattern(
        "[file:hashes.MD5 = '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f']")
    assert pairs == [("md5", "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")]


def test_pattern_extracts_email():
    pairs = si._extract_iocs_from_pattern(
        "[email-addr:value = 'alice@evil.example.com']")
    assert pairs == [("email", "alice@evil.example.com")]


def test_pattern_extracts_compound_and():
    """Real feeds emit compound AND patterns for dual-indicator matches."""
    pairs = si._extract_iocs_from_pattern(
        "[ipv4-addr:value = '203.0.113.10' AND domain-name:value = 'evil.example.com']"
    )
    assert ("ipv4", "203.0.113.10") in pairs
    assert ("domain", "evil.example.com") in pairs


def test_pattern_ignores_unknown_types():
    pairs = si._extract_iocs_from_pattern(
        "[mutex:name = 'Global\\evil']")
    assert pairs == []


# ---------------------------------------------------------------------------
# Bundle parsing — both wrapped + bare-array forms
# ---------------------------------------------------------------------------

def _write_bundle(path: Path, indicators: list[dict]) -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--11111111-2222-3333-4444-555555555555",
        "objects": indicators,
    }
    path.write_text(json.dumps(bundle))


def _indicator(id_suffix: str, pattern: str,
                labels: list[str] | None = None) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{id_suffix}",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-01-01T00:00:00Z",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2024-01-01T00:00:00Z",
        "indicator_types": labels or ["malicious-activity"],
    }


def test_parse_wrapped_bundle(tmp_path):
    p = tmp_path / "bundle.json"
    _write_bundle(p, [
        _indicator("aaaaaaaa-0001", "[ipv4-addr:value = '1.2.3.4']"),
        _indicator("aaaaaaaa-0002", "[domain-name:value = 'bad.example']"),
    ])
    iocs = si.parse_bundle(p)
    assert len(iocs) == 2
    types = {i.ioc_type for i in iocs}
    assert types == {"ipv4", "domain"}


def test_parse_bare_array_bundle(tmp_path):
    """MISP / OpenCTI sometimes emit JUST the indicators as an array."""
    p = tmp_path / "arr.json"
    p.write_text(json.dumps([
        _indicator("aaaaaaaa-0003", "[ipv4-addr:value = '5.6.7.8']"),
    ]))
    iocs = si.parse_bundle(p)
    assert len(iocs) == 1
    assert iocs[0].value == "5.6.7.8"


def test_parse_preserves_labels_and_description(tmp_path):
    p = tmp_path / "b.json"
    ind = _indicator("aaaaaaaa-0004",
                      "[ipv4-addr:value = '9.9.9.9']",
                      labels=["known-c2", "apt-operator"])
    ind["description"] = "observed in campaign X"
    _write_bundle(p, [ind])
    iocs = si.parse_bundle(p)
    assert iocs[0].source_labels == ["known-c2", "apt-operator"]
    assert "campaign X" in iocs[0].description


def test_parse_skips_non_indicator_sdos(tmp_path):
    p = tmp_path / "mixed.json"
    _write_bundle(p, [
        _indicator("aaaaaaaa-0005", "[ipv4-addr:value = '1.1.1.1']"),
        {"type": "identity", "id": "identity--xxx",
         "name": "Attribution Labs"},
        {"type": "malware", "id": "malware--yyy", "name": "Evil"},
    ])
    iocs = si.parse_bundle(p)
    # Only the indicator's IP lands in the extracted list
    assert len(iocs) == 1
    assert iocs[0].value == "1.1.1.1"


def test_parse_missing_file_returns_empty(tmp_path):
    assert si.parse_bundle(tmp_path / "nope.json") == []


def test_parse_invalid_json_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not json")
    assert si.parse_bundle(p) == []


# ---------------------------------------------------------------------------
# End-to-end import into the knowledge DB
# ---------------------------------------------------------------------------

def test_import_bundle_writes_to_knowledge_db(tmp_path, monkeypatch):
    """Uses an isolated DB — doesn't touch ~/.el/knowledge.sqlite."""
    db_path = tmp_path / "iso-knowledge.sqlite"
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(db_path))

    bundle = tmp_path / "feed.json"
    _write_bundle(bundle, [
        _indicator("aaaaaaaa-0006", "[ipv4-addr:value = '10.20.30.40']"),
        _indicator("aaaaaaaa-0007", "[domain-name:value = 'feed-c2.example']"),
        _indicator("aaaaaaaa-0008",
                    "[file:hashes.'SHA-256' = '"
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
                    "]"),
    ])

    total, per_type = si.import_bundle(bundle, case_id="t-feed-2024-01")
    assert total == 3
    assert per_type == {"ipv4": 1, "domain": 1, "sha256": 1}

    # Round-trip: confirm the values landed with correct provenance
    with sqlite3.connect(str(db_path)) as c:
        rows = c.execute(
            "SELECT value, ioc_type, case_id, agent "
            "FROM ioc_observations WHERE case_id = ?",
            ("t-feed-2024-01",),
        ).fetchall()
    assert len(rows) == 3
    assert all(agent == "stix_import" for _, _, _, agent in rows)
    values = {v for v, _, _, _ in rows}
    assert "10.20.30.40" in values
    assert "feed-c2.example" in values


def test_import_bundle_empty_indicators_returns_zero(tmp_path, monkeypatch):
    db_path = tmp_path / "iso.sqlite"
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(db_path))
    bundle = tmp_path / "empty.json"
    _write_bundle(bundle, [])
    total, per_type = si.import_bundle(bundle, case_id="t-empty")
    assert total == 0
    assert per_type == {}


# ---------------------------------------------------------------------------
# CLI wiring — `el stix import`
# ---------------------------------------------------------------------------

def test_cli_stix_import_happy_path(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from el.cli import app

    db_path = tmp_path / "iso.sqlite"
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(db_path))

    bundle = tmp_path / "feed.json"
    _write_bundle(bundle, [
        _indicator("aaaaaaaa-0009", "[ipv4-addr:value = '7.7.7.7']"),
    ])

    runner = CliRunner()
    result = runner.invoke(app, ["stix", "import", str(bundle),
                                   "--case-id", "t-cli-feed"])
    assert result.exit_code == 0, result.output
    assert "imported 1 IOC" in result.output
    assert "ipv4: 1" in result.output


def test_cli_stix_import_missing_bundle_exits_non_zero(tmp_path):
    from typer.testing import CliRunner
    from el.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["stix", "import",
                                   str(tmp_path / "missing.json")])
    assert result.exit_code != 0
    assert "bundle not found" in result.output.lower()


def test_cli_stix_rejects_unknown_action(tmp_path):
    from typer.testing import CliRunner
    from el.cli import app
    runner = CliRunner()
    result = runner.invoke(app, ["stix", "export", "anything"])
    assert result.exit_code != 0
    assert "unknown action" in result.output.lower()

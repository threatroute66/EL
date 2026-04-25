"""MISP / TAXII feed pull into knowledge.sqlite.

Closes gap-doc Intel-depth bullet "MISP / TAXII feed integration".
Tests monkeypatch the HTTP shim so no real network call happens.
"""
import json
import sqlite3
from pathlib import Path

import pytest

from el.skills import threat_feeds as tf
from el import knowledge


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Per-test knowledge DB so feed inserts are isolated from the
    operator's real ~/.el/knowledge.sqlite."""
    p = tmp_path / "knowledge.sqlite"
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(p))
    return p


def _stub_http(monkeypatch, body: bytes, status: int = 200):
    monkeypatch.setattr(tf, "_http_get",
                         lambda *a, **kw: (status, body))


# --- MISP --------------------------------------------------------------

def test_pull_misp_missing_credentials(monkeypatch):
    monkeypatch.delenv("EL_MISP_URL", raising=False)
    monkeypatch.delenv("EL_MISP_KEY", raising=False)
    r = tf.pull_misp("", "")
    assert r.ok is False
    assert "missing" in r.error


def test_pull_misp_basic(monkeypatch):
    payload = {
        "response": {
            "Attribute": [
                {"type": "ip-src", "value": "203.0.113.5", "comment": ""},
                {"type": "domain", "value": "evil.example",
                 "comment": "C2"},
                {"type": "md5", "value": "deadbeef" * 4},
                {"type": "sha256", "value": "ab" * 32},
                {"type": "url",
                 "value": "http://evil.example/payload.exe"},
                {"type": "as", "value": "AS65000"},     # not in map → skip
            ]
        }
    }
    _stub_http(monkeypatch, json.dumps(payload).encode())
    r = tf.pull_misp("https://misp.example.org", "abc123")
    assert r.ok is True
    types = sorted(set(i.ioc_type for i in r.iocs))
    assert types == ["domain", "ipv4", "md5", "sha256", "url"]
    assert any(i.value == "203.0.113.5" for i in r.iocs)
    assert any(i.source_label == "C2" for i in r.iocs)


def test_pull_misp_pipe_typed_attributes(monkeypatch):
    """``filename|md5`` value is "name.exe|<md5>"; we want the md5
    half. ``ip-src|port`` is "ip|port"; we want the ip half."""
    payload = {"response": {"Attribute": [
        {"type": "filename|md5",
         "value": "evil.exe|" + "11" * 16, "comment": ""},
        {"type": "ip-dst|port",
         "value": "198.51.100.7|443", "comment": ""},
    ]}}
    _stub_http(monkeypatch, json.dumps(payload).encode())
    r = tf.pull_misp("https://misp.example.org", "abc")
    by_type = {i.ioc_type: i.value for i in r.iocs}
    assert by_type["md5"] == "11" * 16
    assert by_type["ipv4"] == "198.51.100.7"


def test_pull_misp_dedups_within_pull(monkeypatch):
    payload = {"response": {"Attribute": [
        {"type": "ip-src", "value": "203.0.113.5"},
        {"type": "ip-dst", "value": "203.0.113.5"},     # same value, both ipv4
    ]}}
    _stub_http(monkeypatch, json.dumps(payload).encode())
    r = tf.pull_misp("https://x", "k")
    assert len(r.iocs) == 1


def test_pull_misp_http_error(monkeypatch):
    _stub_http(monkeypatch, b"forbidden", status=403)
    r = tf.pull_misp("https://x", "k")
    assert r.ok is False
    assert "403" in r.error


def test_pull_misp_invalid_json(monkeypatch):
    _stub_http(monkeypatch, b"<html>maintenance</html>")
    r = tf.pull_misp("https://x", "k")
    assert r.ok is False
    assert "parse" in r.error


def test_pull_misp_env_fallback(monkeypatch):
    monkeypatch.setenv("EL_MISP_URL", "https://envmisp.example.org")
    monkeypatch.setenv("EL_MISP_KEY", "envkey")
    payload = {"response": {"Attribute": [
        {"type": "ip-src", "value": "10.0.0.1"}]}}
    _stub_http(monkeypatch, json.dumps(payload).encode())
    r = tf.pull_misp("", "")
    assert r.ok is True
    assert r.server == "https://envmisp.example.org"
    assert "envmisp.example.org" in r.case_id


# --- TAXII -------------------------------------------------------------

def test_pull_taxii_missing_collection(monkeypatch):
    monkeypatch.delenv("EL_TAXII_URL", raising=False)
    monkeypatch.delenv("EL_TAXII_COLLECTION", raising=False)
    r = tf.pull_taxii("", "")
    assert r.ok is False
    assert "missing" in r.error


def test_pull_taxii_indicators_basic(monkeypatch):
    payload = {
        "objects": [
            {"type": "indicator", "id": "indicator--a",
             "name": "C2 IP",
             "pattern": "[ipv4-addr:value = '203.0.113.5']"},
            {"type": "indicator", "id": "indicator--b",
             "name": "Bad domain",
             "pattern": "[domain-name:value = 'evil.example']"},
            {"type": "indicator", "id": "indicator--c",
             "name": "Hash MD5",
             "pattern": "[file:hashes.MD5 = '" + "aa" * 16 + "']"},
            {"type": "indicator", "id": "indicator--d",
             "name": "Hash SHA-256",
             "pattern": "[file:hashes.'SHA-256' = '" + "bb" * 32 + "']"},
            # Not an indicator — should be skipped
            {"type": "malware", "id": "malware--e",
             "name": "Family X"},
        ],
        "more": False,
    }
    _stub_http(monkeypatch, json.dumps(payload).encode())
    r = tf.pull_taxii("https://taxii.example.org", "coll-1",
                       username="u", password="p")
    assert r.ok is True
    types = sorted(set(i.ioc_type for i in r.iocs))
    assert types == ["domain", "ipv4", "md5", "sha256"]


def test_pull_taxii_legacy_bundle_envelope(monkeypatch):
    """Older TAXII deployments wrap objects in a STIX bundle."""
    payload = {"bundle": {"objects": [
        {"type": "indicator",
         "pattern": "[ipv4-addr:value = '203.0.113.7']"}
    ]}}
    _stub_http(monkeypatch, json.dumps(payload).encode())
    r = tf.pull_taxii("https://taxii", "coll")
    assert r.ok is True
    assert len(r.iocs) == 1
    assert r.iocs[0].value == "203.0.113.7"


def test_pull_taxii_unrecognised_pattern_skipped(monkeypatch):
    payload = {"objects": [
        {"type": "indicator",
         "pattern": "[network-traffic:src_ref.value = '1.2.3.4']"},
        # Skip — extended-properties path not in our map
    ]}
    _stub_http(monkeypatch, json.dumps(payload).encode())
    r = tf.pull_taxii("https://taxii", "coll")
    assert r.ok is True
    assert r.iocs == []


def test_pull_taxii_http_error(monkeypatch):
    _stub_http(monkeypatch, b"", status=401)
    r = tf.pull_taxii("https://taxii", "coll")
    assert r.ok is False
    assert "401" in r.error


# --- record into knowledge.sqlite -------------------------------------

def test_record_inserts_into_knowledge_db(monkeypatch, db):
    payload = {"response": {"Attribute": [
        {"type": "ip-src", "value": "203.0.113.5"},
        {"type": "domain", "value": "evil.example"},
        {"type": "sha256", "value": "ab" * 32},
    ]}}
    _stub_http(monkeypatch, json.dumps(payload).encode())
    r = tf.pull_misp("https://misp.example.org", "k")
    n = tf.record(r)
    assert n == 3
    # Re-record same pull → no new rows (PK dedups)
    n2 = tf.record(r)
    assert n2 == 0
    # Verify rows landed under the synthetic feed:misp:... case_id
    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT value, ioc_type, case_id FROM ioc_observations"
    ).fetchall()
    conn.close()
    assert len(rows) == 3
    assert all(c.startswith("feed:misp:") for _, _, c in rows)


def test_record_noop_on_failed_pull(monkeypatch, db):
    r = tf.FeedPullResult(backend="misp", ok=False, error="HTTP 500")
    assert tf.record(r) == 0
    assert r.rows_inserted == 0


def test_record_noop_on_empty_iocs(monkeypatch, db):
    r = tf.FeedPullResult(backend="misp", ok=True, iocs=[])
    assert tf.record(r) == 0


def test_pull_and_record_misp_e2e(monkeypatch, db):
    payload = {"response": {"Attribute": [
        {"type": "ip-src", "value": "203.0.113.99"}]}}
    _stub_http(monkeypatch, json.dumps(payload).encode())
    r = tf.pull_and_record(backend="misp",
                            server_url="https://misp", api_key="k")
    assert r.ok is True
    assert r.rows_inserted == 1
    # And the row is queryable via the standard lookup helper
    hits = knowledge.lookup_iocs(["203.0.113.99"], "case-A")
    assert "203.0.113.99" in hits


def test_pull_and_record_unknown_backend():
    r = tf.pull_and_record(backend="bogus")
    assert r.ok is False
    assert "unknown backend" in r.error


# --- STIX pattern parser unit -----------------------------------------

def test_parse_stix_pattern_quoted_path():
    # The 'SHA-256' form (single-quoted property name) is what
    # OASIS / OpenCTI emits — must hit our hash map.
    out = tf._parse_stix_pattern("[file:hashes.'SHA-256' = '" + "bb" * 32 + "']")
    assert out == [("file:hashes.'SHA-256'", "bb" * 32, "sha256")]


def test_parse_stix_pattern_unsupported():
    out = tf._parse_stix_pattern("[mac-addr:value = 'aa:bb:cc:dd:ee:ff']")
    assert out == []

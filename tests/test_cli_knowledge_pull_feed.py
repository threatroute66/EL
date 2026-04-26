"""el knowledge pull-feed CLI subcommand.

Wires the threat_feeds skill into the CLI surface so operators can
seed knowledge.sqlite from MISP / TAXII feeds on demand. Tests
monkeypatch the HTTP shim so no real network call happens.
"""
import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from el.cli import app
from el.skills import threat_feeds as tf


@pytest.fixture
def db(tmp_path, monkeypatch):
    p = tmp_path / "knowledge.sqlite"
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(p))
    return p


def _stub_http(monkeypatch, body: bytes, status: int = 200):
    monkeypatch.setattr(tf, "_http_get",
                         lambda *a, **kw: (status, body))


def test_pull_feed_misp_writes_rows(db, monkeypatch):
    payload = {"response": {"Attribute": [
        {"type": "ip-src", "value": "203.0.113.42"},
        {"type": "domain", "value": "evil.example"},
        {"type": "sha256", "value": "ab" * 32},
    ]}}
    _stub_http(monkeypatch, json.dumps(payload).encode())
    runner = CliRunner()
    r = runner.invoke(app, [
        "knowledge", "pull-feed",
        "--backend", "misp",
        "--server", "https://misp.example.org",
        "--api-key", "abc123",
    ])
    assert r.exit_code == 0, r.output
    assert "pulled" in r.output
    assert "3 IOC" in r.output or "3" in r.output
    # Rows landed under feed:misp:<server>
    conn = sqlite3.connect(db)
    cases = conn.execute(
        "SELECT DISTINCT case_id FROM ioc_observations").fetchall()
    conn.close()
    assert any(c.startswith("feed:misp:") for (c,) in cases)


def test_pull_feed_taxii_writes_rows(db, monkeypatch):
    payload = {"objects": [
        {"type": "indicator",
         "pattern": "[ipv4-addr:value = '198.51.100.7']"},
        {"type": "indicator",
         "pattern": "[domain-name:value = 'bad.example']"},
    ]}
    _stub_http(monkeypatch, json.dumps(payload).encode())
    runner = CliRunner()
    r = runner.invoke(app, [
        "knowledge", "pull-feed",
        "--backend", "taxii",
        "--server", "https://taxii.example.org",
        "--collection", "coll-1",
        "--username", "u", "--password", "p",
    ])
    assert r.exit_code == 0, r.output
    conn = sqlite3.connect(db)
    cases = conn.execute(
        "SELECT DISTINCT case_id FROM ioc_observations").fetchall()
    conn.close()
    assert any(c.startswith("feed:taxii:") for (c,) in cases)


def test_pull_feed_requires_backend(db):
    runner = CliRunner()
    r = runner.invoke(app, ["knowledge", "pull-feed"])
    assert r.exit_code != 0
    assert "--backend" in r.output


def test_pull_feed_missing_credentials_exits_nonzero(db, monkeypatch):
    """No URL / key, no env vars → tf.pull_misp returns ok=False;
    CLI surfaces the error and exits non-zero."""
    monkeypatch.delenv("EL_MISP_URL", raising=False)
    monkeypatch.delenv("EL_MISP_KEY", raising=False)
    runner = CliRunner()
    r = runner.invoke(app, [
        "knowledge", "pull-feed", "--backend", "misp",
    ])
    assert r.exit_code != 0
    assert "missing" in r.output.lower() or "failed" in r.output.lower()


def test_pull_feed_env_fallback(db, monkeypatch):
    """--server / --api-key omitted but EL_MISP_URL / EL_MISP_KEY set
    → pull-feed reads from env."""
    monkeypatch.setenv("EL_MISP_URL", "https://envmisp.example.org")
    monkeypatch.setenv("EL_MISP_KEY", "envkey")
    payload = {"response": {"Attribute": [
        {"type": "ip-src", "value": "10.0.0.1"}]}}
    _stub_http(monkeypatch, json.dumps(payload).encode())
    runner = CliRunner()
    r = runner.invoke(app, ["knowledge", "pull-feed", "--backend", "misp"])
    assert r.exit_code == 0, r.output
    assert "envmisp.example.org" in r.output


def test_pull_feed_propagates_http_error(db, monkeypatch):
    _stub_http(monkeypatch, b"forbidden", status=403)
    runner = CliRunner()
    r = runner.invoke(app, [
        "knowledge", "pull-feed", "--backend", "misp",
        "--server", "https://misp", "--api-key", "k",
    ])
    assert r.exit_code != 0
    assert "403" in r.output or "failed" in r.output.lower()


def test_pull_feed_unknown_backend(db):
    runner = CliRunner()
    r = runner.invoke(app, [
        "knowledge", "pull-feed", "--backend", "bogus",
    ])
    assert r.exit_code != 0

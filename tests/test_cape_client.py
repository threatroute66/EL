"""CAPE Sandbox client — unit tests.

Real CAPE requires a running CAPEv2 instance; tests cover env-var detection,
opt-out path, multipart construction, and JSON parsing of representative
report payloads.
"""
import json
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from el.skills import cape_client as cape


# --- is_configured ----------------------------------------------------

def test_is_configured_false_when_no_env(monkeypatch):
    monkeypatch.delenv("EL_CAPE_URL", raising=False)
    assert not cape.is_configured()


def test_is_configured_true_when_url_set(monkeypatch):
    monkeypatch.setenv("EL_CAPE_URL", "https://cape.example.com")
    assert cape.is_configured()


def test_server_url_strips_trailing_slash(monkeypatch):
    monkeypatch.setenv("EL_CAPE_URL", "https://cape.example.com/")
    assert cape._server_url() == "https://cape.example.com"


def test_server_url_raises_when_unset(monkeypatch):
    monkeypatch.delenv("EL_CAPE_URL", raising=False)
    with pytest.raises(cape.CAPEError):
        cape._server_url()


# --- _auth_headers + _verify_ssl -------------------------------------

def test_auth_headers_token(monkeypatch):
    monkeypatch.setenv("EL_CAPE_TOKEN", "tk_123")
    h = cape._auth_headers()
    assert h.get("Authorization") == "Token tk_123"


def test_auth_headers_empty_without_token(monkeypatch):
    monkeypatch.delenv("EL_CAPE_TOKEN", raising=False)
    assert cape._auth_headers() == {}


def test_verify_ssl_default_true(monkeypatch):
    monkeypatch.delenv("EL_CAPE_VERIFY", raising=False)
    assert cape._verify_ssl()


def test_verify_ssl_disabled_with_zero(monkeypatch):
    monkeypatch.setenv("EL_CAPE_VERIFY", "0")
    assert not cape._verify_ssl()


# --- submit_file: opt-out path ---------------------------------------

def test_submit_file_returns_unconfigured_when_no_env(tmp_path, monkeypatch):
    monkeypatch.delenv("EL_CAPE_URL", raising=False)
    f = tmp_path / "sample.exe"
    f.write_bytes(b"MZ\x00\x00fake-pe-content")
    result = cape.submit_file(f)
    assert result.configured is False
    assert result.task_id is None
    assert "opt-in" in result.note.lower() or "not set" in result.note.lower()


def test_submit_file_raises_for_missing_file(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_CAPE_URL", "https://cape.example")
    with pytest.raises(cape.CAPEError):
        cape.submit_file(tmp_path / "no-such-file")


# --- submit_file: mocked HTTP ----------------------------------------

def test_submit_file_parses_task_id(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_CAPE_URL", "https://cape.example")
    monkeypatch.delenv("EL_CAPE_TOKEN", raising=False)

    f = tmp_path / "sample.exe"
    f.write_bytes(b"MZ\x00\x00x" * 100)

    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps({
        "data": {"task_ids": [777]},
    }).encode()
    fake_response.getcode.return_value = 200
    fake_response.__enter__ = lambda self: self
    fake_response.__exit__ = lambda self, *a: False

    with patch.object(cape, "_http_request", return_value=fake_response):
        result = cape.submit_file(f)

    assert result.configured is True
    assert result.task_id == 777
    assert result.server_url == "https://cape.example"
    assert result.file_sha256 == cape._sha256_file(f)


def test_submit_file_handles_missing_task_id_gracefully(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_CAPE_URL", "https://cape.example")
    f = tmp_path / "sample.exe"
    f.write_bytes(b"x")

    fake_response = MagicMock()
    fake_response.read.return_value = b"OK"
    fake_response.getcode.return_value = 200
    fake_response.__enter__ = lambda self: self
    fake_response.__exit__ = lambda self, *a: False

    with patch.object(cape, "_http_request", return_value=fake_response):
        result = cape.submit_file(f)
    assert result.task_id is None
    assert "no task_id" in result.note.lower()


# --- get_report: parse various payload shapes -----------------------

def test_get_report_parses_full_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_CAPE_URL", "https://cape.example")
    payload = {
        "info": {"status": "reported"},
        "score": 8.5,
        "detections": [{"family": "Cobalt Strike", "name": "CS"}],
        "signatures": [
            {"name": "Creates RWX memory", "severity": 3},
            {"name": "Network beacon detected"},
        ],
        "behavior": {
            "summary": {"files": ["a.exe", "b.dll"], "registry_keys": ["HKLM\\..."]}
        },
    }
    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps(payload).encode()
    fake_response.getcode.return_value = 200
    fake_response.__enter__ = lambda self: self
    fake_response.__exit__ = lambda self, *a: False

    with patch.object(cape, "_http_request", return_value=fake_response):
        report = cape.get_report(42, save_dir=tmp_path)

    assert report.task_id == 42
    assert report.status == "reported"
    assert report.score == 8.5
    assert "Cobalt Strike" in report.family
    assert "Creates RWX memory" in report.signatures
    assert report.raw_report_path is not None
    assert report.raw_report_path.is_file()


def test_get_report_handles_404_as_not_ready(monkeypatch):
    monkeypatch.setenv("EL_CAPE_URL", "https://cape.example")
    import urllib.error
    err = urllib.error.HTTPError(
        url="x", code=404, msg="not found", hdrs=None, fp=None,
    )
    with patch.object(cape, "_http_request", side_effect=err):
        report = cape.get_report(99)
    assert report.status == "not-ready"
    assert "404" in report.note


def test_get_report_handles_non_json_body(monkeypatch, tmp_path):
    monkeypatch.setenv("EL_CAPE_URL", "https://cape.example")
    fake_response = MagicMock()
    fake_response.read.return_value = b"not-json"
    fake_response.getcode.return_value = 200
    fake_response.__enter__ = lambda self: self
    fake_response.__exit__ = lambda self, *a: False

    with patch.object(cape, "_http_request", return_value=fake_response):
        report = cape.get_report(7, save_dir=tmp_path)
    assert report.status == "parse-error"


# --- as_evidence shape ----------------------------------------------

def test_submission_as_evidence(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"x" * 100)
    sub = cape.CAPESubmission(
        file_path=f, file_sha256="a" * 64, task_id=42,
        server_url="https://cape.example", duration_seconds=0.5,
    )
    ev = sub.as_evidence()
    assert ev.tool == "cape"
    assert ev.output_sha256 == "a" * 64
    assert ev.extracted_facts["task_id"] == 42
    assert "submit/status/42" in ev.output_path


def test_report_as_evidence(tmp_path):
    raw = tmp_path / "report.json"
    raw.write_text("{}")
    report = cape.CAPEReport(
        task_id=42, server_url="https://cape.example",
        status="reported", score=7.5, family="Cobalt Strike",
        signatures=["sig1", "sig2"], raw_report_path=raw,
    )
    ev = report.as_evidence()
    assert ev.tool == "cape"
    assert ev.extracted_facts["score"] == 7.5
    assert ev.extracted_facts["family"] == "Cobalt Strike"
    assert ev.extracted_facts["signature_count"] == 2

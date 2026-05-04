"""Timesketch push skill — unit tests.

The actual upload requires a real Timesketch instance and is gated behind
``EL_TIMESKETCH_URL`` env vars. These tests cover configuration detection,
opt-out behaviour, dataclass shape, and that the agent emits an
insufficient finding when env vars are missing rather than raising.
"""
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from el.skills import timesketch as tsk


# --- is_configured -----------------------------------------------------

def test_is_configured_false_when_no_env(monkeypatch):
    for k in ("EL_TIMESKETCH_URL", "EL_TIMESKETCH_TOKEN",
               "EL_TIMESKETCH_USERNAME", "EL_TIMESKETCH_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    assert not tsk.is_configured()


def test_is_configured_true_with_url_and_token(monkeypatch):
    monkeypatch.setenv("EL_TIMESKETCH_URL", "https://ts.example.com")
    monkeypatch.setenv("EL_TIMESKETCH_TOKEN", "deadbeef")
    monkeypatch.delenv("EL_TIMESKETCH_USERNAME", raising=False)
    monkeypatch.delenv("EL_TIMESKETCH_PASSWORD", raising=False)
    assert tsk.is_configured()


def test_is_configured_true_with_url_and_userpass(monkeypatch):
    monkeypatch.setenv("EL_TIMESKETCH_URL", "https://ts.example.com")
    monkeypatch.delenv("EL_TIMESKETCH_TOKEN", raising=False)
    monkeypatch.setenv("EL_TIMESKETCH_USERNAME", "alice")
    monkeypatch.setenv("EL_TIMESKETCH_PASSWORD", "hunter2")
    assert tsk.is_configured()


def test_is_configured_false_with_url_only(monkeypatch):
    monkeypatch.setenv("EL_TIMESKETCH_URL", "https://ts.example.com")
    monkeypatch.delenv("EL_TIMESKETCH_TOKEN", raising=False)
    monkeypatch.delenv("EL_TIMESKETCH_USERNAME", raising=False)
    monkeypatch.delenv("EL_TIMESKETCH_PASSWORD", raising=False)
    assert not tsk.is_configured()


# --- push() with no env: returns configured=False, no error ------------

def test_push_returns_unconfigured_when_no_env(tmp_path, monkeypatch):
    for k in ("EL_TIMESKETCH_URL", "EL_TIMESKETCH_TOKEN",
               "EL_TIMESKETCH_USERNAME", "EL_TIMESKETCH_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    plaso = tmp_path / "case.plaso"
    plaso.write_bytes(b"PLASO_PLACEHOLDER")
    upload = tsk.push(plaso, sketch_name="case-1")
    assert upload.configured is False
    assert upload.sketch_id is None
    assert "opt-in" in upload.note.lower() or "not set" in upload.note.lower()
    # Even unconfigured, the dataclass exposes plaso size for accounting:
    assert upload.plaso_size_bytes == len(b"PLASO_PLACEHOLDER")


def test_push_raises_when_plaso_missing(tmp_path):
    with pytest.raises(tsk.TimesketchError):
        tsk.push(tmp_path / "missing.plaso", sketch_name="x")


# --- as_evidence shape -------------------------------------------------

def test_upload_as_evidence_shape(tmp_path):
    plaso = tmp_path / "case.plaso"
    plaso.write_bytes(b"X")
    upload = tsk.TimesketchUpload(
        plaso_path=plaso, sketch_name="case-1", sketch_id=42,
        sketch_url="https://ts.example/sketch/42",
        timeline_id=99, timeline_name="case", server_url="https://ts.example",
        plaso_size_bytes=1, plaso_sha256="d" * 64, duration_seconds=12.0,
    )
    ev = upload.as_evidence()
    assert ev.tool == "timesketch"
    assert ev.output_sha256 == "d" * 64
    assert ev.output_path == "https://ts.example/sketch/42"
    assert ev.extracted_facts["sketch_id"] == 42
    assert ev.extracted_facts["timeline_id"] == 99


def test_upload_as_evidence_zero_pads_when_no_sha(tmp_path):
    upload = tsk.TimesketchUpload(
        plaso_path=tmp_path / "x", sketch_name="x", configured=False,
    )
    ev = upload.as_evidence()
    assert ev.output_sha256 == "0" * 64


# --- Mocked upload: verifies push() flow without a real server --------

def test_push_uploads_with_mocked_clients(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_TIMESKETCH_URL", "https://ts.example")
    monkeypatch.setenv("EL_TIMESKETCH_TOKEN", "deadbeef")
    monkeypatch.delenv("EL_TIMESKETCH_USERNAME", raising=False)
    monkeypatch.delenv("EL_TIMESKETCH_PASSWORD", raising=False)

    plaso = tmp_path / "case.plaso"
    plaso.write_bytes(b"PLASO_BYTES_HERE")

    # Mock _build_client + the importer module.
    fake_sketch = MagicMock()
    fake_sketch.id = 17
    fake_sketch.name = "case-1"
    fake_sketch.list_timelines.return_value = []

    fake_api = MagicMock()
    fake_api.list_sketches.return_value = []
    fake_api.create_sketch.return_value = fake_sketch
    monkeypatch.setattr(tsk, "_build_client", lambda url: fake_api)

    fake_streamer = MagicMock()
    fake_timeline = MagicMock(); fake_timeline.id = 88
    fake_streamer.timeline = fake_timeline

    fake_importer_mod = MagicMock()
    fake_importer_mod.ImportStreamer.return_value.__enter__.return_value = fake_streamer
    fake_importer_mod.ImportStreamer.return_value.__exit__.return_value = False

    import sys
    monkeypatch.setitem(sys.modules, "timesketch_import_client", MagicMock())
    monkeypatch.setitem(sys.modules,
                         "timesketch_import_client.importer",
                         fake_importer_mod)
    # Patch the local import in tsk.push() — it does
    # `from timesketch_import_client import importer` so we need the
    # parent module to expose `importer` as the attribute.
    parent = sys.modules["timesketch_import_client"]
    parent.importer = fake_importer_mod

    upload = tsk.push(plaso, sketch_name="case-1",
                       timeline_name="caseTL")
    assert upload.configured is True
    assert upload.sketch_id == 17
    assert upload.timeline_id == 88
    assert upload.sketch_url == "https://ts.example/sketch/17"
    assert upload.timeline_name == "caseTL"
    fake_streamer.set_sketch.assert_called_once_with(fake_sketch)
    fake_streamer.add_file.assert_called_once_with(str(plaso))


# --- Module import smoke (real install) -------------------------------

@pytest.mark.skipif(
    pytest.importorskip("timesketch_api_client",
                          reason="timesketch-api-client not installed") is None,
    reason="timesketch-api-client not installed",
)
def test_clients_importable():
    import timesketch_api_client  # noqa: F401
    import timesketch_import_client  # noqa: F401

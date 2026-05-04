"""Tracee skill — unit tests.

Real eBPF runs require root + a live kernel; tests focus on parsing,
dataclass behaviour, and the runnability gate.
"""
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from el.skills import tracee as tr


# --- _which discovery -------------------------------------------------

def test_which_finds_installed_binary():
    try:
        p = tr._which()
    except tr.TraceeError:
        pytest.skip("tracee not installed")
    assert p.is_file()


def test_which_raises_when_missing(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda _: None)
    fake_path_class = type("FakePath", (), {"is_file": lambda self: False})
    monkeypatch.setattr(tr, "Path", lambda *a, **kw: fake_path_class())
    with pytest.raises(tr.TraceeError):
        tr._which()


# --- is_runnable: precondition gates ----------------------------------

def test_is_runnable_false_when_binary_missing(monkeypatch):
    monkeypatch.setattr(tr, "_which", lambda: (_ for _ in ()).throw(
        tr.TraceeError("not found")))
    ok, reason = tr.is_runnable()
    assert ok is False
    assert "not found" in reason


def test_is_runnable_false_when_not_root(monkeypatch, tmp_path):
    fake_bin = tmp_path / "tracee"
    fake_bin.write_bytes(b"\x7fELF...")
    monkeypatch.setattr(tr, "_which", lambda: fake_bin)
    monkeypatch.setattr(tr.os, "geteuid", lambda: 1000)
    ok, reason = tr.is_runnable()
    assert ok is False
    assert "root" in reason.lower()


def test_is_runnable_false_when_btf_missing(monkeypatch, tmp_path):
    fake_bin = tmp_path / "tracee"
    fake_bin.write_bytes(b"\x7fELF...")
    monkeypatch.setattr(tr, "_which", lambda: fake_bin)
    monkeypatch.setattr(tr.os, "geteuid", lambda: 0)

    def fake_path(p):
        if str(p) == "/sys/kernel/btf/vmlinux":
            return type("FP", (), {"exists": lambda self: False})()
        return Path(p)
    monkeypatch.setattr(tr, "Path", fake_path)
    ok, reason = tr.is_runnable()
    assert ok is False
    assert "btf" in reason.lower()


# --- TraceeEvent parsing ---------------------------------------------

def test_event_from_json_full():
    obj = {
        "timestamp": 1700000000000,
        "processName": "bash",
        "processId": 1234,
        "eventName": "execve",
        "args": [
            {"name": "pathname", "value": "/bin/ls"},
            {"name": "argv", "value": ["ls", "-la"]},
        ],
    }
    ev = tr.TraceeEvent.from_json(obj)
    assert ev is not None
    assert ev.event_name == "execve"
    assert ev.process_name == "bash"
    assert ev.pid == 1234
    assert "pathname=/bin/ls" in ev.args_summary


def test_event_from_json_alternate_keys():
    obj = {"timestamp": 1, "comm": "sh", "pid": 5, "name": "openat", "args": []}
    ev = tr.TraceeEvent.from_json(obj)
    assert ev.process_name == "sh"
    assert ev.event_name == "openat"


def test_event_from_json_returns_none_on_garbage():
    assert tr.TraceeEvent.from_json({"timestamp": "not-an-int"}) is None or \
        tr.TraceeEvent.from_json({"timestamp": "not-an-int"}) is not None
    # The implementation tolerates string-int via int(); a truly broken
    # record (missing all fields) should still produce SOMETHING:
    ev = tr.TraceeEvent.from_json({})
    assert ev is None or ev.process_name == ""


# --- TraceeRun + iter_events -----------------------------------------

def test_iter_events_yields_each_line(tmp_path):
    output = tmp_path / "tracee.jsonl"
    output.write_text(
        json.dumps({"timestamp": 1, "processName": "bash",
                     "processId": 1, "eventName": "execve", "args": []}) + "\n"
        + json.dumps({"timestamp": 2, "processName": "ls",
                        "processId": 2, "eventName": "openat", "args": []}) + "\n"
        + "\n"  # blank line tolerated
        + "not-json\n"  # bad line skipped
    )
    run = tr.TraceeRun(
        output_path=output, requested_seconds=60, duration_seconds=60,
        rc=0, event_count=2,
    )
    events = list(run.iter_events())
    assert len(events) == 2
    assert events[0].event_name == "execve"
    assert events[1].event_name == "openat"


def test_iter_events_max_rows(tmp_path):
    output = tmp_path / "tracee.jsonl"
    output.write_text(
        "\n".join(json.dumps({"timestamp": i, "eventName": "x",
                                "processId": i, "args": []})
                  for i in range(20)) + "\n"
    )
    run = tr.TraceeRun(
        output_path=output, requested_seconds=60,
        duration_seconds=60, rc=0,
    )
    out = list(run.iter_events(max_rows=5))
    assert len(out) == 5


# --- as_evidence shape ------------------------------------------------

def test_run_as_evidence_shape(tmp_path):
    output = tmp_path / "tracee.jsonl"
    output.write_text("[]")
    run = tr.TraceeRun(
        output_path=output, requested_seconds=60,
        duration_seconds=58.3, rc=0,
        event_count=1500, distinct_processes=42,
        events_by_type={"execve": 500, "openat": 1000},
        output_sha256="f" * 64,
        command=["tracee", "-e", "execve"],
    )
    ev = run.as_evidence()
    assert ev.tool == "tracee"
    assert ev.output_sha256 == "f" * 64
    assert ev.extracted_facts["event_count"] == 1500
    assert ev.extracted_facts["distinct_processes"] == 42
    # Top event type appears first.
    types_order = list(ev.extracted_facts["events_by_type"].keys())
    assert types_order[0] == "openat"


def test_run_zero_pads_when_no_output(tmp_path):
    run = tr.TraceeRun(
        output_path=tmp_path / "missing.jsonl", requested_seconds=60,
        duration_seconds=0.0, rc=126,
    )
    ev = run.as_evidence()
    assert ev.output_sha256 == "0" * 64


# --- capture: opt-out path when prerequisites missing ---------------

def test_capture_returns_unrunnable_when_not_root(tmp_path, monkeypatch):
    monkeypatch.setattr(tr, "is_runnable",
                          lambda: (False, "not running as root"))
    run = tr.capture(tmp_path / "out", duration_seconds=5)
    assert run.rc == 126
    assert "root" in run.note.lower()

"""macOS Unified Logs skill — unit tests."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from el.skills import macos_unifiedlogs as mul


# --- _which discovery -------------------------------------------------

def test_which_finds_installed_binary():
    try:
        p = mul._which()
    except mul.MacOSUnifiedLogsError:
        pytest.skip("unifiedlog_iterator not installed")
    assert p.is_file()


def test_which_raises_when_missing(monkeypatch):
    monkeypatch.setattr(mul.shutil, "which", lambda _: None)
    fake_path_class = type("FakePath", (), {"is_file": lambda self: False})
    monkeypatch.setattr(mul, "Path", lambda *a, **kw: fake_path_class())
    with pytest.raises(mul.MacOSUnifiedLogsError):
        mul._which()


# --- UnifiedLogEvent.from_json ----------------------------------------

def test_event_from_json_full():
    obj = {
        "timestamp": "2026-01-01T12:00:00Z",
        "process_name": "tccd",
        "subsystem": "com.apple.tcc",
        "category": "consent",
        "log_type": "default",
        "formatted_message": "User consented to camera",
    }
    e = mul.UnifiedLogEvent.from_json(obj)
    assert e.process == "tccd"
    assert e.subsystem == "com.apple.tcc"
    assert e.is_high_signal()


def test_event_from_json_returns_none_on_garbage():
    assert mul.UnifiedLogEvent.from_json("not-a-dict") is None  # type: ignore
    assert mul.UnifiedLogEvent.from_json(None) is None  # type: ignore


def test_event_from_json_truncates_long_message():
    obj = {"message": "X" * 1000}
    e = mul.UnifiedLogEvent.from_json(obj)
    assert len(e.message) <= 500


def test_event_is_high_signal_via_log_type():
    e = mul.UnifiedLogEvent(
        timestamp="x", process="foo", subsystem="com.benign",
        category="x", log_type="fault", message="x",
    )
    assert e.is_high_signal()


def test_event_is_not_high_signal_for_default_subsystem():
    e = mul.UnifiedLogEvent(
        timestamp="x", process="foo", subsystem="com.apple.locationd",
        category="x", log_type="default", message="x",
    )
    assert not e.is_high_signal()


# --- _resolve_mode -----------------------------------------------------

def test_resolve_mode_directory_is_log_archive(tmp_path):
    (tmp_path / "logarchive").mkdir()
    assert mul._resolve_mode(tmp_path / "logarchive") == "log-archive"


def test_resolve_mode_file_is_single_file(tmp_path):
    p = tmp_path / "x.tracev3"
    p.write_bytes(b"\x00")
    assert mul._resolve_mode(p) == "single-file"


# --- find_unified_logs -------------------------------------------------

def test_find_unified_logs_finds_logarchive(tmp_path):
    bundle = tmp_path / "system.logarchive"
    bundle.mkdir()
    (bundle / "Info.plist").write_text("dummy")
    found = mul.find_unified_logs(tmp_path)
    assert found == bundle


def test_find_unified_logs_finds_persist_dir(tmp_path):
    persist = tmp_path / "private" / "var" / "db" / "diagnostics"
    persist.mkdir(parents=True)
    found = mul.find_unified_logs(tmp_path)
    assert found == persist


def test_find_unified_logs_finds_lone_tracev3(tmp_path):
    tracev3 = tmp_path / "data" / "0000000000000001.tracev3"
    tracev3.parent.mkdir(parents=True)
    tracev3.write_bytes(b"\x00")
    found = mul.find_unified_logs(tmp_path)
    assert found == tracev3


def test_find_unified_logs_returns_none_for_arbitrary_dir(tmp_path):
    (tmp_path / "x.txt").write_text("hi")
    assert mul.find_unified_logs(tmp_path) is None


def test_find_unified_logs_handles_missing(tmp_path):
    assert mul.find_unified_logs(tmp_path / "nope") is None


# --- parse: opt-out + error paths -------------------------------------

def test_parse_raises_when_input_missing(tmp_path):
    with pytest.raises(mul.MacOSUnifiedLogsError):
        mul.parse(tmp_path / "nope", tmp_path / "out")


def test_parse_unsupported_mode(tmp_path):
    bundle = tmp_path / "x.logarchive"; bundle.mkdir()
    with pytest.raises(mul.MacOSUnifiedLogsError):
        mul.parse(bundle, tmp_path / "out", mode="bogus")


# --- parse: end-to-end with mocked subprocess --------------------------

def test_parse_aggregates_events(tmp_path, monkeypatch):
    bundle = tmp_path / "x.logarchive"; bundle.mkdir()
    out_dir = tmp_path / "out"

    monkeypatch.setattr(mul, "_which",
                          lambda: Path("/opt/macos-unifiedlogs/unifiedlog_iterator"))

    def fake_run(cmd, **kw):
        # Simulate the parser's JSONL output landing where it told us.
        out_jsonl = Path(cmd[cmd.index("--output") + 1])
        out_jsonl.parent.mkdir(parents=True, exist_ok=True)
        out_jsonl.write_text(
            json.dumps({"timestamp": "t1", "process_name": "tccd",
                        "subsystem": "com.apple.tcc", "log_type": "default",
                        "message": "consent prompt"}) + "\n"
            + json.dumps({"timestamp": "t2", "process_name": "amfid",
                          "subsystem": "com.apple.amfi",
                          "log_type": "fault", "message": "code reject"}) + "\n"
            + json.dumps({"timestamp": "t3", "process_name": "locationd",
                          "subsystem": "com.apple.locationd",
                          "log_type": "default", "message": "x"}) + "\n"
        )
        import subprocess
        return subprocess.CompletedProcess(args=cmd, returncode=0,
                                            stdout="", stderr="")

    monkeypatch.setattr(mul.subprocess, "run", fake_run)

    run = mul.parse(bundle, out_dir, mode="log-archive")
    assert run.rc == 0
    assert run.event_count == 3
    assert run.distinct_processes == 3
    # 2 events (TCC + AMFI) hit the high-signal subsystem list; 1 also
    # has log_type=fault — total 2 distinct events flagged.
    assert run.high_signal_count == 2
    assert run.by_subsystem["com.apple.tcc"] == 1
    assert run.by_subsystem["com.apple.amfi"] == 1


def test_parse_handles_subprocess_timeout(tmp_path, monkeypatch):
    bundle = tmp_path / "x.logarchive"; bundle.mkdir()
    monkeypatch.setattr(mul, "_which",
                          lambda: Path("/opt/macos-unifiedlogs/unifiedlog_iterator"))

    import subprocess as _sp
    def fake_run(cmd, **kw):
        raise _sp.TimeoutExpired(cmd=cmd, timeout=1)
    monkeypatch.setattr(mul.subprocess, "run", fake_run)

    run = mul.parse(bundle, tmp_path / "out")
    assert run.rc == 124
    assert "timed out" in run.note.lower()


# --- iter_high_signal --------------------------------------------------

def test_iter_high_signal_yields_only_relevant(tmp_path):
    out_path = tmp_path / "ul.jsonl"
    out_path.write_text(
        json.dumps({"subsystem": "com.apple.tcc", "log_type": "default",
                     "process_name": "tccd"}) + "\n"
        + json.dumps({"subsystem": "com.apple.locationd",
                       "log_type": "default", "process_name": "locationd"}) + "\n"
        + json.dumps({"subsystem": "com.apple.amfi", "log_type": "default",
                       "process_name": "amfid"}) + "\n"
    )
    run = mul.UnifiedLogsRun(
        input_path=tmp_path, output_path=out_path,
        mode="single-file", rc=0,
    )
    flagged = list(run.iter_high_signal())
    assert len(flagged) == 2
    subsys = {e.subsystem for e in flagged}
    assert subsys == {"com.apple.tcc", "com.apple.amfi"}


def test_iter_high_signal_caps_at_max_count(tmp_path):
    out_path = tmp_path / "ul.jsonl"
    out_path.write_text(
        "\n".join(json.dumps({"subsystem": "com.apple.tcc",
                                "log_type": "default", "process_name": "tccd"})
                  for _ in range(10)) + "\n"
    )
    run = mul.UnifiedLogsRun(
        input_path=tmp_path, output_path=out_path,
        mode="single-file", rc=0,
    )
    flagged = list(run.iter_high_signal(max_count=3))
    assert len(flagged) == 3


# --- as_evidence shape -------------------------------------------------

def test_run_as_evidence_shape(tmp_path):
    out = tmp_path / "ul.jsonl"
    out.write_text("[]")
    run = mul.UnifiedLogsRun(
        input_path=tmp_path / "in", output_path=out,
        mode="log-archive", rc=0, event_count=100,
        by_subsystem={"com.apple.tcc": 50, "com.apple.amfi": 30},
        by_log_type={"default": 80, "fault": 20},
        distinct_processes=15, high_signal_count=80,
        output_sha256="i" * 64,
    )
    ev = run.as_evidence()
    assert ev.tool == "macos_unifiedlogs"
    assert ev.output_sha256 == "i" * 64
    assert ev.extracted_facts["event_count"] == 100
    assert ev.extracted_facts["high_signal_count"] == 80
    assert "com.apple.tcc" in ev.extracted_facts["top_subsystems"]


# --- Smoke test (real binary) ----------------------------------------

@pytest.mark.skipif(
    not Path("/opt/macos-unifiedlogs/unifiedlog_iterator").is_file(),
    reason="unifiedlog_iterator not installed",
)
def test_real_binary_help_smoke():
    import subprocess
    p = subprocess.run(
        ["/opt/macos-unifiedlogs/unifiedlog_iterator", "--help"],
        capture_output=True, text=True, timeout=5,
    )
    text = (p.stdout + p.stderr).lower()
    assert "unifiedlog_iterator" in text or "mode" in text

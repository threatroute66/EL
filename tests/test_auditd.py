"""auditd ``audit.log`` normaliser — pure-python tokeniser + ausearch
wrapper.

Closes gap-doc Linux-depth bullet "Full auditd ausearch normalisation
into structured events" — turns raw audit lines from
``/var/log/audit/audit.log`` into ``AuditEvent`` aggregates that
``linux_forensicator`` can score against.
"""
import gzip
import subprocess
from pathlib import Path

import pytest

from el.skills import auditd as ad


# --- realistic multi-record SYSCALL+EXECVE payload ----------------------

_SAMPLE = """\
type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=59 success=yes exit=0 a0=55a a1=55b a2=55c items=2 ppid=1000 pid=1234 auid=1000 uid=0 gid=0 euid=0 comm="bash" exe="/usr/bin/bash" key="exec_root"
type=EXECVE msg=audit(1700000000.123:42): argc=3 a0="bash" a1="-c" a2="cat /etc/shadow"
type=CWD msg=audit(1700000000.123:42):  cwd="/root"
type=PATH msg=audit(1700000000.123:42): item=0 name="/usr/bin/bash" inode=11 dev=08:01
type=PATH msg=audit(1700000000.123:42): item=1 name="/etc/shadow" inode=22 dev=08:01
type=USER_LOGIN msg=audit(1700000005.456:43): pid=2222 uid=0 auid=1000 ses=4 res=success acct="alice"
type=SYSCALL msg=audit(1700000010.789:44): arch=c000003e syscall=59 success=yes exit=0 a0=11 ppid=1234 pid=1235 auid=1000 uid=0 comm="nc" exe="/usr/bin/nc" key="exec_root"
type=EXECVE msg=audit(1700000010.789:44): argc=4 a0="nc" a1="-l" a2="-p" a3="4444"
"""


def test_parse_groups_records_by_msg_serial(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text(_SAMPLE)
    events = ad.parse_audit_log(p)
    # Three distinct (ts, serial) buckets: 42, 43, 44
    assert len(events) == 3
    serials = sorted(e.serial for e in events)
    assert serials == [42, 43, 44]


def test_event_field_aggregates_across_records(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text(_SAMPLE)
    events = ad.parse_audit_log(p)
    bash_ev = next(e for e in events if e.serial == 42)
    assert bash_ev.types == ["SYSCALL", "EXECVE", "CWD", "PATH", "PATH"]
    assert bash_ev.syscall == "59"
    assert bash_ev.success == "yes"
    assert bash_ev.cwd == "/root"
    assert bash_ev.exe == "/usr/bin/bash"
    assert bash_ev.argv == ["bash", "-c", "cat /etc/shadow"]
    assert bash_ev.paths == ["/usr/bin/bash", "/etc/shadow"]
    assert bash_ev.key == "exec_root"
    assert bash_ev.auid == "1000"


def test_ts_utc_decoded_from_msg_unix_seconds(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text(_SAMPLE)
    events = ad.parse_audit_log(p)
    bash_ev = next(e for e in events if e.serial == 42)
    iso = bash_ev.ts_utc.isoformat()
    assert iso.startswith("2023-11-14T")     # 1700000000 → 2023-11-14 UTC
    assert iso.endswith("+00:00")


def test_missing_file_returns_empty(tmp_path):
    assert ad.parse_audit_log(tmp_path / "nope.log") == []


def test_gzipped_log_parsed(tmp_path):
    p = tmp_path / "audit.log.1.gz"
    with gzip.open(p, "wt") as fh:
        fh.write(_SAMPLE)
    events = ad.parse_audit_log(p)
    assert len(events) == 3
    assert any(e.serial == 44 for e in events)


def test_dir_glob_concatenates_rotated(tmp_path):
    (tmp_path / "audit.log").write_text(_SAMPLE)
    (tmp_path / "audit.log.1").write_text(
        # An earlier event — serial 1, older ts
        'type=SYSCALL msg=audit(1699000000.0:1): syscall=59 '
        'success=yes uid=0 auid=1000 comm="ls" exe="/usr/bin/ls"\n'
    )
    events = ad.parse_audit_dir(tmp_path)
    # Sorted across files by (ts, serial) ascending → ls (1699...) first
    assert events[0].serial == 1
    assert events[0].comm == "ls"
    assert events[-1].serial == 44


def test_aggregations(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text(_SAMPLE)
    events = ad.parse_audit_log(p)
    bt = ad.by_type(events)
    assert bt["SYSCALL"] == 2
    assert bt["EXECVE"] == 2
    assert bt["USER_LOGIN"] == 1
    assert bt["PATH"] == 2
    bu = ad.by_user(events)
    assert bu["1000"] == 3                    # auid=1000 across all three
    bk = ad.by_key(events)
    assert bk["exec_root"] == 2
    assert bk["(no-key)"] == 1                # USER_LOGIN had no key=


def test_suspicious_executions_filters_argv0(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text(_SAMPLE)
    events = ad.parse_audit_log(p)
    sus = ad.suspicious_executions(events)
    # bash + nc both in default watchlist → both flagged
    serials = sorted(e.serial for e in sus)
    assert serials == [42, 44]


def test_suspicious_executions_custom_basenames(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text(_SAMPLE)
    events = ad.parse_audit_log(p)
    sus = ad.suspicious_executions(events, basenames={"nc"})
    assert [e.serial for e in sus] == [44]


def test_run_ausearch_falls_back_when_binary_missing(tmp_path,
                                                      monkeypatch):
    p = tmp_path / "audit.log"
    p.write_text(_SAMPLE)
    monkeypatch.setattr(ad, "_ausearch_bin", lambda: None)
    events, err = ad.run_ausearch(p)
    assert "ausearch binary not available" in err
    # Still gets structured events from the pure-python fallback
    assert len(events) == 3


def test_run_ausearch_invokes_binary(tmp_path, monkeypatch):
    p = tmp_path / "audit.log"
    p.write_text(_SAMPLE)
    monkeypatch.setattr(ad, "_ausearch_bin", lambda: "/fake/ausearch")
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=_SAMPLE, stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)
    events, err = ad.run_ausearch(p, key="exec_root", msgtype="SYSCALL")
    assert err == ""
    assert "-k" in captured["cmd"] and "exec_root" in captured["cmd"]
    assert "-m" in captured["cmd"] and "SYSCALL" in captured["cmd"]
    assert "-i" in captured["cmd"]
    assert len(events) == 3


def test_run_ausearch_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(ad, "_ausearch_bin", lambda: "/fake/ausearch")
    events, err = ad.run_ausearch(tmp_path / "absent.log")
    assert events == []
    assert "file not found" in err


def test_tokeniser_handles_quoted_and_escaped_values(tmp_path):
    line = (
        'type=EXECVE msg=audit(1.0:1): argc=2 '
        'a0="bash" a1="echo \\"hello\\""\n'
    )
    p = tmp_path / "audit.log"
    p.write_text(line)
    events = ad.parse_audit_log(p)
    assert len(events) == 1
    # The escaped inner quotes are preserved verbatim — we don't try to
    # un-escape because that would lose information. argv stays as-emitted.
    assert events[0].argv[0] == "bash"
    assert "hello" in events[0].argv[1]


def test_malformed_lines_silently_skipped(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text(
        "this is not an audit line\n"
        "# a comment\n"
        "\n"
        "type=DAEMON_START msg=audit(notanumber:1): unparseable timestamp\n"
        'type=SYSCALL msg=audit(1.0:1): syscall=59 comm="x"\n'
    )
    events = ad.parse_audit_log(p)
    assert len(events) == 1
    assert events[0].comm == "x"


def test_max_events_cap(tmp_path):
    """Pathological-size audit.log shouldn't OOM the parser."""
    p = tmp_path / "audit.log"
    lines = [
        f'type=SYSCALL msg=audit(1.0:{i}): syscall=59 comm="x"'
        for i in range(1, 101)
    ]
    p.write_text("\n".join(lines) + "\n")
    events = ad.parse_audit_log(p, max_events=5)
    assert len(events) == 5

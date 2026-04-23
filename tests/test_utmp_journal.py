"""Tests for utmp/wtmp/btmp binary parser + systemd-journal wrapper."""
import os
import struct
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from el.skills import utmp, systemd_journal as jnl


# ---------------------------------------------------------------------------
# utmp binary parsing
# ---------------------------------------------------------------------------

def _make_utmp_record(
    ut_type: int, pid: int, tty: str, user: str, host: str,
    tv_sec: int, addr_ipv4: str = "",
) -> bytes:
    """Build a single 384-byte utmpx record for testing."""
    addr_buf = bytearray(16)
    if addr_ipv4:
        import socket
        addr_buf[:4] = socket.inet_pton(socket.AF_INET, addr_ipv4)
    return struct.pack(
        "<hxx i 32s 4s 32s 256s hhi ii 16s 20s",
        ut_type, pid,
        tty.encode().ljust(32, b"\x00"),
        b"\x00" * 4,
        user.encode().ljust(32, b"\x00"),
        host.encode().ljust(256, b"\x00"),
        0, 0, 0,          # exit status + session
        tv_sec, 0,
        bytes(addr_buf),
        b"\x00" * 20,
    )


def test_parse_file_reads_valid_record(tmp_path):
    f = tmp_path / "wtmp"
    f.write_bytes(_make_utmp_record(
        ut_type=7, pid=1234, tty="pts/0", user="jean",
        host="203.0.113.7", tv_sec=1500000000, addr_ipv4="203.0.113.7"))
    recs = utmp.parse_file(f)
    assert len(recs) == 1
    r = recs[0]
    assert r.type_name == "USER_PROCESS"
    assert r.user == "jean"
    assert r.tty == "pts/0"
    assert r.pid == 1234
    assert r.host == "203.0.113.7"
    assert r.addr == "203.0.113.7"
    assert r.ts_utc.startswith("2017-")    # 1.5e9 = mid-2017


def test_parse_file_skips_empty_records(tmp_path):
    """ut_type = 0 (EMPTY) and 1 (RUN_LVL) should be filtered out."""
    f = tmp_path / "wtmp"
    f.write_bytes(
        _make_utmp_record(0, 0, "", "", "", 0)  # EMPTY
        + _make_utmp_record(1, 0, "runlevel", "", "", 0)  # RUN_LVL
        + _make_utmp_record(7, 1, "pts/0", "u", "", 1500000000)  # USER
    )
    assert len(utmp.parse_file(f)) == 1


def test_parse_file_handles_missing(tmp_path):
    assert utmp.parse_file(tmp_path / "nope.wtmp") == []


def test_parse_file_handles_truncated(tmp_path):
    """Truncated (non-multiple of 384) — parse what fits."""
    f = tmp_path / "wtmp"
    good = _make_utmp_record(7, 1, "pts/0", "u", "", 1500000000)
    f.write_bytes(good + b"\x00" * 100)          # partial second rec
    assert len(utmp.parse_file(f)) == 1


def test_failed_auth_bursts_groups_by_user_and_source(tmp_path):
    f = tmp_path / "btmp"
    records = b""
    # 6 × attacker@203.0.113.7 trying "root"
    for _ in range(6):
        records += _make_utmp_record(
            6, 0, "ssh:notty", "root", "203.0.113.7",
            1500000000, "203.0.113.7")
    # 2 × random single failure (below threshold — ignored)
    records += _make_utmp_record(
        6, 0, "ssh:notty", "admin", "192.0.2.1",
        1500000100, "192.0.2.1")
    f.write_bytes(records)
    recs = utmp.parse_file(f)
    bursts = utmp.failed_auth_bursts(recs, threshold=5)
    assert len(bursts) == 1
    b = bursts[0]
    assert b.user == "root"
    assert b.source_host == "203.0.113.7"
    assert b.count == 6


def test_root_direct_logins_flags_remote(tmp_path):
    f = tmp_path / "wtmp"
    recs_data = (
        _make_utmp_record(7, 1, "pts/0", "root", "attacker.example",
                          1500000000, "203.0.113.7")
        + _make_utmp_record(7, 2, "pts/1", "jean", "workstation.corp",
                          1500000100, "10.0.0.5")
        + _make_utmp_record(7, 3, "tty1", "root", "", 1500000200)
        # ^ local root on tty1 — not remote, should NOT fire
    )
    f.write_bytes(recs_data)
    recs = utmp.parse_file(f)
    roots = utmp.root_direct_logins(recs)
    assert len(roots) == 1
    assert roots[0].user == "root"
    assert roots[0].host == "attacker.example"


def test_source_diversity_counts_unique_hosts_per_user(tmp_path):
    f = tmp_path / "wtmp"
    data = b""
    # Jean from 11 distinct sources
    for i in range(11):
        data += _make_utmp_record(
            7, 100 + i, f"pts/{i}", "jean",
            f"src{i}.example", 1500000000 + i)
    f.write_bytes(data)
    recs = utmp.parse_file(f)
    div = utmp.source_diversity(recs)
    assert "jean" in div
    assert len(div["jean"]) == 11


# ---------------------------------------------------------------------------
# systemd-journal SSH + sudo extractors
# ---------------------------------------------------------------------------

def _mk_entry(msg: str, syslog_id: str = "sshd", unit: str = "",
               ts: str = "2026-04-23T10:00:00Z", pid: int = 42) -> jnl.JournalEntry:
    return jnl.JournalEntry(
        ts_utc=ts, priority=5, unit=unit,
        hostname="host", syslog_id=syslog_id,
        pid=pid, uid=0, message=msg, raw={"MESSAGE": msg})


def test_extract_ssh_auth_failed_password():
    e = _mk_entry("Failed password for root from 1.2.3.4 port 22 ssh2")
    out = jnl.extract_ssh_auth([e])
    assert len(out) == 1
    a = out[0]
    assert a.kind == "failed"
    assert a.user == "root"
    assert a.source_host == "1.2.3.4"


def test_extract_ssh_auth_accepted_publickey():
    e = _mk_entry("Accepted publickey for jean from 10.0.0.5 port 54321 ssh2")
    a = jnl.extract_ssh_auth([e])[0]
    assert a.kind == "accepted"
    assert a.user == "jean"


def test_extract_ssh_auth_invalid_user():
    e = _mk_entry("Invalid user evil from 6.6.6.6 port 22")
    a = jnl.extract_ssh_auth([e])[0]
    assert a.kind == "invalid_user"
    assert a.user == "evil"
    assert a.source_host == "6.6.6.6"


def test_extract_ssh_auth_ignores_non_sshd():
    e = _mk_entry("Failed password for root from 1.2.3.4 port 22 ssh2",
                   syslog_id="kernel")    # not sshd
    assert jnl.extract_ssh_auth([e]) == []


def test_extract_sudo_invocations_parses_command():
    e = _mk_entry(
        "pat : TTY=pts/0 ; PWD=/home/pat ; USER=root ; COMMAND=/bin/bash",
        syslog_id="sudo")
    out = jnl.extract_sudo_invocations([e])
    assert len(out) == 1
    s = out[0]
    assert s.user == "pat"
    assert s.as_user == "root"
    assert s.command == "/bin/bash"


def test_extract_sudo_invocations_ignores_non_command_lines():
    e = _mk_entry(
        "pam_unix(sudo:session): session opened for user root(uid=0)",
        syslog_id="sudo")
    assert jnl.extract_sudo_invocations([e]) == []


def test_parse_journal_dir_empty_returns_empty(tmp_path):
    # Dir exists but has no .journal files
    assert jnl.parse_journal_dir(tmp_path) == []


def test_parse_journal_dir_missing_returns_empty(tmp_path):
    assert jnl.parse_journal_dir(tmp_path / "nope") == []

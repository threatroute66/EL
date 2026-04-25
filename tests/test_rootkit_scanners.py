"""chkrootkit / rkhunter / Lynis wrappers.

Closes gap-doc Linux-depth bullet "Rootkit scanners (chkrootkit,
rkhunter, Lynis) over mounted images". Tests monkeypatch the
binary lookup + subprocess so the suite doesn't require any of the
three tools to be installed.
"""
import subprocess
from pathlib import Path

import pytest

from el.skills import rootkit_scanners as rs


@pytest.fixture
def fake_root(tmp_path):
    """A directory the scanners can pretend is a mounted root."""
    root = tmp_path / "root"
    root.mkdir()
    return root


def _fake_run(stdout: str, returncode: int = 0, stderr: str = ""):
    return lambda *a, **kw: subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# --- chkrootkit ---------------------------------------------------------

def test_chkrootkit_unavailable(monkeypatch, fake_root):
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: None)
    r = rs.run_chkrootkit(fake_root)
    assert r.available is False
    assert "chkrootkit" in r.error
    assert r.findings == []


def test_chkrootkit_missing_rootdir(monkeypatch, tmp_path):
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: "/fake/chkrootkit")
    r = rs.run_chkrootkit(tmp_path / "nope")
    assert r.available is False
    assert "rootdir not found" in r.error


def test_chkrootkit_parses_infected_lines(monkeypatch, fake_root):
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: "/fake/chkrootkit")
    stdout = (
        "Checking `aliens'... no suspect files\n"
        "Checking `bindshell'... INFECTED (PORTS:  31337 47017)\n"
        "Checking `lkm'... You have    1 process hidden for readdir command\n"
        "Possible LKM Trojan installed\n"
        "Checking `chkutmp'... not infected\n"
        "Checking `wted'... Vulnerable but not exploited\n"
    )
    monkeypatch.setattr(rs.subprocess, "run", _fake_run(stdout))
    r = rs.run_chkrootkit(fake_root, out_dir=fake_root.parent / "out")
    assert r.available is True
    msgs = [f.message for f in r.findings]
    # Two INFECTED/Vulnerable lines + one Possible
    assert any("bindshell" in m for m in msgs)
    assert any("Possible LKM" in m for m in msgs)
    assert any("Vulnerable" in m for m in msgs)
    # "not infected" line must NOT have matched
    assert not any("not infected" in m for m in msgs)
    assert r.vulnerable_count >= 2
    assert Path(r.raw_path).is_file()


def test_chkrootkit_clean_run(monkeypatch, fake_root):
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: "/fake/chkrootkit")
    stdout = ("Checking `aliens'... no suspect files\n"
              "Checking `bindshell'... not infected\n")
    monkeypatch.setattr(rs.subprocess, "run", _fake_run(stdout))
    r = rs.run_chkrootkit(fake_root)
    assert r.available is True
    assert r.findings == []


def test_chkrootkit_timeout(monkeypatch, fake_root):
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: "/fake/chkrootkit")

    def raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="chkrootkit", timeout=1)
    monkeypatch.setattr(rs.subprocess, "run", raise_timeout)
    r = rs.run_chkrootkit(fake_root)
    assert r.available is False
    assert "failed" in r.error.lower()


# --- rkhunter -----------------------------------------------------------

def test_rkhunter_unavailable(monkeypatch, fake_root):
    monkeypatch.setattr(rs, "_rkhunter_bin", lambda: None)
    r = rs.run_rkhunter(fake_root)
    assert r.available is False
    assert "rkhunter" in r.error


def test_rkhunter_parses_warning_lines(monkeypatch, fake_root):
    monkeypatch.setattr(rs, "_rkhunter_bin", lambda: "/fake/rkhunter")
    stdout = (
        "[ Rootkit Hunter version 1.4.6 ]\n"
        "[Warning] Found exclusion file '/etc/popularity-contest.conf'\n"
        "[Possibly] Hidden directory found: /etc/.java\n"
        "[Info] No suspect strings found\n"
        "[Warning] Suspicious file found: /tmp/.X11-unix/X0\n"
    )
    monkeypatch.setattr(rs.subprocess, "run", _fake_run(stdout))
    r = rs.run_rkhunter(fake_root, out_dir=fake_root.parent / "out")
    assert r.available is True
    msgs = [f.message for f in r.findings]
    assert any("popularity-contest" in m for m in msgs)
    assert any("Hidden directory" in m for m in msgs)
    assert any("Suspicious file" in m for m in msgs)
    # [Info] line excluded
    assert not any("No suspect strings" in m for m in msgs)
    assert r.vulnerable_count == 2          # 2x Warning
    assert r.warning_count == 1             # 1x Possibly


# --- Lynis --------------------------------------------------------------

def test_lynis_unavailable(monkeypatch, fake_root):
    monkeypatch.setattr(rs, "_lynis_bin", lambda: None)
    r = rs.run_lynis(fake_root)
    assert r.available is False


def test_lynis_parses_warnings_and_suggestions(monkeypatch, fake_root):
    monkeypatch.setattr(rs, "_lynis_bin", lambda: "/fake/lynis")
    stdout = (
        "[+] Boot and services\n"
        "  - Service Manager [ systemd ]\n"
        "  - Warning: Found one or more vulnerable packages [PKGS-7392]\n"
        "  - Suggestion: Install a file integrity tool [FINT-4350]\n"
        "  - Suggestion: Set a password on GRUB bootloader [BOOT-5121]\n"
        "[+] Hardening\n"
        "  - Hardening index : 64 [############        ]\n"
    )
    monkeypatch.setattr(rs.subprocess, "run", _fake_run(stdout))
    r = rs.run_lynis(fake_root)
    assert r.available is True
    assert r.vulnerable_count == 1          # the one Warning:
    assert r.warning_count == 2             # two Suggestion:
    msgs = [f.message for f in r.findings]
    assert any("PKGS-7392" in m for m in msgs)
    assert any("FINT-4350" in m for m in msgs)


# --- run_all ------------------------------------------------------------

def test_run_all_returns_three_results(monkeypatch, fake_root):
    """All three scanners absent — run_all still returns a per-tool
    record so the audit trail shows what was attempted."""
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: None)
    monkeypatch.setattr(rs, "_rkhunter_bin", lambda: None)
    monkeypatch.setattr(rs, "_lynis_bin", lambda: None)
    results = rs.run_all(fake_root)
    assert [r.tool for r in results] == ["chkrootkit", "rkhunter", "lynis"]
    assert all(not r.available for r in results)


def test_run_all_partial_install(monkeypatch, fake_root):
    """Only chkrootkit installed — run_all reports it ran the one
    that's there and notes the absence of the other two."""
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: "/fake/chkrootkit")
    monkeypatch.setattr(rs, "_rkhunter_bin", lambda: None)
    monkeypatch.setattr(rs, "_lynis_bin", lambda: None)
    monkeypatch.setattr(rs.subprocess, "run",
                         _fake_run("Checking `bindshell'... not infected\n"))
    results = rs.run_all(fake_root)
    by_tool = {r.tool: r for r in results}
    assert by_tool["chkrootkit"].available is True
    assert by_tool["rkhunter"].available is False
    assert by_tool["lynis"].available is False


def test_raw_output_persisted(monkeypatch, fake_root):
    """Operator chain-of-custody: stdout is saved verbatim under
    out_dir so the rule-engine match can be re-verified."""
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: "/fake/chkrootkit")
    monkeypatch.setattr(rs.subprocess, "run",
                         _fake_run("INFECTED foo\n",
                                   returncode=0, stderr="some warning"))
    out = fake_root.parent / "scanner_out"
    r = rs.run_chkrootkit(fake_root, out_dir=out)
    assert (out / "chkrootkit.stdout").read_text() == "INFECTED foo\n"
    assert (out / "chkrootkit.stderr").read_text() == "some warning"


def test_finding_str_format():
    f = rs.Finding(severity="vulnerable", message="bindshell INFECTED")
    assert str(f) == "[vulnerable] bindshell INFECTED"

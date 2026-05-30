"""Tests for syslog_rfc5424 + LogCorpusAgent + triage log-corpus detection."""
import json
from pathlib import Path

import pytest

from el.skills import syslog_rfc5424 as sl


# --- syslog_rfc5424 ---------------------------------------------------------

_SYSLOG = """\
<30>1 2024-05-14T12:00:10.274719Z WEB-BO-01 polkitd 54246 - - authenticated as root
<11>1 2024-05-14T12:00:11.0Z WEB-BO-01 sshd 700 - - error: maximum authentication attempts exceeded
<30>1 2024-05-14T12:00:12.5Z WEB-BO-01 rsyslogd 16869 - - queue has messages pending
<34>Oct 11 22:14:15 mymachine su[123]: BSD style fallback line
not a syslog line at all
"""


def test_syslog_parse_fields(tmp_path):
    p = tmp_path / "syslog.log"; p.write_text(_SYSLOG)
    run = sl.parse(p, output_dir=tmp_path / "out")
    assert run.total == 4 and run.skipped == 1
    e = run.events[0]
    assert e.app == "polkitd" and e.procid == "54246"
    assert e.timestamp_utc == "2024-05-14 12:00:10"
    assert e.severity == 6 and e.severity_name == "info"   # PRI 30 -> 30%8=6
    assert "authenticated as root" in e.message


def test_syslog_severity_and_apps(tmp_path):
    p = tmp_path / "syslog.log"; p.write_text(_SYSLOG)
    run = sl.parse(p)
    # PRI 11 -> sev 3 (err, sshd); PRI 34 -> sev 2 (crit, su) — both high.
    hs = run.high_severity()
    assert {e.app for e in hs} == {"sshd", "su"}
    assert run.by_app()["polkitd"] == 1
    assert run.find("authentication")
    assert run.as_evidence().extracted_facts["event_count"] == 4


def test_syslog_bsd_fallback(tmp_path):
    p = tmp_path / "s.log"; p.write_text(_SYSLOG)
    run = sl.parse(p)
    su = [e for e in run.events if e.app == "su"]
    assert su and su[0].host == "mymachine"


def test_syslog_missing_raises(tmp_path):
    with pytest.raises(sl.SyslogError):
        sl.parse(tmp_path / "nope.log")


# --- corpus fixture ---------------------------------------------------------

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_EVTX = f"""<?xml version="1.0"?>
<Events>
<Event xmlns="{_NS}"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>
<EventID>4625</EventID><TimeCreated SystemTime="2024-05-14T12:00:00.0Z"/>
<Computer>DC</Computer><Channel>Security</Channel></System>
<EventData><Data Name="TargetUserName">admin</Data></EventData></Event>
</Events>"""


def _make_corpus(root: Path):
    dc = root / "DC-BO-01"; dc.mkdir(parents=True)
    (dc / "windows_event_security.xml").write_text(_EVTX)
    (dc / "ecar.json").write_text(json.dumps(
        {"timestamp_ms": 1715688000000, "hostname": "DC", "object": "PROCESS",
         "action": "CREATE", "properties": {"command_line": "cmd.exe"}}) + "\n")
    fw = root / "FW-EDGE"; fw.mkdir(parents=True)
    (fw / "cisco_asa.log").write_text(
        "<166>May 14 12:00:00 FW %ASA-4-106023: Deny tcp src o:1.2.3.4/5 "
        "dst i:10.0.0.1/3389 by access-group x\n")
    ids = root / "IDS-EDGE"; ids.mkdir(parents=True)
    (ids / "snort_alert.log").write_text(
        "05/14-12:00:28.844 [**] [1:384:1] PING [**] [Priority: 1] {ICMP} "
        "1.2.3.4 -> 10.0.0.1\n")


# --- triage detection -------------------------------------------------------

def test_triage_detects_log_corpus(tmp_path):
    from el.agents.triage import TriageAgent
    root = tmp_path / "corpus"
    _make_corpus(root)
    assert TriageAgent._looks_like_log_corpus(root) is True


def test_triage_rejects_non_corpus(tmp_path):
    from el.agents.triage import TriageAgent
    d = tmp_path / "plain"
    (d / "onlyhost").mkdir(parents=True)
    (d / "onlyhost" / "random.txt").write_text("x")
    assert TriageAgent._looks_like_log_corpus(d) is False


def test_coordinator_routes_log_corpus():
    from el.orchestrator.coordinator import KIND_TO_AGENT
    from el.agents.log_corpus import LogCorpusAgent
    assert KIND_TO_AGENT["log-corpus"] is LogCorpusAgent


# --- LogCorpusAgent fan-out -------------------------------------------------

def _ctx(tmp_path, monkeypatch, case_id, root):
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ev"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=root, manifest=m.__dict__)


def test_log_corpus_agent_fans_out(tmp_path, monkeypatch):
    from el.agents.log_corpus import LogCorpusAgent
    root = tmp_path / "corpus"
    _make_corpus(root)
    ctx = _ctx(tmp_path, monkeypatch, "t-corpus", root)
    findings = LogCorpusAgent().run(ctx)
    claims = " || ".join(f.claim for f in findings)
    assert "Log corpus parsed:" in claims
    assert "3 host(s)" in claims
    assert "Cisco ASA" in claims and "ACL deny" in claims
    assert "Snort IDS" in claims and "priority-1" in claims
    assert "Windows Event XML" in claims and "failed-logon" in claims
    assert "eCAR EDR" in claims


def _evtx_n_4625(n: int) -> str:
    ev = (f'<Event xmlns="{_NS}"><System>'
          '<Provider Name="Microsoft-Windows-Security-Auditing"/>'
          '<EventID>4625</EventID>'
          '<TimeCreated SystemTime="2024-05-14T12:00:00.0Z"/>'
          '<Computer>DC</Computer><Channel>Security</Channel></System>'
          '<EventData><Data Name="TargetUserName">admin</Data></EventData></Event>')
    return '<?xml version="1.0"?>\n<Events>\n' + ev * n + '\n</Events>'


def _make_threat_corpus(root: Path):
    edr = root / "EDR"; edr.mkdir(parents=True)
    (edr / "ecar.json").write_text("\n".join(json.dumps(d) for d in [
        {"timestamp_ms": 1715688000000, "hostname": "EDR", "object": "PROCESS",
         "action": "CREATE", "properties": {"command_line": "x"}},
        {"timestamp_ms": 1715688001000, "hostname": "EDR", "object": "THREAD",
         "action": "REMOTE_CREATE", "properties": {"target_pid": 1234,
         "image_path": "inj.exe"}},
    ]) + "\n")
    dc = root / "DC"; dc.mkdir(parents=True)
    (dc / "windows_event_security.xml").write_text(_evtx_n_4625(12))
    fw = root / "FW"; fw.mkdir(parents=True)
    deny = ("<166>May 14 12:00:00 FW %ASA-4-106023: Deny tcp src o:1.2.3.4/5 "
            "dst i:10.0.0.1/3389 by access-group x\n")
    (fw / "cisco_asa.log").write_text(deny * 60)
    ids = root / "IDS"; ids.mkdir(parents=True)
    (ids / "snort_alert.log").write_text(
        "05/14-12:00:28.844 [**] [1:2000575:8] ET SCAN ICMP PING IPTools [**] "
        "[Classification: attempted-recon] [Priority: 3] {ICMP} 1.2.3.4 -> 10.0.0.1\n")


def test_log_corpus_lifts_intrusion_hypotheses(tmp_path, monkeypatch):
    from el.agents.log_corpus import LogCorpusAgent
    root = tmp_path / "threat"
    _make_threat_corpus(root)
    ctx = _ctx(tmp_path, monkeypatch, "t-threat", root)
    findings = LogCorpusAgent().run(ctx)
    tags = {t for f in findings for t in f.hypotheses_supported}
    assert "H_PROCESS_INJECTION" in tags       # eCAR remote-thread creation
    assert "H_BRUTE_FORCE" in tags             # 12 × Event 4625
    assert "H_SCAN_RECON" in tags              # 60 ASA denies + Snort scan
    # the inventory findings remain (low-FP separation)
    assert "H_DISK_ARTIFACTS" in tags
    # a targeted finding names the brute-force burst
    assert any("brute-force" in f.claim and "H_BRUTE_FORCE" in f.hypotheses_supported
               for f in findings)


def test_log_corpus_w3c_proxy_routing(tmp_path, monkeypatch):
    # A W3C-extended proxy log must route to iis_w3c (NOT the Apache parser,
    # which returns 0 on W3C) and surface the scripted-client recon hit.
    from el.agents.log_corpus import LogCorpusAgent
    root = tmp_path / "corpus"
    px = root / "PROXY"; px.mkdir(parents=True)
    lines = [
        "#Software: Test Secure Web Gateway", "#Version: 7.4",
        "#Fields: date time c-ip cs-username cs-method cs-uri cs-version "
        "sc-status sc-bytes cs-bytes time-taken cs-host cs(User-Agent) "
        "cs(Referer) rs(Content-Type) s-cache-result x-proxy-action",
    ]
    for i in range(6):
        lines.append(
            f"2024-05-14 12:0{i}:00 10.44.30.10 - CONNECT evil{i}.test:443 "
            f"HTTP/1.1 200 1 1 1 evil{i}.test python-requests/2.31.0 - - NONE "
            "tunnel")
    (px / "proxy_access.log").write_text("\n".join(lines) + "\n")
    fw = root / "FW"; fw.mkdir(parents=True)
    (fw / "cisco_asa.log").write_text(
        "<166>May 14 12:00:00 FW %ASA-6-302013: Built outbound TCP connection "
        "1 for o:1.2.3.4/5 to i:10.0.0.1/80\n")

    ctx = _ctx(tmp_path, monkeypatch, "t-w3c", root)
    findings = LogCorpusAgent().run(ctx)
    web = [f for f in findings if "proxy access (W3C" in f.claim]
    assert web, "proxy_access.log should be parsed as W3C"
    assert "6 request(s) parsed" in web[0].claim       # not 0 (the old bug)
    assert not any("(Apache/nginx, proxy_access.log)" in f.claim
                   for f in findings)


def test_log_corpus_below_threshold_no_lift(tmp_path, monkeypatch):
    # 3 failed logons (< 10) and no injection -> inventory only, no lift.
    from el.agents.log_corpus import LogCorpusAgent
    root = tmp_path / "quiet"
    dc = root / "DC"; dc.mkdir(parents=True)
    (dc / "windows_event_security.xml").write_text(_evtx_n_4625(3))
    h2 = root / "H2"; h2.mkdir(parents=True)
    (h2 / "cisco_asa.log").write_text(
        "<166>May 14 12:00:00 FW %ASA-6-302013: Built outbound TCP connection 1 "
        "for o:1.2.3.4/5 to i:10.0.0.1/80\n")
    ctx = _ctx(tmp_path, monkeypatch, "t-quiet", root)
    findings = LogCorpusAgent().run(ctx)
    tags = {t for f in findings for t in f.hypotheses_supported}
    assert "H_BRUTE_FORCE" not in tags and "H_PROCESS_INJECTION" not in tags
    assert "H_SCAN_RECON" not in tags
    assert tags == {"H_DISK_ARTIFACTS"}


def test_log_corpus_agent_empty(tmp_path, monkeypatch):
    from el.agents.log_corpus import LogCorpusAgent
    root = tmp_path / "empty"
    (root / "h1").mkdir(parents=True)
    (root / "h1" / "notes.txt").write_text("nothing parseable")
    ctx = _ctx(tmp_path, monkeypatch, "t-corpus-empty", root)
    findings = LogCorpusAgent().run(ctx)
    assert len(findings) == 1 and findings[0].confidence == "insufficient"

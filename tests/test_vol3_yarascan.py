"""vol3 windows.yarascan integration in threat_hunter.

Complements the existing standalone-yara raw-image sweep by giving
matches process attribution (PID, task, VA). Tests mock vol3.yarascan
so we don't require a real memory image on disk.
"""
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.threat_hunter import ThreatHunterAgent
from el.skills import vol3


# --- skill-level signature --------------------------------------------------

def test_vol3_yarascan_passes_family_and_rules(monkeypatch, tmp_path):
    captured = {}

    def fake_run(*, image, plugin, out_dir, extra_args, timeout):
        captured["image"] = image
        captured["plugin"] = plugin
        captured["extra_args"] = extra_args
        captured["timeout"] = timeout
        return vol3.PluginRun(
            plugin=plugin, image=image, rc=0,
            stdout_path=tmp_path / "o.json",
            stderr_path=tmp_path / "o.err",
            rows=[], command=["vol"], version="2.27.0",
        )
    monkeypatch.setattr(vol3, "run_plugin", fake_run)

    rules = tmp_path / "rules.yar"
    rules.write_text('rule x { condition: true }')
    img = tmp_path / "mem.img"
    img.touch()

    r = vol3.yarascan(img, rules, tmp_path, family="linux")
    assert captured["plugin"] == "linux.yarascan.YaraScan"
    assert captured["extra_args"] == ["--yara-rules", str(rules)]
    assert captured["timeout"] == 1800
    assert r.rc == 0


# --- agent-level dispatch ---------------------------------------------------

def _ctx(tmp_path: Path, *, mem_os: str | None = "windows") -> AgentContext:
    case_dir = tmp_path / "case"
    (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    ctx = AgentContext(
        case_id="test", case_dir=case_dir,
        input_path=tmp_path / "mem.img", manifest={},
    )
    if mem_os:
        ctx.shared["mem_os"] = mem_os
    return ctx


def _fake_plugin_run(rows, *, rc=0, tmp_path=None):
    if tmp_path is None:
        tmp_path = Path("/tmp")
    stdout_path = tmp_path / "o.json"
    stderr_path = tmp_path / "o.err"
    stdout_path.write_text("{}")
    stderr_path.write_text("")
    return vol3.PluginRun(
        plugin="windows.yarascan.YaraScan",
        image=Path("/tmp/mem.img"), rc=rc,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        rows=rows, command=["vol"], version="2.27.0",
    )


def test_agent_skips_when_not_memory_case(tmp_path, monkeypatch):
    """No mem_os set — the yarascan path must skip silently."""
    agent = ThreatHunterAgent()
    monkeypatch.setattr(agent, "emit", lambda ctx, f: f)
    ctx = _ctx(tmp_path, mem_os=None)

    rules = tmp_path / "rules.yar"
    rules.write_text("rule x {}")
    findings = agent._vol3_yarascan(ctx, rules, tmp_path / "case" / "analysis")
    assert findings == []


def test_agent_skips_when_rules_file_missing(tmp_path, monkeypatch):
    agent = ThreatHunterAgent()
    monkeypatch.setattr(agent, "emit", lambda ctx, f: f)
    ctx = _ctx(tmp_path, mem_os="windows")

    findings = agent._vol3_yarascan(ctx, tmp_path / "nope.yar",
                                     tmp_path / "case" / "analysis")
    assert findings == []


def test_agent_emits_high_conf_finding_per_rule_with_attribution(
        tmp_path, monkeypatch):
    agent = ThreatHunterAgent()
    monkeypatch.setattr(agent, "emit", lambda ctx, f: f)

    fake_rows = [
        {"Rule": "mimi_sig", "PID": 624, "Owner": "lsass.exe",
         "Offset": 0x7fff1234, "Component": "ntdll.dll"},
        {"Rule": "mimi_sig", "PID": 624, "Owner": "lsass.exe",
         "Offset": 0x7fff5678, "Component": "ntdll.dll"},
        {"Rule": "cobaltstrike", "PID": 1024, "Task": "svchost.exe",
         "Offset": 0x1234},
    ]
    monkeypatch.setattr(
        vol3, "yarascan",
        lambda *a, **k: _fake_plugin_run(fake_rows, tmp_path=tmp_path),
    )

    ctx = _ctx(tmp_path, mem_os="windows")
    rules = tmp_path / "rules.yar"
    rules.write_text("rule x {}")

    findings = agent._vol3_yarascan(ctx, rules, tmp_path / "case" / "analysis")
    assert len(findings) == 2, f"expected 2 rule groups, got {len(findings)}"
    for f in findings:
        assert f.confidence == "high"
        assert "PID" in f.claim
        assert any(h in f.hypotheses_supported
                   for h in ("H_IOC_CORROBORATED", "H_APT_ESPIONAGE"))
    mimi = next(f for f in findings if "mimi_sig" in f.claim)
    assert "lsass.exe" in mimi.claim
    assert "2 time(s)" in mimi.claim


def test_agent_emits_low_conf_on_zero_rows(tmp_path, monkeypatch):
    """vol3 ran successfully but no in-memory hits — emit a 'not
    corroborating, not refuting' low-confidence finding so the absence
    is visible in the ledger rather than being silent."""
    agent = ThreatHunterAgent()
    monkeypatch.setattr(agent, "emit", lambda ctx, f: f)
    monkeypatch.setattr(
        vol3, "yarascan",
        lambda *a, **k: _fake_plugin_run([], tmp_path=tmp_path),
    )

    ctx = _ctx(tmp_path, mem_os="windows")
    rules = tmp_path / "rules.yar"
    rules.write_text("rule x {}")

    findings = agent._vol3_yarascan(ctx, rules, tmp_path / "case" / "analysis")
    assert len(findings) == 1
    assert findings[0].confidence == "low"
    assert "0 in-memory matches" in findings[0].claim


def test_agent_recovers_from_vol3error(tmp_path, monkeypatch):
    agent = ThreatHunterAgent()
    monkeypatch.setattr(agent, "emit", lambda ctx, f: f)

    def boom(*a, **k):
        raise vol3.Vol3Error("timeout running windows.yarascan")
    monkeypatch.setattr(vol3, "yarascan", boom)

    ctx = _ctx(tmp_path, mem_os="windows")
    rules = tmp_path / "rules.yar"
    rules.write_text("rule x {}")
    findings = agent._vol3_yarascan(ctx, rules, tmp_path / "case" / "analysis")
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"
    assert "timeout" in findings[0].claim.lower()

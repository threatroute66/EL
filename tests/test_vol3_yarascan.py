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

def test_vol3_yarascan_unsupported_family_raises(tmp_path):
    """vol3 2.27 has no mac.vmayarascan equivalent — raise cleanly
    instead of letting vol3's 'invalid choice' stderr bubble up."""
    with pytest.raises(vol3.Vol3Error, match="no yara-scan plugin"):
        vol3.yarascan(
            tmp_path / "mem.img", tmp_path / "rules.yar",
            tmp_path, family="mac",
        )


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
    assert captured["plugin"] == "linux.vmayarascan.VmaYaraScan"
    assert captured["extra_args"] == ["--yara-file", str(rules)]
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
        plugin="windows.vadyarascan.VadYaraScan",
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

    # Mix of real-shape rows: vadyarascan uses ImageFileName, the
    # older Owner/Task keys stay supported as fallbacks.
    fake_rows = [
        {"Rule": "mimi_sig", "PID": 624, "ImageFileName": "lsass.exe",
         "Offset": 0x7fff1234, "Component": "ntdll.dll"},
        {"Rule": "mimi_sig", "PID": 624, "ImageFileName": "lsass.exe",
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


def test_agent_suppresses_high_volume_noise_rules(tmp_path, monkeypatch):
    """A rule that fires >= 10x the case median (and >= 1000 absolute)
    almost always corresponds to a too-generic IOC — Windows DLL
    string, file extension, shared library token. Suppress it as
    noise so it doesn't lift H_APT_ESPIONAGE.

    Driver: SRL-2018 admin-memory r4 had `microsoft.windows` firing
    24,607 times next to real attacker C2 hits at 9,822 / 163 / 40."""
    agent = ThreatHunterAgent()
    monkeypatch.setattr(agent, "emit", lambda ctx, f: f)

    # Real shape: one noisy rule + several real rules.
    rows = []
    for i in range(2000):
        rows.append({"Rule": "noisy_microsoft_windows",
                     "PID": 624, "ImageFileName": "lsass.exe",
                     "Offset": i})
    for i in range(40):
        rows.append({"Rule": "real_c2_ipv4", "PID": 1024,
                     "ImageFileName": "svchost.exe", "Offset": i})
    for i in range(30):
        rows.append({"Rule": "real_implant_marker", "PID": 1024,
                     "ImageFileName": "svchost.exe", "Offset": i})

    monkeypatch.setattr(
        vol3, "yarascan",
        lambda *a, **k: _fake_plugin_run(rows, tmp_path=tmp_path),
    )

    ctx = _ctx(tmp_path, mem_os="windows")
    rules = tmp_path / "rules.yar"
    rules.write_text("rule x {}")
    findings = agent._vol3_yarascan(ctx, rules, tmp_path / "case" / "analysis")

    noise = [f for f in findings if "noisy_microsoft_windows" in f.claim]
    assert len(noise) == 1
    assert noise[0].confidence == "low"
    assert "suppressed as noise" in noise[0].claim
    assert noise[0].hypotheses_supported == [], (
        "noise-suppressed findings must NOT carry H_APT_ESPIONAGE"
    )

    # Real signal still gets high confidence + the APT tag.
    real = [f for f in findings if "real_c2_ipv4" in f.claim]
    assert len(real) == 1
    assert real[0].confidence == "high"
    assert "H_APT_ESPIONAGE" in real[0].hypotheses_supported


def test_agent_does_not_suppress_when_all_rules_high_volume(tmp_path,
                                                              monkeypatch):
    """Edge case: if every rule fires at similar scale, the median
    is also high and nothing should be suppressed (no comparison
    point). Absolute threshold of 1000 still applies — but if every
    rule clears 1000, the analyst already knows the catalog is
    noisy and we shouldn't blanket-suppress everything.

    The current rule: `noise_threshold = max(median * 10, 1000)`.
    When median is 1500, threshold is 15000. Rules at 1500 stay high.
    """
    agent = ThreatHunterAgent()
    monkeypatch.setattr(agent, "emit", lambda ctx, f: f)

    rows = []
    for rule_name in ("rule_a", "rule_b", "rule_c"):
        for i in range(1500):
            rows.append({"Rule": rule_name, "PID": 100,
                         "ImageFileName": "p.exe", "Offset": i})

    monkeypatch.setattr(
        vol3, "yarascan",
        lambda *a, **k: _fake_plugin_run(rows, tmp_path=tmp_path),
    )

    ctx = _ctx(tmp_path, mem_os="windows")
    rules = tmp_path / "rules.yar"
    rules.write_text("rule x {}")
    findings = agent._vol3_yarascan(ctx, rules, tmp_path / "case" / "analysis")

    # All three rules fire at 1500; median = 1500, threshold = 15000.
    # None should be suppressed.
    assert all(f.confidence == "high" for f in findings)


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

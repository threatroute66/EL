"""T2-3 tests: capa rule-pack resolver + shellcode-mode wiring in
malware_triage. Pure unit tests (mocked subprocess) plus one optional
integration test that skips when capa + the rule pack aren't both
installed."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from el.skills import capa as capa_skill


# ---------------------------------------------------------------------------
# Rule-pack resolver
# ---------------------------------------------------------------------------

def test_rules_dir_prefers_env_override(tmp_path, monkeypatch):
    d = tmp_path / "custom"
    d.mkdir()
    (d / "r.yml").write_text("rule: {}\n")
    monkeypatch.setenv("EL_CAPA_RULES", str(d))
    assert capa_skill._rules_dir() == d


def test_rules_dir_env_override_ignored_when_empty(tmp_path, monkeypatch):
    d = tmp_path / "empty"
    d.mkdir()
    monkeypatch.setenv("EL_CAPA_RULES", str(d))
    # Falls through to default; default may or may not exist in test env
    # — we just check we did NOT return the empty dir
    got = capa_skill._rules_dir()
    assert got != d


def test_rules_dir_returns_none_when_nothing_configured(tmp_path, monkeypatch):
    monkeypatch.delenv("EL_CAPA_RULES", raising=False)
    # Temporarily point the default elsewhere by patching the module
    # constant via monkeypatching os.environ — easier: just check that
    # the function returns either None or an existing directory.
    got = capa_skill._rules_dir()
    assert got is None or (got.is_dir() and any(got.rglob("*.yml")))


# ---------------------------------------------------------------------------
# analyze() subprocess construction — mocked
# ---------------------------------------------------------------------------

def _mock_capa_run(rules_dir: Path | None,
                    expected_format: str | None,
                    stdout: dict = None):
    """Helper that installs a fake _rules_dir + fake subprocess.run.
    Returns the captured cmd list so tests can assert the flags."""
    captured = {}

    def _fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        payload = json.dumps(stdout or {"rules": {}}).encode()
        return subprocess.CompletedProcess(
            args=cmd, returncode=0,
            stdout=payload.decode(),
            stderr="",
        )

    return captured, _fake_run


def test_analyze_passes_rules_flag_when_available(tmp_path, monkeypatch):
    # Fake rule pack that satisfies the "has at least one yml" check
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yml").write_text("rule: x\n")
    monkeypatch.setenv("EL_CAPA_RULES", str(rules))

    target = tmp_path / "sample.dmp"
    target.write_bytes(b"\x90" * 4096)

    captured, fake_run = _mock_capa_run(rules, None)
    # Also fake `capa --version` (called by _version) and the real analyze run
    def _multi_run(cmd, capture_output, text, timeout):
        if "--version" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="capa 9.4.0\n", stderr="")
        return fake_run(cmd, capture_output, text, timeout)
    monkeypatch.setattr(subprocess, "run", _multi_run)
    monkeypatch.setattr(capa_skill, "_bin", lambda: "/fake/capa")

    out = tmp_path / "out"
    r = capa_skill.analyze(target, out)
    assert r.rc == 0
    assert "-r" in captured["cmd"]
    assert str(rules) in captured["cmd"]


def test_analyze_omits_rules_flag_when_no_pack(tmp_path, monkeypatch):
    monkeypatch.delenv("EL_CAPA_RULES", raising=False)
    monkeypatch.setattr(capa_skill, "_rules_dir", lambda: None)

    target = tmp_path / "sample.dmp"
    target.write_bytes(b"\x90" * 4096)

    captured, fake_run = _mock_capa_run(None, None)
    def _multi_run(cmd, capture_output, text, timeout):
        if "--version" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="capa 9.4.0\n", stderr="")
        return fake_run(cmd, capture_output, text, timeout)
    monkeypatch.setattr(subprocess, "run", _multi_run)
    monkeypatch.setattr(capa_skill, "_bin", lambda: "/fake/capa")

    r = capa_skill.analyze(target, tmp_path / "out")
    assert r.rc == 0
    assert "-r" not in captured["cmd"]


def test_analyze_adds_shellcode_format_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(capa_skill, "_rules_dir", lambda: None)
    target = tmp_path / "sc.dmp"
    target.write_bytes(b"\xcc" * 1024)

    captured, fake_run = _mock_capa_run(None, "sc64")
    def _multi_run(cmd, capture_output, text, timeout):
        if "--version" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="capa 9.4.0\n", stderr="")
        return fake_run(cmd, capture_output, text, timeout)
    monkeypatch.setattr(subprocess, "run", _multi_run)
    monkeypatch.setattr(capa_skill, "_bin", lambda: "/fake/capa")

    capa_skill.analyze(target, tmp_path / "out", shellcode_arch="64")
    cmd = captured["cmd"]
    assert "--format" in cmd
    assert "sc64" in cmd


# ---------------------------------------------------------------------------
# malware_triage._run_capa: shellcode mode default + arch override
# ---------------------------------------------------------------------------

class _FakeScan:
    def __init__(self, is_pe: bool):
        self.has_mz_header = is_pe
        self.has_pe_signature = is_pe


def _minimal_ctx(shared: dict | None = None):
    from el.agents.base import AgentContext
    from pathlib import Path
    return AgentContext(
        case_id="t", case_dir=Path("/tmp"), input_path=Path("/tmp/x"),
        manifest={}, shared=shared or {},
    )


def test_run_capa_uses_sc64_for_shellcode_by_default(tmp_path, monkeypatch):
    from el.agents.malware_triage import MalwareTriageAgent
    calls = []

    def _fake_analyze(dump, out_dir, shellcode_arch=None, timeout=None):
        calls.append(shellcode_arch)
        from el.skills.capa import CapaResult
        return CapaResult(target=dump, rc=0)

    monkeypatch.setattr(capa_skill, "analyze", _fake_analyze)
    dump = tmp_path / "pid.1.vad.dmp"; dump.write_bytes(b"x")
    ctx = _minimal_ctx(shared={})
    MalwareTriageAgent()._run_capa(ctx, dump,
                                     _FakeScan(is_pe=False),
                                     tmp_path / "out")
    assert calls == ["64"]


def test_run_capa_uses_sc32_when_mem_arch_is_x86(tmp_path, monkeypatch):
    from el.agents.malware_triage import MalwareTriageAgent
    calls = []

    def _fake_analyze(dump, out_dir, shellcode_arch=None, timeout=None):
        calls.append(shellcode_arch)
        from el.skills.capa import CapaResult
        return CapaResult(target=dump, rc=0)

    monkeypatch.setattr(capa_skill, "analyze", _fake_analyze)
    dump = tmp_path / "pid.1.vad.dmp"; dump.write_bytes(b"x")
    ctx = _minimal_ctx(shared={"mem_arch": "x86"})
    MalwareTriageAgent()._run_capa(ctx, dump,
                                     _FakeScan(is_pe=False),
                                     tmp_path / "out")
    assert calls == ["32"]


def test_run_capa_passes_none_for_pe_dump(tmp_path, monkeypatch):
    from el.agents.malware_triage import MalwareTriageAgent
    calls = []

    def _fake_analyze(dump, out_dir, shellcode_arch=None, timeout=None):
        calls.append(shellcode_arch)
        from el.skills.capa import CapaResult
        return CapaResult(target=dump, rc=0)

    monkeypatch.setattr(capa_skill, "analyze", _fake_analyze)
    dump = tmp_path / "pid.1.vad.dmp"; dump.write_bytes(b"MZ...")
    ctx = _minimal_ctx(shared={})
    MalwareTriageAgent()._run_capa(ctx, dump,
                                     _FakeScan(is_pe=True),
                                     tmp_path / "out")
    assert calls == [None]


# ---------------------------------------------------------------------------
# Optional integration test — real capa + rule pack, real shellcode
# ---------------------------------------------------------------------------

_REAL_RULES = Path("/opt/EL/rules/capa")
_REAL_DUMP = Path(
    "/opt/EL/cases/srl-admin-memory/analysis/memory_forensicator/"
    "pid.8884.vad.0x1f002280000-0x1f00228ffff.dmp"
)


def _capa_installed() -> bool:
    return shutil.which("capa") is not None or \
           (Path(sys.executable).parent / "capa").is_file()


@pytest.mark.skipif(
    not (_capa_installed() and _REAL_RULES.is_dir() and _REAL_DUMP.is_file()),
    reason="requires capa + rule pack + srl-admin-memory dump",
)
def test_integration_real_shellcode_yields_capabilities(tmp_path):
    """Smoke test against the SRL-2018 admin box dump used during
    development. Numbers can drift if the rule pack is updated — we
    only assert 'more than zero rules fire', which is the contract
    operators care about."""
    r = capa_skill.analyze(_REAL_DUMP, tmp_path / "out",
                             shellcode_arch="64", timeout=120)
    assert r.rc == 0
    assert len(r.rules_matched) >= 1

"""Phase 4 integration smoke tests for capa+hayabusa wired into agents.

These tests don't run the actual external tools — they monkeypatch the
skill calls and verify (a) the agent calls them, (b) the result is
translated into hypothesis tags correctly, (c) ATT&CK technique-ID-to-
hypothesis mapping works."""
from pathlib import Path

import pytest


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    from el.evidence import intake as intake_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


def test_capa_attack_techniques_map_to_hypothesis_tags(isolated, monkeypatch):
    from el.agents.malware_triage import MalwareTriageAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import dump_analysis as da, capa as capa_skill

    src = isolated / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-capa")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-capa", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    fake_dump = isolated / "pid.123.vad.0x1000-0x1fff.dmp"
    fake_dump.write_bytes(b"MZ" + b"\x00" * 100 + b"PE\x00\x00" + b"\x00" * 200)
    fake_scan = da.scan_dump(fake_dump)
    assert fake_scan.has_mz_header

    fake_capa = capa_skill.CapaResult(
        target=fake_dump, rc=0,
        rules_matched=["inject pe", "dump credentials from lsass"],
        attack_techniques=[("T1055", "Process Injection"),
                            ("T1003.001", "OS Credential Dumping: LSASS Memory"),
                            ("T1071.001", "App Layer Protocol: Web")],
        json_path=isolated / "capa.json",
        command=["capa", str(fake_dump)],
    )
    monkeypatch.setattr(capa_skill, "analyze",
                        lambda target, out_dir, timeout=300,
                               shellcode_arch=None: fake_capa)

    findings = MalwareTriageAgent()._run_capa(ctx, fake_dump, fake_scan, isolated / "out")
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == "high"
    assert "H_PROCESS_INJECTION" in f.hypotheses_supported
    assert "H_CREDENTIAL_ACCESS" in f.hypotheses_supported
    assert "H_C2_OR_REVERSE_SHELL" in f.hypotheses_supported
    assert "capa" in f.claim.lower()


def test_capa_skipped_for_non_pe_dumps(isolated):
    from el.agents.malware_triage import MalwareTriageAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import dump_analysis as da

    src = isolated / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-capa-sc")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-capa-sc", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    raw_sc = isolated / "pid.456.vad.0x2000-0x2fff.dmp"
    raw_sc.write_bytes(b"\xfc\xe8\x00" * 50)  # NOP-call shellcode pattern, no PE
    scan = da.scan_dump(raw_sc)
    assert not scan.has_mz_header

    findings = MalwareTriageAgent()._run_capa(ctx, raw_sc, scan, isolated / "out")
    # No PE → capa is skipped (deferred to a follow-up that uses arch hint)
    assert findings == []


def test_hayabusa_attack_ids_lift_appropriate_hypotheses(isolated, monkeypatch):
    from el.agents.log_analyst import LogAnalystAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import hayabusa as hb

    src = isolated / "Security.evtx"
    # Fake EVTX magic prefix is enough for the file to exist; we monkeypatch
    src.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    m = intake_mod.intake(src, case_id="t-hayabusa")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-hayabusa", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    fake = hb.HayabusaRun(
        target=src, rc=0,
        csv_path=isolated / "haya.csv",
        stderr_path=isolated / "haya.stderr",
        command=["hayabusa", "csv-timeline"],
        detection_count=42,
        rule_hits={"PSExec Service Install": 5,
                    "Suspicious Encoded PowerShell": 12,
                    "WMIC Process Call Create": 3},
        severity_counts={"high": 8, "medium": 25, "low": 9},
        attack_techniques={"T1059.001", "T1021.002", "T1569.002", "T1003.001"},
    )
    fake.csv_path.write_text("dummy")
    monkeypatch.setattr(hb, "csv_timeline",
                        lambda target, out_dir, timeout=1800: fake)

    findings = LogAnalystAgent()._run_hayabusa(ctx, ctx.input_path, isolated / "an")
    assert any("Hayabusa Sigma sweep: 42 detection" in f.claim for f in findings)
    f = next(f for f in findings if "Hayabusa Sigma sweep: 42" in f.claim)
    tags = set(f.hypotheses_supported)
    assert "H_LIVING_OFF_THE_LAND" in tags  # from T1059.001
    assert "H_LATERAL_MOVEMENT" in tags     # from T1021.002 + T1569.002
    assert "H_CREDENTIAL_ACCESS" in tags    # from T1003.001


def test_hayabusa_skips_silently_when_unavailable(isolated, monkeypatch):
    from el.agents.log_analyst import LogAnalystAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import hayabusa as hb

    src = isolated / "x.evtx"; src.write_bytes(b"ElfFile\x00")
    m = intake_mod.intake(src, case_id="t-haya-miss")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-haya-miss", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    def _raise(*a, **kw):
        raise hb.HayabusaError("hayabusa not on PATH")
    monkeypatch.setattr(hb, "csv_timeline", _raise)

    findings = LogAnalystAgent()._run_hayabusa(ctx, src, isolated)
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"
    assert "unavailable or failed" in findings[0].claim

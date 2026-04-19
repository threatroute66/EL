"""Phase 4 wave 2: bulk_extractor → DiskForensicator, suricata →
NetworkAnalyst, floss → MalwareTriage. Smoke tests via monkeypatch
since the actual tools are slow + need real evidence."""
from pathlib import Path

import pytest


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    from el.evidence import intake as intake_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


# ----- bulk_extractor → DiskForensicator -----

def test_bulk_extractor_emits_finding_with_feature_counts(isolated, monkeypatch):
    from el.agents.disk_forensicator import DiskForensicatorAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import bulk_extractor as be

    src = isolated / "x.bin"; src.write_bytes(b"x" * 100)
    m = intake_mod.intake(src, case_id="t-be")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-be", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    fake = be.BulkRun(target=src, out_dir=isolated / "be-out", rc=0,
                      feature_files=[], command=["bulk_extractor"])
    monkeypatch.setattr(fake, "features", lambda: {"email": 12, "url": 30, "ip": 5})
    monkeypatch.setattr(be, "scan",
                        lambda target, out_dir,
                               enable_scanners=None, disable_scanners=None,
                               threads=4, timeout=3600: fake)

    findings = DiskForensicatorAgent()._run_bulk_extractor(ctx, src, isolated)
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == "high"
    assert "47 feature" in f.claim or "47 feature(s)" in f.claim
    assert "H_DISK_ARTIFACTS" in f.hypotheses_supported


def test_bulk_extractor_skipped_gracefully_when_unavailable(isolated, monkeypatch):
    from el.agents.disk_forensicator import DiskForensicatorAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import bulk_extractor as be

    src = isolated / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-be-miss")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-be-miss", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    def _raise(*a, **kw):
        raise be.BulkExtractorError("not on PATH")
    monkeypatch.setattr(be, "scan", _raise)

    findings = DiskForensicatorAgent()._run_bulk_extractor(ctx, src, isolated)
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"


# ----- suricata → NetworkAnalyst -----

def test_suricata_named_malware_alerts_lift_c2_hypothesis(isolated, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import network_extra as nx

    src = isolated / "x.pcap"; src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    m = intake_mod.intake(src, case_id="t-suri")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-suri", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    fake_eve = isolated / "eve.json"
    fake_eve.write_text("{}")
    fake = nx.SuricataRun(
        pcap=src, out_dir=isolated, rc=0, eve_path=fake_eve,
        alert_count=42,
        sig_hits={"ET MALWARE Trickbot CnC": 12,
                  "ET POLICY HTTP traffic on port": 25,
                  "ET EXPLOIT Possible Equation Group ETERNALBLUE": 5},
        command=["suricata"],
    )
    monkeypatch.setattr(nx, "replay_pcap",
                        lambda pcap, out_dir, timeout=1800: fake)

    findings = NetworkAnalystAgent()._run_suricata(ctx, isolated)
    f = next(f for f in findings if "Suricata IDS: 42" in f.claim)
    tags = set(f.hypotheses_supported)
    assert "H_C2_OR_REVERSE_SHELL" in tags  # from Trickbot + EXPLOIT signatures


def test_suricata_no_alerts_yields_low_confidence_finding(isolated, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import network_extra as nx

    src = isolated / "x.pcap"; src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    m = intake_mod.intake(src, case_id="t-suri-clean")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-suri-clean", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    fake_eve = isolated / "eve.json"; fake_eve.write_text("{}")
    fake = nx.SuricataRun(
        pcap=src, out_dir=isolated, rc=0, eve_path=fake_eve,
        alert_count=0, sig_hits={}, command=["suricata"],
    )
    monkeypatch.setattr(nx, "replay_pcap",
                        lambda pcap, out_dir, timeout=1800: fake)

    findings = NetworkAnalystAgent()._run_suricata(ctx, isolated)
    assert len(findings) == 1
    assert findings[0].confidence == "low"
    assert "0 alerts" in findings[0].claim


# ----- floss → MalwareTriage -----

def test_floss_recovers_strings_for_non_pe_dump(isolated, monkeypatch):
    from el.agents.malware_triage import MalwareTriageAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import dump_analysis as da, floss as floss_skill

    src = isolated / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-floss")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-floss", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    raw_sc = isolated / "pid.456.dmp"
    raw_sc.write_bytes(b"\xfc\xe8\x00" * 50)
    scan = da.scan_dump(raw_sc)

    fake = floss_skill.FlossResult(
        target=raw_sc, rc=0,
        stack_strings=["mimikatz!sekurlsa::"],
        tight_strings=["evil.example.com"],
        decoded_strings=["powershell -enc"],
        json_path=isolated / "f.json",
    )
    monkeypatch.setattr(floss_skill, "analyze",
                        lambda target, out_dir, shellcode_arch=None, timeout=300: fake)

    recovered = MalwareTriageAgent()._run_floss_recover(ctx, raw_sc, scan, isolated)
    assert "mimikatz!sekurlsa::" in recovered
    assert "evil.example.com" in recovered
    assert "powershell -enc" in recovered


def test_floss_silent_when_unavailable(isolated, monkeypatch):
    from el.agents.malware_triage import MalwareTriageAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import dump_analysis as da, floss as floss_skill

    src = isolated / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-floss-miss")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-floss-miss", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    raw = isolated / "pid.789.dmp"
    raw.write_bytes(b"\xfc" * 100)
    scan = da.scan_dump(raw)

    def _raise(*a, **kw):
        raise floss_skill.FlossError("not installed")
    monkeypatch.setattr(floss_skill, "analyze", _raise)

    recovered = MalwareTriageAgent()._run_floss_recover(ctx, raw, scan, isolated)
    assert recovered == set()

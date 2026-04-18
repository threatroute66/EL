"""Phase 4 wave 3: zeek + tshark → NetworkAnalyst, exiftool →
DiskForensicator. Smoke tests via monkeypatch (real tools are slow + need
real evidence)."""
from pathlib import Path

import pytest


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    from el.evidence import intake as intake_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


# ----- zeek → NetworkAnalyst -----

def test_zeek_family_marker_lifts_c2_hypothesis(isolated, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import zeek as zeek_skill

    src = isolated / "x.pcap"; src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    m = intake_mod.intake(src, case_id="t-zeek")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-zeek", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    out_dir = isolated / "zeek-out"
    out_dir.mkdir()
    log = out_dir / "http.log"; log.write_text("")
    fake = zeek_skill.ZeekRun(
        pcap=src, out_dir=out_dir, rc=0, log_files=[log],
        summary={"http": 5, "dns": 3, "conn": 12},
        notable={"http_user_agents": ["Trickbot/1.0 (Win10)"],
                 "dns_queries": ["benign.example.com"]},
        command=["zeek"],
    )
    monkeypatch.setattr(zeek_skill, "replay_pcap",
                        lambda pcap, out_dir, timeout=1800: fake)

    findings = NetworkAnalystAgent()._run_zeek(ctx, isolated)
    tags = set()
    for f in findings:
        tags.update(f.hypotheses_supported)
    assert "H_C2_OR_REVERSE_SHELL" in tags
    assert any("trickbot" in f.claim.lower() for f in findings)


def test_zeek_unavailable_emits_insufficient(isolated, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import zeek as zeek_skill

    src = isolated / "x.pcap"; src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    m = intake_mod.intake(src, case_id="t-zeek-miss")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-zeek-miss", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    def _raise(*a, **kw):
        raise zeek_skill.ZeekError("not on PATH")
    monkeypatch.setattr(zeek_skill, "replay_pcap", _raise)

    findings = NetworkAnalystAgent()._run_zeek(ctx, isolated)
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"


def test_zeek_empty_logs_yield_low_confidence(isolated, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import zeek as zeek_skill

    src = isolated / "x.pcap"; src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    m = intake_mod.intake(src, case_id="t-zeek-empty")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-zeek-empty", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    fake = zeek_skill.ZeekRun(pcap=src, out_dir=isolated, rc=0,
                               log_files=[], summary={}, notable={},
                               command=["zeek"])
    monkeypatch.setattr(zeek_skill, "replay_pcap",
                        lambda pcap, out_dir, timeout=1800: fake)
    findings = NetworkAnalystAgent()._run_zeek(ctx, isolated)
    assert len(findings) == 1
    assert findings[0].confidence == "low"


# ----- tshark → NetworkAnalyst -----

def test_tshark_extracts_http_tls_fields(isolated, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import network_extra as nx

    src = isolated / "x.pcap"; src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    m = intake_mod.intake(src, case_id="t-tshark")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-tshark", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    out_path = isolated / "tshark.json"; out_path.write_text("{}")
    fake = nx.TsharkExtract(
        pcap=src, out_path=out_path, rc=0,
        fields={"http.request.full_uri": ["http://evil.example/x"],
                "http.user_agent": ["Mozilla/5.0"],
                "tls.handshake.extensions_server_name": ["c2.example.com"],
                "x509sat.printableString": []},
        command=["tshark"],
    )
    monkeypatch.setattr(nx, "extract_http_tls",
                        lambda pcap, out_dir, timeout=600: fake)
    findings = NetworkAnalystAgent()._run_tshark(ctx, isolated)
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert "H_NETWORK_TRAFFIC_OBSERVED" in findings[0].hypotheses_supported


def test_tshark_unavailable_silent(isolated, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import network_extra as nx

    src = isolated / "x.pcap"; src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    m = intake_mod.intake(src, case_id="t-tshark-miss")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-tshark-miss", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    def _raise(*a, **kw):
        raise nx.TsharkError("not on PATH")
    monkeypatch.setattr(nx, "extract_http_tls", _raise)
    findings = NetworkAnalystAgent()._run_tshark(ctx, isolated)
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"


# ----- exiftool → DiskForensicator -----

def test_exiftool_dominant_author_emits_attribution_finding(isolated, monkeypatch):
    from el.agents.disk_forensicator import DiskForensicatorAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import exiftool as exif_skill

    src = isolated / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-exif")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-exif", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    target = isolated / "artifacts"; target.mkdir()
    fake_metas = {
        "/a/doc1.docx": {"Author": "j.smith", "Producer": "Word 2019"},
        "/a/doc2.docx": {"Author": "j.smith", "Producer": "Word 2019"},
        "/a/doc3.docx": {"Author": "j.smith", "Producer": "Word 2019"},
        "/a/photo.jpg": {"Author": "j.smith", "GPSPosition": "1,2",
                          "SerialNumber": "SN-XYZ"},
    }
    monkeypatch.setattr(exif_skill, "metadata_dir",
                        lambda d, max_files=500, timeout=600: fake_metas)

    findings = DiskForensicatorAgent()._run_exiftool(ctx, target)
    assert len(findings) == 2
    assert findings[0].confidence == "high"
    assert "4 file(s)" in findings[0].claim
    assert "j.smith" in findings[1].claim
    assert findings[1].confidence == "medium"


def test_exiftool_unavailable_emits_insufficient(isolated, monkeypatch):
    from el.agents.disk_forensicator import DiskForensicatorAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import exiftool as exif_skill

    src = isolated / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-exif-miss")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-exif-miss", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    target = isolated / "artifacts"; target.mkdir()

    def _raise(*a, **kw):
        raise exif_skill.ExifError("not installed")
    monkeypatch.setattr(exif_skill, "metadata_dir", _raise)

    findings = DiskForensicatorAgent()._run_exiftool(ctx, target)
    assert len(findings) == 1
    assert findings[0].confidence == "insufficient"


def test_exiftool_empty_metas_returns_no_findings(isolated, monkeypatch):
    from el.agents.disk_forensicator import DiskForensicatorAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    from el.skills import exiftool as exif_skill

    src = isolated / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-exif-empty")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-exif-empty", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    target = isolated / "artifacts"; target.mkdir()
    monkeypatch.setattr(exif_skill, "metadata_dir",
                        lambda d, max_files=500, timeout=600: {})
    findings = DiskForensicatorAgent()._run_exiftool(ctx, target)
    assert findings == []

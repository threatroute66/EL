"""PR-M: Zeek-log-class surfacer tests.

Verifies that the Zeek skill extracts weird.log / signatures.log /
software.log / known_services.log / files.log columns correctly, and
that NetworkAnalystAgent promotes them into Findings at appropriate
confidence tiers.
"""
from pathlib import Path

import pytest

from el.skills import zeek as zeek_skill


def _zeek_header(path_name: str, fields: list[str]) -> str:
    return (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        f"#path\t{path_name}\n"
        "#fields\t" + "\t".join(fields) + "\n"
    )


def _write_zeek_log(path: Path, path_name: str,
                    fields: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        f.write(_zeek_header(path_name, fields))
        for r in rows:
            f.write("\t".join(r) + "\n")


# ---------------------------------------------------------------------------
# _extract_column covers the new logs
# ---------------------------------------------------------------------------

def test_weird_log_name_column_extracted(tmp_path):
    _write_zeek_log(
        tmp_path / "weird.log", "weird",
        ["ts", "uid", "id.orig_h", "name", "addl", "notice"],
        [
            ["1", "C1", "10.0.0.5", "above_hole_data_without_any_acks", "", "F"],
            ["2", "C2", "10.0.0.5", "inappropriate_FIN", "", "F"],
            ["3", "C3", "10.0.0.5", "above_hole_data_without_any_acks", "", "F"],
        ],
    )
    names = zeek_skill._extract_column(tmp_path / "weird.log", "name", 100)
    # duplicates preserved in column extraction; dedup happens upstream
    assert set(names) == {"above_hole_data_without_any_acks",
                           "inappropriate_FIN"}


def test_signatures_log_sig_id_extracted(tmp_path):
    _write_zeek_log(
        tmp_path / "signatures.log", "signatures",
        ["ts", "src_addr", "sig_id", "note"],
        [
            ["1", "10.0.0.5", "sig-evil-001", "Zeek::Sensitive-URI"],
            ["2", "10.0.0.5", "sig-evil-002", "Zeek::Suspicious-UA"],
        ],
    )
    ids = zeek_skill._extract_column(tmp_path / "signatures.log", "sig_id", 50)
    assert "sig-evil-001" in ids
    assert "sig-evil-002" in ids


def test_files_log_sha256_extracted(tmp_path):
    _write_zeek_log(
        tmp_path / "files.log", "files",
        ["ts", "fuid", "mime_type", "sha256"],
        [
            ["1", "F1", "application/x-dosexec", "a" * 64],
            ["2", "F2", "text/html", "b" * 64],
        ],
    )
    hashes = zeek_skill._extract_column(tmp_path / "files.log", "sha256", 50)
    assert ("a" * 64) in hashes
    assert ("b" * 64) in hashes


def test_known_services_log_extracted(tmp_path):
    _write_zeek_log(
        tmp_path / "known_services.log", "known_services",
        ["ts", "host", "port_num", "service"],
        [
            ["1", "203.0.113.10", "80", "http"],
            ["2", "203.0.113.10", "443", "ssl"],
        ],
    )
    svcs = zeek_skill._extract_column(
        tmp_path / "known_services.log", "service", 100)
    assert "http" in svcs
    assert "ssl" in svcs


# ---------------------------------------------------------------------------
# Agent-level: Findings emitted at correct confidence
# ---------------------------------------------------------------------------

def _fake_ctx(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.pcap"; src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00"*60)
    m = intake_mod.intake(src, case_id="t-zeek-surfacer")
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id="t-zeek-surfacer", case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


def test_weird_names_above_threshold_emit_finding(tmp_path, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.skills import zeek as zeek_skill

    ctx = _fake_ctx(tmp_path, monkeypatch)
    fake = zeek_skill.ZeekRun(
        pcap=ctx.input_path, out_dir=tmp_path, rc=0,
        log_files=[], summary={"conn": 100},
        notable={
            "weird_names": [f"weird_name_{i}" for i in range(15)],
            "http_user_agents": [], "cert_subjects": [], "dns_queries": [],
        },
        command=["zeek"],
    )
    monkeypatch.setattr(zeek_skill, "replay_pcap",
                        lambda pcap, out_dir, timeout=1800: fake)
    # Also stub out network_anomaly to avoid file IO
    import el.skills.network_anomaly as na
    monkeypatch.setattr(na, "run_all", lambda _d: [])

    findings = NetworkAnalystAgent()._run_zeek(ctx, tmp_path)
    weird = [f for f in findings if "weird.log" in f.claim]
    assert weird, f"expected weird.log finding; got {[f.claim[:80] for f in findings]}"
    assert weird[0].confidence == "medium"


def test_weird_names_below_threshold_no_finding(tmp_path, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.skills import zeek as zeek_skill

    ctx = _fake_ctx(tmp_path, monkeypatch)
    fake = zeek_skill.ZeekRun(
        pcap=ctx.input_path, out_dir=tmp_path, rc=0,
        log_files=[], summary={"conn": 100},
        notable={"weird_names": ["only_a_few", "weird_things", "seen"]},
        command=["zeek"],
    )
    monkeypatch.setattr(zeek_skill, "replay_pcap",
                        lambda pcap, out_dir, timeout=1800: fake)
    import el.skills.network_anomaly as na
    monkeypatch.setattr(na, "run_all", lambda _d: [])

    findings = NetworkAnalystAgent()._run_zeek(ctx, tmp_path)
    assert not any("weird.log" in f.claim for f in findings)


def test_signatures_log_fires_high_confidence(tmp_path, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.skills import zeek as zeek_skill

    ctx = _fake_ctx(tmp_path, monkeypatch)
    fake = zeek_skill.ZeekRun(
        pcap=ctx.input_path, out_dir=tmp_path, rc=0,
        log_files=[], summary={"conn": 100},
        notable={"signature_ids": ["sig-c2-001", "sig-scan-002"]},
        command=["zeek"],
    )
    monkeypatch.setattr(zeek_skill, "replay_pcap",
                        lambda pcap, out_dir, timeout=1800: fake)
    import el.skills.network_anomaly as na
    monkeypatch.setattr(na, "run_all", lambda _d: [])

    findings = NetworkAnalystAgent()._run_zeek(ctx, tmp_path)
    sigs = [f for f in findings if "signatures.log" in f.claim]
    assert sigs
    assert sigs[0].confidence == "high"
    assert "H_C2_OR_REVERSE_SHELL" in sigs[0].hypotheses_supported


def test_file_sha256_fires_low_confidence(tmp_path, monkeypatch):
    from el.agents.network_analyst import NetworkAnalystAgent
    from el.skills import zeek as zeek_skill

    ctx = _fake_ctx(tmp_path, monkeypatch)
    fake = zeek_skill.ZeekRun(
        pcap=ctx.input_path, out_dir=tmp_path, rc=0,
        log_files=[], summary={"conn": 100},
        notable={"file_sha256": ["a" * 64, "b" * 64]},
        command=["zeek"],
    )
    monkeypatch.setattr(zeek_skill, "replay_pcap",
                        lambda pcap, out_dir, timeout=1800: fake)
    import el.skills.network_anomaly as na
    monkeypatch.setattr(na, "run_all", lambda _d: [])

    findings = NetworkAnalystAgent()._run_zeek(ctx, tmp_path)
    files = [f for f in findings if "files.log" in f.claim]
    assert files
    assert files[0].confidence == "low"

"""Layer 2 (case seal) + Layer 3 (knowledge store) contract tests."""
import json
from pathlib import Path

import pytest

from el import knowledge as kb
from el import seal as case_seal
from el.evidence import intake as intake_mod
from el.orchestrator.coordinator import Coordinator


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "knowledge.sqlite"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


# --- Seal -----------------------------------------------------------------

def test_seal_writes_manifest_with_per_file_sha256(tmp_path):
    case = tmp_path / "case-x"
    case.mkdir()
    (case / "a.txt").write_text("alpha")
    (case / "sub").mkdir()
    (case / "sub" / "b.bin").write_bytes(b"\x00\x01\x02")
    m = case_seal.seal_case(case, "case-x", archive=False)
    assert (case / "seal.json").exists()
    assert m["case_id"] == "case-x"
    assert "merkle_root" in m
    assert "a.txt" in m["files"]
    assert m["files"]["a.txt"]["sha256"]
    assert m["file_count"] >= 2


def test_seal_archive_creates_tar_gz(tmp_path):
    case = tmp_path / "case-arch"
    case.mkdir()
    (case / "report.md").write_text("# x")
    archive_root = tmp_path / "_archives"
    m = case_seal.seal_case(case, "case-arch", archive=True, archive_root=archive_root)
    assert m["archive_path"].endswith(".tar.gz")
    assert Path(m["archive_path"]).exists()
    assert m["archive_sha256"]
    # The ON-DISK seal.json must also record the archive it produced
    # (re-written after archiving) — chain-of-custody, not just the
    # returned dict.
    on_disk = json.loads((case / "seal.json").read_text())
    assert on_disk["archive_path"] == m["archive_path"]
    assert on_disk["archive_sha256"] == m["archive_sha256"]
    assert on_disk["archive_size"] == m["archive_size"]


def test_verify_seal_detects_drift(tmp_path):
    case = tmp_path / "case-drift"
    case.mkdir()
    (case / "x.txt").write_text("original")
    case_seal.seal_case(case, "case-drift", archive=False)
    ok, drift = case_seal.verify_seal(case)
    assert ok and drift == []
    # Mutate
    (case / "x.txt").write_text("tampered")
    ok, drift = case_seal.verify_seal(case)
    assert not ok
    assert any("hash drift" in d for d in drift)


def _bundle_with_recovery(tmp_path):
    """A case dir with a normal report + a large tsk_recover tree under
    exports/recovery/ (mirrors a disk-image bundle device)."""
    case = tmp_path / "case-rec"
    (case / "reports").mkdir(parents=True)
    (case / "reports" / "report.md").write_text("# findings")
    rec = case / "devices" / "h1" / "exports" / "recovery" / "tsk_recover"
    rec.mkdir(parents=True)
    (rec / "big1.bin").write_bytes(b"\xde" * 4096)
    (rec / "big2.bin").write_bytes(b"\xad" * 4096)
    return case


def test_recovery_tree_hashed_but_excluded_from_archive(tmp_path):
    import tarfile
    case = _bundle_with_recovery(tmp_path)
    archive_root = tmp_path / "_archives"
    m = case_seal.seal_case(case, "case-rec", archive=True,
                            archive_root=archive_root)

    # Manifest STILL hashes every recovered file (integrity preserved)
    rec_keys = [k for k in m["files"] if "exports/recovery/" in k]
    assert len(rec_keys) == 2
    assert all(m["files"][k]["sha256"] for k in rec_keys)
    assert all(m["files"][k]["archived"] is False for k in rec_keys)
    assert m["archive_excluded_count"] == 2
    assert m["archive_excluded_bytes"] == 8192

    # ...but the tar.gz omits them, while keeping the report
    with tarfile.open(m["archive_path"]) as tar:
        names = tar.getnames()
    assert any(n.endswith("reports/report.md") for n in names)
    assert not any("exports/recovery/" in n for n in names)


def test_verify_tolerates_excluded_recovery_when_extracted(tmp_path):
    """Verifying an extracted archive (recovery tree absent) is NOT drift,
    but the report (which WAS archived) is still checked."""
    case = _bundle_with_recovery(tmp_path)
    case_seal.seal_case(case, "case-rec", archive=False)
    # Simulate an extracted archive: delete the excluded recovery tree
    import shutil
    shutil.rmtree(case / "devices" / "h1" / "exports" / "recovery")
    ok, drift = case_seal.verify_seal(case)
    assert ok, f"excluded-and-absent recovery must not be drift: {drift}"


def test_verify_still_detects_tamper_of_recovered_file_on_live_dir(tmp_path):
    """Excluded-from-archive does NOT mean unchecked: on the live case dir
    the recovered file is present and its hash is still verified."""
    case = _bundle_with_recovery(tmp_path)
    case_seal.seal_case(case, "case-rec", archive=False)
    rec = case / "devices" / "h1" / "exports" / "recovery" / "tsk_recover"
    (rec / "big1.bin").write_bytes(b"\x00" * 4096)   # tamper in place
    ok, drift = case_seal.verify_seal(case)
    assert not ok and any("hash drift" in d for d in drift)


def test_empty_exclude_archives_everything(tmp_path):
    """archive_exclude=() restores the pre-existing 'archive everything'
    behaviour."""
    import tarfile
    case = _bundle_with_recovery(tmp_path)
    m = case_seal.seal_case(case, "case-rec", archive=True,
                            archive_root=tmp_path / "_arch", archive_exclude=())
    assert m["archive_excluded_count"] == 0
    with tarfile.open(m["archive_path"]) as tar:
        assert any("exports/recovery/" in n for n in tar.getnames())


# --- Knowledge store ------------------------------------------------------

def test_record_then_lookup_iocs_excludes_current_case(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))
    kb.record_iocs("case-A", "agent_x",
                   {"ipv4": ["8.8.8.8"], "domain": ["evil.example.com"]})
    kb.record_iocs("case-B", "agent_y",
                   {"ipv4": ["8.8.8.8"], "domain": ["other.example.com"]})

    # From case-C, lookup should return BOTH prior observations of 8.8.8.8
    out = kb.lookup_iocs(["8.8.8.8", "evil.example.com"], current_case_id="case-C")
    assert "8.8.8.8" in out
    cases_for_ip = sorted({o["case_id"] for o in out["8.8.8.8"]})
    assert cases_for_ip == ["case-A", "case-B"]
    # And from case-A, lookup of 8.8.8.8 should NOT include itself
    out2 = kb.lookup_iocs(["8.8.8.8"], current_case_id="case-A")
    assert "8.8.8.8" in out2
    assert all(o["case_id"] != "case-A" for o in out2["8.8.8.8"])


def test_record_iocs_dedups_same_case(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "kb.sqlite"))
    n1 = kb.record_iocs("case-A", "agent_x", {"ipv4": ["1.1.1.1"]})
    n2 = kb.record_iocs("case-A", "agent_x", {"ipv4": ["1.1.1.1"]})
    assert n1 == 1 and n2 == 0


# --- End-to-end: cross-case "previously seen" finding emitted -------------

def test_coordinator_seals_and_emits_cross_case_finding(isolated, monkeypatch):
    """First case extracts IOCs, gets sealed, knowledge store populated.
    Second case re-extracts the same IOCs, must emit a low-confidence
    'cross-case overlap' Finding pointing at the first case."""
    from scapy.all import wrpcap
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP

    def make_pcap(p, dst_ip, dns_name):
        pkts = [IP(src="10.0.0.5", dst=dst_ip) / UDP(sport=33333, dport=53)
                / DNS(rd=1, qd=DNSQR(qname=dns_name))]
        wrpcap(str(p), pkts)

    a = isolated / "a.pcap"; make_pcap(a, "203.0.113.7", "shared.example.com")
    b = isolated / "b.pcap"; make_pcap(b, "203.0.113.7", "shared.example.com")

    res_a = Coordinator().investigate(a, case_id="case-AA")
    res_b = Coordinator().investigate(b, case_id="case-BB")

    from el.evidence.ledger import list_findings
    rows_b = list_findings(res_b.case_dir, case_id="case-BB")
    cross = [f for f in rows_b if f.agent == "knowledge_lookup"]
    assert cross, "expected at least one cross-case knowledge finding in case-BB"
    assert any("case-AA" in f.claim for f in cross), \
        "cross-case finding should reference the prior case-AA"
    # Confidence MUST be low (suggestive only, never load-bearing)
    assert all(f.confidence == "low" for f in cross)


def test_seal_emitted_at_done(isolated):
    src = isolated / "x.bin"; src.write_bytes(b"x")
    res = Coordinator().investigate(src, case_id="case-seal-test")
    seal_path = res.case_dir / "seal.json"
    assert seal_path.exists()
    m = json.loads(seal_path.read_text())
    assert m["case_id"] == "case-seal-test"
    assert m.get("merkle_root")
    # Archive should also be present
    archives = list((res.case_dir.parent / "_archives").glob("case-seal-test-*.tar.gz"))
    assert archives

"""Skill + agent tests for inbound RDP brute-force detection.

The skill side (analyze_netscan) is exercised against synthetic vol3
netscan rows that mirror the rocba memory image's pattern: many
CLOSED rows from a few external IPs, one or two ESTABLISHED rows
showing successful authentication. The agent side (RDPBruteForceAnalyst)
verifies findings are emitted with the right confidence + tag, and
that the H_BRUTE_FORCE hypothesis lifts under ACH scoring.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.rdp_brute_force import RDPBruteForceAnalyst
from el.intel.ach import score_findings
from el.schemas.finding import EvidenceItem, Finding
from el.skills import rdp_brute_force as rdp


# ---------------------------------------------------------------------------
# Skill helpers
# ---------------------------------------------------------------------------

def _row(*, foreign_addr="1.2.3.4", foreign_port=12345, state="CLOSED",
           local_port=3389, local_addr="192.168.1.5",
           proto="TCPv4", created="2020-11-16T02:34:58+00:00",
           pid=1248, owner="svchost.exe") -> dict:
    return {
        "PID": pid, "Owner": owner, "Proto": proto, "State": state,
        "LocalAddr": local_addr, "LocalPort": local_port,
        "ForeignAddr": foreign_addr, "ForeignPort": foreign_port,
        "Created": created,
    }


def _write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return path


# ---------------------------------------------------------------------------
# External-IP filter
# ---------------------------------------------------------------------------

def test_is_external_ip_rejects_rfc1918_loopback_etc():
    for internal in ("10.0.0.5", "172.16.4.1", "192.168.1.5",
                       "127.0.0.1", "169.254.0.1", "224.0.0.1", ""):
        assert not rdp._is_external_ip(internal), internal
    for external in ("8.8.8.8", "81.30.144.115", "213.202.233.104"):
        assert rdp._is_external_ip(external), external


def test_is_external_ip_rejects_invalid_strings():
    for bad in ("not-an-ip", "999.0.0.1", None):
        assert not rdp._is_external_ip(bad)


# ---------------------------------------------------------------------------
# Skill — clustering + threshold
# ---------------------------------------------------------------------------

def test_below_threshold_external_goes_to_other_external(tmp_path):
    """Single probe from an external IP must NOT be classified as a
    brute-force cluster — that's recon noise. It still surfaces in
    other_external for the analyst."""
    rows = [_row(foreign_addr="8.8.8.8", state="CLOSED")]
    p = _write_jsonl(tmp_path / "ns.jsonl", rows)
    report = rdp.analyze_netscan(p)
    assert report.inbound_3389_total == 1
    assert report.external_clusters == []
    assert report.breach_clusters == []
    assert len(report.other_external) == 1
    assert report.other_external[0].foreign_ip == "8.8.8.8"


def test_above_threshold_external_becomes_brute_force_cluster(tmp_path):
    """≥MIN_CLUSTER_CONNECTIONS rows from one external IP ⇒ brute-force
    cluster. ESTABLISHED count > 0 means breach."""
    rows = [_row(foreign_addr="81.30.144.115", state="CLOSED")
            for _ in range(11)]
    rows.append(_row(foreign_addr="81.30.144.115", state="ESTABLISHED"))
    p = _write_jsonl(tmp_path / "ns.jsonl", rows)
    report = rdp.analyze_netscan(p)
    assert report.inbound_3389_total == 12
    assert len(report.external_clusters) == 1
    cluster = report.external_clusters[0]
    assert cluster.total_connections == 12
    assert cluster.closed_count == 11
    assert cluster.established_count == 1
    assert cluster.is_breach
    assert len(report.breach_clusters) == 1


def test_internal_3389_is_ignored_lateral_movement_owns_it(tmp_path):
    """RFC1918 → RFC1918 RDP traffic is the lateral-movement story,
    not the external-attack story. The skill must drop those rows."""
    rows = [_row(foreign_addr="10.0.0.50", state="ESTABLISHED")
            for _ in range(20)]
    p = _write_jsonl(tmp_path / "ns.jsonl", rows)
    report = rdp.analyze_netscan(p)
    assert report.inbound_3389_total == 0
    assert report.external_clusters == []
    assert report.breach_clusters == []


def test_listening_socket_rows_excluded(tmp_path):
    """The host's own LISTENING socket on 3389 must not count as an
    inbound attempt — it's the server side, not a remote attempt."""
    rows = [_row(foreign_addr="0.0.0.0", foreign_port=0,
                  state="LISTENING", local_addr="0.0.0.0")]
    p = _write_jsonl(tmp_path / "ns.jsonl", rows)
    report = rdp.analyze_netscan(p)
    assert report.inbound_3389_total == 0


def test_non_3389_traffic_excluded(tmp_path):
    rows = [_row(foreign_addr="8.8.8.8", local_port=445, state="CLOSED")
            for _ in range(20)]
    p = _write_jsonl(tmp_path / "ns.jsonl", rows)
    report = rdp.analyze_netscan(p)
    assert report.inbound_3389_total == 0


def test_multiple_external_sources_clustered_independently(tmp_path):
    rows = []
    rows += [_row(foreign_addr="81.30.144.115", state="CLOSED")
             for _ in range(15)]
    rows += [_row(foreign_addr="213.202.233.104", state="CLOSED")
             for _ in range(11)]
    rows.append(_row(foreign_addr="213.202.233.104", state="ESTABLISHED"))
    rows += [_row(foreign_addr="201.193.188.114", state="CLOSED")
             for _ in range(3)]   # below threshold, should be in other
    p = _write_jsonl(tmp_path / "ns.jsonl", rows)
    report = rdp.analyze_netscan(p)
    assert {c.foreign_ip for c in report.external_clusters} == {
        "81.30.144.115", "213.202.233.104"
    }
    # Order is hot to cool
    assert report.external_clusters[0].foreign_ip == "81.30.144.115"
    assert {c.foreign_ip for c in report.breach_clusters} == {
        "213.202.233.104"
    }
    assert {c.foreign_ip for c in report.other_external} == {
        "201.193.188.114"
    }


def test_duration_seconds_populated_when_timestamps_present(tmp_path):
    rows = [_row(foreign_addr="81.30.144.115", state="CLOSED",
                  created="2020-11-16T02:30:00+00:00")]
    rows += [_row(foreign_addr="81.30.144.115", state="CLOSED",
                   created="2020-11-16T02:36:00+00:00")
             for _ in range(11)]
    p = _write_jsonl(tmp_path / "ns.jsonl", rows)
    report = rdp.analyze_netscan(p)
    cluster = report.external_clusters[0]
    assert cluster.duration_seconds == pytest.approx(360.0)


def test_missing_netscan_file_returns_empty_report(tmp_path):
    report = rdp.analyze_netscan(tmp_path / "does-not-exist.jsonl")
    assert report.inbound_3389_total == 0
    assert report.external_clusters == []


def test_malformed_jsonl_lines_silently_skipped(tmp_path):
    p = tmp_path / "ns.jsonl"
    valid = json.dumps(_row(foreign_addr="8.8.8.8", state="CLOSED"))
    p.write_text(f"{valid}\nthis is not json\n{valid}\n\n")
    report = rdp.analyze_netscan(p)
    assert report.inbound_3389_total == 2     # both valid rows counted


# ---------------------------------------------------------------------------
# Agent — wiring + Finding emission
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_case(tmp_path, monkeypatch):
    """Standard EL test-isolation fixture."""
    from el.evidence import intake as intake_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "knowledge.sqlite"))
    case_dir = tmp_path / "cases" / "rdp-bf-test"
    (case_dir / "analysis" / "memory_forensicator").mkdir(parents=True)
    (case_dir / "reports").mkdir(parents=True)
    return case_dir


@pytest.fixture
def ctx(isolated_case):
    from el.evidence.ledger import open_ledger
    with open_ledger(isolated_case):
        pass
    return AgentContext(
        case_id="rdp-bf-test",
        case_dir=isolated_case,
        input_path=Path("/dev/null"),
        manifest={},
        shared={"mem_os": "windows"},
    )


def test_agent_skips_non_windows(ctx):
    ctx.shared["mem_os"] = "linux"
    out = RDPBruteForceAnalyst().run(ctx)
    assert len(out) == 1
    assert out[0].confidence == "insufficient"


def test_agent_returns_insufficient_when_no_netscan_jsonl(ctx):
    out = RDPBruteForceAnalyst().run(ctx)
    assert len(out) == 1
    assert out[0].confidence == "insufficient"
    assert "netscan" in out[0].claim.lower()


def test_agent_emits_brute_force_and_breach_findings(ctx):
    """End-to-end: synthetic netscan JSONL with the rocba pattern
    (many CLOSED + a few ESTABLISHED from one external IP) drives
    two Findings — one brute-force cluster claim, one breach claim."""
    netscan = (ctx.case_dir / "analysis" / "memory_forensicator"
               / "windows_netscan_NetScan.jsonl")
    rows = [_row(foreign_addr="81.30.144.115", state="CLOSED")
            for _ in range(11)]
    rows.append(_row(foreign_addr="81.30.144.115", state="ESTABLISHED"))
    _write_jsonl(netscan, rows)

    findings = RDPBruteForceAnalyst().run(ctx)
    claims = [f.claim for f in findings]
    assert any("brute-force pattern" in c.lower() for c in claims)
    assert any("authenticated session" in c.lower() for c in claims)
    # Tag propagation
    assert all(
        "H_BRUTE_FORCE" in (f.hypotheses_supported or [])
        for f in findings
        if "brute" in f.claim.lower() or "authenticated" in f.claim.lower()
    )


def test_agent_subthreshold_only_emits_low_confidence(ctx):
    """When the only external activity is below the brute-force
    threshold, the agent must surface it as 'low' — not high.
    Important: a single port-scan probe must not pretend to be a
    credentialled attack."""
    netscan = (ctx.case_dir / "analysis" / "memory_forensicator"
               / "windows_netscan_NetScan.jsonl")
    _write_jsonl(netscan, [_row(foreign_addr="8.8.8.8", state="CLOSED")])

    findings = RDPBruteForceAnalyst().run(ctx)
    assert len(findings) == 1
    assert findings[0].confidence == "low"
    assert "below brute-force threshold" in findings[0].claim


def test_ach_lifts_brute_force_from_agent_finding(ctx):
    """The whole point of the H_BRUTE_FORCE tag — verify that an
    emitted Finding scores under ACH."""
    finding = Finding(
        case_id=ctx.case_id, agent="rdp_brute_force",
        claim=("Inbound RDP brute-force pattern: 1 external source(s) "
               "with ≥10 connection(s) each to local TCP/3389."),
        confidence="high",
        evidence=[EvidenceItem(
            tool="rdp_brute_force", version="1",
            command="walk(...)", output_sha256="0" * 64,
            output_path=str(ctx.case_dir / "stub.json"),
        )],
        hypotheses_supported=["H_BRUTE_FORCE"],
    )
    ranked, _ = score_findings([finding])
    by_id = {row.hyp_id: row for row in ranked}
    assert by_id["H_BRUTE_FORCE"].score >= 3, by_id["H_BRUTE_FORCE"]

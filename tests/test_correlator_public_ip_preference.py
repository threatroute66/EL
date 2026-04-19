"""PR-B: Correlator must prefer public IPs for "top destination by flows".

Batch-1 corpus signal (2013-07 … 2014-12 pcaps, 18/18 cases) showed the
correlator reporting an RFC1918 address (192.168.x.x, typically the
victim host receiving response traffic) as THE top destination. That
buries the real external C2 destination.

Fix: split external vs internal destinations; lead the claim with the
top external, mention the top internal secondarily with an explanatory
note. If ALL destinations are internal, emit a low-confidence finding
that says so explicitly rather than claim a C2 destination.
"""
from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.correlator import (
    CorrelatorAgent, _is_internal_ipv4, _INTERNAL_IPV4_PREFIXES,
)
from el.evidence import intake as intake_mod
from el.evidence.graph import init_graph, open_graph
from el.evidence.ledger import open_ledger


# ---------------------------------------------------------------------------
# _is_internal_ipv4 predicate
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("addr", [
    "192.168.0.1", "192.168.204.137",
    "10.0.0.5", "10.255.255.255",
    "172.16.0.1", "172.20.0.1", "172.31.255.254",
    "127.0.0.1",
    "169.254.1.1",
    "224.0.0.1",   # multicast
    "255.255.255.255",
    "0.0.0.0",
])
def test_internal_prefixes_detected(addr):
    assert _is_internal_ipv4(addr), f"{addr} should be classified internal"


@pytest.mark.parametrize("addr", [
    "203.0.113.17", "8.8.8.8", "1.1.1.1",
    "65.19.164.93",
    "172.15.0.1",    # NOT in 172.16/12
    "172.32.0.1",
    "100.64.0.1",    # CGNAT — arguably internal but not in RFC1918 set
])
def test_external_prefixes_not_flagged(addr):
    assert not _is_internal_ipv4(addr)


# ---------------------------------------------------------------------------
# CorrelatorAgent end-to-end
# ---------------------------------------------------------------------------

def _seed_graph_with_flows(case_dir: Path, dst_flows: list[tuple[str, int]]) -> None:
    """Populate the Kùzu graph with NetworkFlow → IPAddress edges.
    dst_flows: list of (ipv4_addr, flow_count)."""
    init_graph(case_dir)
    _, conn = open_graph(case_dir)
    for i, (addr, count) in enumerate(dst_flows):
        version = 4 if ":" not in addr else 6
        conn.execute(
            f"CREATE (:IPAddress {{addr: '{addr}', version: {version}}})"
        )
        for j in range(count):
            flow_id = f"flow-{i}-{j}"
            conn.execute(
                f"CREATE (:NetworkFlow {{flow_id: '{flow_id}', "
                f"src: '10.0.0.5', dst: '{addr}', sport: {1024+j}, "
                f"dport: 443, proto: 'tcp', bytes: 100, start_utc: '2020'}})"
            )
            conn.execute(
                f"MATCH (f:NetworkFlow), (i:IPAddress) "
                f"WHERE f.flow_id = '{flow_id}' AND i.addr = '{addr}' "
                f"CREATE (f)-[:FLOW_DST]->(i)"
            )


def _ctx(tmp_path, monkeypatch, case_id="t-corr"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.pcap"; src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00"*60)
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=src, manifest=m.__dict__)


def test_external_destination_leads_claim(tmp_path, monkeypatch):
    """Mixed internal + external flows: the public IP must lead the claim."""
    ctx = _ctx(tmp_path, monkeypatch, "t-mixed")
    # Internal victim with more flows than external C2 — classic bug shape.
    _seed_graph_with_flows(ctx.case_dir, [
        ("192.168.204.137", 25),   # RFC1918 — most flows
        ("203.0.113.17", 8),       # real external C2 — fewer flows
    ])

    findings = CorrelatorAgent().run(ctx)
    top = [f for f in findings if "Top external destination" in f.claim]
    assert top, f"expected external destination claim; got {[f.claim for f in findings]}"
    f = top[0]
    # External IP leads the claim
    assert "203.0.113.17" in f.claim
    # Internal is mentioned secondarily with context
    assert "192.168.204.137" in f.claim
    assert "Internal top" in f.claim or "victim host" in f.claim
    assert f.confidence == "medium"


def test_only_internal_flows_emits_low_confidence(tmp_path, monkeypatch):
    """If every destination is RFC1918, don't pretend we found a C2."""
    ctx = _ctx(tmp_path, monkeypatch, "t-internal-only")
    _seed_graph_with_flows(ctx.case_dir, [
        ("192.168.1.10", 5),
        ("10.0.0.20", 3),
    ])

    findings = CorrelatorAgent().run(ctx)
    internal = [f for f in findings
                if "All observed destination IPs are internal" in f.claim]
    assert internal
    assert internal[0].confidence == "low"
    assert "No external destination" in internal[0].claim


def test_only_external_flows_no_internal_note(tmp_path, monkeypatch):
    """All external — don't confuse the analyst with a gratuitous
    'Internal top' line."""
    ctx = _ctx(tmp_path, monkeypatch, "t-external-only")
    _seed_graph_with_flows(ctx.case_dir, [
        ("203.0.113.17", 10),
        ("198.51.100.8", 3),
    ])

    findings = CorrelatorAgent().run(ctx)
    top = [f for f in findings if "Top external destination" in f.claim]
    assert top
    f = top[0]
    assert "203.0.113.17" in f.claim
    assert "Internal top" not in f.claim


def test_no_flows_emits_insufficient_or_zero_external_claim(tmp_path, monkeypatch):
    """Empty graph — correlator's other queries still run but the
    top-destination claim should not appear."""
    ctx = _ctx(tmp_path, monkeypatch, "t-empty")
    init_graph(ctx.case_dir)
    findings = CorrelatorAgent().run(ctx)
    assert not any("Top external destination" in f.claim for f in findings)
    assert not any("All observed destination IPs are internal" in f.claim
                   for f in findings)

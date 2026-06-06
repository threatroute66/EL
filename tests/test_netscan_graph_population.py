"""Tests for MemoryForensicatorAgent._populate_netscan_graph.

Before this change, a memory-only case left the graph's IPAddress /
CONNECTED_TO tables empty — vol3 netscan is the only network
visibility such a case has, but nothing ingested it (Rocba bundle:
430 netscan rows incl. two external RDP attack sources, correlator
reported "0 IP(s)").

Pins:
  - foreign endpoints land as IPAddress nodes (v4 + v6 versioning)
  - CONNECTED_TO edges link the owning Process to each endpoint
  - unspecified/loopback foreign addrs are skipped
  - a Process unknown to pslist is MERGEd with the row's Owner name
  - re-runs are idempotent (MERGE not CREATE — counts stable)
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import AgentContext
from el.agents.memory_forensicator import MemoryForensicatorAgent
from el.evidence.graph import init_graph, open_graph


def _row(foreign: str, fport: int = 3389, pid: int = 4444,
         owner: str | None = "svchost.exe", state: str = "CLOSED") -> dict:
    return {
        "Proto": "TCPv4", "LocalAddr": "192.168.1.5", "LocalPort": 3389,
        "ForeignAddr": foreign, "ForeignPort": fport, "State": state,
        "PID": pid, "Owner": owner, "Created": "2020-11-16T02:31:18+00:00",
    }


def _ctx(tmp_path: Path) -> AgentContext:
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    init_graph(case_dir)
    return AgentContext(case_id="netscan-graph-test", case_dir=case_dir,
                        input_path=tmp_path / "mem.raw", manifest={})


def _counts(case_dir: Path) -> tuple[int, int]:
    db, conn = open_graph(case_dir)
    n_ip = conn.execute(
        "MATCH (i:IPAddress) RETURN count(i)").get_next()[0]
    n_edge = conn.execute(
        "MATCH (:Process)-[r:CONNECTED_TO]->(:IPAddress) "
        "RETURN count(r)").get_next()[0]
    return n_ip, n_edge


def test_foreign_endpoints_become_ip_nodes_and_edges(tmp_path):
    ctx = _ctx(tmp_path)
    agent = MemoryForensicatorAgent()
    rows = [
        _row("81.30.144.115", pid=4444),
        _row("213.202.233.104", pid=4444),
        _row("2606:4700::6810:84e5", fport=443, pid=5555,
             owner="msedge.exe"),
    ]
    written = agent._populate_netscan_graph(ctx, rows)
    assert written == 3
    n_ip, n_edge = _counts(ctx.case_dir)
    assert n_ip == 3
    assert n_edge == 3

    db, conn = open_graph(ctx.case_dir)
    r = conn.execute(
        "MATCH (i:IPAddress {addr: '2606:4700::6810:84e5'}) "
        "RETURN i.version")
    assert r.get_next()[0] == 6
    r = conn.execute(
        "MATCH (i:IPAddress {addr: '81.30.144.115'}) RETURN i.version")
    assert r.get_next()[0] == 4


def test_unspecified_and_loopback_skipped(tmp_path):
    ctx = _ctx(tmp_path)
    agent = MemoryForensicatorAgent()
    rows = [
        _row("0.0.0.0"), _row("*"), _row("::"),
        _row("127.0.0.1"), _row("::1"), _row(""),
        {"Proto": "TCPv4", "PID": None, "ForeignAddr": "10.1.1.1"},
    ]
    assert agent._populate_netscan_graph(ctx, rows) == 0
    assert _counts(ctx.case_dir) == (0, 0)


def test_unknown_process_merged_with_owner_name(tmp_path):
    """netscan pool-tag scanning survives process exit — the owning
    PID may not exist in the graph. We MERGE it with the row Owner."""
    ctx = _ctx(tmp_path)
    agent = MemoryForensicatorAgent()
    agent._populate_netscan_graph(
        ctx, [_row("81.30.144.115", pid=9999, owner="TermService")])
    db, conn = open_graph(ctx.case_dir)
    r = conn.execute("MATCH (p:Process {pid: 9999}) RETURN p.name")
    assert r.get_next()[0] == "TermService"


def test_existing_process_name_not_clobbered(tmp_path):
    """pslist already named the process — ON CREATE must not
    overwrite it with the netscan Owner string."""
    ctx = _ctx(tmp_path)
    db, conn = open_graph(ctx.case_dir)
    conn.execute("MERGE (p:Process {pid: 4444}) SET p.name = 'svchost.exe'")
    # Kùzu cannot tolerate two live writable Database handles on one
    # path in-process (native segfault) — drop ours before the agent
    # opens its own.
    del conn, db
    agent = MemoryForensicatorAgent()
    agent._populate_netscan_graph(
        ctx, [_row("81.30.144.115", pid=4444, owner="different-name")])
    db, conn = open_graph(ctx.case_dir)
    r = conn.execute("MATCH (p:Process {pid: 4444}) RETURN p.name")
    assert r.get_next()[0] == "svchost.exe"


def test_rerun_idempotent(tmp_path):
    ctx = _ctx(tmp_path)
    agent = MemoryForensicatorAgent()
    rows = [_row("81.30.144.115"), _row("213.202.233.104")]
    agent._populate_netscan_graph(ctx, rows)
    agent._populate_netscan_graph(ctx, rows)
    assert _counts(ctx.case_dir) == (2, 2)

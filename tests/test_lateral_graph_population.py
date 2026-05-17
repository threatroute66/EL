"""Tests for the extended graph-population in
LateralMovementAnalystAgent._populate_graph.

Before this change, the analyst wrote only Host + Event nodes —
case.html#graph rendered Events as disconnected dots with no edges,
no users, no source IPs. Now per finding the analyst also writes:
  - User nodes from sample_ev.user_name (synthetic SID
    `acct:<name>@<host>`)
  - IPAddress nodes for every distinct source IP in source_ips
  - Edges: Event→Host (OBSERVED_ON), Event→User (AUTHENTICATED_AS),
    Event→IPAddress (SOURCE_IP)

Pins:
  - schema DDL applied (new rels exist after init_graph)
  - graph writes survive empty / missing sample_events
  - synthetic SID is host-scoped (same username on two hosts =
    two distinct User nodes, no spurious merging)
  - source_ips aggregate iterated (every distinct IP lands, not
    just the 3 sampled events' IPs)
  - re-runs are idempotent (MERGE not CREATE — node count stable)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.lateral_movement_analyst import LateralMovementAnalystAgent
from el.evidence.graph import init_graph, open_graph
from el.skills.evtx_triage import EvtxEvent, LMHit


def _ev(eid: int, channel: str = "System", user: str = "",
        ts: str = "2012-04-04 17:29:33") -> EvtxEvent:
    return EvtxEvent(
        time_created=ts, event_id=eid, channel=channel,
        provider="X", computer="dc01", user_name=user,
        map_description="", payload={},
    )


def _hit(technique: str, events: list[EvtxEvent],
         source_ips: list[tuple[str, int]] | None = None) -> LMHit:
    return LMHit(
        technique=technique, subtechnique=technique,
        description=f"{technique} test", event_count=len(events),
        first_seen=events[0].time_created if events else "",
        last_seen=events[-1].time_created if events else "",
        sample_events=events[:3],
        source_ip=(source_ips[0][0] if source_ips else ""),
        source_ips=source_ips or [],
    )


def _setup_case(tmp_path: Path) -> AgentContext:
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    init_graph(case_dir)
    return AgentContext(case_id="srl-2015-dc-test", case_dir=case_dir,
                        input_path=case_dir, manifest={})


def _count(conn, query: str) -> int:
    r = conn.execute(query)
    return int(r.get_next()[0])


# ---------------------------------------------------------------------------
# Schema — new rels are created by init_graph
# ---------------------------------------------------------------------------

def test_schema_has_observed_on_and_source_ip_rels(tmp_path):
    """The new rels (OBSERVED_ON Event→Host, SOURCE_IP Event→IPAddress)
    must be in the schema so the agent can MATCH against them.
    Regression for a 'tables in DDL list but typo' kind of bug."""
    ctx = _setup_case(tmp_path)
    db, conn = open_graph(ctx.case_dir)
    # Both new rels must be queryable — Kùzu errors when a rel name
    # doesn't exist.
    conn.execute("MATCH ()-[r:OBSERVED_ON]->() RETURN count(r)")
    conn.execute("MATCH ()-[r:SOURCE_IP]->() RETURN count(r)")


# ---------------------------------------------------------------------------
# Basic graph population — single hit, single source IP
# ---------------------------------------------------------------------------

def test_single_rdp_hit_creates_host_event_user_ip_and_edges(tmp_path):
    """RDP inbound — 1 sample event with user_name 'Administrator',
    1 source IP. Expected after population:
      Host: 1 (the DC)
      Event: 1 (the sample)
      User: 1 (Administrator on this host)
      IPAddress: 1 (the source)
      OBSERVED_ON: 1, AUTHENTICATED_AS: 1, SOURCE_IP: 1"""
    ctx = _setup_case(tmp_path)
    agent = LateralMovementAnalystAgent()
    hit = _hit("rdp",
                [_ev(1149, "TerminalServices", "Administrator")],
                source_ips=[("10.3.16.5", 55)])
    agent._populate_graph(ctx, [hit])
    db, conn = open_graph(ctx.case_dir)
    assert _count(conn, "MATCH (h:Host) RETURN count(h)") == 1
    assert _count(conn, "MATCH (e:Event) RETURN count(e)") == 1
    assert _count(conn, "MATCH (u:User) RETURN count(u)") == 1
    assert _count(conn, "MATCH (i:IPAddress) RETURN count(i)") == 1
    assert _count(conn, "MATCH ()-[r:OBSERVED_ON]->() RETURN count(r)") == 1
    assert _count(conn, "MATCH ()-[r:AUTHENTICATED_AS]->() RETURN count(r)") == 1
    assert _count(conn, "MATCH ()-[r:SOURCE_IP]->() RETURN count(r)") == 1


# ---------------------------------------------------------------------------
# Multi-IP fan-in — every distinct source_ip lands, not just sampled rows
# ---------------------------------------------------------------------------

def test_multi_ip_rdp_brute_force_creates_one_ipaddress_per_distinct_ip(tmp_path):
    """SRL-2015 DC's RDP finding has 11+ source IPs from a fan-in
    pattern. All must land as IPAddress nodes — the previous shape
    (sample_events-only) would have missed 8+ of them."""
    ctx = _setup_case(tmp_path)
    agent = LateralMovementAnalystAgent()
    source_ips = [
        ("10.3.16.5", 55), ("10.3.58.10", 9), ("10.3.58.15", 8),
        ("10.3.58.12", 6), ("10.3.58.11", 4), ("96.255.98.154", 2),
        ("173.173.64.19", 1), ("10.3.58.13", 1),
    ]
    hit = _hit("rdp", [_ev(1149, user="Administrator")], source_ips=source_ips)
    agent._populate_graph(ctx, [hit])
    db, conn = open_graph(ctx.case_dir)
    assert _count(conn, "MATCH (i:IPAddress) RETURN count(i)") == 8
    # Every IPAddress reachable from the sampled Event via SOURCE_IP
    assert _count(conn, "MATCH (:Event)-[:SOURCE_IP]->(i:IPAddress) "
                          "RETURN count(DISTINCT i)") == 8


# ---------------------------------------------------------------------------
# User scoping — synthetic SID is host-qualified
# ---------------------------------------------------------------------------

def test_user_sid_includes_host_for_disambiguation(tmp_path):
    """Two hits on the same case with the SAME username produce
    ONE User node (host-scoped SID). Two hits across two cases
    with the same username produce two User nodes (different
    case_id → different host → different synthetic SID).
    Pin the schema so a cross-case correlator doesn't accidentally
    merge unrelated `Administrator` accounts."""
    ctx = _setup_case(tmp_path)
    agent = LateralMovementAnalystAgent()
    h1 = _hit("rdp", [_ev(1149, user="Administrator")],
               source_ips=[("10.0.0.1", 1)])
    h2 = _hit("psexec", [_ev(7045, user="Administrator")])
    agent._populate_graph(ctx, [h1, h2])
    db, conn = open_graph(ctx.case_dir)
    assert _count(conn, "MATCH (u:User) RETURN count(u)") == 1
    r = conn.execute("MATCH (u:User) RETURN u.sid, u.name, u.host")
    sid, name, host = r.get_next()
    assert sid == "acct:Administrator@srl-2015-dc-test"
    assert name == "Administrator"
    assert host == "srl-2015-dc-test"


# ---------------------------------------------------------------------------
# Defensive — empty/null user_name is dropped, not added as ghost User
# ---------------------------------------------------------------------------

def test_empty_user_name_creates_no_user_node(tmp_path):
    """EVTX rows where UserName is blank / '-' / '(null)' must NOT
    create empty-name User nodes (they'd all merge on one synthetic
    SID and look like a single ghost user). Pin the negative case."""
    ctx = _setup_case(tmp_path)
    agent = LateralMovementAnalystAgent()
    # Distinct timestamps so events don't collapse via the synthetic
    # event_id MERGE (host:technique:eid:ts) — that collapse is a
    # separate behaviour pinned in test_repeated_population_is_idempotent.
    h = _hit("service_install", [
        _ev(7045, user="",       ts="2012-04-04 17:29:33"),
        _ev(7045, user="-",      ts="2012-04-04 17:30:00"),
        _ev(7045, user="(null)", ts="2012-04-04 17:31:00"),
    ])
    agent._populate_graph(ctx, [h])
    db, conn = open_graph(ctx.case_dir)
    assert _count(conn, "MATCH (u:User) RETURN count(u)") == 0
    # Events still exist (we don't drop the event just because
    # no user is named)
    assert _count(conn, "MATCH (e:Event) RETURN count(e)") == 3


def test_empty_source_ips_does_not_create_ipaddress(tmp_path):
    """Hit with no source_ips (e.g. service_install on local
    machine) must NOT create stray IPAddress nodes."""
    ctx = _setup_case(tmp_path)
    agent = LateralMovementAnalystAgent()
    h = _hit("service_install", [_ev(7045, user="SYSTEM")])
    agent._populate_graph(ctx, [h])
    db, conn = open_graph(ctx.case_dir)
    assert _count(conn, "MATCH (i:IPAddress) RETURN count(i)") == 0
    assert _count(conn, "MATCH ()-[r:SOURCE_IP]->() RETURN count(r)") == 0


# ---------------------------------------------------------------------------
# Idempotency — running twice does not double the graph
# ---------------------------------------------------------------------------

def test_repeated_population_is_idempotent(tmp_path):
    """Re-running the agent (e.g. an `el investigate` retry) must
    not double node/edge counts — MERGE semantics keep the graph
    stable across runs."""
    ctx = _setup_case(tmp_path)
    agent = LateralMovementAnalystAgent()
    h = _hit("rdp", [_ev(1149, user="Administrator")],
             source_ips=[("10.0.0.1", 1)])
    agent._populate_graph(ctx, [h])
    agent._populate_graph(ctx, [h])  # second run
    db, conn = open_graph(ctx.case_dir)
    assert _count(conn, "MATCH (h:Host) RETURN count(h)") == 1
    assert _count(conn, "MATCH (e:Event) RETURN count(e)") == 1
    assert _count(conn, "MATCH (u:User) RETURN count(u)") == 1
    assert _count(conn, "MATCH (i:IPAddress) RETURN count(i)") == 1
    assert _count(conn, "MATCH ()-[r:OBSERVED_ON]->() RETURN count(r)") == 1


# ---------------------------------------------------------------------------
# IP-version inference (v6 vs v4)
# ---------------------------------------------------------------------------

def test_ipv6_source_ip_creates_v6_address_node(tmp_path):
    """If a source IP contains `:`, mark it as IPv6 so the
    IPAddress schema's `version` attr is correct (4/6)."""
    ctx = _setup_case(tmp_path)
    agent = LateralMovementAnalystAgent()
    h = _hit("rdp", [_ev(1149, user="Admin")],
             source_ips=[("2001:db8::1", 1)])
    agent._populate_graph(ctx, [h])
    db, conn = open_graph(ctx.case_dir)
    r = conn.execute("MATCH (i:IPAddress) RETURN i.addr, i.version")
    addr, version = r.get_next()
    assert addr == "2001:db8::1"
    assert version == 6


# ---------------------------------------------------------------------------
# graph_export sees the new edges
# ---------------------------------------------------------------------------

def test_graph_export_surfaces_new_relations(tmp_path):
    """End-to-end — the case's graph exporter (used by case.html)
    must return the new OBSERVED_ON + SOURCE_IP + AUTHENTICATED_AS
    edges so they render on the entity-graph SVG."""
    from el.reporting.graph_export import export_graph
    ctx = _setup_case(tmp_path)
    agent = LateralMovementAnalystAgent()
    h = _hit("rdp", [_ev(1149, user="Administrator")],
             source_ips=[("10.3.16.5", 55)])
    agent._populate_graph(ctx, [h])
    g = export_graph(ctx.case_dir)
    edge_types = {e["type"] for e in g["edges"]}
    assert "OBSERVED_ON" in edge_types
    assert "AUTHENTICATED_AS" in edge_types
    assert "SOURCE_IP" in edge_types
    # Node count: 1 Host + 1 Event + 1 User + 1 IP = 4
    assert g["stats"]["total_nodes"] == 4
    # 3 edges
    assert g["stats"]["total_edges"] == 3

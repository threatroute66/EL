"""Kùzu → {nodes, edges} export tests (Tier 2)."""
import json
from pathlib import Path

import pytest

from el.evidence.graph import init_graph, open_graph
from el.reporting.graph_export import export_graph


def test_export_missing_graph_returns_empty(tmp_path):
    out = export_graph(tmp_path)
    assert out["nodes"] == []
    assert out["edges"] == []
    assert out["stats"]["total_nodes"] == 0


def test_export_empty_graph_returns_empty(tmp_path):
    init_graph(tmp_path)
    out = export_graph(tmp_path)
    assert out["nodes"] == []
    assert out["edges"] == []


def _seed(case_dir: Path) -> None:
    init_graph(case_dir)
    db, conn = open_graph(case_dir)
    try:
        conn.execute("CREATE (:Host {name: 'dc01', os: 'Windows Server'})")
        conn.execute("CREATE (:Host {name: 'wkstn-01', os: 'Windows 10'})")
        conn.execute("CREATE (:IPAddress {addr: '10.0.0.5', version: 4})")
        conn.execute("CREATE (:IPAddress {addr: '203.0.113.7', version: 4})")
        conn.execute("CREATE (:Domain {name: 'evil.example.com'})")
        conn.execute(
            "CREATE (:Process {pid: 1234, ppid: 1, name: 'svchost.exe', "
            "cmdline: 'svchost -k NetworkService', host: 'wkstn-01', "
            "start_utc: ''})")
        conn.execute(
            "MATCH (d:Domain {name:'evil.example.com'}), "
            "(i:IPAddress {addr:'203.0.113.7'}) "
            "CREATE (d)-[:RESOLVED_TO]->(i)")
        conn.execute(
            "MATCH (p:Process {pid: 1234}), "
            "(i:IPAddress {addr:'203.0.113.7'}) "
            "CREATE (p)-[:CONNECTED_TO]->(i)")
    finally:
        del conn; del db


def test_export_returns_typed_nodes_and_edges(tmp_path):
    _seed(tmp_path)
    out = export_graph(tmp_path)
    types = {n["type"] for n in out["nodes"]}
    assert {"Host", "IPAddress", "Domain", "Process"}.issubset(types)
    # Every node has id + type + label
    for n in out["nodes"]:
        assert n["id"] and ":" in n["id"]
        assert n["type"]
        assert n["label"]
    edge_types = {e["type"] for e in out["edges"]}
    assert "RESOLVED_TO" in edge_types
    assert "CONNECTED_TO" in edge_types
    # Every edge references real node ids
    ids = {n["id"] for n in out["nodes"]}
    for e in out["edges"]:
        assert e["from"] in ids
        assert e["to"] in ids


def test_export_caps_at_max_nodes(tmp_path):
    init_graph(tmp_path)
    db, conn = open_graph(tmp_path)
    try:
        # Create a star: central host connected to 50 IPs
        conn.execute("CREATE (:Host {name: 'center', os: 'x'})")
        for i in range(50):
            conn.execute(f"CREATE (:IPAddress {{addr: '10.0.0.{i}', version: 4}})")
        # Need a Process to link Host→IP (via CONNECTED_TO which goes Process→IPAddress)
        conn.execute("CREATE (:Process {pid: 1, ppid: 0, name: 'p', "
                     "cmdline: '', host: 'center', start_utc: ''})")
        for i in range(50):
            conn.execute(
                f"MATCH (p:Process {{pid:1}}), (i:IPAddress {{addr:'10.0.0.{i}'}}) "
                f"CREATE (p)-[:CONNECTED_TO]->(i)")
    finally:
        del conn; del db
    out = export_graph(tmp_path, max_nodes=10)
    assert out["stats"]["capped"] is True
    assert len(out["nodes"]) == 10
    # All edges reference retained nodes
    kept = {n["id"] for n in out["nodes"]}
    for e in out["edges"]:
        assert e["from"] in kept and e["to"] in kept


def test_export_serialises_as_json(tmp_path):
    _seed(tmp_path)
    out = export_graph(tmp_path)
    s = json.dumps(out)
    parsed = json.loads(s)
    assert len(parsed["nodes"]) == len(out["nodes"])

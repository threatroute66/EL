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


def _seed_minimal(case_dir: Path, pid_name: str) -> None:
    """One Process + one IPAddress + a CONNECTED_TO edge."""
    init_graph(case_dir)
    db, conn = open_graph(case_dir)
    try:
        conn.execute(
            f"CREATE (:Process {{pid: 4444, ppid: 1, name: '{pid_name}', "
            f"cmdline: '', host: 'h', start_utc: ''}})")
        conn.execute("CREATE (:IPAddress {addr: '203.0.113.7', version: 4})")
        conn.execute(
            "MATCH (p:Process {pid: 4444}), "
            "(i:IPAddress {addr: '203.0.113.7'}) "
            "CREATE (p)-[:CONNECTED_TO]->(i)")
    finally:
        del conn; del db


def test_export_bundle_unions_device_graphs(tmp_path):
    """A bundle dir has no top-level graph.kuzu — the export must union
    the device graphs with per-device namespaced ids so identical PKs
    (same pid on two devices) stay distinct nodes."""
    _seed_minimal(tmp_path / "devices" / "memory", "from-memory.exe")
    _seed_minimal(tmp_path / "devices" / "cdrive", "from-cdrive.exe")

    out = export_graph(tmp_path)
    assert out["stats"]["devices"] == ["cdrive", "memory"]
    assert out["stats"]["total_nodes"] == 4   # 2× (Process + IPAddress)
    assert out["stats"]["total_edges"] == 2

    ids = {n["id"] for n in out["nodes"]}
    assert "memory/proc:4444" in ids
    assert "cdrive/proc:4444" in ids          # no pid collision
    by_id = {n["id"]: n for n in out["nodes"]}
    assert by_id["memory/proc:4444"]["attrs"]["device"] == "memory"
    assert by_id["memory/proc:4444"]["label"] == "from-memory.exe (4444)"

    for e in out["edges"]:
        assert e["from"].split("/", 1)[0] in ("memory", "cdrive")
        assert e["from"].split("/", 1)[0] == e["to"].split("/", 1)[0]


def test_export_bundle_prefers_top_level_graph(tmp_path):
    """When a top-level graph.kuzu DOES exist, device graphs must be
    ignored (single-case semantics unchanged)."""
    _seed(tmp_path)
    _seed_minimal(tmp_path / "devices" / "x", "ignored.exe")
    out = export_graph(tmp_path)
    assert "devices" not in out["stats"]
    assert not any(n["id"].startswith("x/") for n in out["nodes"])


def test_export_bundle_empty_devices_dir(tmp_path):
    (tmp_path / "devices").mkdir()
    out = export_graph(tmp_path)
    assert out["nodes"] == [] and out["stats"]["total_nodes"] == 0


def test_export_scrubs_control_characters(tmp_path):
    """Memory-carved strings (cmdlines, paths) carry NUL/control bytes;
    embedded raw they make case.html invalid HTML and flip grep/sed
    into binary mode (observed: 327 NULs in the Rocba bundle report)."""
    init_graph(tmp_path)
    db, conn = open_graph(tmp_path)
    try:
        conn.execute(
            "CREATE (:Process {pid: 7, ppid: 1, name: 'evil\x00.exe', "
            "cmdline: 'run\x00 -x\x01\x1f ok\ttab', host: 'h', "
            "start_utc: ''})")
    finally:
        del conn; del db
    out = export_graph(tmp_path)
    import json as _json
    blob = _json.dumps(out)
    assert "\\u0000" not in blob and "\x00" not in blob
    node = out["nodes"][0]
    assert node["attrs"]["name"] == "evil.exe"
    assert node["attrs"]["cmdline"] == "run -x ok\ttab"   # tab survives
    assert node["label"] == "evil.exe (7)"

"""Kùzu → graph JSON exporter — Tier 2 of docs/web-view-design.md.

Reads the per-case Kùzu graph (`cases/<id>/graph.kuzu/`) read-only and
materialises a `{nodes, edges}` adjacency for `case.html`'s attack-chain
visualisation. Never mutates the graph.

Output format:

  {
    "nodes": [
      {"id": "host:dc01", "type": "Host", "label": "dc01",
       "attrs": {"os": "Windows Server 2019"}},
      {"id": "ip:10.0.0.1", "type": "IPAddress", "label": "10.0.0.1",
       "attrs": {"version": 4}},
      ...
    ],
    "edges": [
      {"from": "process:1234", "to": "ip:10.0.0.1",
       "type": "CONNECTED_TO"},
      ...
    ],
    "stats": {"total_nodes": N, "total_edges": M, "capped": bool, ...}
  }

Degree-based cap so large cases (48k+ nodes on scan-and-probe pcaps)
don't blow up the browser. Default cap 500 nodes — keeps the HTML under
~3MB even for worst-case graphs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any


_NODE_TABLES: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    # (table_name, pk_field, id_prefix, attr_fields_to_export)
    ("Host",         "name",     "host",    ("os",)),
    ("User",         "sid",      "user",    ("name", "host")),
    ("Process",      "pid",      "proc",    ("name", "ppid", "host", "cmdline")),
    ("File",         "path",     "file",    ("sha256", "size", "host")),
    ("IPAddress",    "addr",     "ip",      ("version",)),
    ("Domain",       "name",     "dom",     ()),
    ("Hash",         "value",    "hash",    ("algo",)),
    ("NetworkFlow",  "flow_id",  "flow",    ("src", "dst", "dport", "proto")),
    ("Event",        "event_id", "event",   ("source", "eid", "host")),
    ("Email",        "msg_id",   "email",   ("subject", "folder",
                                              "pst_path", "sent_utc")),
)


_REL_TABLES: tuple[tuple[str, str, str], ...] = (
    # (table, from_table, to_table)
    ("EXECUTED",           "User",         "Process"),
    ("CHILD_OF",           "Process",      "Process"),
    ("WROTE",              "Process",      "File"),
    ("LOADED",             "Process",      "File"),
    ("HASHES_TO",          "File",         "Hash"),
    ("WROTE_KEY",          "Process",      "RegistryKey"),
    ("RESOLVED_TO",        "Domain",       "IPAddress"),
    ("CONNECTED_TO",       "Process",      "IPAddress"),
    ("FLOW_SRC",           "NetworkFlow",  "IPAddress"),
    ("FLOW_DST",           "NetworkFlow",  "IPAddress"),
    ("AUTHENTICATED_AS",   "Event",        "User"),
    ("RAISED_BY",          "Event",        "Process"),
    ("RUNS_ON",            "Process",      "Host"),
    ("SENT_FROM",          "Email",        "User"),
    ("SENT_TO",            "Email",        "User"),
    ("HAS_ATTACHMENT",     "Email",        "File"),
    ("EMAILS_ON_DOMAIN",   "User",         "Domain"),
)


_TABLE_ID_PREFIX = {tbl: pre for tbl, _pk, pre, _a in _NODE_TABLES}
_TABLE_PK = {tbl: pk for tbl, pk, _pre, _a in _NODE_TABLES}


def _node_id(table: str, pk_value: Any) -> str:
    return f"{_TABLE_ID_PREFIX.get(table, table.lower())}:{pk_value}"


def _label_for(table: str, attrs: dict, pk_value: Any) -> str:
    # Short, human-readable label. Falls back to pk_value.
    if table == "Process":
        n = attrs.get("name") or ""
        return f"{n} ({pk_value})" if n else str(pk_value)
    if table == "User":
        return str(attrs.get("name") or pk_value)
    if table == "File":
        p = str(pk_value)
        return p.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or p
    if table == "NetworkFlow":
        return f"{attrs.get('src','?')}→{attrs.get('dst','?')}:{attrs.get('dport','?')}"
    if table == "Event":
        return f"EID {attrs.get('eid','?')}"
    return str(pk_value)


def export_graph(case_dir: str | Path, max_nodes: int = 500) -> dict:
    """Read the case's Kùzu graph and return {nodes, edges, stats}.

    Falls back to an empty graph if Kùzu is unavailable, the case's
    graph.kuzu dir is missing, or the graph has no nodes (common on
    fresh/mobile cases where the investigator agents haven't populated
    the graph yet)."""
    case_dir = Path(case_dir)
    gp = case_dir / "graph.kuzu"
    stats: dict[str, Any] = {"total_nodes": 0, "total_edges": 0,
                              "capped": False, "max_nodes": max_nodes}
    if not gp.exists():
        return {"nodes": [], "edges": [], "stats": stats}

    try:
        import kuzu
    except Exception:
        return {"nodes": [], "edges": [], "stats":
                {**stats, "error": "kuzu unavailable"}}

    try:
        db = kuzu.Database(str(gp), read_only=True)
    except TypeError:
        db = kuzu.Database(str(gp))
    conn = kuzu.Connection(db)

    nodes: dict[str, dict] = {}   # id → {id, type, label, attrs}
    for table, pk_field, prefix, attr_fields in _NODE_TABLES:
        fields = (pk_field,) + attr_fields
        proj = ", ".join(f"n.{f} AS {f}" for f in fields)
        try:
            res = conn.execute(f"MATCH (n:{table}) RETURN {proj}")
        except Exception:
            continue
        while res.has_next():
            row = res.get_next()
            rec = dict(zip(fields, row))
            pkv = rec.get(pk_field)
            if pkv is None:
                continue
            nid = _node_id(table, pkv)
            attrs = {k: v for k, v in rec.items() if k != pk_field and v is not None}
            nodes[nid] = {
                "id": nid, "type": table,
                "label": _label_for(table, attrs, pkv),
                "attrs": attrs,
            }

    stats["total_nodes"] = len(nodes)

    edges: list[dict] = []
    for rel_table, from_table, to_table in _REL_TABLES:
        from_pk = _TABLE_PK.get(from_table)
        to_pk = _TABLE_PK.get(to_table)
        if not (from_pk and to_pk):
            continue
        try:
            res = conn.execute(
                f"MATCH (a:{from_table})-[r:{rel_table}]->(b:{to_table}) "
                f"RETURN a.{from_pk} AS fpk, b.{to_pk} AS tpk"
            )
        except Exception:
            continue
        while res.has_next():
            fpk, tpk = res.get_next()
            if fpk is None or tpk is None:
                continue
            edges.append({
                "from": _node_id(from_table, fpk),
                "to": _node_id(to_table, tpk),
                "type": rel_table,
            })
    stats["total_edges"] = len(edges)

    # Cap by degree — keep the top-max_nodes most-connected nodes
    if len(nodes) > max_nodes:
        degree: dict[str, int] = {}
        for e in edges:
            degree[e["from"]] = degree.get(e["from"], 0) + 1
            degree[e["to"]] = degree.get(e["to"], 0) + 1
        ranked = sorted(nodes.keys(),
                         key=lambda n: (-degree.get(n, 0), n))
        keep = set(ranked[:max_nodes])
        nodes = {k: v for k, v in nodes.items() if k in keep}
        edges = [e for e in edges if e["from"] in keep and e["to"] in keep]
        stats["capped"] = True
        stats["shown_nodes"] = len(nodes)
        stats["shown_edges"] = len(edges)

    return {"nodes": list(nodes.values()), "edges": edges, "stats": stats}


__all__ = ["export_graph"]

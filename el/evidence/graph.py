from __future__ import annotations

from pathlib import Path

import kuzu


NODE_DDL = [
    "CREATE NODE TABLE IF NOT EXISTS Host(name STRING, os STRING, PRIMARY KEY(name))",
    "CREATE NODE TABLE IF NOT EXISTS User(sid STRING, name STRING, host STRING, PRIMARY KEY(sid))",
    "CREATE NODE TABLE IF NOT EXISTS Process(pid INT64, ppid INT64, name STRING, cmdline STRING, host STRING, start_utc STRING, PRIMARY KEY(pid))",
    "CREATE NODE TABLE IF NOT EXISTS File(path STRING, sha256 STRING, size INT64, host STRING, PRIMARY KEY(path))",
    "CREATE NODE TABLE IF NOT EXISTS RegistryKey(path STRING, hive STRING, host STRING, last_write_utc STRING, PRIMARY KEY(path))",
    "CREATE NODE TABLE IF NOT EXISTS IPAddress(addr STRING, version INT64, PRIMARY KEY(addr))",
    "CREATE NODE TABLE IF NOT EXISTS Domain(name STRING, PRIMARY KEY(name))",
    "CREATE NODE TABLE IF NOT EXISTS Hash(value STRING, algo STRING, PRIMARY KEY(value))",
    "CREATE NODE TABLE IF NOT EXISTS NetworkFlow(flow_id STRING, src STRING, dst STRING, sport INT64, dport INT64, proto STRING, bytes INT64, start_utc STRING, PRIMARY KEY(flow_id))",
    "CREATE NODE TABLE IF NOT EXISTS Event(event_id STRING, source STRING, channel STRING, eid INT64, ts_utc STRING, host STRING, PRIMARY KEY(event_id))",
    "CREATE NODE TABLE IF NOT EXISTS Email(msg_id STRING, subject STRING, folder STRING, pst_path STRING, sent_utc STRING, has_attachments INT64, PRIMARY KEY(msg_id))",
]

REL_DDL = [
    "CREATE REL TABLE IF NOT EXISTS EXECUTED(FROM User TO Process)",
    "CREATE REL TABLE IF NOT EXISTS CHILD_OF(FROM Process TO Process)",
    "CREATE REL TABLE IF NOT EXISTS WROTE(FROM Process TO File)",
    "CREATE REL TABLE IF NOT EXISTS LOADED(FROM Process TO File)",
    "CREATE REL TABLE IF NOT EXISTS HASHES_TO(FROM File TO Hash)",
    "CREATE REL TABLE IF NOT EXISTS WROTE_KEY(FROM Process TO RegistryKey)",
    "CREATE REL TABLE IF NOT EXISTS RESOLVED_TO(FROM Domain TO IPAddress)",
    "CREATE REL TABLE IF NOT EXISTS CONNECTED_TO(FROM Process TO IPAddress)",
    "CREATE REL TABLE IF NOT EXISTS FLOW_SRC(FROM NetworkFlow TO IPAddress)",
    "CREATE REL TABLE IF NOT EXISTS FLOW_DST(FROM NetworkFlow TO IPAddress)",
    "CREATE REL TABLE IF NOT EXISTS AUTHENTICATED_AS(FROM Event TO User)",
    "CREATE REL TABLE IF NOT EXISTS RAISED_BY(FROM Event TO Process)",
    "CREATE REL TABLE IF NOT EXISTS RUNS_ON(FROM Process TO Host)",
    # Event provenance — every observed event lives on a host
    # (lateral_movement_analyst writes one per finding). Without
    # this rel Events floated as disconnected dots on case.html#graph.
    "CREATE REL TABLE IF NOT EXISTS OBSERVED_ON(FROM Event TO Host)",
    # Source IP for inbound events (RDP 4624 Type 10, EID 1149,
    # SMB share-mount, etc.). Lets the graph show "attacker IP →
    # event → host" without inventing synthetic Process / Flow nodes.
    "CREATE REL TABLE IF NOT EXISTS SOURCE_IP(FROM Event TO IPAddress)",
    # Email case correlation — sender/recipient Users, attached Files,
    # sender-domain Domain. Populated by EmailForensicatorAgent.
    "CREATE REL TABLE IF NOT EXISTS SENT_FROM(FROM Email TO User)",
    "CREATE REL TABLE IF NOT EXISTS SENT_TO(FROM Email TO User)",
    "CREATE REL TABLE IF NOT EXISTS HAS_ATTACHMENT(FROM Email TO File)",
    "CREATE REL TABLE IF NOT EXISTS EMAILS_ON_DOMAIN(FROM User TO Domain)",
]


def graph_path(case_dir: str | Path) -> Path:
    return Path(case_dir) / "graph.kuzu"


def init_graph(case_dir: str | Path) -> Path:
    """Create (or open) the per-case Kùzu graph and apply the Locard schema."""
    p = graph_path(case_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    db = kuzu.Database(str(p))
    conn = kuzu.Connection(db)
    for ddl in NODE_DDL + REL_DDL:
        conn.execute(ddl)
    return p


def open_graph(case_dir: str | Path) -> tuple[kuzu.Database, kuzu.Connection]:
    p = graph_path(case_dir)
    if not p.exists():
        init_graph(case_dir)
    db = kuzu.Database(str(p))
    return db, kuzu.Connection(db)

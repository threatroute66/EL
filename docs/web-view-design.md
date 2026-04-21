# EL Case Web View — Design Note

_Planning document. Nothing implemented yet._

## Goal

Add a single-page web view per case that gives an analyst the full
picture at a glance: timeline, host-to-host attack graph, per-
finding detail drill-down, ATT&CK map, IOC catalog. Reference
design — **Horizon3 NodeZero attack-path UI**
(see `/mnt/hgfs/hackathon/nodezero.png`): horizontal host timeline
at the top, clicked node opens a detail panel on the right with
severity + description + mitigations + "View Full Details" link,
bottom-left shows timestamped evidence cards with raw command
output. EL keeps the same layout but surfaces its Findings + ACH
+ Kùzu graph rather than CVEs.

## What we already have per case (no new data required)

EL's per-case workspace already contains everything a web view needs
— it's just not rendered visually today.

| File | Holds |
|---|---|
| `findings.sqlite` | Every Finding (agent, claim, confidence, evidence items w/ sha256 + command, hypotheses supported/refuted, ATT&CK techniques in `extracted_facts`, red-review verdict, created_utc) |
| `reports/findings.json` | Same data, already exported to JSON by `el report` |
| `iocs.json` | IOC catalog by type (ipv4/ipv6/domain/url/md5/sha1/sha256/email) |
| `ach_matrix.json` | Hypothesis × finding score matrix |
| `reports/stix-bundle.json` | STIX 2.1 bundle (Indicators, AttackPatterns, Report) |
| `graph.kuzu/` | Kùzu entity graph (Host, User, Process, File, IPAddress, Domain, Hash, NetworkFlow, Event nodes; EXECUTED / WROTE / CONNECTED_TO / CHILD_OF / RESOLVED_TO / AUTHENTICATED_AS edges) |
| `transitions.json` | Coordinator state-machine trace |
| `analysis/forensic_audit.log` | Append-only event log |
| `seal.json` | SHA-256 manifest + merkle root |

**One new data step** is needed: export the Kùzu graph to a JSON
adjacency format the web view can consume. All other data is
already export-ready.

## Proposed architecture

### Zero-server static HTML

Open `reports/case.html` directly in a browser. Everything loads via
`fetch('./findings.json')` etc. from sibling files. No Python web
server, no build step. Works offline, works inside a sealed tar.gz
archive. Matches EL's "no LLM at runtime" ethos — the web view is a
deterministic projection of sealed data, the same philosophy as the
Markdown report.

### File layout

```
cases/<case_id>/reports/
├── case.html            ← new; rendered by `el report`
├── case.css             ← new; ~200 lines, dark theme like NodeZero
├── case.js              ← new; vanilla JS + one viz library
├── findings.json        ← already produced
├── ach_matrix.json      ← already produced
├── graph.json           ← NEW: Kùzu → node+edge export
├── iocs.json            ← already produced
└── stix-bundle.json     ← already produced
```

### Dependency budget

One viz library, vendored into the case dir so the report stays
self-contained:

- **[vis-network](https://visjs.org/)** (~500 KB min.js, Apache-2.0)
  for the attack-chain graph. Handles force-directed layout +
  click-to-highlight + edge labels out of the box.
- **No framework.** Vanilla JS + `fetch` + `DOMParser`. Page-level
  state lives in a plain object; detail panel renders from it.

Alternative: **cytoscape.js** (~400 KB, MIT) — broader DFIR adoption
(Neo4j's NEuler uses it). Either is fine; decide at implementation
time from real-case graph sizes.

## Layout (NodeZero-style)

```
┌─────────────────────────────────────────────────────────────────┐
│ EL · case-id · Leading: H_APT_ESPIONAGE (30, gap +12)           │
│ [ Timeline ][ Graph ][ ACH Matrix ][ IOCs ][ ATT&CK ]            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│    ● ────────── ● ────────── ● ────────── ● ─────────── ●      │
│  dmz-ftp   base-admin   base-rd-01  base-sp    base-mail        │
│                                                                  │
│          ┌──────────────────────────────┐                        │
│          │  base-rd-01  (H_APT 20)      │                        │
│          │                              │                        │
│          │  14× beacon to .4.10:8080    │                        │
│          │  csrss from \\.4.6\C$\...    │                        │
│          │  4 hidden processes          │                        │
│          │                              │                        │
│          │  [View Full Details]  ←───── │  per-finding drill-in │
│          └──────────────────────────────┘                        │
│                                                                  │
├──────────────────────────────────────┬──────────────────────────┤
│  TIMELINE                            │  DETAIL                   │
│  2018-08-04 15:53 scheduled-task     │  Finding 01KPMZC32QYA…    │
│  2018-08-15 16:32 ps_remoting        │  agent: lateral_movement  │
│  2018-09-07 18:08 rc4-kerberoasting  │  confidence: high         │
│  …                                   │  claim: Inbound RDP …     │
│                                      │  evidence[0]:             │
│                                      │    tool: el.evtx_triage   │
│                                      │    sha256: …               │
│                                      │    attack: T1021.001      │
│                                      │  supports:                │
│                                      │    H_LATERAL_MOVEMENT +3  │
│                                      │    H_APT_ESPIONAGE +4     │
│                                      │  red_review: passed       │
└──────────────────────────────────────┴──────────────────────────┘
```

Every finding is addressable by its ULID — deep-linkable as
`case.html#01KPMZC32QYA976TVHC026F5K0` — so the markdown report,
STIX bundle, and web view all cite the same canonical ID.

## Implementation tiers

Scoped so each tier ships independently.

### Tier 1 — Static render (no graph)

Minimum viable surface. Delivers the biggest usability win per unit
of effort.

- New `el report --html` flag on the existing `el report` command
- New `el/reporting/html.py` renders `case.html` from the same data
  the Markdown report consumes
- Sections: Executive summary, ACH ranking (as NodeZero-style
  horizontal timeline), findings grid filterable by
  agent/confidence, detail drawer on click, IOC table
- No graph visualisation (deferred to Tier 2)
- Self-contained: vendored CSS + JS (no CDN)

**Effort:** ~1 week. No new pip deps (uses stdlib `html`,
`json`). Ships as a single ~600-line Python module + ~400 lines of
HTML/CSS/JS template files.

### Tier 2 — Attack-chain graph

The NodeZero-shaped visual: hosts as nodes, attacker pivots as
edges, severity colour-coded by ACH-lifting finding count per host.

- New Kùzu → graph JSON exporter in `el/reporting/graph_export.py`
  — run read-only Cypher over `graph.kuzu`, materialise as
  `{nodes: [...], edges: [...]}`
- Vendor vis-network (or cytoscape.js) into `reports/assets/`
- Extend `case.html` with a graph pane; click-to-select syncs with
  the existing detail drawer

**Effort:** ~1-2 weeks. Depends on Tier 1.

### Tier 3 — ATT&CK heatmap + Diamond Model view

- ATT&CK technique coverage grid (14 tactics × ~12 techniques each)
  with per-technique finding counts, leveraging `el.intel.attack_map`
- Diamond Model visualisation: four vertices (Adversary / Capability
  / Infrastructure / Victim) linked to the findings that populate each

**Effort:** ~1 week.

### Tier 4 — Live update mode (optional)

An `el report --html --watch <case>` that re-renders on every
Finding insert. Useful during an ongoing investigation. Needs a
small file watcher on `findings.sqlite`'s mtime; browser does a
periodic fetch. Static-served (no websockets).

**Effort:** ~2 days.

## Integration points with existing code

- **CLI** — add `--html` flag to `el report`; keep Markdown as default
- **Reporting module** — new file next to `render.py`, `stix.py`,
  `ach_matrix.py`, `diamond.py`
- **Kùzu export** — query graph read-only; never mutates. Caches to
  `graph.json` sibling so repeat renders are cheap
- **Sealing** — when coordinator DONE seals the case, the HTML
  bundle gets hashed into the manifest alongside the other report
  files; `el seal-verify` catches drift
- **Knowledge layer** — unchanged. Cross-case overlap findings
  already show up as findings; they render the same as every other
  finding

## Out of scope

- **Live analyst collaboration** (multi-user edit, comments) —
  requires a server; keep EL single-operator
- **PDF export** — browser can print to PDF; no need to ship a
  headless-chrome pipeline ourselves
- **External CDN loads** — every dependency must vendor into the case
  dir so the report works inside a sealed air-gapped archive
- **Custom analyst notes** — any free-text annotation breaks the "no
  LLM at runtime" guarantee and the "every claim ships with the tool
  + version + sha256" contract. Notes live in `CLAUDE.md` as a
  follow-up consideration

## Next step

When ready, start with Tier 1. It's the smallest unit of value that
ships independently — a case you could hand to a non-DFIR stakeholder
(legal, exec) and have them navigate without needing to know
Markdown or grep a SQLite file.

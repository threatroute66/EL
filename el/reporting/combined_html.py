"""Combined multi-host HTML dashboard — Tier 3 of web-view-design.

Stitches N per-case ledgers into one self-contained `combined.html`
with the four cross-host views the analyst actually needs:

  1. Combined narrative — cross-host prose prefix + per-case
     Executive Narrative blocks stitched in leading-hypothesis order.
  2. Joint ACH matrix — cases × hypotheses heatmap (shows which
     hypotheses dominate across the scenario).
  3. Unified event timeline — swim-lane SVG, one lane per case,
     all findings plotted on a shared time axis.
  4. Cross-host graph — merged Kùzu graphs with host-origin colouring.

Also kept: cross-host signal matrix, unified ATT&CK heatmap, IOC
overlap, links to each host's own case.html for drill-down.

Design constraints (same as single-case html.py):
  - One self-contained HTML file. No CDN, no build step, no framework.
  - SVG for graph + timeline. Plain CSS / vanilla JS.
  - Opens via file:// from inside a sealed tar.gz.
  - Deterministic projection — no LLM.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from el.reporting.combined import (
    CaseSlice, load_case, _signal_matrix, _technique_union,
    _ioc_overlap, _SIGNAL_ROWS,
)
from el.reporting.graph_export import export_graph


_CSS = """
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont,
    "Segoe UI", system-ui, sans-serif; }
body { background: #0d1117; color: #c9d1d9; line-height: 1.5; }
/* Single sticky region wrapping topbar + subnav so they stack
   naturally without brittle pixel offsets — the previous shape
   (two separate stickies, subnav at `top: 57px`) silently slid
   the subnav under the topbar by ~17px on layouts where the
   topbar's meta-line wrapped or rendered taller than 57px,
   clipping the tops of every nav label. Wrapping both into one
   `<div class="stickyhdr">` makes the sticky height self-
   adjust to whatever the content needs. */
.stickyhdr { position: sticky; top: 0; z-index: 20;
    background: #161b22; border-bottom: 1px solid #30363d; }
header.topbar { padding: 12px 24px 4px; }
header.topbar h1 { margin: 0; font-size: 18px; font-weight: 600; color: #f0f6fc; }
header.topbar h1 .badge { background: #58a6ff; color: #0d1117; padding: 2px 8px;
    border-radius: 10px; font-size: 12px; font-weight: 600; margin-left: 10px; }
header.topbar .meta { margin-top: 4px; font-size: 12px; color: #8b949e; }
/* Same visual language as the per-case nav (header.topbar nav in
   el/reporting/html.py): blue chip-pill links with a subtle grey
   hover background, single-row flex with overflow-x for long
   menus. Combined nav has 9 items today and could grow as more
   cross-host panels land, so the overflow safety net matters. */
nav.subnav { padding: 6px 24px 8px; display: flex; flex-wrap: nowrap;
    gap: 4px; overflow-x: auto; scrollbar-width: thin; }
nav.subnav a { color: #58a6ff; text-decoration: none;
    font-size: 12px; font-weight: 500; padding: 3px 7px;
    border-radius: 5px; white-space: nowrap; flex-shrink: 0; }
nav.subnav a:hover { background: #21262d; text-decoration: none; }
/* scroll-padding-top is updated dynamically from the rendered
   sticky height (see the small inline script at the page bottom)
   so anchor jumps land below the entire sticky region regardless
   of viewport / content shape. The static fallback keeps anchors
   working even if JS is disabled. */
html { scroll-padding-top: 130px; }
main { padding: 24px; max-width: 1800px; margin: 0 auto; }
section { margin-bottom: 40px; }
section h2 { color: #f0f6fc; font-size: 20px; font-weight: 600;
    border-bottom: 1px solid #30363d; padding-bottom: 8px; margin: 0 0 16px; }
section h3 { color: #f0f6fc; font-size: 16px; margin: 20px 0 8px; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
a.pdf-download {
    display: inline-flex; align-items: center; gap: 4px;
    margin-left: 10px; padding: 2px 8px; border-radius: 5px;
    background: #1f6feb22; color: #79c0ff;
    border: 1px solid #1f6feb55; font-size: 11px; font-weight: 500;
    text-decoration: none; }
a.pdf-download:hover {
    background: #1f6feb44; color: #ffffff; text-decoration: none; }
a.pdf-download svg { display: block; }
code, pre, .mono { font-family: "SF Mono", Menlo, Consolas, monospace;
    font-size: 12px; color: #8b949e; }
.grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    padding: 16px; }
.card .num { font-size: 28px; font-weight: 700; color: #58a6ff; }
.card .lbl { font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
table th, table td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #21262d; }
table th { color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 11px;
    letter-spacing: 0.5px; background: #0d1117; position: sticky; top: 0; }
table td.num { text-align: right; font-variant-numeric: tabular-nums; }

/* Joint ACH matrix heatmap */
.ach-matrix { overflow-x: auto; }
.ach-matrix table { min-width: 100%; }
.ach-matrix th.case, .ach-matrix td.case { text-align: left; color: #c9d1d9; }
.ach-matrix td.score { text-align: center; font-variant-numeric: tabular-nums;
    font-weight: 600; font-size: 12px; min-width: 50px; }
.ach-matrix td.score.s0 { color: #484f58; }
.ach-matrix td.score.s1 { background: rgba(56, 139, 253, 0.10); color: #58a6ff; }
.ach-matrix td.score.s2 { background: rgba(56, 139, 253, 0.25); color: #79c0ff; }
.ach-matrix td.score.s3 { background: rgba(210, 153, 34, 0.35); color: #f2cc60; }
.ach-matrix td.score.s4 { background: rgba(248, 81, 73, 0.45); color: #ffa198; }
.ach-matrix td.score.s5 { background: rgba(248, 81, 73, 0.70); color: #ffffff; }

/* Clock baselines — per-host TZ / sync / skew calibration table */
.clock-baseline table { min-width: 100%; border-collapse: collapse;
    font-size: 13px; }
.clock-baseline th { color: #c9d1d9; text-align: left; padding: 6px 10px;
    background: #161b22; border-bottom: 1px solid #30363d; font-weight: 600;
    font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
.clock-baseline td { padding: 8px 10px; border-bottom: 1px solid #21262d;
    color: #c9d1d9; font-variant-numeric: tabular-nums; }
.clock-baseline tr:hover td { background: rgba(56, 139, 253, 0.06); }
.clock-baseline .tz, .clock-baseline .ntp { font-family: "SF Mono",
    Consolas, monospace; font-size: 12px; }
.clock-baseline .skew-zero { color: #3fb950; }
.clock-baseline .skew-warn { color: #f2cc60; font-weight: 600; }
.clock-baseline .sync-trust { color: #3fb950; }
.clock-baseline .sync-warn { color: #f85149; font-weight: 600; }
.clock-baseline .sync-unknown { color: #8b949e; }
.clock-baseline .missing { color: #484f58; font-style: italic; }
.clock-alerts { margin: 12px 0 8px 0; display: flex; flex-wrap: wrap;
    gap: 8px; }
.clock-alert { display: inline-block; padding: 4px 10px; border-radius: 4px;
    font-size: 12px; border: 1px solid; }
.clock-alert.warn { color: #f2cc60; border-color: rgba(210, 153, 34, 0.5);
    background: rgba(210, 153, 34, 0.08); }
.clock-alert.bad { color: #f85149; border-color: rgba(248, 81, 73, 0.5);
    background: rgba(248, 81, 73, 0.08); }
.clock-alert.ok { color: #3fb950; border-color: rgba(63, 185, 80, 0.4);
    background: rgba(63, 185, 80, 0.08); }

/* Signal matrix */
.sig-matrix table { min-width: 100%; }
/* Rotate the header LABEL (inner span), not the cell — keeps the
   rotated text horizontally centered within its column, so the dots
   in data rows below line up with the host name above. Rotating the
   <th> itself with `writing-mode: vertical-rl + rotate(180deg)`
   pushed the visible text to the right edge of the cell, leaving
   the dots ~25px left of where each header appeared. */
.sig-matrix th.case { height: 120px; vertical-align: bottom; padding: 6px 4px;
    text-align: center; color: #c9d1d9; text-transform: none;
    letter-spacing: 0; font-size: 12px; font-weight: 500;
    white-space: nowrap; }
.sig-matrix th.case span { display: inline-block;
    writing-mode: vertical-rl; transform: rotate(180deg); }
.sig-matrix td.dot { text-align: center; font-size: 14px; color: #3fb950; }
.sig-matrix td.signame { color: #c9d1d9; font-weight: 500; }

/* Timeline swim-lane */
.tl-toggle { background: #161b22; border: 1px solid #30363d; color: #c9d1d9;
    padding: 6px 12px; border-radius: 4px; font-size: 12px; cursor: pointer;
    margin-right: 6px; }
.tl-toggle:hover { border-color: #58a6ff; color: #58a6ff; }
.tl-toggle.active { background: #58a6ff; color: #0d1117; border-color: #58a6ff;
    font-weight: 600; }
#timeline-svg { width: 100%; height: 360px; background: #0d1117;
    border: 1px solid #21262d; border-radius: 6px; display: block; }
.tl-lane-label { fill: #8b949e; font-size: 11px; font-family: "SF Mono", monospace; }
.tl-event { cursor: pointer; }
.tl-event:hover { stroke: #f0f6fc; stroke-width: 2px; }
.tl-axis-text { fill: #8b949e; font-size: 10px; }
.tl-grid { stroke: #21262d; stroke-width: 1px; }

/* Graph pane */
#graph-pane { background: #0d1117; border: 1px solid #21262d; border-radius: 6px;
    height: 560px; position: relative; overflow: hidden; }
#graph-svg { width: 100%; height: 100%; display: block; }
.graph-legend { position: absolute; top: 10px; right: 10px; background: rgba(22,27,34,0.92);
    padding: 10px; border-radius: 4px; font-size: 11px; border: 1px solid #30363d; }
.graph-legend .sw { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
    margin-right: 6px; vertical-align: middle; }
.node-circle { cursor: pointer; }
.node-circle:hover { stroke: #f0f6fc; stroke-width: 2px; }
.node-shared { cursor: pointer; }
.node-shared:hover { stroke: #f0f6fc; stroke-width: 2px; }
.node-anchor { cursor: pointer; }
.node-anchor:hover { stroke: #f0f6fc; stroke-width: 3px; }
.node-anchor-label { fill: #c9d1d9; font-size: 11px; font-weight: 600;
    paint-order: stroke; stroke: #0d1117; stroke-width: 3px; }
.node-shared-label { fill: #f0f6fc; font-size: 10px; font-family: "SF Mono", monospace;
    paint-order: stroke; stroke: #0d1117; stroke-width: 3px; }
.edge-line { stroke: #30363d; stroke-opacity: 0.5; }
.edge-line:hover { stroke: #58a6ff; stroke-opacity: 1; }
.edge-line.bridge { stroke: #f0883e; stroke-opacity: 0.6;
    stroke-dasharray: 4 3; stroke-width: 1.2px; }
.edge-line.bridge:hover { stroke-opacity: 1; stroke-width: 2px; }

/* ATT&CK heatmap — reuse simple table */
.attack-grid td { padding: 4px 8px; }
.attack-grid td.tid { color: #79c0ff; font-family: "SF Mono", monospace; }
.attack-grid td.bar { width: 40%; }
.attack-grid .bar-inner { height: 10px; background: linear-gradient(90deg, #2ea043, #f0883e, #f85149);
    border-radius: 2px; }
/* ATT&CK row click-to-expand */
.attack-grid tr.att-row { cursor: pointer; }
.attack-grid tr.att-row:hover { background: #161b22; }
.attack-grid td.att-toggle { width: 1.5em; color: #8b949e; user-select: none;
    font-family: "SF Mono", monospace; }
.attack-grid tr.att-details > td { background: #0d1117; padding: 12px 16px; }
.attack-grid table.att-sub { width: 100%; border-collapse: collapse;
    font-size: 12px; }
.attack-grid table.att-sub th { color: #8b949e; text-align: left;
    padding: 4px 6px; border-bottom: 1px solid #30363d; }
.attack-grid table.att-sub td { padding: 3px 6px; vertical-align: top;
    border-bottom: 1px solid #21262d; }
.attack-grid table.att-sub td.att-host { color: #79c0ff; white-space: nowrap; }
.attack-grid table.att-sub td.att-agent { color: #c9d1d9; font-family: "SF Mono", monospace; }
.attack-grid table.att-sub td.att-claim { color: #c9d1d9; max-width: 60ch; }
.attack-grid table.att-sub td.att-fid a { color: #79c0ff; font-family: "SF Mono", monospace; }
.attack-grid table.att-sub td.conf-high    { color: #f85149; font-weight: 600; }
.attack-grid table.att-sub td.conf-medium  { color: #d29922; }
.attack-grid table.att-sub td.conf-low     { color: #58a6ff; }
.attack-grid table.att-sub td.conf-insufficient { color: #8b949e; font-style: italic; }

/* Finding drawer — slides in from the right on timeline / ATT&CK click */
#drawer { position: fixed; top: 0; right: 0; height: 100vh; width: 520px;
    background: #161b22; border-left: 1px solid #30363d; z-index: 200;
    transform: translateX(540px); transition: transform 0.18s ease-out;
    box-shadow: -4px 0 16px rgba(0,0,0,0.6);
    display: flex; flex-direction: column; overflow: hidden; }
#drawer.open { transform: translateX(0); }
#drawer .drawer-head { display: flex; align-items: flex-start;
    justify-content: space-between; padding: 14px 18px;
    border-bottom: 1px solid #30363d; gap: 12px; }
#drawer .drawer-title { font-weight: 600; color: #f0f6fc; font-size: 14px;
    line-height: 1.4; }
#drawer .drawer-close { background: transparent; border: none;
    color: #8b949e; font-size: 22px; cursor: pointer; padding: 0 4px; }
#drawer .drawer-close:hover { color: #f0f6fc; }
#drawer .drawer-body { padding: 14px 18px; overflow-y: auto; flex: 1;
    font-size: 13px; color: #c9d1d9; }
#drawer .drawer-row { margin-bottom: 8px; }
#drawer .drawer-row b { color: #8b949e; font-weight: 500; margin-right: 6px; }
#drawer .drawer-row code { color: #79c0ff; font-size: 12px; }
#drawer .drawer-row .muted { color: #6e7681; font-style: italic; }
#drawer .drawer-claim { background: #0d1117; border-left: 3px solid #58a6ff;
    padding: 10px 12px; margin: 12px 0; line-height: 1.5;
    white-space: pre-wrap; word-break: break-word; }
#drawer table.drawer-ev { width: 100%; border-collapse: collapse;
    font-size: 11px; margin-top: 6px; }
#drawer table.drawer-ev th { color: #8b949e; text-align: left;
    padding: 3px 6px; border-bottom: 1px solid #30363d; font-weight: 500; }
#drawer table.drawer-ev td { padding: 3px 6px; vertical-align: top;
    border-bottom: 1px solid #21262d; word-break: break-all; }
#drawer table.drawer-ev code { color: #c9d1d9; font-size: 11px; }

/* Narrative block */
.narrative { background: #161b22; border-left: 3px solid #58a6ff;
    padding: 16px 20px; border-radius: 0 6px 6px 0; }
.narrative h3 { margin-top: 0; }
.narrative p { color: #c9d1d9; }
.narrative .case-nar { margin-bottom: 16px; padding-bottom: 12px;
    border-bottom: 1px dashed #30363d; }
.narrative .case-nar:last-child { border: none; }
.narrative .case-nar-hdr { font-weight: 600; color: #79c0ff; margin-bottom: 6px; }

/* Tooltip for timeline hover */
.tt { position: fixed; background: #161b22; border: 1px solid #58a6ff;
    padding: 8px 10px; border-radius: 4px; font-size: 12px; color: #c9d1d9;
    pointer-events: none; z-index: 100; box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    max-width: 440px; }
"""


# ---------------------------------------------------------------------------
# Data wrangling for the views
# ---------------------------------------------------------------------------

_ALL_HYPOTHESES = [
    # Order matches el/intel/hypotheses.py HYPOTHESES list
    "H_BENIGN_NO_INCIDENT", "H_OPPORTUNISTIC_COMMODITY", "H_RANSOMWARE",
    "H_APT_ESPIONAGE", "H_INSIDER_DATA_EXFIL", "H_INSIDER_EMAIL_EXFIL",
    "H_SUPPLY_CHAIN", "H_BEC_ACCOUNT_TAKEOVER", "H_C2_BEACONING",
    "H_SCAN_RECON", "H_BRUTE_FORCE", "H_CLOUD_PERSISTENCE",
    "H_CREDENTIAL_ACCESS", "H_LATERAL_MOVEMENT",
    "H_PERSISTENCE_SCHEDULED_TASK", "H_PERSISTENCE_SERVICE",
]


def _joint_ach(cases: list[CaseSlice]) -> dict:
    """Return {hyp_id: {case_id: score}} for rendering the heatmap."""
    out: dict[str, dict[str, int]] = {}
    # Bootstrap from known hypothesis list so rows stay stable
    known = set(_ALL_HYPOTHESES)
    # Also collect any case-level hypothesis not in the known list
    for c in cases:
        for r in c.ach_ranking:
            known.add(r.get("hyp_id"))
    for h in known:
        out[h] = {}
    for c in cases:
        by_hid = {r.get("hyp_id"): int(r.get("score", 0))
                  for r in c.ach_ranking}
        for h in known:
            out[h][c.case_id] = by_hid.get(h, 0)
    # Drop rows where every case scored 0 (keeps matrix tight)
    return {h: row for h, row in out.items()
            if any(v != 0 for v in row.values())}


def _timeline_events(cases: list[CaseSlice],
                      mode: str = "findings") -> list[dict]:
    """Flatten all findings into one event stream, one lane per case.

    Two modes:
      - "findings" (default): uses `evidence_time` — the real artifact
        timestamp embedded in the finding's evidence. This is the
        attacker's clock, not EL's. Only findings that carry an
        extractable artifact timestamp appear; insufficient findings
        are excluded.
      - "processing": uses `created_utc` — when EL emitted the finding
        (the forensic-process timeline). Every timestamped finding
        appears regardless of whether the evidence carries a real
        event time.
    """
    events = []
    for c in cases:
        for f in c.findings:
            if mode == "findings":
                ts = f.get("evidence_time")
                if not ts:
                    continue
                if f.get("confidence") == "insufficient":
                    continue
            else:
                ts = f.get("created_utc")
                if not ts:
                    continue
            conf = f.get("confidence", "low")
            # Compact evidence projection so the drawer can show the
            # full provenance chain without bloating the JSON with raw
            # tool output. One row per EvidenceItem with the columns
            # the analyst actually pivots on.
            ev_compact = []
            for e in (f.get("evidence") or [])[:6]:
                ev_compact.append({
                    "tool": e.get("tool", ""),
                    "version": e.get("version", ""),
                    "command": (e.get("command") or "")[:240],
                    "output_path": e.get("output_path", ""),
                    "output_sha256": (e.get("output_sha256") or "")[:16],
                })
            rr = f.get("red_review") or {}
            events.append({
                "case_id": c.case_id,
                "case_label": c.host_label,
                "ts": ts,
                "conf": conf,
                "agent": f.get("agent", ""),
                "finding_id": f.get("finding_id", ""),
                "claim": f.get("claim") or "",
                "hypotheses": f.get("hypotheses_supported") or [],
                "evidence": ev_compact,
                "red_review_status": (
                    rr.get("status", "") if isinstance(rr, dict) else ""
                ),
            })
    events.sort(key=lambda e: e["ts"])
    return events


def _merged_graph(cases: list[CaseSlice]) -> dict:
    """Stitch per-case Kùzu graphs into a single graph that surfaces
    cross-host structure. Three node classes:

    - **Shared global entities** (`IPAddress`, `Domain`, `Hash`) are
      keyed by unprefixed id, so the same `8.8.8.8` / `evil.com` /
      sha256 across N cases collapses into ONE node. An `attrs.cases`
      list records every case_id that observed it. These are the
      pivots that make the cross-host story visible.

    - **Per-case internal entities** (`Process`, `User`, `File`,
      `Event`, `Email`, `NetworkFlow`, `Host`) keep the `case_id|`
      prefix because pid 4242 in case A and case B are unrelated.

    - **Synthetic `Case` nodes** — one per case_id — are added as
      anchors. Each shared node gets an `OBSERVED_IN` edge to every
      Case node that saw it; this is what bridges the per-case
      islands into one connected component when the shared IOCs
      actually overlap.

    Returns the same {nodes, edges, stats} shape; stats now also
    report `shared_nodes` and `bridge_edges` so the renderer can
    decide whether to draw the cross-host layout."""
    SHARED_TYPES = {"IPAddress", "Domain", "Hash"}

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    capped = False
    total = 0
    bridges = 0

    # Synthetic Case anchor nodes — one per case, always present.
    for c in cases:
        nid = f"case:{c.case_id}"
        nodes[nid] = {
            "id": nid, "type": "Case",
            "label": c.host_label or c.case_id,
            "attrs": {"case_id": c.case_id},
            "origin_case": c.case_id,
            "origin_host": c.host_label,
            "is_case_anchor": True,
        }

    for c in cases:
        try:
            g = export_graph(c.case_dir)
        except Exception:
            continue
        if (g.get("stats") or {}).get("capped"):
            capped = True
        total += (g.get("stats") or {}).get("total_nodes", 0)
        # First pass: nodes — merge shared, prefix case-internal.
        case_local_id_map: dict[str, str] = {}
        for n in g.get("nodes", []):
            ntype = n.get("type", "")
            if ntype in SHARED_TYPES:
                merged_id = n["id"]   # unprefixed → merges across cases
                if merged_id in nodes:
                    # Accumulate the cases that observed this entity
                    cs = nodes[merged_id]["attrs"].setdefault("cases", [])
                    if c.case_id not in cs:
                        cs.append(c.case_id)
                else:
                    attrs = dict(n.get("attrs") or {})
                    attrs["cases"] = [c.case_id]
                    nodes[merged_id] = {
                        **n, "id": merged_id, "attrs": attrs,
                        "origin_case": "_shared",
                        "origin_host": "(shared across cases)",
                        "is_shared": True,
                    }
                case_local_id_map[n["id"]] = merged_id
                # Bridge: shared entity → this case's anchor
                bridge_id = (merged_id, f"case:{c.case_id}")
                edges.append({
                    "from": merged_id,
                    "to": f"case:{c.case_id}",
                    "type": "OBSERVED_IN",
                    "origin_case": c.case_id,
                    "is_bridge": True,
                })
                bridges += 1
            else:
                prefixed = f"{c.case_id}|{n['id']}"
                nodes[prefixed] = {
                    **n, "id": prefixed, "origin_case": c.case_id,
                    "origin_host": c.host_label,
                }
                case_local_id_map[n["id"]] = prefixed
        # Second pass: edges — remap each endpoint via case_local_id_map.
        for e in g.get("edges", []):
            f_id = case_local_id_map.get(e["from"])
            t_id = case_local_id_map.get(e["to"])
            if not (f_id and t_id):
                continue
            edges.append({
                "from": f_id, "to": t_id,
                "type": e.get("type", ""),
                "origin_case": c.case_id,
            })

    # Supplement the Kùzu union with iocs.json — agents persist IOCs
    # to <case_dir>/iocs.json but most don't write them into the per-case
    # Kùzu graph (it primarily captures process trees + file ops). Pull
    # them in as shared nodes so the cross-host graph actually shows
    # the C2 overlap that drove the case.
    _IOC_TYPE_TO_NODE = {
        "ipv4":   ("IPAddress", "ip"),
        "ipv6":   ("IPAddress", "ip"),
        "domain": ("Domain",    "dom"),
        "url":    ("Domain",    "dom"),    # URL host extracted as domain
        "md5":    ("Hash",      "hash"),
        "sha1":   ("Hash",      "hash"),
        "sha256": ("Hash",      "hash"),
    }
    # Re-apply the live IOC filters to the per-case iocs.json values
    # so stale noise from old runs (Windows .pf / .hve filenames that
    # the pre-filter extractor classified as domains) doesn't pollute
    # the cross-host graph. The iocs.json on disk is immutable case
    # state; the filter is a pure function so re-applying is safe.
    try:
        from el.skills.ioc_extract import _filter_domains, _filter_ipv4
    except Exception:
        _filter_domains = lambda d: set(d)
        _filter_ipv4 = lambda i: set(i)
    for c in cases:
        case_anchor = f"case:{c.case_id}"
        ioc_clean = dict(c.iocs or {})
        if "domain" in ioc_clean:
            ioc_clean["domain"] = sorted(_filter_domains(ioc_clean["domain"]))
        if "ipv4" in ioc_clean:
            ioc_clean["ipv4"] = sorted(_filter_ipv4(ioc_clean["ipv4"]))
        for ioc_type, values in ioc_clean.items():
            mapping = _IOC_TYPE_TO_NODE.get(ioc_type)
            if not mapping:
                continue
            ntype, prefix = mapping
            for v in values[:80]:           # cap per type per case
                if not v:
                    continue
                # url -> domain extraction: keep host portion only
                if ioc_type == "url":
                    try:
                        from urllib.parse import urlparse
                        h = urlparse(v).hostname or ""
                    except Exception:
                        h = ""
                    if not h:
                        continue
                    v_norm = h.lower()
                else:
                    v_norm = v.lower() if ioc_type in ("domain",) else v
                merged_id = f"{prefix}:{v_norm}"
                if merged_id in nodes:
                    cs = nodes[merged_id]["attrs"].setdefault("cases", [])
                    if c.case_id not in cs:
                        cs.append(c.case_id)
                else:
                    extra_attrs = {"cases": [c.case_id]}
                    if ioc_type in ("md5", "sha1", "sha256"):
                        extra_attrs["algo"] = ioc_type
                    nodes[merged_id] = {
                        "id": merged_id, "type": ntype,
                        "label": v_norm if len(v_norm) <= 40
                                 else v_norm[:18] + "…" + v_norm[-12:],
                        "attrs": extra_attrs,
                        "origin_case": "_shared",
                        "origin_host": "(shared across cases)",
                        "is_shared": True,
                    }
                edges.append({
                    "from": merged_id, "to": case_anchor,
                    "type": "OBSERVED_IN",
                    "origin_case": c.case_id,
                    "is_bridge": True,
                })
                bridges += 1

    shared_count = sum(1 for n in nodes.values()
                       if n.get("is_shared"))
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {"total_nodes": total,
                  "merged_nodes": len(nodes),
                  "merged_edges": len(edges),
                  "shared_nodes": shared_count,
                  "bridge_edges": bridges,
                  "case_anchors": len(cases),
                  "capped": capped},
    }


def _combined_narrative(cases: list[CaseSlice]) -> dict:
    """Read each case's narrative.md if present + synthesize a
    cross-host intro from the joint ACH matrix + signal matrix."""
    # Cross-host intro — prose summary of WHAT this scenario is
    leaders = [(c.case_id, c.leading, c.host_label) for c in cases]
    leaders.sort(key=lambda t: -t[1][1])  # by score desc
    top_host = leaders[0]
    top_hid, top_score = top_host[1]

    all_hids = [c.leading[0] for c in cases if c.leading[0]]
    from collections import Counter
    hid_counts = Counter(all_hids)
    dominant = hid_counts.most_common(1)[0] if hid_counts else (None, 0)

    intro_parts = [
        f"**Scope.** This combined report stitches **{len(cases)}** "
        f"per-case ledgers into one cross-host narrative. The dominant "
        f"hypothesis across cases is "
        f"**{dominant[0] or '—'}** (lead in {dominant[1]} of {len(cases)} "
        f"cases)."
    ]
    strongest = [(c, score) for c in cases
                 for score in [c.leading[1]] if score >= 20]
    if strongest:
        names = ", ".join(f"`{c.case_id}` ({s})" for c, s in strongest[:5])
        intro_parts.append(
            f"**Strongest per-case signal (score ≥ 20):** {names}.")
    # Pull in the most common signal-matrix cells
    matrix = _signal_matrix(cases)
    if len(matrix) > 1:
        hits_by_sig: list[tuple[str, int]] = []
        for row in matrix[1:]:
            nhits = sum(1 for cell in row[1:] if cell)
            hits_by_sig.append((row[0], nhits))
        hits_by_sig.sort(key=lambda t: -t[1])
        top_sigs = hits_by_sig[:5]
        if top_sigs:
            intro_parts.append(
                "**Top cross-host signals:** " +
                ", ".join(f"{name} ({n}/{len(cases)} hosts)"
                           for name, n in top_sigs) + ".")

    # Per-case narrative blocks (pulled from cases/<id>/reports/narrative.md)
    case_narratives: list[dict] = []
    for c in cases:
        nar_path = c.case_dir / "reports" / "narrative.md"
        body = ""
        if nar_path.exists():
            try:
                body = nar_path.read_text()
            except Exception:
                body = ""
        case_narratives.append({
            "case_id": c.case_id,
            "host_label": c.host_label,
            "leading_hid": c.leading[0] or "—",
            "leading_score": c.leading[1],
            "body": body,
        })
    # Order by descending leading score so the report reads top-down
    case_narratives.sort(key=lambda d: -d["leading_score"])
    return {
        "intro": "\n\n".join(intro_parts),
        "case_narratives": case_narratives,
    }


# ---------------------------------------------------------------------------
# HTML block builders
# ---------------------------------------------------------------------------

def _heat_cls(score: int, max_score: int) -> str:
    if score <= 0:
        return "s0"
    frac = score / max(max_score, 1)
    if frac >= 0.9: return "s5"
    if frac >= 0.7: return "s4"
    if frac >= 0.5: return "s3"
    if frac >= 0.3: return "s2"
    return "s1"


def _joint_ach_html(cases: list[CaseSlice], joint: dict) -> str:
    if not joint:
        return '<p style="color:#8b949e">No ACH rankings in any case.</p>'
    max_score = max((v for row in joint.values() for v in row.values()),
                    default=1) or 1
    hdr = "<tr><th class='case'>Hypothesis</th>"
    for c in cases:
        hdr += f"<th class='case'>{html.escape(c.host_label)}</th>"
    hdr += "</tr>"
    body = []
    # Order rows by maximum score across cases
    ordered_hids = sorted(joint.keys(),
                          key=lambda h: -max(joint[h].values(), default=0))
    for hid in ordered_hids:
        row = joint[hid]
        tds = [f"<td class='case mono'>{html.escape(hid)}</td>"]
        for c in cases:
            s = row.get(c.case_id, 0)
            cls = _heat_cls(s, max_score)
            disp = str(s) if s != 0 else "·"
            tds.append(f"<td class='score {cls}' "
                       f"title='{html.escape(hid)} = {s} in "
                       f"{html.escape(c.case_id)}'>{disp}</td>")
        body.append("<tr>" + "".join(tds) + "</tr>")
    return (f"<div class='ach-matrix'><table>"
            f"<thead>{hdr}</thead><tbody>{''.join(body)}</tbody>"
            f"</table></div>")


def _signal_matrix_html(cases: list[CaseSlice]) -> str:
    matrix = _signal_matrix(cases)
    if len(matrix) <= 1:
        return "<p style='color:#8b949e'>No signal-matrix rows fired.</p>"
    header = matrix[0]
    # First header cell ("Signal") gets `class='signame'` — same as
    # the data-row first cell — so column 0 has horizontal text top
    # and bottom and the column widths align. The remaining headers
    # are host names rendered vertically (`class='case'` invokes
    # writing-mode: vertical-rl). Without this, the rotated "Signal"
    # cell collapsed to a narrow column while the wide signal-name
    # data cells expanded a separate column, skewing the matrix.
    hdr_cells = [
        f"<th class='signame'>{html.escape(header[0])}</th>"
    ]
    for h in header[1:]:
        # Wrap the rotated label in a span so CSS can rotate just
        # the text node (not the cell box). The <th> stays a normal
        # block with text-align: center; the inner span is what gets
        # writing-mode: vertical-rl + rotate(180deg). Without the
        # wrapper, rotating the <th> directly puts the visible text
        # on the cell's right edge and the dots in data rows below
        # drift ~25px out of alignment with each host name.
        hdr_cells.append(
            f"<th class='case'><span>{html.escape(h)}</span></th>")
    rows_html = []
    for row in matrix[1:]:
        cells = [f"<td class='signame'>{html.escape(row[0])}</td>"]
        for cell in row[1:]:
            cells.append(f"<td class='dot'>{'•' if cell else ''}</td>")
        rows_html.append("<tr>" + "".join(cells) + "</tr>")
    return (f"<div class='sig-matrix'><table><thead><tr>"
            f"{''.join(hdr_cells)}</tr>"
            f"</thead><tbody>{''.join(rows_html)}</tbody></table></div>")


def _clock_baselines(cases: list[CaseSlice]) -> dict:
    """Aggregate the per-case time_baseline findings across all
    stitched cases. Returns:

      {
        "rows": [ {host_label, case_id, tz_display, utc_offset,
                    sync_mode, ntp_peer, skew_seconds, config_lwt}, ...],
        "alerts": [ {level: 'warn'|'bad'|'ok', text: str}, ... ]
      }

    `rows` is one entry per case (missing-finding cases get a sentinel
    entry so the analyst sees the gap rather than silently dropping
    that host). `alerts` summarise the cross-host disagreements that
    actually matter forensically — TZ mismatch (correlator must
    apply offset), sync-mode mismatch (some hosts have unbounded
    drift), large skew (acquirer's clock disagreed with the target).
    """
    rows: list[dict] = []
    tz_seen: set[str] = set()
    sync_seen: set[str] = set()
    ntp_seen: set[str] = set()
    skews: list[int] = []
    nosync_hosts: list[str] = []
    missing_hosts: list[str] = []
    for c in cases:
        # Skim findings for the time_baseline marker
        baseline_facts = None
        skew_facts = None
        for f in c.findings:
            for ev in (f.get("evidence") or []):
                facts = (ev.get("extracted_facts") or {})
                if facts.get("phase") != "time_baseline":
                    continue
                # Two shapes — disk_forensicator emits skew_seconds;
                # windows_artifact emits the TZ + W32Time bundle.
                if "skew_seconds" in facts:
                    skew_facts = facts
                if "tz_display_name" in facts or "tz_standard_name" in facts:
                    baseline_facts = facts
        if not baseline_facts and not skew_facts:
            rows.append({
                "host_label": c.host_label,
                "case_id": c.case_id,
                "tz_display": "", "utc_offset": "",
                "sync_mode": "", "ntp_peer": "",
                "skew_seconds": None,
                "config_lwt": "",
                "missing": True,
            })
            missing_hosts.append(c.host_label)
            continue
        b = baseline_facts or {}
        tz_disp = (b.get("tz_display_name") or b.get("tz_standard_name")
                   or "")
        # Reconstruct UTC offset from active bias minutes (Windows
        # convention: positive = local clock BEHIND UTC, so flip).
        utc_off = ""
        atb = b.get("tz_active_bias_minutes")
        if isinstance(atb, int):
            mins = -atb
            sign = "+" if mins >= 0 else "-"
            utc_off = f"UTC{sign}{abs(mins)//60:02d}:{abs(mins)%60:02d}"
        sync_mode = (b.get("w32time_type") or "").upper()
        ntp_peer = b.get("w32time_ntp_server") or ""
        config_lwt = (b.get("w32time_config_last_write_utc") or "")[:10]
        skew = None
        if skew_facts and isinstance(skew_facts.get("skew_seconds"), int):
            skew = skew_facts["skew_seconds"]
            skews.append(skew)
        if tz_disp:
            tz_seen.add(tz_disp)
        if sync_mode:
            sync_seen.add(sync_mode)
        if ntp_peer:
            ntp_seen.add(ntp_peer)
        if sync_mode == "NOSYNC":
            nosync_hosts.append(c.host_label)
        rows.append({
            "host_label": c.host_label,
            "case_id": c.case_id,
            "tz_display": tz_disp,
            "utc_offset": utc_off,
            "sync_mode": sync_mode,
            "ntp_peer": ntp_peer,
            "skew_seconds": skew,
            "config_lwt": config_lwt,
            "missing": False,
        })

    alerts: list[dict] = []
    if len(tz_seen) > 1:
        alerts.append({
            "level": "warn",
            "text": ("TZ split across enterprise: "
                     f"{', '.join(sorted(tz_seen))}. Apply the per-host "
                     "offset when correlating local-time values between "
                     "machines."),
        })
    if nosync_hosts:
        alerts.append({
            "level": "bad",
            "text": (f"NoSync orphan clock on: "
                     f"{', '.join(nosync_hosts)}. Drift is unbounded — "
                     "treat wall-clock timestamps from this host with "
                     "caution; cross-host correlation may be off by "
                     "minutes."),
        })
    if len(sync_seen) > 1 and not nosync_hosts:
        # Heterogeneous sync mode but no NoSync — usually NTP vs NT5DS
        # (a host outside the domain). Informational, not bad.
        alerts.append({
            "level": "warn",
            "text": ("Sync-mode mismatch across hosts: "
                     f"{', '.join(sorted(sync_seen))}. Likely a host is "
                     "outside the domain time hierarchy."),
        })
    if len(ntp_seen) > 1:
        alerts.append({
            "level": "warn",
            "text": ("NTP-peer / flag mismatch: "
                     f"{', '.join(sorted(ntp_seen))}. Minor config "
                     "drift — typically benign, worth noting on the "
                     "case timeline (one host was reconfigured)."),
        })
    if any(abs(s) > 60 for s in skews if isinstance(s, int)):
        big = max(skews, key=abs)
        alerts.append({
            "level": "bad",
            "text": (f"Large acquirer-vs-target skew observed (max "
                     f"{big}s). Back this out of FAT / EXIF / Office-"
                     "metadata local-time values."),
        })
    if missing_hosts:
        alerts.append({
            "level": "warn",
            "text": ("No time-baseline finding emitted for: "
                     f"{', '.join(missing_hosts)}. Likely a non-Windows "
                     "or non-EWF input — baseline parsers can't read "
                     "those hives. Calibration unavailable for those "
                     "hosts."),
        })
    if not alerts and rows:
        alerts.append({
            "level": "ok",
            "text": ("Per-host baselines consistent — single TZ, single "
                     "sync mode, zero acquirer skew. Wall-clock "
                     "timestamps can be trusted across all hosts in "
                     "the bundle."),
        })

    return {"rows": rows, "alerts": alerts}


def _clock_baselines_html(cases: list[CaseSlice]) -> str:
    data = _clock_baselines(cases)
    if not data["rows"]:
        return ("<p style='color:#8b949e'>No per-case time baselines "
                "emitted.</p>")
    # Alerts block — render up-top so the analyst sees the call-to-
    # action before the table.
    alert_html = ""
    if data["alerts"]:
        chips = "".join(
            f"<span class='clock-alert {html.escape(a['level'])}'>"
            f"{html.escape(a['text'])}</span>"
            for a in data["alerts"])
        alert_html = f"<div class='clock-alerts'>{chips}</div>"
    rows_html = []
    for r in data["rows"]:
        if r["missing"]:
            rows_html.append(
                f"<tr>"
                f"<td><b>{html.escape(r['host_label'])}</b></td>"
                f"<td class='missing' colspan='6'>"
                f"no time-baseline finding emitted for this case</td>"
                f"</tr>")
            continue
        skew = r["skew_seconds"]
        if skew is None:
            skew_cell = "<td class='missing'>—</td>"
        elif skew == 0:
            skew_cell = "<td class='skew-zero'>0s</td>"
        else:
            cls = "skew-warn" if abs(skew) > 60 else ""
            sign = "+" if skew > 0 else ""
            skew_cell = f"<td class='{cls}'>{sign}{skew}s</td>"
        sync = r["sync_mode"]
        if sync in ("NTP", "NT5DS"):
            sync_cell = (f"<td class='sync-trust'>{html.escape(sync)}"
                         " — trusted</td>")
        elif sync == "NOSYNC":
            sync_cell = ("<td class='sync-warn'>NoSync — drift "
                         "unbounded</td>")
        else:
            sync_cell = (f"<td class='sync-unknown'>"
                         f"{html.escape(sync) or '(unknown)'}</td>")
        rows_html.append(
            f"<tr>"
            f"<td><b>{html.escape(r['host_label'])}</b></td>"
            f"<td class='tz'>{html.escape(r['tz_display'] or '?')}</td>"
            f"<td>{html.escape(r['utc_offset'] or '?')}</td>"
            f"{sync_cell}"
            f"<td class='ntp'>{html.escape(r['ntp_peer'] or '—')}</td>"
            f"{skew_cell}"
            f"<td>{html.escape(r['config_lwt'] or '—')}</td>"
            f"</tr>")
    table_html = (
        "<div class='clock-baseline'><table>"
        "<thead><tr>"
        "<th>Host</th><th>TZ (display)</th><th>UTC offset</th>"
        "<th>Sync mode</th><th>NTP peer</th>"
        "<th>Acq. skew</th><th>W32Time config LWT</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows_html)}</tbody>"
        "</table></div>")
    return alert_html + table_html


def _attack_heatmap_html(techniques: dict) -> str:
    if not techniques:
        return "<p style='color:#8b949e'>No ATT&amp;CK techniques.</p>"
    max_findings = max((info["findings"] for info in techniques.values()),
                       default=1) or 1
    rows = []
    for tid in sorted(techniques, key=lambda t: -techniques[t]["findings"]):
        info = techniques[tid]
        url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        pct = int(100 * info["findings"] / max_findings)
        slug = tid.replace(".", "_")
        # Header row — clicking the disclosure caret toggles the
        # details row below. Anchor on the TID itself goes out to
        # MITRE's reference page (target=_blank); the toggle stays
        # on the disclosure cell.
        rows.append(
            f"<tr class='att-row' data-att='{slug}'>"
            f"<td class='att-toggle'>▸</td>"
            f"<td class='tid'><a href='{url}' target='_blank' "
            f"onclick='event.stopPropagation()'>{html.escape(tid)}</a></td>"
            f"<td>{html.escape(info.get('name',''))}</td>"
            f"<td class='num'>{len(info['cases'])}</td>"
            f"<td class='num'>{info['findings']}</td>"
            f"<td class='bar'><div class='bar-inner' "
            f"style='width:{pct}%'></div></td></tr>"
        )
        # Hidden details row — sub-table of contributing findings.
        # Each finding_id is clickable; the click handler reuses the
        # timeline drawer (DATA.event_by_id lookup).
        sub_rows = []
        for ref in info.get("finding_refs", []):
            fid = ref.get("finding_id") or ""
            short_fid = fid[:14] + "…" if len(fid) > 16 else fid
            conf = ref.get("confidence", "")
            sub_rows.append(
                f"<tr><td class='att-host'>{html.escape(ref.get('case_label') or ref.get('case_id') or '')}</td>"
                f"<td class='att-agent'>{html.escape(ref.get('agent') or '')}</td>"
                f"<td class='conf-{html.escape(conf)}'>{html.escape(conf)}</td>"
                f"<td class='att-claim'>{html.escape((ref.get('claim') or '')[:220])}</td>"
                f"<td class='att-fid'><a href='#' class='att-fid-link' "
                f"data-fid='{html.escape(fid)}' "
                f"data-cid='{html.escape(ref.get('case_id') or '')}'>"
                f"{html.escape(short_fid)}</a></td></tr>"
            )
        rows.append(
            f"<tr class='att-details' data-att='{slug}' style='display:none'>"
            f"<td colspan='6'>"
            f"<table class='att-sub'><thead><tr>"
            f"<th>Host</th><th>Agent</th><th>Conf</th>"
            f"<th>Claim</th><th>finding_id</th>"
            f"</tr></thead><tbody>{''.join(sub_rows)}</tbody></table>"
            f"</td></tr>"
        )
    return (f"<div class='attack-grid'><table>"
            f"<thead><tr><th></th><th>Technique</th><th>Name</th>"
            f"<th>Cases</th><th>Findings</th><th>Frequency</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>")


def _ioc_overlap_html(cases: list[CaseSlice]) -> str:
    overlap = _ioc_overlap(cases)
    if not overlap:
        return ("<p style='color:#8b949e'>No IOC overlap found in "
                "~/.el/knowledge.sqlite.</p>")
    rows = []
    for ioc_type, value, ids in overlap[:200]:
        ids_h = ", ".join(f"<code>{html.escape(i)}</code>" for i in ids)
        rows.append(
            f"<tr><td>{html.escape(ioc_type)}</td>"
            f"<td><code>{html.escape(value)}</code></td>"
            f"<td>{ids_h}</td></tr>")
    return (f"<table><thead><tr><th>IOC type</th><th>Value</th>"
            f"<th>Seen in</th></tr></thead><tbody>{''.join(rows)}</tbody></table>")


def _per_case_links_html(cases: list[CaseSlice], out_path: Path) -> str:
    """Render the Hosts & Drill-down table. Hrefs are relative to
    `out_path` (the combined.html on disk) so the link resolves
    correctly under both `file://` and `el serve` (which roots its
    URL space at `/opt/EL/cases`, not `/`). Absolute filesystem paths
    fail under the served path because the server does not expose
    `/opt/EL/cases/...` — it serves `/<case>/reports/case.html`."""
    import os as _os
    # Inline SVG download icon — same one used in case.html so the
    # affordance is consistent across single + combined report views.
    _PDF_SVG = (
        "<svg width='12' height='12' viewBox='0 0 16 16' fill='none' "
        "stroke='currentColor' stroke-width='1.6' stroke-linecap='round' "
        "stroke-linejoin='round' aria-hidden='true'>"
        "<path d='M8 1v10M4 7.5l4 4 4-4M2 14.5h12'/></svg>"
    )
    rows = []
    for c in cases:
        case_html = c.case_dir / "reports" / "case.html"
        exec_pdf = c.case_dir / "reports" / "executive.pdf"
        link_parts: list[str] = []
        if case_html.exists():
            href = _os.path.relpath(case_html, out_path.parent)
            link_parts.append(
                f"<a href='{html.escape(href)}' "
                f"target='_blank'>open case.html</a>"
            )
        else:
            link_parts.append(
                "<span style='color:#8b949e'>case.html "
                "not rendered yet</span>"
            )
        if exec_pdf.exists():
            pdf_href = _os.path.relpath(exec_pdf, out_path.parent)
            link_parts.append(
                f"<a href='{html.escape(pdf_href)}' "
                f"download class='pdf-download' "
                f"title='Download executive PDF for {html.escape(c.case_id)}' "
                f"aria-label='Download executive PDF'>"
                f"{_PDF_SVG} PDF</a>"
            )
        link_html = "".join(link_parts)
        hid, score = c.leading
        rows.append(
            f"<tr><td><code>{html.escape(c.case_id)}</code></td>"
            f"<td>{html.escape(c.host_label)}</td>"
            f"<td>{html.escape(hid or '—')}</td>"
            f"<td class='num'>{score}</td>"
            f"<td>{link_html}</td></tr>")
    return (f"<table><thead><tr><th>Case</th><th>Host / kind</th>"
            f"<th>Leading hypothesis</th><th>Score</th><th>Drill-down</th>"
            f"</tr></thead><tbody>{''.join(rows)}</tbody></table>")


_JS_TEMPLATE = r"""
const DATA = __DATA_JSON__;

// ---------------------------------------------------------------------------
// Unified timeline (SVG swim-lane)
// ---------------------------------------------------------------------------
let _tlMode = "findings";  // "findings" = artifact time, "processing" = EL wall clock
function renderTimeline() {
  const svg = document.getElementById("timeline-svg");
  if (!svg) return;
  const events = _tlMode === "processing"
    ? (DATA.processing_timeline || [])
    : (DATA.findings_timeline || []);
  const status = document.getElementById("tl-status");
  if (status) {
    const total = _tlMode === "processing"
      ? events.length
      : `${events.length} of ${DATA.counts.findings} (${Math.round(100*events.length/(DATA.counts.findings||1))}% carry an artifact timestamp)`;
    status.textContent = `${events.length ? events.length : 0} events · ${_tlMode === "findings" ? "real-world attacker clock" : "EL processing clock"}` +
      (_tlMode === "findings" && DATA.counts.findings ? ` · ${events.length}/${DATA.counts.findings} findings have an extractable artifact timestamp` : "");
  }
  if (!events.length) {
    svg.innerHTML = `<text x="20" y="40" class="tl-axis-text">${_tlMode === "findings" ? "No findings carry an extractable artifact timestamp. Switch to the Processing clock to see all emitted findings." : "No timestamped findings."}</text>`;
    return;
  }
  const lanes = DATA.lanes;   // [{case_id, host_label}, ...]
  const laneIdx = Object.fromEntries(lanes.map((l,i) => [l.case_id, i]));
  const tmin = Math.min(...events.map(e => Date.parse(e.ts)));
  const tmax = Math.max(...events.map(e => Date.parse(e.ts))) || (tmin + 1);
  const W = svg.clientWidth || 1200;
  const H = lanes.length * 36 + 60;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const LANE_H = 36, LANE_X0 = 180;
  const plotW = W - LANE_X0 - 20;
  svg.innerHTML = "";
  const NS = "http://www.w3.org/2000/svg";
  // Lane labels + grid
  lanes.forEach((l, i) => {
    const y = i * LANE_H + 30;
    const label = document.createElementNS(NS, "text");
    label.setAttribute("x", 10);
    label.setAttribute("y", y + LANE_H/2 + 4);
    label.setAttribute("class", "tl-lane-label");
    label.textContent = l.host_label.slice(0, 26);
    svg.appendChild(label);
    const hl = document.createElementNS(NS, "line");
    hl.setAttribute("x1", LANE_X0); hl.setAttribute("x2", W-20);
    hl.setAttribute("y1", y + LANE_H); hl.setAttribute("y2", y + LANE_H);
    hl.setAttribute("class", "tl-grid");
    svg.appendChild(hl);
  });
  // Time axis labels (start, middle, end)
  [0, 0.5, 1].forEach(frac => {
    const t = new Date(tmin + frac * (tmax - tmin));
    const x = LANE_X0 + frac * plotW;
    const txt = document.createElementNS(NS, "text");
    txt.setAttribute("x", x); txt.setAttribute("y", lanes.length * LANE_H + 50);
    txt.setAttribute("class", "tl-axis-text");
    txt.setAttribute("text-anchor", "middle");
    txt.textContent = t.toISOString().slice(0, 19) + "Z";
    svg.appendChild(txt);
  });
  // Event circles
  const CONF_COLOR = {
    high: "#f85149", medium: "#d29922",
    low: "#58a6ff", insufficient: "#484f58",
  };
  events.forEach(e => {
    const laneI = laneIdx[e.case_id];
    if (laneI === undefined) return;
    const x = LANE_X0 + ((Date.parse(e.ts) - tmin) / Math.max(tmax - tmin, 1)) * plotW;
    const y = laneI * LANE_H + 30 + LANE_H/2;
    const c = document.createElementNS(NS, "circle");
    c.setAttribute("cx", x); c.setAttribute("cy", y);
    c.setAttribute("r", e.conf === "high" ? 5 : e.conf === "medium" ? 4 : 3);
    c.setAttribute("fill", CONF_COLOR[e.conf] || "#8b949e");
    c.setAttribute("fill-opacity", "0.8");
    c.setAttribute("class", "tl-event");
    c.addEventListener("mouseenter", evt => showTT(evt, e));
    c.addEventListener("mouseleave", hideTT);
    c.addEventListener("click", () => showDrawer(e));
    svg.appendChild(c);
  });
}

// ---------------------------------------------------------------------------
// Cross-host graph (force-directed, SVG)
// ---------------------------------------------------------------------------
function renderGraph() {
  const svg = document.getElementById("graph-svg");
  if (!svg) return;
  const g = DATA.graph;
  if (!g || !g.nodes.length) {
    svg.innerHTML = '<text x="20" y="40" class="tl-axis-text">No entities in any per-case Kùzu graph.</text>';
    return;
  }
  // Layout: shared global entities (IPs / domains / hashes) in the
  // central region; one Case anchor per case at a fixed ring radius;
  // per-case internal entities (processes / files / events) cluster
  // around their case anchor. Bridge edges (OBSERVED_IN) connect
  // shared nodes to every case anchor that observed them — that's
  // what makes the cross-host story visible.
  const casesList = DATA.lanes.map(l => l.case_id);
  const W = svg.clientWidth || 1400, H = 600;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const cx = W / 2, cy = H / 2;
  const RING_R = Math.min(W, H) * 0.38;       // case anchors here
  const PERCASE_R = Math.min(W, H) * 0.085;   // internals around anchor
  const SHARED_R = Math.min(W, H) * 0.18;     // shared zone radius

  const PAL = ["#58a6ff","#f85149","#3fb950","#d29922","#bc8cff",
               "#ff7b72","#79c0ff","#f0883e","#a371f7","#56d364",
               "#e3b341","#39c5cf","#ffa198","#7ee787","#d2a8ff"];
  const CASE_COLOR = {};
  casesList.forEach((cid, i) => CASE_COLOR[cid] = PAL[i % PAL.length]);

  // 1. Case anchors evenly spaced on outer ring, top-aligned.
  const anchorPos = {};
  casesList.forEach((cid, i) => {
    const a = (2 * Math.PI * i) / Math.max(casesList.length, 1) - Math.PI / 2;
    anchorPos[cid] = { x: cx + Math.cos(a) * RING_R, y: cy + Math.sin(a) * RING_R };
  });

  // Bucket nodes
  const shared = [], anchors = [], internals = {};
  casesList.forEach(cid => internals[cid] = []);
  g.nodes.forEach(n => {
    if (n.is_case_anchor) anchors.push(n);
    else if (n.is_shared) shared.push(n);
    else (internals[n.origin_case] = internals[n.origin_case] || []).push(n);
  });

  // Sort shared by # of cases observing (most-shared first → drawn larger + more central)
  shared.sort((a, b) => (b.attrs.cases || []).length - (a.attrs.cases || []).length);

  const pos = {};
  // 2. Case anchor positions (look up by 'case:<cid>' id)
  anchors.forEach(n => { pos[n.id] = anchorPos[n.attrs.case_id] || { x: cx, y: cy }; });
  // 3. Per-case internals around their anchor
  casesList.forEach(cid => {
    const anchor = anchorPos[cid];
    const cn = internals[cid] || [];
    cn.forEach((n, i) => {
      const a = (2 * Math.PI * i) / Math.max(cn.length, 1);
      pos[n.id] = { x: anchor.x + Math.cos(a) * PERCASE_R,
                    y: anchor.y + Math.sin(a) * PERCASE_R };
    });
  });
  // 4. Shared nodes — distribute within the central zone using a small
  //    sunflower spiral so highly-shared nodes sit near the centre.
  shared.forEach((n, i) => {
    const t = i / Math.max(shared.length, 1);
    const r = SHARED_R * Math.sqrt(t);
    const a = i * 137.508 * Math.PI / 180;   // golden-angle spiral
    pos[n.id] = { x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r };
  });

  svg.innerHTML = "";
  const NS = "http://www.w3.org/2000/svg";

  // Edges — bridges (OBSERVED_IN) drawn first under everything, dashed
  // and orange so cross-host pivots are visible. Then per-case edges.
  const drawEdge = (e, klass) => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    const line = document.createElementNS(NS, "line");
    line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
    line.setAttribute("class", klass);
    svg.appendChild(line);
  };
  const bridges = g.edges.filter(e => e.is_bridge);
  const others = g.edges.filter(e => !e.is_bridge).slice(0, 2000);
  bridges.forEach(e => drawEdge(e, "edge-line bridge"));
  others.forEach(e => drawEdge(e, "edge-line"));

  // Nodes — three visual classes:
  //   anchor: large square, case-coloured, label = host
  //   shared: circle sized by #cases observing, type-coloured
  //   internal: small circle, case-coloured
  const SHARED_TYPE_COLOR = {
    "IPAddress": "#f0883e", "Domain": "#bc8cff", "Hash": "#56d364",
  };
  // Anchors
  anchors.forEach(n => {
    const p = pos[n.id]; if (!p) return;
    const sq = document.createElementNS(NS, "rect");
    const SIZE = 14;
    sq.setAttribute("x", p.x - SIZE/2); sq.setAttribute("y", p.y - SIZE/2);
    sq.setAttribute("width", SIZE); sq.setAttribute("height", SIZE);
    sq.setAttribute("fill", CASE_COLOR[n.attrs.case_id] || "#8b949e");
    sq.setAttribute("stroke", "#0d1117"); sq.setAttribute("stroke-width", "2");
    sq.setAttribute("class", "node-anchor");
    sq.addEventListener("mouseenter", evt => showTT(evt, {
      ts: "", conf: "", agent: "Case", case_label: n.label,
      claim: `${n.attrs.case_id} · case anchor`,
    }));
    sq.addEventListener("mouseleave", hideTT);
    svg.appendChild(sq);
    // Label below the anchor
    const txt = document.createElementNS(NS, "text");
    txt.setAttribute("x", p.x); txt.setAttribute("y", p.y + SIZE);
    txt.setAttribute("class", "node-anchor-label");
    txt.setAttribute("text-anchor", "middle");
    txt.textContent = (n.label || n.id).slice(0, 24);
    svg.appendChild(txt);
  });
  // Shared
  shared.forEach(n => {
    const p = pos[n.id]; if (!p) return;
    const ncases = (n.attrs.cases || []).length;
    const r = 4 + Math.min(ncases, 8);   // 5..12 px
    const c = document.createElementNS(NS, "circle");
    c.setAttribute("cx", p.x); c.setAttribute("cy", p.y);
    c.setAttribute("r", r);
    c.setAttribute("fill", SHARED_TYPE_COLOR[n.type] || "#f85149");
    c.setAttribute("stroke", "#0d1117");
    c.setAttribute("stroke-width", ncases >= 2 ? "1.5" : "0.5");
    c.setAttribute("class", "node-shared");
    c.addEventListener("mouseenter", evt => showTT(evt, {
      ts: "", conf: ncases >= 2 ? `seen in ${ncases} cases` : "",
      agent: n.type, case_label: n.label || n.id,
      claim: `${ncases} case(s): ${(n.attrs.cases || []).slice(0,5).join(", ")}` +
             (ncases > 5 ? ` …` : ""),
    }));
    c.addEventListener("mouseleave", hideTT);
    svg.appendChild(c);
    // Label highly-shared (≥2 cases) so the analyst can read them
    if (ncases >= 2) {
      const txt = document.createElementNS(NS, "text");
      txt.setAttribute("x", p.x + r + 3); txt.setAttribute("y", p.y + 3);
      txt.setAttribute("class", "node-shared-label");
      txt.textContent = (n.label || n.id).slice(0, 24);
      svg.appendChild(txt);
    }
  });
  // Internals
  casesList.forEach(cid => {
    (internals[cid] || []).forEach(n => {
      const p = pos[n.id]; if (!p) return;
      const c = document.createElementNS(NS, "circle");
      c.setAttribute("cx", p.x); c.setAttribute("cy", p.y);
      c.setAttribute("r", 3);
      c.setAttribute("fill", CASE_COLOR[cid] || "#8b949e");
      c.setAttribute("class", "node-circle");
      c.addEventListener("mouseenter", evt => showTT(evt, {
        ts: "", conf: "", agent: n.type, case_label: n.origin_host,
        claim: n.label || n.id,
      }));
      c.addEventListener("mouseleave", hideTT);
      svg.appendChild(c);
    });
  });

  // Legend
  const legend = document.getElementById("graph-legend");
  if (legend) {
    const stats = g.stats || {};
    legend.innerHTML =
      "<div style='margin-bottom:6px;color:#c9d1d9'><b>Cases (anchors)</b></div>" +
      casesList.map(cid => {
        const lane = DATA.lanes.find(l => l.case_id === cid);
        return `<div><span class="sw" style="background:${CASE_COLOR[cid]}"></span>${lane ? lane.host_label : cid}</div>`;
      }).join("") +
      "<div style='margin-top:8px;color:#c9d1d9'><b>Shared entities</b></div>" +
      `<div><span class="sw" style="background:${SHARED_TYPE_COLOR.IPAddress}"></span>IPAddress</div>` +
      `<div><span class="sw" style="background:${SHARED_TYPE_COLOR.Domain}"></span>Domain</div>` +
      `<div><span class="sw" style="background:${SHARED_TYPE_COLOR.Hash}"></span>Hash</div>` +
      `<div style="margin-top:8px;color:#8b949e;font-size:11px">` +
      `${g.nodes.length} nodes · ${g.edges.length} edges · ` +
      `${stats.shared_nodes || 0} shared · ${stats.bridge_edges || 0} bridges` +
      `${stats.capped ? ' · capped' : ''}</div>`;
  }
}

// ---------------------------------------------------------------------------
// Tooltip
// ---------------------------------------------------------------------------
let _tt = null;
function showTT(evt, e) {
  hideTT();
  _tt = document.createElement("div");
  _tt.className = "tt";
  _tt.innerHTML =
    (e.ts ? `<b>${e.ts}</b><br>` : '') +
    `<b>${e.case_label || ''}</b> — ${e.agent || ''}${e.conf ? ' (' + e.conf + ')' : ''}<br>` +
    `<span style="color:#c9d1d9">${(e.claim || '').replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}</span>`;
  document.body.appendChild(_tt);
  _tt.style.left = (evt.clientX + 12) + "px";
  _tt.style.top  = (evt.clientY + 12) + "px";
}
function hideTT() { if (_tt) { _tt.remove(); _tt = null; } }

function setupTimelineToggle() {
  const btns = document.querySelectorAll("[data-tl-mode]");
  btns.forEach(b => b.addEventListener("click", () => {
    _tlMode = b.dataset.tlMode;
    btns.forEach(x => x.classList.toggle("active", x === b));
    renderTimeline();
  }));
}

// ---------------------------------------------------------------------------
// Finding drawer — opens on timeline-event click and ATT&CK finding_id click.
// One DOM node, populated per click. Closes via the × button or Esc.
// ---------------------------------------------------------------------------
function _eventByFid() {
  if (!DATA._eventByFid) {
    const ix = {};
    (DATA.findings_timeline || []).forEach(e => { if (e.finding_id) ix[e.finding_id] = e; });
    (DATA.processing_timeline || []).forEach(e => { if (e.finding_id && !ix[e.finding_id]) ix[e.finding_id] = e; });
    DATA._eventByFid = ix;
  }
  return DATA._eventByFid;
}

function showDrawer(e) {
  if (!e) return;
  let d = document.getElementById("drawer");
  if (!d) {
    d = document.createElement("div");
    d.id = "drawer";
    d.innerHTML = `
      <div class="drawer-head">
        <div class="drawer-title"></div>
        <button class="drawer-close" aria-label="Close">×</button>
      </div>
      <div class="drawer-body"></div>`;
    document.body.appendChild(d);
    d.querySelector(".drawer-close").addEventListener("click", hideDrawer);
    document.addEventListener("keydown", evt => {
      if (evt.key === "Escape") hideDrawer();
    });
  }
  const esc = s => (s == null ? "" : String(s).replace(/[<>&]/g,
    c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c])));
  const evRows = (e.evidence || []).map(ev => `
    <tr>
      <td><code>${esc(ev.tool)}</code> ${esc(ev.version)}</td>
      <td><code>${esc(ev.command)}</code></td>
      <td>sha256=<code>${esc(ev.output_sha256)}</code>…</td>
      <td><code>${esc(ev.output_path)}</code></td>
    </tr>`).join("");
  d.querySelector(".drawer-title").textContent =
    `${e.case_label || e.case_id || ""} · ${e.agent || ""} · ${e.conf || ""}`;
  d.querySelector(".drawer-body").innerHTML = `
    <div class="drawer-row"><b>Time:</b> ${esc(e.ts || "—")}</div>
    <div class="drawer-row"><b>finding_id:</b> <code>${esc(e.finding_id || "")}</code></div>
    <div class="drawer-row"><b>Hypotheses:</b> ${
      (e.hypotheses || []).length
        ? (e.hypotheses || []).map(h => `<code>${esc(h)}</code>`).join(" ")
        : "<span class='muted'>none</span>"
    }</div>
    <div class="drawer-row"><b>Red review:</b> ${esc(e.red_review_status || "—")}</div>
    <div class="drawer-claim">${esc(e.claim || "")}</div>
    ${evRows ? `<div class="drawer-row"><b>Evidence chain:</b></div>
        <table class="drawer-ev"><thead><tr>
          <th>Tool</th><th>Command</th><th>Hash</th><th>Output path</th>
        </tr></thead><tbody>${evRows}</tbody></table>`
      : "<div class='drawer-row muted'>No evidence items recorded.</div>"}
  `;
  d.classList.add("open");
}

function hideDrawer() {
  const d = document.getElementById("drawer");
  if (d) d.classList.remove("open");
}

function setupAttackToggles() {
  document.querySelectorAll(".att-row").forEach(row => {
    row.addEventListener("click", () => {
      const slug = row.getAttribute("data-att");
      const det = document.querySelector(
        `.att-details[data-att="${slug}"]`);
      if (!det) return;
      const open = det.style.display !== "none";
      det.style.display = open ? "none" : "table-row";
      const t = row.querySelector(".att-toggle");
      if (t) t.textContent = open ? "▸" : "▾";
    });
  });
  document.querySelectorAll(".att-fid-link").forEach(a => {
    a.addEventListener("click", evt => {
      evt.preventDefault();
      evt.stopPropagation();
      const fid = a.getAttribute("data-fid");
      const e = _eventByFid()[fid];
      if (e) showDrawer(e);
    });
  });
}

window.addEventListener("DOMContentLoaded", () => {
  setupTimelineToggle();
  renderTimeline();
  renderGraph();
  setupAttackToggles();
  window.addEventListener("resize", () => { renderTimeline(); renderGraph(); });
});
"""


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def render_combined_html(
    case_dirs: list[Path], out_path: Path, name: str = "combined-case",
    *, executive_pdf_path: Path | None = None,
) -> Path:
    """Render the combined multi-host HTML dashboard.

    *executive_pdf_path* (optional) — when supplied, the dashboard's top
    navigation gains a download icon linking to the per-bundle executive
    (non-technical) PDF. Mirrors the per-case ``case.html`` ↔ ``executive.pdf``
    pairing.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cases = [load_case(Path(d)) for d in case_dirs]
    if not cases:
        raise ValueError("no cases supplied")

    joint = _joint_ach(cases)
    techniques = _technique_union(cases)
    # Two timelines:
    #   * findings_timeline — artifact-time events (what the attacker
    #     did, WHEN it happened in the source data). Primary view.
    #   * processing_timeline — EL's per-finding created_utc (when EL
    #     analysed the artifact). Secondary view, toggle in the UI.
    findings_timeline = _timeline_events(cases, mode="findings")
    processing_timeline = _timeline_events(cases, mode="processing")
    lanes = [{"case_id": c.case_id, "host_label": c.host_label}
              for c in cases]
    graph = _merged_graph(cases)
    narrative = _combined_narrative(cases)

    total_findings = sum(len(c.findings) for c in cases)
    high_count = sum(1 for c in cases for f in c.findings
                     if f.get("confidence") == "high"
                     and f.get("agent") != "knowledge_lookup")

    data = {
        "name": name,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "lanes": lanes,
        "findings_timeline": findings_timeline,
        "processing_timeline": processing_timeline,
        "graph": graph,
        "counts": {"cases": len(cases),
                    "findings": total_findings,
                    "high": high_count,
                    "techniques": len(techniques),
                    "timestamped_findings": len(findings_timeline)},
    }
    data_json = json.dumps(data, separators=(",", ":"))

    # Server-rendered blocks
    ach_html = _joint_ach_html(cases, joint)
    sig_html = _signal_matrix_html(cases)
    clock_html = _clock_baselines_html(cases)
    attack_html = _attack_heatmap_html(techniques)
    ioc_html = _ioc_overlap_html(cases)
    hosts_html = _per_case_links_html(cases, out_path)

    # Narrative — intro + per-case blocks
    from el.reporting.narrative import evidence_time as _nar_time
    nar_blocks: list[str] = []
    for n in narrative["case_narratives"]:
        body_html = ""
        if n["body"]:
            # Minimal markdown → HTML conversion: bold, paragraphs, lists
            paras = []
            for para in n["body"].split("\n\n"):
                stripped = para.strip()
                if not stripped:
                    continue
                stripped = html.escape(stripped)
                stripped = stripped.replace("**", "__BOLD__")
                parts = stripped.split("__BOLD__")
                out = []
                for i, seg in enumerate(parts):
                    if i % 2 == 1:
                        out.append(f"<b>{seg}</b>")
                    else:
                        out.append(seg)
                paras.append(f"<p>{''.join(out)}</p>")
            body_html = "".join(paras)
        else:
            body_html = ("<p style='color:#8b949e'>No narrative.md was "
                         "rendered for this case. Run "
                         f"<code>el report /opt/EL/cases/{n['case_id']}</code> "
                         "to synthesize.</p>")
        nar_blocks.append(
            f"<div class='case-nar'>"
            f"<div class='case-nar-hdr'>"
            f"<code>{html.escape(n['case_id'])}</code> "
            f"— leading <b>{html.escape(n['leading_hid'])}</b> "
            f"(score={n['leading_score']})</div>"
            f"{body_html}</div>")

    intro_html = "<p>" + html.escape(narrative["intro"]).replace(
        "**", "").replace("\n\n", "</p><p>") + "</p>"
    # Restore bold markers we escaped
    intro_html = intro_html.replace("&lt;b&gt;", "<b>").replace(
        "&lt;/b&gt;", "</b>")
    # Quick fallback conversion: translate **x** in the raw intro to <b>x</b>
    import re as _re
    raw_intro = narrative["intro"]
    def _intro_md(s):
        s = html.escape(s)
        s = _re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', s)
        s = _re.sub(r'`([^`]+)`', r'<code>\1</code>', s)
        return "<p>" + s.replace("\n\n", "</p><p>") + "</p>"
    intro_html = _intro_md(raw_intro)

    js = _JS_TEMPLATE.replace("__DATA_JSON__", data_json)
    now = data["generated_utc"]
    counts = data["counts"]

    # Executive-PDF download icon for the top-bar — wired only when the
    # caller supplied a path AND the file actually exists. Use a relative
    # path so the rendered HTML is portable (analyst can copy the
    # combined/ dir anywhere).
    exec_link_html = ""
    if executive_pdf_path is not None:
        exec_pdf = Path(executive_pdf_path)
        if exec_pdf.is_file():
            try:
                rel = exec_pdf.relative_to(out_path.parent)
            except ValueError:
                rel = exec_pdf
            exec_link_html = (
                f"<a href='{html.escape(str(rel))}' download "
                "class='pdf-download' "
                "title='Download the combined executive (non-expert) "
                "report as PDF' "
                "aria-label='Download combined executive PDF'>"
                "<svg width='12' height='12' viewBox='0 0 16 16' "
                "fill='currentColor' aria-hidden='true'>"
                "<path d='M8 0a1 1 0 011 1v8.586l2.293-2.293a1 1 0 111.414 "
                "1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L7 "
                "9.586V1a1 1 0 011-1zM2 13a1 1 0 011 1v1h10v-1a1 1 0 "
                "112 0v2a1 1 0 01-1 1H2a1 1 0 01-1-1v-2a1 1 0 011-1z'/>"
                "</svg>Executive PDF</a>"
            )

    body = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>EL combined — {html.escape(name)}</title>
<style>{_CSS}</style>
</head><body>
<div class="stickyhdr">
<header class="topbar">
  <h1>EL Combined Report <span class="badge">{html.escape(name)}</span>{exec_link_html}</h1>
  <div class="meta">
    {counts['cases']} cases · {counts['findings']:,} findings
    ({counts['high']:,} high) · {counts['techniques']} ATT&amp;CK techniques ·
    generated {html.escape(now)} UTC
  </div>
</header>
<nav class="subnav">
  <a href="#narrative">Narrative</a>
  <a href="#hosts">Hosts</a>
  <a href="#clocks">Clock baselines</a>
  <a href="#ach">Joint ACH</a>
  <a href="#signals">Signal matrix</a>
  <a href="#timeline">Findings timeline</a>
  <a href="#graph">Graph</a>
  <a href="#attack">ATT&amp;CK</a>
  <a href="#iocs">IOC overlap</a>
</nav>
</div>
<main>

<section id="narrative">
  <h2>Combined Narrative</h2>
  <div class="narrative">
    <h3>Cross-host introduction</h3>
    {intro_html}
  </div>
  <div class="narrative" style="margin-top:16px">
    <h3>Per-case narratives (ordered by leading-hypothesis score)</h3>
    {''.join(nar_blocks)}
  </div>
</section>

<section id="hosts">
  <h2>Hosts &amp; drill-down</h2>
  {hosts_html}
</section>

<section id="clocks">
  <h2>Per-Host Clock Baselines</h2>
  <p style="color:#8b949e">
    Calibration data extracted from each host's SYSTEM hive + EWF
    acquisition header. <b>Document-only</b> — no timestamps are
    modified anywhere in the case data. Use this matrix when
    correlating local-time values across hosts (FAT / EXIF / Office
    metadata) or when a finding's wall-clock time needs to be
    trusted against an external reference.
  </p>
  {clock_html}
</section>

<section id="ach">
  <h2>Joint ACH Matrix</h2>
  <p style="color:#8b949e">Heatmap of ACH scores per hypothesis × case. Hover a cell for the exact score.</p>
  {ach_html}
</section>

<section id="signals">
  <h2>Cross-Host Signal Matrix</h2>
  <p style="color:#8b949e">Dotted cells mark the signal fired in that host's ledger.</p>
  {sig_html}
</section>

<section id="timeline">
  <h2>Unified Findings Timeline</h2>
  <p style="color:#8b949e">
    One swim-lane per case. Default view shows every finding on the
    <b>real-world attacker clock</b> (artifact timestamps mined from
    evidence <code>extracted_facts</code> — EID record times, file
    MACB times, logon timestamps, etc.). Toggle to <b>Processing
    clock</b> to see findings on EL's wall clock (when each finding
    was emitted during analysis). Dot colour = confidence
    (<span style="color:#f85149">high</span>,
    <span style="color:#d29922">medium</span>,
    <span style="color:#58a6ff">low</span>,
    <span style="color:#484f58">insufficient</span>). Hover for details.
  </p>
  <div style="margin-bottom:10px">
    <button class="tl-toggle active" data-tl-mode="findings">Real-world attacker clock</button>
    <button class="tl-toggle" data-tl-mode="processing">EL processing clock</button>
    <span id="tl-status" style="margin-left:14px;color:#8b949e;font-size:12px"></span>
  </div>
  <svg id="timeline-svg"></svg>
</section>

<section id="graph">
  <h2>Cross-Host Graph</h2>
  <p style="color:#8b949e">Merged entity graph from all per-case Kùzu stores. Node colour = origin case.</p>
  <div id="graph-pane">
    <svg id="graph-svg"></svg>
    <div id="graph-legend" class="graph-legend"></div>
  </div>
</section>

<section id="attack">
  <h2>MITRE ATT&amp;CK Coverage (Union)</h2>
  {attack_html}
</section>

<section id="iocs">
  <h2>Cross-Case IOC Overlap</h2>
  <p style="color:#8b949e">IOC values observed in ≥ 2 of the stitched cases (via <code>~/.el/knowledge.sqlite</code>).</p>
  {ioc_html}
</section>

</main>
<script>
/* Sync scroll-padding-top to the actual sticky-header height —
   the CSS fallback (130px) is a safe upper bound, but on wide
   layouts the real height is closer to 110px and unused
   padding makes anchor jumps land too low. Recalculate on load
   and on resize (the meta line can wrap → topbar grows). */
(function() {{
  function syncPad() {{
    var h = document.querySelector('.stickyhdr');
    if (!h) return;
    document.documentElement.style.scrollPaddingTop =
        h.getBoundingClientRect().height + 'px';
  }}
  syncPad();
  window.addEventListener('resize', syncPad);
  /* In case fonts load late and reflow the header. */
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(syncPad);
}})();
</script>
<script>{js}</script>
</body></html>"""
    out_path.write_text(body)
    return out_path

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
header.topbar { background: #161b22; border-bottom: 1px solid #30363d;
    padding: 12px 24px; position: sticky; top: 0; z-index: 20; }
header.topbar h1 { margin: 0; font-size: 18px; font-weight: 600; color: #f0f6fc; }
header.topbar h1 .badge { background: #58a6ff; color: #0d1117; padding: 2px 8px;
    border-radius: 10px; font-size: 12px; font-weight: 600; margin-left: 10px; }
header.topbar .meta { margin-top: 4px; font-size: 12px; color: #8b949e; }
nav.subnav { background: #161b22; border-bottom: 1px solid #30363d;
    padding: 6px 24px; position: sticky; top: 57px; z-index: 15; }
nav.subnav a { color: #8b949e; text-decoration: none; margin-right: 20px;
    font-size: 13px; padding: 4px 0; border-bottom: 2px solid transparent; }
nav.subnav a:hover { color: #58a6ff; border-bottom-color: #58a6ff; }
main { padding: 24px; max-width: 1800px; margin: 0 auto; }
section { margin-bottom: 40px; }
section h2 { color: #f0f6fc; font-size: 20px; font-weight: 600;
    border-bottom: 1px solid #30363d; padding-bottom: 8px; margin: 0 0 16px; }
section h3 { color: #f0f6fc; font-size: 16px; margin: 20px 0 8px; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
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

/* Signal matrix */
.sig-matrix table { min-width: 100%; }
.sig-matrix th.case { writing-mode: vertical-rl; transform: rotate(180deg);
    height: 120px; vertical-align: bottom; padding: 6px 4px;
    color: #c9d1d9; text-transform: none; letter-spacing: 0; font-size: 12px; }
.sig-matrix td.dot { text-align: center; font-size: 14px; color: #3fb950; }
.sig-matrix td.signame { color: #c9d1d9; font-weight: 500; }

/* Timeline swim-lane */
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
.edge-line { stroke: #30363d; stroke-opacity: 0.5; }
.edge-line:hover { stroke: #58a6ff; stroke-opacity: 1; }

/* ATT&CK heatmap — reuse simple table */
.attack-grid td { padding: 4px 8px; }
.attack-grid td.tid { color: #79c0ff; font-family: "SF Mono", monospace; }
.attack-grid td.bar { width: 40%; }
.attack-grid .bar-inner { height: 10px; background: linear-gradient(90deg, #2ea043, #f0883e, #f85149);
    border-radius: 2px; }

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


def _timeline_events(cases: list[CaseSlice]) -> list[dict]:
    """Flatten all findings into one event stream, one lane per case."""
    events = []
    for c in cases:
        for f in c.findings:
            ts = f.get("created_utc")
            if not ts:
                continue
            conf = f.get("confidence", "low")
            events.append({
                "case_id": c.case_id,
                "case_label": c.host_label,
                "ts": ts,
                "conf": conf,
                "agent": f.get("agent", ""),
                "finding_id": f.get("finding_id", ""),
                "claim": (f.get("claim") or "")[:220],
            })
    events.sort(key=lambda e: e["ts"])
    return events


def _merged_graph(cases: list[CaseSlice]) -> dict:
    """Union the per-case Kùzu graphs. Each node gets an `origin_case`
    attr so the renderer can colour-code by source host."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    capped = False
    total = 0
    for c in cases:
        try:
            g = export_graph(c.case_dir)
        except Exception:
            continue
        if (g.get("stats") or {}).get("capped"):
            capped = True
        total += (g.get("stats") or {}).get("total_nodes", 0)
        for n in g.get("nodes", []):
            # Prefix the node id with case_id to avoid cross-case clashes
            nid = f"{c.case_id}|{n['id']}"
            nodes[nid] = {
                **n, "id": nid, "origin_case": c.case_id,
                "origin_host": c.host_label,
            }
        for e in g.get("edges", []):
            edges.append({
                "from": f"{c.case_id}|{e['from']}",
                "to": f"{c.case_id}|{e['to']}",
                "type": e.get("type", ""),
                "origin_case": c.case_id,
            })
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {"total_nodes": total,
                  "merged_nodes": len(nodes),
                  "merged_edges": len(edges),
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
    hdr_cells = "".join(
        f"<th class='case'>{html.escape(h)}</th>" for h in header)
    rows_html = []
    for row in matrix[1:]:
        cells = [f"<td class='signame'>{html.escape(row[0])}</td>"]
        for cell in row[1:]:
            cells.append(f"<td class='dot'>{'•' if cell else ''}</td>")
        rows_html.append("<tr>" + "".join(cells) + "</tr>")
    return (f"<div class='sig-matrix'><table><thead><tr>{hdr_cells}</tr>"
            f"</thead><tbody>{''.join(rows_html)}</tbody></table></div>")


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
        rows.append(
            f"<tr><td class='tid'><a href='{url}' target='_blank'>{html.escape(tid)}</a></td>"
            f"<td>{html.escape(info.get('name',''))}</td>"
            f"<td class='num'>{len(info['cases'])}</td>"
            f"<td class='num'>{info['findings']}</td>"
            f"<td class='bar'><div class='bar-inner' style='width:{pct}%'></div></td></tr>"
        )
    return (f"<div class='attack-grid'><table>"
            f"<thead><tr><th>Technique</th><th>Name</th><th>Cases</th>"
            f"<th>Findings</th><th>Frequency</th></tr></thead>"
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


def _per_case_links_html(cases: list[CaseSlice]) -> str:
    rows = []
    for c in cases:
        case_html = c.case_dir / "reports" / "case.html"
        link_html = (f"<a href='{case_html}' target='_blank'>open case.html</a>"
                     if case_html.exists() else
                     "<span style='color:#8b949e'>case.html not rendered yet</span>")
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
function renderTimeline() {
  const svg = document.getElementById("timeline-svg");
  if (!svg) return;
  const events = DATA.timeline || [];
  if (!events.length) {
    svg.innerHTML = '<text x="20" y="40" class="tl-axis-text">No timestamped findings.</text>';
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
  // Deterministic layout: circle per case, concentric
  const casesList = DATA.lanes.map(l => l.case_id);
  const nodesByCase = {};
  casesList.forEach(cid => nodesByCase[cid] = []);
  g.nodes.forEach(n => {
    (nodesByCase[n.origin_case] = nodesByCase[n.origin_case] || []).push(n);
  });
  const W = svg.clientWidth || 1400, H = 560;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const CASE_COLOR = {};
  const PAL = ["#58a6ff","#f85149","#3fb950","#d29922","#bc8cff","#ff7b72","#79c0ff","#f0883e"];
  casesList.forEach((cid, i) => CASE_COLOR[cid] = PAL[i % PAL.length]);
  const cx = W/2, cy = H/2;
  const casesN = casesList.length;
  const pos = {};
  casesList.forEach((cid, ci) => {
    const caseAngle = (2*Math.PI * ci) / casesN;
    const caseCX = cx + Math.cos(caseAngle) * (Math.min(W,H) * 0.30);
    const caseCY = cy + Math.sin(caseAngle) * (Math.min(W,H) * 0.30);
    const cn = nodesByCase[cid] || [];
    cn.forEach((n, ni) => {
      const a = (2*Math.PI * ni) / Math.max(cn.length, 1);
      pos[n.id] = {
        x: caseCX + Math.cos(a) * (Math.min(W,H) * 0.10),
        y: caseCY + Math.sin(a) * (Math.min(W,H) * 0.10),
      };
    });
  });
  svg.innerHTML = "";
  const NS = "http://www.w3.org/2000/svg";
  // Edges first (so nodes paint on top)
  g.edges.slice(0, 2000).forEach(e => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    const line = document.createElementNS(NS, "line");
    line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
    line.setAttribute("class", "edge-line");
    svg.appendChild(line);
  });
  // Nodes
  g.nodes.forEach(n => {
    const p = pos[n.id]; if (!p) return;
    const c = document.createElementNS(NS, "circle");
    c.setAttribute("cx", p.x); c.setAttribute("cy", p.y);
    c.setAttribute("r", 4);
    c.setAttribute("fill", CASE_COLOR[n.origin_case] || "#8b949e");
    c.setAttribute("class", "node-circle");
    c.addEventListener("mouseenter", evt => showTT(evt, {
      ts: "", conf: "",
      agent: n.type, case_label: n.origin_host, claim: n.label || n.id,
    }));
    c.addEventListener("mouseleave", hideTT);
    svg.appendChild(c);
  });
  // Legend
  const legend = document.getElementById("graph-legend");
  if (legend) {
    legend.innerHTML = casesList.map(cid => {
      const lane = DATA.lanes.find(l => l.case_id === cid);
      return `<div><span class="sw" style="background:${CASE_COLOR[cid]}"></span>${lane ? lane.host_label : cid}</div>`;
    }).join("") +
    `<div style="margin-top:6px;color:#8b949e">${g.nodes.length} nodes · ${g.edges.length} edges${g.stats.capped ? ' · capped' : ''}</div>`;
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

window.addEventListener("DOMContentLoaded", () => {
  renderTimeline();
  renderGraph();
  window.addEventListener("resize", () => { renderTimeline(); renderGraph(); });
});
"""


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def render_combined_html(
    case_dirs: list[Path], out_path: Path, name: str = "combined-case",
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cases = [load_case(Path(d)) for d in case_dirs]
    if not cases:
        raise ValueError("no cases supplied")

    joint = _joint_ach(cases)
    techniques = _technique_union(cases)
    timeline = _timeline_events(cases)
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
        "timeline": timeline,
        "graph": graph,
        "counts": {"cases": len(cases),
                    "findings": total_findings,
                    "high": high_count,
                    "techniques": len(techniques)},
    }
    data_json = json.dumps(data, separators=(",", ":"))

    # Server-rendered blocks
    ach_html = _joint_ach_html(cases, joint)
    sig_html = _signal_matrix_html(cases)
    attack_html = _attack_heatmap_html(techniques)
    ioc_html = _ioc_overlap_html(cases)
    hosts_html = _per_case_links_html(cases)

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

    body = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>EL combined — {html.escape(name)}</title>
<style>{_CSS}</style>
</head><body>
<header class="topbar">
  <h1>EL Combined Report <span class="badge">{html.escape(name)}</span></h1>
  <div class="meta">
    {counts['cases']} cases · {counts['findings']:,} findings
    ({counts['high']:,} high) · {counts['techniques']} ATT&amp;CK techniques ·
    generated {html.escape(now)} UTC
  </div>
</header>
<nav class="subnav">
  <a href="#narrative">Narrative</a>
  <a href="#hosts">Hosts</a>
  <a href="#ach">Joint ACH</a>
  <a href="#signals">Signal matrix</a>
  <a href="#timeline">Timeline</a>
  <a href="#graph">Graph</a>
  <a href="#attack">ATT&amp;CK</a>
  <a href="#iocs">IOC overlap</a>
</nav>
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
  <h2>Unified Event Timeline</h2>
  <p style="color:#8b949e">One swim-lane per case. Dot colour = confidence (<span style="color:#f85149">high</span>, <span style="color:#d29922">medium</span>, <span style="color:#58a6ff">low</span>, <span style="color:#484f58">insufficient</span>). Hover for finding details.</p>
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
<script>{js}</script>
</body></html>"""
    out_path.write_text(body)
    return out_path

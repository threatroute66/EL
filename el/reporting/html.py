"""HTML case-report renderer — Tier 1 of docs/web-view-design.md.

Emits a single self-contained `case.html` alongside the Markdown report.
Same philosophy as `render.py`: deterministic projection of structured
Findings + ACH + IOCs + ATT&CK. No LLM. No server.

The output is one file — JSON data embedded as `<script type=
application/json>`, CSS and JS inlined. Opens directly in any modern
browser via `file://`, works inside a sealed tar.gz. No CDN, no build
step, no framework.

Sections (Tier 1):
  - Header: case-id, leading hypothesis, run metadata
  - Nav: jump-to-section links
  - ACH ranking: NodeZero-style horizontal bar chart
  - Findings grid: filterable by agent + confidence, click → detail drawer
  - IOC table: grouped by type
  - ATT&CK table: technique ID → finding count

Tier 2 (attack-chain graph from Kùzu) and Tier 3 (ATT&CK heatmap,
Diamond Model) are separate follow-up modules.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from el.intel.attack_tactics import TACTICS, group_by_tactic
from el.reporting.graph_export import export_graph
from el.schemas.finding import Finding


_CSS = """
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont,
    "Segoe UI", system-ui, sans-serif; }
body { background: #0d1117; color: #c9d1d9; line-height: 1.5; }
header.topbar { background: #161b22; border-bottom: 1px solid #30363d;
    padding: 12px 24px; position: sticky; top: 0; z-index: 10; }
header.topbar h1 { margin: 0; font-size: 18px; font-weight: 600; color: #f0f6fc; }
header.topbar h1 .case-id { font-family: "SF Mono", Menlo, Consolas, monospace;
    color: #58a6ff; font-weight: 500; margin-left: 10px; }
header.topbar .meta { margin-top: 4px; font-size: 12px; color: #8b949e; }
header.topbar .meta .lead { color: #f85149; font-weight: 600; }
header.topbar nav { margin-top: 10px; }
header.topbar nav a { color: #58a6ff; text-decoration: none; margin-right: 18px;
    font-size: 13px; font-weight: 500; padding: 4px 10px; border-radius: 6px; }
header.topbar nav a:hover { background: #21262d; }
main { padding: 24px; max-width: 1200px; margin: 0 auto; }
section { margin-bottom: 48px; }
section h2 { color: #f0f6fc; border-bottom: 1px solid #30363d; padding-bottom: 8px;
    font-size: 20px; font-weight: 600; }
section h2 .count { font-size: 13px; color: #8b949e; font-weight: 400; margin-left: 10px; }

/* Summary grid */
.summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
    margin-top: 16px; }
.summary-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    padding: 14px; }
.summary-card .k { font-size: 11px; color: #8b949e; text-transform: uppercase;
    letter-spacing: 0.05em; }
.summary-card .v { font-size: 24px; color: #f0f6fc; font-weight: 600; margin-top: 4px; }
.summary-card.high .v { color: #f85149; }
.summary-card.medium .v { color: #d29922; }
.summary-card.low .v { color: #58a6ff; }
.summary-card.insufficient .v { color: #8b949e; }

/* ACH ranking */
.ach-row { display: grid; grid-template-columns: 40px 220px 1fr 80px;
    gap: 12px; align-items: center; padding: 6px 0; border-bottom: 1px solid #21262d; }
.ach-rank { font-family: monospace; color: #8b949e; text-align: right; }
.ach-hyp { font-weight: 500; }
.ach-hyp .hid { font-family: monospace; color: #8b949e; font-size: 11px;
    margin-left: 6px; }
.ach-bar { background: #21262d; border-radius: 4px; height: 20px; position: relative;
    overflow: hidden; }
.ach-bar .fill { background: #238636; height: 100%; border-radius: 4px;
    transition: width 0.25s ease; }
.ach-bar.lead .fill { background: #f85149; }
.ach-score { text-align: right; font-family: monospace; color: #f0f6fc; }

/* Findings filter bar */
.filters { display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0; padding: 12px;
    background: #161b22; border: 1px solid #30363d; border-radius: 6px; }
.filter-group { display: flex; gap: 4px; align-items: center; }
.filter-group label { color: #8b949e; font-size: 12px; margin-right: 6px; }
.filter-chip { background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
    padding: 4px 10px; border-radius: 14px; cursor: pointer; font-size: 12px;
    user-select: none; }
.filter-chip.active { background: #1f6feb; border-color: #1f6feb; color: white; }
.filter-chip:hover { background: #30363d; }
.filter-chip.active:hover { background: #1158c7; }

/* Findings list */
.findings-list { display: flex; flex-direction: column; gap: 6px; }
.finding { background: #161b22; border: 1px solid #30363d; border-left: 3px solid #8b949e;
    border-radius: 4px; padding: 10px 14px; cursor: pointer; transition: background 0.1s; }
.finding:hover { background: #1c2128; border-color: #484f58; }
.finding.conf-high { border-left-color: #f85149; }
.finding.conf-medium { border-left-color: #d29922; }
.finding.conf-low { border-left-color: #58a6ff; }
.finding.conf-insufficient { border-left-color: #484f58; opacity: 0.75; }
.finding .row1 { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; }
.finding .agent { color: #7ee787; font-family: monospace; font-size: 12px;
    font-weight: 500; }
.finding .fid { color: #484f58; font-family: monospace; font-size: 10px; }
.finding .claim { margin-top: 4px; color: #e6edf3; }
.finding .tags { margin-top: 6px; display: flex; gap: 6px; flex-wrap: wrap; }
.finding .tag { background: #21262d; color: #8b949e; padding: 2px 8px; border-radius: 10px;
    font-size: 11px; font-family: monospace; }
.finding .tag.supports { background: #0d4429; color: #7ee787; }
.finding .tag.refutes { background: #4a1111; color: #ff9d8d; }

/* IOC table */
table.ioc { width: 100%; border-collapse: collapse; margin-top: 16px; }
table.ioc th { text-align: left; padding: 8px 12px; background: #161b22;
    color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em;
    border-bottom: 1px solid #30363d; }
table.ioc td { padding: 6px 12px; border-bottom: 1px solid #21262d;
    font-family: monospace; font-size: 12px; }
table.ioc td.type { color: #7ee787; width: 100px; }
table.ioc td.value { color: #e6edf3; word-break: break-all; }

/* ATT&CK table */
table.attack { width: 100%; border-collapse: collapse; margin-top: 16px; }
table.attack th { text-align: left; padding: 8px 12px; background: #161b22;
    color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em;
    border-bottom: 1px solid #30363d; }
table.attack td { padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 13px; }
table.attack td.tid { font-family: monospace; color: #58a6ff; width: 120px; }
table.attack td.tid a { color: #58a6ff; text-decoration: none; }
table.attack td.tid a:hover { text-decoration: underline; }

/* Detail drawer */
aside.drawer { position: fixed; top: 0; right: 0; width: 520px; height: 100vh;
    background: #0d1117; border-left: 1px solid #30363d; padding: 24px; overflow-y: auto;
    transform: translateX(100%); transition: transform 0.2s ease; z-index: 20;
    box-shadow: -4px 0 16px rgba(0,0,0,0.5); }
aside.drawer.open { transform: translateX(0); }
aside.drawer .close-btn { background: transparent; border: 1px solid #30363d;
    color: #c9d1d9; padding: 4px 12px; border-radius: 4px; cursor: pointer; float: right; }
aside.drawer .close-btn:hover { background: #21262d; }
aside.drawer h3 { margin: 0; color: #f0f6fc; font-size: 15px; }
aside.drawer .sub { color: #8b949e; font-size: 12px; font-family: monospace; margin-top: 4px; }
aside.drawer .field { margin-top: 16px; }
aside.drawer .field .label { color: #8b949e; font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.05em; margin-bottom: 4px; }
aside.drawer .field .val { color: #e6edf3; word-break: break-word; }
aside.drawer .evidence-item { background: #161b22; border: 1px solid #30363d; border-radius: 4px;
    padding: 10px; margin-top: 6px; font-size: 12px; font-family: monospace; }
aside.drawer .evidence-item .cmd { color: #7ee787; }
aside.drawer .evidence-item .sha { color: #484f58; font-size: 11px; margin-top: 4px; }

/* ATT&CK heatmap (Tier 3) */
.attack-heatmap { display: grid; gap: 12px; margin-top: 16px; }
.tactic-col { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    padding: 10px 12px; }
.tactic-col h3 { margin: 0 0 8px 0; font-size: 12px; color: #8b949e;
    text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }
.tactic-col .tcount { color: #f0f6fc; margin-left: 4px; font-size: 11px;
    background: #21262d; padding: 1px 6px; border-radius: 8px; }
.tactic-col .t-row { display: flex; align-items: center; gap: 8px;
    padding: 4px 0; border-bottom: 1px dotted #21262d; font-size: 12px; }
.tactic-col .t-row:last-child { border-bottom: 0; }
.tactic-col .t-row .tid { font-family: monospace; color: #58a6ff; width: 90px; flex: 0 0 90px; }
.tactic-col .t-row .tname { color: #c9d1d9; flex: 1; }
.tactic-col .t-row .fcount { font-family: monospace; color: #f0f6fc;
    background: #238636; padding: 1px 8px; border-radius: 4px; font-size: 11px; }
.tactic-col .t-row .fcount.heat1 { background: #0d4429; }
.tactic-col .t-row .fcount.heat2 { background: #238636; }
.tactic-col .t-row .fcount.heat3 { background: #d29922; color: #0d1117; }
.tactic-col .t-row .fcount.heat4 { background: #f85149; }

/* Diamond Model (Tier 3) */
.diamond { display: grid; grid-template-columns: 1fr 1fr; gap: 12px;
    margin-top: 16px; }
.diamond .vertex { background: #161b22; border: 1px solid #30363d;
    border-radius: 6px; padding: 14px; position: relative; }
.diamond .vertex h3 { margin: 0 0 4px 0; color: #f0f6fc; font-size: 14px; }
.diamond .vertex .sub { font-size: 11px; color: #8b949e; margin-bottom: 10px; }
.diamond .vertex ul { margin: 0; padding-left: 16px; font-size: 12px; color: #c9d1d9; }
.diamond .vertex li { font-family: monospace; margin-bottom: 3px;
    word-break: break-all; }
.diamond .vertex.adversary { border-left: 3px solid #f85149; }
.diamond .vertex.capability { border-left: 3px solid #d29922; }
.diamond .vertex.infrastructure { border-left: 3px solid #58a6ff; }
.diamond .vertex.victim { border-left: 3px solid #7ee787; }
.diamond .empty { color: #8b949e; font-style: italic; font-size: 12px; }

/* Graph pane */
#graph-pane { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    height: 560px; margin-top: 16px; position: relative; overflow: hidden; }
#graph-pane svg { width: 100%; height: 100%; cursor: grab; display: block; }
#graph-pane svg:active { cursor: grabbing; }
#graph-pane .empty { color: #8b949e; text-align: center; padding: 220px 24px;
    font-size: 13px; }
#graph-pane .legend { position: absolute; top: 10px; right: 10px;
    background: rgba(13, 17, 23, 0.88); border: 1px solid #30363d;
    border-radius: 4px; padding: 8px 10px; font-size: 11px; color: #8b949e; }
#graph-pane .legend .sw { display: inline-block; width: 10px; height: 10px;
    border-radius: 50%; margin-right: 6px; vertical-align: middle; }
#graph-pane .controls { position: absolute; top: 10px; left: 10px;
    display: flex; gap: 6px; }
#graph-pane .controls button { background: #21262d; color: #c9d1d9;
    border: 1px solid #30363d; border-radius: 4px; padding: 4px 10px;
    font-size: 12px; cursor: pointer; }
#graph-pane .controls button:hover { background: #30363d; }
#graph-pane text { font-family: -apple-system, system-ui, sans-serif;
    font-size: 10px; fill: #c9d1d9; pointer-events: none; }
#graph-pane circle { cursor: pointer; stroke: #0d1117; stroke-width: 1.5; }
#graph-pane circle:hover { stroke: #f0f6fc; stroke-width: 2; }
#graph-pane circle.selected { stroke: #f85149; stroke-width: 3; }
#graph-pane line { stroke: #30363d; stroke-opacity: 0.6; }

/* Hidden sections */
section[hidden] { display: none !important; }

/* Footer */
footer { margin-top: 64px; padding: 16px 24px; color: #484f58; font-size: 11px;
    text-align: center; border-top: 1px solid #21262d; }
"""


_JS = r"""
(function(){
  const data = JSON.parse(document.getElementById("data").textContent);
  const findingsById = Object.fromEntries(data.findings.map(f => [f.finding_id, f]));
  let activeAgent = "all";
  let activeConf = "all";

  // ----- Tier 4: live-update mode --------------------------------------
  // Opt-in via ?watch=N (seconds; default 3) or ?watch=1. Plain reload —
  // matches the design doc's "static-served, no websockets" constraint.
  // When `el report --html --watch` is running on the same case dir, the
  // page content updates on every ledger change.
  function startWatch() {
    const params = new URLSearchParams(window.location.search);
    const raw = params.get("watch");
    if (raw === null) return;
    let interval = parseFloat(raw);
    if (!(interval > 0) || interval < 1) interval = 3;
    const badge = document.createElement("span");
    badge.id = "watch-badge";
    badge.textContent = "LIVE · " + interval + "s";
    badge.style.cssText = "background:#f85149;color:white;font-size:11px;font-weight:600;padding:2px 8px;border-radius:10px;margin-left:10px;letter-spacing:0.03em;";
    const h1 = document.querySelector("header.topbar h1");
    if (h1) h1.appendChild(badge);
    let counter = Math.floor(interval);
    const tick = document.createElement("span");
    tick.id = "watch-tick";
    tick.style.cssText = "color:#8b949e;font-size:11px;margin-left:8px;font-family:monospace;";
    if (h1) h1.appendChild(tick);
    function update() {
      tick.textContent = "reload in " + counter + "s";
      counter -= 1;
      if (counter < 0) { window.location.reload(); return; }
      setTimeout(update, 1000);
    }
    update();
  }
  startWatch();

  // ----- Attack-chain graph (Tier 2) ------------------------------------
  const NODE_COLORS = {
    Host: "#58a6ff", User: "#d2a8ff", Process: "#7ee787",
    File: "#ffa657", IPAddress: "#ff7b72", Domain: "#79c0ff",
    Hash: "#8b949e", NetworkFlow: "#f0883e", Event: "#d29922",
    RegistryKey: "#bc8cff",
  };

  function renderGraph() {
    const pane = document.getElementById("graph-pane");
    if (!pane) return;
    const g = data.graph || {nodes: [], edges: [], stats: {total_nodes:0}};
    if (!g.nodes.length) {
      pane.innerHTML = '<div class="empty">No entities in this case\'s Kùzu graph yet. Agents that populate the graph (NetworkAnalyst, MemoryForensicator, LogAnalyst) haven\'t produced nodes for this evidence type.</div>';
      return;
    }
    const W = pane.clientWidth, H = pane.clientHeight;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
    pane.innerHTML = "";
    pane.appendChild(svg);

    // Legend
    const typesPresent = Array.from(new Set(g.nodes.map(n => n.type))).sort();
    const legend = document.createElement("div");
    legend.className = "legend";
    legend.innerHTML = `<div><b>${g.nodes.length}</b> nodes · <b>${g.edges.length}</b> edges${g.stats.capped ? ' · <span style="color:#d29922">capped from '+g.stats.total_nodes+'</span>' : ''}</div>` +
      typesPresent.map(t => `<div><span class="sw" style="background:${NODE_COLORS[t]||"#8b949e"}"></span>${t}</div>`).join("");
    pane.appendChild(legend);

    // Init node positions in a circle
    const nodes = g.nodes.map((n, i) => {
      const angle = (2 * Math.PI * i) / g.nodes.length;
      const r = Math.min(W, H) * 0.35;
      return {...n, x: W/2 + r*Math.cos(angle), y: H/2 + r*Math.sin(angle),
              vx: 0, vy: 0};
    });
    const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
    const edges = g.edges.filter(e => nodeById[e.from] && nodeById[e.to]);

    // Degree-based radius (more connections = bigger)
    const degree = {};
    edges.forEach(e => {
      degree[e.from] = (degree[e.from]||0) + 1;
      degree[e.to] = (degree[e.to]||0) + 1;
    });
    nodes.forEach(n => {
      n.r = Math.min(16, 4 + Math.sqrt(degree[n.id]||0) * 2);
    });

    // SVG elements
    const gEdges = document.createElementNS("http://www.w3.org/2000/svg", "g");
    const gNodes = document.createElementNS("http://www.w3.org/2000/svg", "g");
    const gLabels = document.createElementNS("http://www.w3.org/2000/svg", "g");
    svg.appendChild(gEdges); svg.appendChild(gNodes); svg.appendChild(gLabels);

    const lineEls = edges.map(e => {
      const l = document.createElementNS("http://www.w3.org/2000/svg", "line");
      gEdges.appendChild(l);
      return l;
    });
    const circleEls = nodes.map(n => {
      const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      c.setAttribute("r", n.r);
      c.setAttribute("fill", NODE_COLORS[n.type] || "#8b949e");
      c.addEventListener("click", (ev) => { ev.stopPropagation(); selectNode(n); });
      gNodes.appendChild(c);
      return c;
    });
    const labelEls = nodes.map(n => {
      const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
      t.setAttribute("text-anchor", "start");
      t.textContent = (n.label || "").slice(0, 24);
      gLabels.appendChild(t);
      return t;
    });

    function selectNode(n) {
      circleEls.forEach(c => c.classList.remove("selected"));
      const idx = nodes.indexOf(n);
      if (idx >= 0) circleEls[idx].classList.add("selected");
      openNodeDrawer(n);
    }

    // Simple force-directed step
    const LINK_DIST = 70, LINK_K = 0.02, REPEL = 1200, CENTER_K = 0.005,
          DAMP = 0.82, STEPS = 180;
    function step() {
      for (let i=0; i<nodes.length; i++) {
        for (let j=i+1; j<nodes.length; j++) {
          const a=nodes[i], b=nodes[j];
          const dx=b.x-a.x, dy=b.y-a.y;
          let d2 = dx*dx+dy*dy; if (d2<1) d2=1;
          const f = REPEL / d2;
          const d = Math.sqrt(d2);
          const fx = (dx/d)*f, fy = (dy/d)*f;
          a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
        }
      }
      edges.forEach(e => {
        const a=nodeById[e.from], b=nodeById[e.to];
        const dx=b.x-a.x, dy=b.y-a.y;
        const d=Math.sqrt(dx*dx+dy*dy)||1;
        const f = (d - LINK_DIST) * LINK_K;
        const fx=(dx/d)*f, fy=(dy/d)*f;
        a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
      });
      nodes.forEach(n => {
        n.vx += (W/2 - n.x) * CENTER_K;
        n.vy += (H/2 - n.y) * CENTER_K;
        n.vx *= DAMP; n.vy *= DAMP;
        n.x += n.vx; n.y += n.vy;
      });
    }
    function draw() {
      nodes.forEach((n, i) => {
        circleEls[i].setAttribute("cx", n.x);
        circleEls[i].setAttribute("cy", n.y);
        labelEls[i].setAttribute("x", n.x + n.r + 2);
        labelEls[i].setAttribute("y", n.y + 3);
      });
      edges.forEach((e, i) => {
        const a=nodeById[e.from], b=nodeById[e.to];
        lineEls[i].setAttribute("x1", a.x);
        lineEls[i].setAttribute("y1", a.y);
        lineEls[i].setAttribute("x2", b.x);
        lineEls[i].setAttribute("y2", b.y);
      });
    }
    for (let s=0; s<STEPS; s++) step();
    draw();

    // Pan + zoom
    let viewX=0, viewY=0, viewK=1, dragging=false, dragX=0, dragY=0;
    function applyView() {
      gEdges.setAttribute("transform", `translate(${viewX},${viewY}) scale(${viewK})`);
      gNodes.setAttribute("transform", `translate(${viewX},${viewY}) scale(${viewK})`);
      gLabels.setAttribute("transform", `translate(${viewX},${viewY}) scale(${viewK})`);
    }
    svg.addEventListener("mousedown", e => { dragging=true; dragX=e.clientX; dragY=e.clientY; });
    svg.addEventListener("mousemove", e => {
      if (!dragging) return;
      viewX += (e.clientX - dragX); viewY += (e.clientY - dragY);
      dragX=e.clientX; dragY=e.clientY; applyView();
    });
    svg.addEventListener("mouseup", () => dragging=false);
    svg.addEventListener("mouseleave", () => dragging=false);
    svg.addEventListener("wheel", e => {
      e.preventDefault();
      const k = e.deltaY < 0 ? 1.1 : 0.9;
      viewK = Math.max(0.2, Math.min(5, viewK * k));
      applyView();
    });

    // Controls
    const controls = document.createElement("div");
    controls.className = "controls";
    controls.innerHTML = '<button id="graph-reset">Reset view</button>';
    pane.appendChild(controls);
    document.getElementById("graph-reset").addEventListener("click", () => {
      viewX=0; viewY=0; viewK=1; applyView();
    });
  }

  function openNodeDrawer(n) {
    const d = document.getElementById("drawer");
    const body = document.getElementById("drawer-body");
    const attrs = Object.entries(n.attrs || {}).map(([k,v]) =>
      `<div class="field"><div class="label">${esc(k)}</div><div class="val">${esc(String(v))}</div></div>`).join("");
    body.innerHTML = `
      <h3>${esc(n.label || n.id)}</h3>
      <div class="sub">${esc(n.type)} · ${esc(n.id)}</div>
      ${attrs}
      <div class="field"><div class="label">Source</div><div class="val">Kùzu entity graph (graph.kuzu)</div></div>`;
    d.classList.add("open");
  }

  // Render findings list
  function renderFindings() {
    const list = document.getElementById("findings-list");
    list.innerHTML = "";
    const filtered = data.findings.filter(f =>
      (activeAgent === "all" || f.agent === activeAgent) &&
      (activeConf === "all" || f.confidence === activeConf)
    );
    document.getElementById("findings-count").textContent = `${filtered.length} shown / ${data.findings.length} total`;
    filtered.forEach(f => {
      const el = document.createElement("div");
      el.className = `finding conf-${f.confidence}`;
      el.dataset.fid = f.finding_id;
      const supports = f.hypotheses_supported.map(h => `<span class="tag supports">+${h}</span>`).join("");
      const refutes = f.hypotheses_refuted.map(h => `<span class="tag refutes">-${h}</span>`).join("");
      el.innerHTML = `
        <div class="row1">
          <span class="agent">${esc(f.agent)}</span>
          <span class="fid">${esc(f.finding_id)}</span>
        </div>
        <div class="claim">${esc(f.claim)}</div>
        <div class="tags">
          <span class="tag">${esc(f.confidence)}</span>
          ${supports}${refutes}
        </div>`;
      el.addEventListener("click", () => openDrawer(f));
      list.appendChild(el);
    });
  }

  function esc(s){ return String(s).replace(/[&<>"']/g, c => (
    {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }

  function openDrawer(f) {
    const d = document.getElementById("drawer");
    const body = document.getElementById("drawer-body");
    const evidenceHtml = (f.evidence || []).map(e => `
      <div class="evidence-item">
        <div class="cmd">${esc(e.tool)} ${esc(e.version)} — ${esc(e.command)}</div>
        <div class="sha">sha256=${esc((e.output_sha256 || "").slice(0,16))}… path=${esc(e.output_path || "")}</div>
      </div>`).join("");
    body.innerHTML = `
      <h3>${esc(f.claim)}</h3>
      <div class="sub">${esc(f.finding_id)} · ${esc(f.agent)} · ${esc(f.confidence)}</div>
      <div class="field"><div class="label">Created (UTC)</div><div class="val">${esc(f.created_utc || "")}</div></div>
      ${f.hypotheses_supported.length ? `<div class="field"><div class="label">Supports</div><div class="val">${f.hypotheses_supported.map(esc).join(", ")}</div></div>` : ""}
      ${f.hypotheses_refuted.length ? `<div class="field"><div class="label">Refutes</div><div class="val">${f.hypotheses_refuted.map(esc).join(", ")}</div></div>` : ""}
      ${evidenceHtml ? `<div class="field"><div class="label">Evidence (${f.evidence.length})</div>${evidenceHtml}</div>` : ""}
      ${f.red_review ? `<div class="field"><div class="label">Red Review</div><div class="val">status=${esc(f.red_review.status || "")} ${f.red_review.challenger_notes ? "— " + esc(f.red_review.challenger_notes) : ""}</div></div>` : ""}`;
    d.classList.add("open");
    history.replaceState(null, "", "#" + f.finding_id);
  }

  function closeDrawer() {
    document.getElementById("drawer").classList.remove("open");
    history.replaceState(null, "", window.location.pathname);
  }

  // Wire up filter chips
  document.querySelectorAll(".filter-chip").forEach(c => {
    c.addEventListener("click", () => {
      const group = c.dataset.group;
      const val = c.dataset.val;
      document.querySelectorAll(`.filter-chip[data-group="${group}"]`).forEach(x => x.classList.remove("active"));
      c.classList.add("active");
      if (group === "agent") activeAgent = val;
      if (group === "conf") activeConf = val;
      renderFindings();
    });
  });

  document.getElementById("close-drawer").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

  renderFindings();
  renderGraph();

  // Deep-link: case.html#<finding_id> opens drawer
  if (window.location.hash) {
    const fid = window.location.hash.slice(1);
    if (findingsById[fid]) openDrawer(findingsById[fid]);
  }
})();
"""


def _heat_class(n: int) -> str:
    if n <= 1:   return "heat1"
    if n <= 3:   return "heat2"
    if n <= 8:   return "heat3"
    return "heat4"


def _build_attack_heatmap_html(techniques: dict[str, dict]) -> str:
    """Group the case's ATT&CK techniques by primary tactic and render
    a tactic-per-column grid. Each cell shows technique id, name, and
    finding count — heat-coloured by finding count."""
    if not techniques:
        return '<p style="color:#8b949e">No MITRE ATT&amp;CK techniques tagged on any finding.</p>'
    grouped = group_by_tactic(techniques)
    cols: list[str] = []
    for tactic, items in grouped.items():
        total = sum(len(info.get("evidence_finding_ids", []))
                     for _tid, info in items)
        rows: list[str] = []
        for tid, info in items:
            n = len(info.get("evidence_finding_ids", []))
            name = info.get("name", "")
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            rows.append(
                f'<div class="t-row">'
                f'<span class="tid"><a href="{html.escape(url)}" '
                f'target="_blank" rel="noopener">{html.escape(tid)}</a></span>'
                f'<span class="tname">{html.escape(name)}</span>'
                f'<span class="fcount {_heat_class(n)}">{n}</span>'
                f'</div>'
            )
        cols.append(
            f'<div class="tactic-col"><h3>{html.escape(tactic)}'
            f'<span class="tcount">{total}</span></h3>'
            + "".join(rows) + '</div>'
        )
    return f'<div class="attack-heatmap">{"".join(cols)}</div>'


def _build_diamond_html(
    findings: list[Finding], ach_ranking: list,
    iocs: dict[str, list[str]] | None, manifest: dict | None,
) -> str:
    """Diamond Model view for the leading hypothesis. Reuses the
    projection logic from el.reporting.diamond (public IPs/domains
    → Adversary + Infrastructure, technique IDs → Capability,
    local hosts/users → Victim)."""
    import ipaddress
    from collections import Counter
    if not ach_ranking:
        return ('<p style="color:#8b949e">No ACH ranking yet — Diamond '
                 'view renders for the leading hypothesis once the '
                 'ACH engine has produced one.</p>')
    leader = ach_ranking[0]
    leader_hyp = leader.hyp_id
    supporting = [f for f in findings
                   if leader_hyp in f.hypotheses_supported]
    # Adversary + Infrastructure from IOCs
    pub_ips: set[str] = set()
    int_ips: set[str] = set()
    domains: set[str] = set()
    for v in (iocs or {}).get("ipv4", []) + (iocs or {}).get("ipv6", []):
        try:
            ip = ipaddress.ip_address(v)
            (int_ips if (ip.is_private or ip.is_loopback
                         or ip.is_link_local) else pub_ips).add(v)
        except ValueError:
            continue
    for d in (iocs or {}).get("domain", []):
        domains.add(d)
    # Capability from technique IDs on supporting findings
    tech_counter: Counter = Counter()
    for f in supporting:
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            for tid in facts.get("attack_techniques") or []:
                tech_counter[str(tid)] += 1
            for tid in facts.get("attack_techniques_list") or []:
                tech_counter[str(tid)] += 1
    # Victim from manifest + principals in findings
    victim_hosts: set[str] = set()
    victim_users: set[str] = set()
    if manifest and manifest.get("case_id"):
        victim_hosts.add(str(manifest["case_id"]))
    for f in supporting:
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            for key in ("top_principals", "top_targets", "top_sources"):
                for item in facts.get(key) or []:
                    if isinstance(item, (list, tuple)) and item:
                        name = str(item[0])
                        if "@" in name or "\\" in name or name.lower().startswith("s-1-"):
                            victim_users.add(name)

    def _ul(items, cap=20):
        if not items:
            return '<div class="empty">_no entries surfaced yet_</div>'
        shown = list(items)[:cap]
        rest = len(items) - len(shown)
        tail = f'<li>… +{rest} more</li>' if rest > 0 else ""
        return "<ul>" + "".join(f"<li>{html.escape(str(x))}</li>"
                                 for x in shown) + tail + "</ul>"

    lead_label = (f'{html.escape(leader.name)} '
                   f'({html.escape(leader.hyp_id)}, score {leader.score})')
    return f"""
<p style="color:#8b949e;margin-bottom:8px">Projection for leading hypothesis <b>{lead_label}</b> — {len(supporting)} supporting finding(s). Not attribution to a named actor; the Adversary vertex is the public attribution surface (public IPs + domains) observed in supporting findings.</p>
<div class="diamond">
  <div class="vertex adversary"><h3>Adversary</h3>
    <div class="sub">public attribution surface — external IPs + domains</div>
    {_ul(sorted(pub_ips | domains))}
  </div>
  <div class="vertex capability"><h3>Capability</h3>
    <div class="sub">MITRE ATT&amp;CK techniques on supporting findings</div>
    {_ul([f"{t} (×{n})" for t, n in tech_counter.most_common(20)])}
  </div>
  <div class="vertex infrastructure"><h3>Infrastructure</h3>
    <div class="sub">pivot points — internal + external IPs + domains</div>
    {_ul(sorted(int_ips) + sorted(pub_ips) + sorted(domains))}
  </div>
  <div class="vertex victim"><h3>Victim</h3>
    <div class="sub">local hosts + principals named in findings</div>
    {_ul(sorted(victim_hosts) + sorted(victim_users))}
  </div>
</div>"""


def _finding_to_dict(f: Finding) -> dict:
    return {
        "finding_id": f.finding_id,
        "case_id": f.case_id,
        "agent": f.agent,
        "claim": f.claim,
        "confidence": f.confidence,
        "evidence": [
            {"tool": e.tool, "version": e.version, "command": e.command,
             "output_sha256": e.output_sha256, "output_path": e.output_path}
            for e in f.evidence
        ],
        "hypotheses_supported": list(f.hypotheses_supported),
        "hypotheses_refuted": list(f.hypotheses_refuted),
        "red_review": {
            "status": f.red_review.status,
            "challenger_notes": f.red_review.challenger_notes or "",
        } if f.red_review else None,
        "created_utc": f.created_utc.isoformat()
                          if getattr(f, "created_utc", None) else "",
    }


def render_html(
    case_dir: str | Path, case_id: str, manifest: dict,
    findings: list[Finding],
    ach_ranking: list | None = None,
    iocs: dict[str, list[str]] | None = None,
    techniques: dict[str, dict] | None = None,
    graph: dict | None = None,
) -> Path:
    case_dir = Path(case_dir)
    reports = case_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    out_path = reports / "case.html"

    ach_ranking = ach_ranking or []
    iocs = iocs or {}
    techniques = techniques or {}
    # Export Kùzu graph on demand when not supplied (Tier 2).
    if graph is None:
        try:
            graph = export_graph(case_dir)
        except Exception:
            graph = {"nodes": [], "edges": [], "stats": {"total_nodes": 0}}

    by_conf: dict[str, int] = {"high": 0, "medium": 0, "low": 0,
                                 "insufficient": 0}
    agents: set[str] = set()
    for f in findings:
        by_conf[f.confidence] = by_conf.get(f.confidence, 0) + 1
        agents.add(f.agent)
    agents_sorted = sorted(agents)

    leading = ach_ranking[0] if ach_ranking else None
    max_score = max((r.score for r in ach_ranking), default=1) or 1

    data = {
        "case_id": case_id,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "manifest": {k: str(v) for k, v in manifest.items()},
        "findings": [_finding_to_dict(f) for f in findings],
        "graph": graph,
    }
    data_json = json.dumps(data, separators=(",", ":"))

    # Build ACH ranking HTML (server-rendered; it's static)
    ach_rows: list[str] = []
    for i, r in enumerate(ach_ranking, 1):
        pct = int(100 * r.score / max_score) if r.score > 0 else 0
        lead_cls = " lead" if i == 1 and r.score > 0 else ""
        ach_rows.append(
            f'<div class="ach-row"><div class="ach-rank">{i}</div>'
            f'<div class="ach-hyp">{html.escape(r.name)}'
            f'<span class="hid">{html.escape(r.hyp_id)}</span></div>'
            f'<div class="ach-bar{lead_cls}">'
            f'<div class="fill" style="width: {pct}%"></div></div>'
            f'<div class="ach-score">{r.score}</div></div>'
        )
    ach_html = "\n".join(ach_rows) or (
        '<p style="color:#8b949e">No hypotheses ranked yet.</p>')

    # Filter chips
    agent_chips = (
        '<span class="filter-chip active" data-group="agent" '
        'data-val="all">all</span>'
    )
    for a in agents_sorted:
        agent_chips += (
            f'<span class="filter-chip" data-group="agent" '
            f'data-val="{html.escape(a)}">{html.escape(a)}</span>'
        )
    conf_chips = ""
    for c in ("all", "high", "medium", "low", "insufficient"):
        active = " active" if c == "all" else ""
        conf_chips += (
            f'<span class="filter-chip{active}" data-group="conf" '
            f'data-val="{c}">{c}</span>'
        )

    # IOC table
    ioc_rows: list[str] = []
    for t in sorted(iocs.keys()):
        for v in iocs[t]:
            ioc_rows.append(
                f'<tr><td class="type">{html.escape(t)}</td>'
                f'<td class="value">{html.escape(v)}</td></tr>'
            )
    ioc_count = sum(len(v) for v in iocs.values())
    ioc_html = (
        '<table class="ioc"><thead><tr><th>Type</th><th>Value</th></tr>'
        '</thead><tbody>' + "\n".join(ioc_rows) + '</tbody></table>'
    ) if ioc_rows else '<p style="color:#8b949e">No IOCs extracted.</p>'

    # ATT&CK table (flat) — kept alongside the Tier-3 heatmap
    att_rows: list[str] = []
    for tid, info in sorted(techniques.items()):
        url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        n = len(info.get("evidence_finding_ids", []))
        att_rows.append(
            f'<tr><td class="tid"><a href="{html.escape(url)}" '
            f'target="_blank" rel="noopener">{html.escape(tid)}</a></td>'
            f'<td>{html.escape(info.get("name", ""))}</td>'
            f'<td>{n}</td></tr>'
        )
    att_html = (
        '<table class="attack"><thead><tr><th>Technique</th><th>Name</th>'
        '<th>Findings</th></tr></thead><tbody>'
        + "\n".join(att_rows) + '</tbody></table>'
    ) if att_rows else (
        '<p style="color:#8b949e">No MITRE ATT&amp;CK techniques mapped.</p>')

    # Tier 3: ATT&CK heatmap grouped by tactic + Diamond Model view
    heatmap_html = _build_attack_heatmap_html(techniques)
    diamond_html = _build_diamond_html(findings, ach_ranking, iocs, manifest)

    # Summary cards
    total = len(findings)
    lead_html = (
        f'<span class="lead">{html.escape(leading.name)} '
        f'({leading.hyp_id}, score={leading.score})</span>'
        if leading else "no ranked hypotheses"
    )

    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>EL · {html.escape(case_id)}</title>
<meta name="generator" content="el.reporting.html">
<style>{_CSS}</style>
</head>
<body>
<header class="topbar">
  <h1>EL<span class="case-id">{html.escape(case_id)}</span></h1>
  <div class="meta">Leading: {lead_html} · Generated {data['generated_utc']}</div>
  <nav>
    <a href="#summary">Summary</a>
    <a href="#ach">ACH</a>
    <a href="#graph">Graph</a>
    <a href="#findings">Findings</a>
    <a href="#iocs">IOCs</a>
    <a href="#attack">ATT&amp;CK</a>
    <a href="#heatmap">Heatmap</a>
    <a href="#diamond">Diamond</a>
  </nav>
</header>
<main>

<section id="summary">
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-card"><div class="k">Findings</div><div class="v">{total}</div></div>
    <div class="summary-card high"><div class="k">High</div><div class="v">{by_conf.get("high",0)}</div></div>
    <div class="summary-card medium"><div class="k">Medium</div><div class="v">{by_conf.get("medium",0)}</div></div>
    <div class="summary-card low"><div class="k">Low</div><div class="v">{by_conf.get("low",0)}</div></div>
  </div>
</section>

<section id="ach">
  <h2>Hypothesis Ranking <span class="count">(Heuer ACH — highest = leading, never declared 'true')</span></h2>
  {ach_html}
</section>

<section id="graph">
  <h2>Entity Graph <span class="count">(Locard contacts — hosts, users, processes, IPs, domains, flows)</span></h2>
  <div id="graph-pane"></div>
</section>

<section id="findings">
  <h2>Findings <span class="count" id="findings-count"></span></h2>
  <div class="filters">
    <div class="filter-group"><label>Confidence</label>{conf_chips}</div>
    <div class="filter-group"><label>Agent</label>{agent_chips}</div>
  </div>
  <div class="findings-list" id="findings-list"></div>
</section>

<section id="iocs">
  <h2>IOCs <span class="count">({ioc_count})</span></h2>
  {ioc_html}
</section>

<section id="attack">
  <h2>MITRE ATT&amp;CK Techniques <span class="count">({len(techniques)})</span></h2>
  {att_html}
</section>

<section id="heatmap">
  <h2>ATT&amp;CK Coverage Heatmap <span class="count">(by tactic — finding count per technique, heat-coloured)</span></h2>
  {heatmap_html}
</section>

<section id="diamond">
  <h2>Diamond Model <span class="count">(Caltagirone / Pendergast / Betz 2013 — four intrusion-analysis vertices)</span></h2>
  {diamond_html}
</section>

</main>

<aside class="drawer" id="drawer">
  <button class="close-btn" id="close-drawer">Close ✕</button>
  <div id="drawer-body"></div>
</aside>

<footer>
  Generated by EL · Edmond Locard DFIR orchestrator ·
  deterministic projection of {total} Findings from case {html.escape(case_id)}
</footer>

<script id="data" type="application/json">{data_json}</script>
<script>{_JS}</script>
</body>
</html>"""

    out_path.write_text(body, encoding="utf-8")
    return out_path


__all__ = ["render_html"]

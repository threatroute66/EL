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
from el.reporting.narrative import (
    BEATS as _BEATS,
    evidence_time as _nar_evidence_time,
    is_swimlane_metadata as _nar_is_swimlane_metadata,
    synthesize as _narrative_synth,
    _beat_from_finding as _nar_beat_from_finding,
    _BEAT_HEADING as _NAR_BEAT_HEADING,
)
from el.schemas.finding import Finding


_CSS = """
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont,
    "Segoe UI", system-ui, sans-serif; }
body { background: #0d1117; color: #c9d1d9; line-height: 1.5; }
/* Sticky-header offset for in-page anchor jumps (#findings,
   #timeline, drawer-on-fid clicks). Without this the browser
   scrolls the target into the area covered by the sticky topbar,
   making the anchor appear "several lines below" the heading. */
html { scroll-padding-top: 110px; }
header.topbar { background: #161b22; border-bottom: 1px solid #30363d;
    padding: 12px 24px; position: sticky; top: 0; z-index: 10; }
header.topbar h1 { margin: 0; font-size: 18px; font-weight: 600; color: #f0f6fc; }
header.topbar h1 .case-id { font-family: "SF Mono", Menlo, Consolas, monospace;
    color: #58a6ff; font-weight: 500; margin-left: 10px; }
header.topbar .meta { margin-top: 4px; font-size: 12px; color: #8b949e; }
header.topbar .meta .lead { color: #f85149; font-weight: 600; }
/* Single-line nav: 14 anchors must fit on one row so the sticky-
   header height stays predictable and `scroll-padding-top` lands
   anchor jumps on the right heading. flex + nowrap forces a
   horizontal overflow on narrow viewports rather than wrapping. */
header.topbar nav { margin-top: 8px; display: flex; flex-wrap: nowrap;
    gap: 4px; overflow-x: auto; scrollbar-width: thin; }
header.topbar nav a { color: #58a6ff; text-decoration: none;
    font-size: 12px; font-weight: 500; padding: 3px 7px;
    border-radius: 5px; white-space: nowrap; flex-shrink: 0; }
header.topbar nav a:hover { background: #21262d; }
header.topbar nav a.pdf-download {
    margin-left: auto; background: #1f6feb22;
    color: #79c0ff; border: 1px solid #1f6feb55;
    display: inline-flex; align-items: center; gap: 4px; }
header.topbar nav a.pdf-download:hover {
    background: #1f6feb44; color: #ffffff; }
header.topbar nav a.pdf-download svg { display: block; }
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
table.attack a.tech-count { color: #f0f6fc; background: #238636;
    padding: 1px 8px; border-radius: 4px; text-decoration: none;
    font-family: monospace; font-size: 12px; font-weight: 600; }
table.attack a.tech-count:hover { background: #2ea043;
    box-shadow: 0 0 0 2px #58a6ff; }
a.fcount.tech-count { text-decoration: none; }
a.fcount.tech-count:hover { outline: 2px solid #58a6ff;
    outline-offset: 1px; }

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

/* Executive Narrative (prose — answers "what happened") */
.narrative { background: #161b22; border: 1px solid #30363d; border-left: 3px solid #d2a8ff;
    border-radius: 6px; padding: 18px 22px; margin-top: 16px; font-size: 14px;
    line-height: 1.55; color: #e6edf3; }
.narrative h3 { color: #f0f6fc; font-size: 15px; margin-top: 16px;
    margin-bottom: 6px; }
.narrative h3:first-child { margin-top: 0; }
.narrative .earliest { color: #8b949e; font-size: 11px;
    font-family: monospace; margin-bottom: 4px; }
.narrative p { margin: 6px 0 10px 0; }
.narrative .lead { color: #c9d1d9; margin-bottom: 12px;
    padding-bottom: 10px; border-bottom: 1px solid #30363d; font-weight: 500; }
.narrative .gap-warn { color: #d29922; background: #3a2a0a;
    border: 1px solid #5a420c; padding: 8px 12px; border-radius: 4px;
    margin-bottom: 12px; font-size: 13px; }
.narrative ul { padding-left: 20px; margin: 6px 0; }
.narrative li { margin-bottom: 4px; font-size: 13px; }
.narrative a.cite { color: #58a6ff; text-decoration: none;
    font-family: monospace; font-size: 11px;
    background: #21262d; padding: 1px 6px; border-radius: 3px; }
.narrative a.cite:hover { background: #1f6feb; color: white; }
.narrative .alt-section { margin-top: 18px; padding-top: 14px;
    border-top: 2px dashed #30363d; }
.narrative .alt-section h2 { color: #d2a8ff; font-size: 15px;
    margin-bottom: 8px; }
.narrative .gap-statement { color: #ffa657; font-style: italic;
    background: #2a1c0a; padding: 6px 10px; border-radius: 4px;
    border-left: 2px solid #d29922; }

/* Timeline (narrative) */
.timeline { border-left: 2px solid #30363d; margin-left: 20px; padding-left: 20px;
    margin-top: 16px; }
.tl-item { position: relative; margin-bottom: 10px; background: #161b22;
    border: 1px solid #30363d; border-radius: 4px; padding: 10px 14px; cursor: pointer; }
.tl-item:hover { background: #1c2128; border-color: #484f58; }
.tl-item::before { content: ""; position: absolute; left: -26px; top: 16px;
    width: 10px; height: 10px; background: #58a6ff; border: 2px solid #0d1117;
    border-radius: 50%; }
.tl-item.conf-high::before { background: #f85149; }
.tl-item.conf-medium::before { background: #d29922; }
.tl-item.conf-low::before { background: #58a6ff; }
.tl-item.conf-insufficient::before { background: #484f58; }
.tl-item .ts { font-family: monospace; color: #8b949e; font-size: 11px;
    margin-right: 10px; }
.tl-item .agent { color: #7ee787; font-family: monospace; font-size: 11px;
    margin-right: 10px; }
.tl-item .cnf { font-size: 10px; color: #0d1117; padding: 1px 6px;
    border-radius: 8px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.05em; }
.tl-item.conf-high .cnf    { background: #f85149; color: white; }
.tl-item.conf-medium .cnf  { background: #d29922; }
.tl-item.conf-low .cnf     { background: #58a6ff; color: white; }
.tl-item.conf-insufficient .cnf { background: #484f58; color: #c9d1d9; }
.tl-item .claim { margin-top: 4px; color: #e6edf3; font-size: 13px; }

/* Attack Timeline — ordered by artifact time, not EL wall clock */
.attack-tl { border-left: 2px solid #f85149; margin-left: 24px;
    padding-left: 20px; margin-top: 16px; }
.atl-item { position: relative; margin-bottom: 10px; background: #161b22;
    border: 1px solid #30363d; border-left: 3px solid #f85149;
    border-radius: 4px; padding: 10px 14px; cursor: pointer; transition: background 0.1s; }
.atl-item:hover { background: #1c2128; border-color: #f85149; }
.atl-item::before { content: ""; position: absolute; left: -30px; top: 18px;
    width: 12px; height: 12px; background: #f85149; border: 3px solid #0d1117;
    border-radius: 50%; }
.atl-item.conf-medium::before { background: #d29922; }
.atl-item.conf-low::before { background: #58a6ff; }
.atl-item .evtime { font-family: monospace; color: #f0f6fc; font-size: 13px;
    font-weight: 600; background: #21262d; padding: 2px 8px;
    border-radius: 3px; margin-right: 10px; }
.atl-item .agent { color: #7ee787; font-family: monospace; font-size: 11px;
    margin-right: 8px; }
.atl-item .cnf { font-size: 10px; padding: 1px 6px; border-radius: 8px;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
.atl-item.conf-high .cnf    { background: #f85149; color: white; }
.atl-item.conf-medium .cnf  { background: #d29922; }
.atl-item.conf-low .cnf     { background: #58a6ff; color: white; }
.atl-item .claim { margin-top: 6px; color: #e6edf3; font-size: 13px; }
.atl-empty { color: #8b949e; font-style: italic; padding: 16px;
    background: #161b22; border: 1px dashed #30363d; border-radius: 6px;
    margin-top: 10px; font-size: 13px; }

/* Kill-chain swimlane — Y=beat, X=time. Per-case beat × time scatter
   that turns the flat finding list into one-glance attacker progression. */
.swimlane-wrap { background: #0d1117; border: 1px solid #30363d;
    border-radius: 6px; padding: 8px; margin-top: 12px; }
.swimlane-wrap svg { width: 100%; display: block; }
.sw-lane-label { fill: #c9d1d9; font-size: 11px;
    font-family: "SF Mono", Menlo, monospace; }
.sw-lane-bg { fill: #0d1117; stroke: none; }
.sw-lane-bg.alt { fill: #11161d; }
.sw-grid { stroke: #21262d; stroke-width: 1; }
.sw-axis-label { fill: #8b949e; font-size: 10px;
    font-family: "SF Mono", Menlo, monospace; }
.sw-tick { stroke: #30363d; stroke-width: 1; }
.sw-marker { cursor: pointer; transition: r 0.1s, opacity 0.1s; }
.sw-marker:hover { r: 7; opacity: 1; }
.sw-marker.high   { fill: #f85149; opacity: 0.95; }
.sw-marker.medium { fill: #d29922; opacity: 0.85; }
.sw-marker.low    { fill: #58a6ff; opacity: 0.70; }
.sw-marker.insufficient { fill: #6e7681; opacity: 0.50; }
.sw-marker.ingest { stroke: #6e7681; stroke-width: 1.5;
    stroke-dasharray: 2 1; }
.sw-empty { color: #8b949e; font-style: italic; padding: 16px;
    background: #161b22; border: 1px dashed #30363d; border-radius: 6px;
    margin-top: 10px; font-size: 13px; }
.sw-legend { display: flex; flex-wrap: wrap; gap: 10px;
    color: #8b949e; font-size: 11px; margin-top: 8px;
    font-family: "SF Mono", Menlo, monospace; }
.sw-legend .dot { display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; margin-right: 4px; vertical-align: middle; }

/* Diagnostic findings (Heuer — high score-delta spread) */
.diagnostic-list { margin-top: 16px; display: flex; flex-direction: column; gap: 8px; }
.diag-card { background: #161b22; border: 1px solid #30363d; border-left: 3px solid #d2a8ff;
    border-radius: 4px; padding: 12px 14px; cursor: pointer; }
.diag-card:hover { background: #1c2128; }
.diag-card .head { display: flex; gap: 10px; align-items: baseline; }
.diag-card .fid { font-family: monospace; color: #8b949e; font-size: 11px; }
.diag-card .agent { color: #7ee787; font-family: monospace; font-size: 11px; }
.diag-card .claim { margin-top: 4px; color: #e6edf3; }
.diag-card .deltas { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px; }
.diag-card .delta { font-family: monospace; font-size: 11px; padding: 1px 8px;
    border-radius: 3px; background: #21262d; color: #c9d1d9; }
.diag-card .delta.pos { background: #0d4429; color: #7ee787; }
.diag-card .delta.neg { background: #4a1111; color: #ff9d8d; }

/* ACH consistency matrix (Heuer standard grid) */
.ach-matrix { overflow-x: auto; margin-top: 16px; }
table.ach-mat { border-collapse: collapse; width: 100%; font-size: 11px; }
table.ach-mat th, table.ach-mat td { border: 1px solid #30363d; padding: 4px 8px;
    vertical-align: middle; text-align: center; }
table.ach-mat th { background: #161b22; color: #8b949e; font-weight: 500;
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; }
table.ach-mat th.hyp { text-align: left; font-family: monospace; color: #58a6ff;
    font-size: 10px; writing-mode: vertical-rl; transform: rotate(180deg);
    height: 120px; padding: 8px 4px; }
table.ach-mat th.fid { text-align: left; font-family: monospace; color: #c9d1d9;
    font-size: 11px; max-width: 220px; overflow: hidden; text-overflow: ellipsis;
    white-space: nowrap; cursor: pointer; text-transform: none; letter-spacing: 0; }
table.ach-mat th.fid:hover { background: #1f6feb; color: white; }
table.ach-mat td.pos { background: #0d4429; color: #7ee787; }
table.ach-mat td.neg { background: #4a1111; color: #ff9d8d; }
table.ach-mat td.zero { color: #484f58; }

/* Drawer — disconfirming checklist */
aside.drawer ul.checklist { margin: 6px 0 0 0; padding-left: 20px; }
aside.drawer ul.checklist li { color: #c9d1d9; font-size: 12px;
    margin-bottom: 4px; list-style-type: square; }

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
    const evidenceHtml = (f.evidence || []).map(e => {
      const facts = e.extracted_facts || {};
      const factList = Object.entries(facts).slice(0, 8).map(([k,v]) =>
        `<div style="margin-top:4px;font-size:11px;color:#8b949e">${esc(k)}: <span style="color:#c9d1d9">${esc(String(v)).slice(0,160)}</span></div>`).join("");
      return `<div class="evidence-item">
        <div class="cmd">${esc(e.tool)} ${esc(e.version)} — ${esc(e.command)}</div>
        <div class="sha">sha256=${esc((e.output_sha256 || "").slice(0,16))}… path=${esc(e.output_path || "")}</div>
        ${factList}
      </div>`;
    }).join("");
    const deltaHtml = (() => {
      const d = f.ach_score_delta || {};
      const keys = Object.keys(d).sort();
      if (!keys.length) return "";
      const rows = keys.map(k => {
        const v = d[k];
        const cls = v > 0 ? "pos" : v < 0 ? "neg" : "";
        const sign = v > 0 ? "+" : "";
        return `<span class="delta ${cls}">${esc(k)} ${sign}${v}</span>`;
      }).join(" ");
      return `<div class="field"><div class="label">ACH score Δ</div><div class="deltas" style="display:flex;flex-wrap:wrap;gap:4px">${rows}</div></div>`;
    })();
    const rr = f.red_review;
    const checklistHtml = (rr && rr.disconfirming_checklist && rr.disconfirming_checklist.length)
      ? `<div class="field"><div class="label">Disconfirming checklist</div><ul class="checklist">${rr.disconfirming_checklist.map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>`
      : "";
    body.innerHTML = `
      <h3>${esc(f.claim)}</h3>
      <div class="sub">${esc(f.finding_id)} · ${esc(f.agent)} · ${esc(f.confidence)}</div>
      <div class="field"><div class="label">Created (UTC)</div><div class="val">${esc(f.created_utc || "")}</div></div>
      ${f.hypotheses_supported.length ? `<div class="field"><div class="label">Supports</div><div class="val">${f.hypotheses_supported.map(esc).join(", ")}</div></div>` : ""}
      ${f.hypotheses_refuted.length ? `<div class="field"><div class="label">Refutes</div><div class="val">${f.hypotheses_refuted.map(esc).join(", ")}</div></div>` : ""}
      ${deltaHtml}
      ${evidenceHtml ? `<div class="field"><div class="label">Evidence (${f.evidence.length})</div>${evidenceHtml}</div>` : ""}
      ${rr ? `<div class="field"><div class="label">Red Review</div><div class="val">status=${esc(rr.status || "")} ${rr.challenger_notes ? "— " + esc(rr.challenger_notes) : ""}</div></div>` : ""}
      ${checklistHtml}`;
    d.classList.add("open");
    history.replaceState(null, "", "#" + f.finding_id);
  }

  // ----- Kill-chain swimlane -------------------------------------------
  // Y axis: beat lanes from data.beat_lanes (ordered, MITRE-ish).
  // X axis: time. Real artifact time when present (evidence_time),
  //   else EL ingest time as fallback (created_utc, dashed stroke).
  // Empty lanes are still drawn so absence is visible — that's the
  // forensic point: a silent Persistence lane MEANS something.
  function renderSwimlane() {
    const svg = document.getElementById("swimlane-svg");
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const ns = "http://www.w3.org/2000/svg";

    const lanes = data.beat_lanes || [];
    if (!lanes.length) {
      svg.innerHTML = '<text x="20" y="30" class="sw-empty">No beat lanes defined.</text>';
      return;
    }
    const laneIdx = {};
    lanes.forEach((l, i) => { laneIdx[l.beat] = i; });

    // Collect all events. evidence_time wins; created_utc is fallback.
    // Skip timeline_synthesist — its super-timeline finding spans the
    // case (Plaso bookends), so a single dot at the earliest event is
    // misleading and stretches the X axis without conveying density.
    const events = [];
    (data.findings || []).forEach(f => {
      if (f.agent === "timeline_synthesist") return;
      // Parse-confirmation findings (windows_artifact "parsed
      // successfully" notes) are metadata about the parse, not
      // discrete events. The server already set the flag — keep
      // them off the strip so a hive-install timestamp doesn't
      // stretch the X axis decades back.
      if (f.swimlane_eligible === false) return;
      const t = f.evidence_time || f.created_utc || "";
      if (!t) return;
      if (laneIdx[f.beat] === undefined) return;
      events.push({
        fid: f.finding_id, beat: f.beat,
        ts: t, isArtifact: !!f.evidence_time,
        conf: f.confidence, agent: f.agent, claim: f.claim,
      });
    });
    if (!events.length) {
      const txt = document.createElementNS(ns, "text");
      txt.setAttribute("x", 20); txt.setAttribute("y", 30);
      txt.setAttribute("class", "sw-empty");
      txt.textContent = "No timeline-able findings yet.";
      svg.appendChild(txt);
      return;
    }
    // Axis bounds: when ANY events carry a real artifact timestamp,
    // compute tmin/tmax from those alone and drop the ingest-time
    // fallback events from the plot. Otherwise an old case
    // investigated today (M57-Jean is 2008-era events; we ran EL
    // in 2026) compresses every real event into a one-pixel sliver
    // on the left while the EL-ingest dots claim the rest of the
    // axis. The accuracy report's case-glance fix (commit 55e1ad3)
    // applied this same plausible-window principle to the
    // narrative time range; this is the swimlane sibling.
    const artifactEvents = events.filter(e => e.isArtifact);
    let plotEvents, droppedIngest = 0;
    if (artifactEvents.length > 0) {
      plotEvents = artifactEvents;
      droppedIngest = events.length - artifactEvents.length;
    } else {
      // No artifact-timed findings yet — fall back to all events
      // (preserves the swimlane for cases where extraction hasn't
      // surfaced a real-world clock anywhere).
      plotEvents = events;
    }
    const tmin = Math.min(...plotEvents.map(e => Date.parse(e.ts)));
    const tmax = Math.max(...plotEvents.map(e => Date.parse(e.ts)));
    const span = Math.max(tmax - tmin, 1);

    const wrap = svg.parentElement;
    const W = Math.max(wrap.clientWidth - 16, 600);
    const LANE_H = 32, LABEL_W = 200, PAD_T = 18;
    // Bottom padding holds the x-axis labels + the off-axis count
    // note (when droppedIngest > 0). +14 px for the italic note,
    // unused but reserved when no drop is needed — keeps the chart
    // height stable regardless of which axis-bounds branch ran.
    const PAD_B = 44;
    const H = lanes.length * LANE_H + PAD_T + PAD_B;
    const plotW = W - LABEL_W - 16;
    svg.setAttribute("width", W);
    svg.setAttribute("height", H);
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);

    // Lane backgrounds + labels
    lanes.forEach((l, i) => {
      const y = PAD_T + i * LANE_H;
      const bg = document.createElementNS(ns, "rect");
      bg.setAttribute("x", 0); bg.setAttribute("y", y);
      bg.setAttribute("width", W); bg.setAttribute("height", LANE_H);
      bg.setAttribute("class", "sw-lane-bg" + (i % 2 ? " alt" : ""));
      svg.appendChild(bg);
      const lab = document.createElementNS(ns, "text");
      lab.setAttribute("x", 8); lab.setAttribute("y", y + LANE_H / 2 + 4);
      lab.setAttribute("class", "sw-lane-label");
      lab.textContent = l.heading;
      svg.appendChild(lab);
      const div = document.createElementNS(ns, "line");
      div.setAttribute("x1", LABEL_W); div.setAttribute("x2", W);
      div.setAttribute("y1", y + LANE_H); div.setAttribute("y2", y + LANE_H);
      div.setAttribute("class", "sw-grid");
      svg.appendChild(div);
    });

    // X-axis ticks — 5 evenly spaced
    for (let k = 0; k <= 4; k++) {
      const frac = k / 4;
      const x = LABEL_W + frac * plotW;
      const tick = document.createElementNS(ns, "line");
      tick.setAttribute("x1", x); tick.setAttribute("x2", x);
      tick.setAttribute("y1", PAD_T - 4);
      tick.setAttribute("y2", H - PAD_B + 4);
      tick.setAttribute("class", "sw-tick");
      svg.appendChild(tick);
      const t = new Date(tmin + frac * span);
      const lab = document.createElementNS(ns, "text");
      lab.setAttribute("x", x); lab.setAttribute("y", H - PAD_B + 18);
      lab.setAttribute("class", "sw-axis-label");
      lab.setAttribute("text-anchor", "middle");
      lab.textContent = t.toISOString().slice(0, 16).replace("T", " ");
      svg.appendChild(lab);
    }

    // Markers — small jitter on Y so overlaps don't fully stack.
    // plotEvents already filtered (artifact-time only when any exist)
    // so the axis bounds match every dot we're about to draw.
    plotEvents.forEach(e => {
      const x = LABEL_W + ((Date.parse(e.ts) - tmin) / span) * plotW;
      const li = laneIdx[e.beat];
      const yC = PAD_T + li * LANE_H + LANE_H / 2;
      const jitter = (e.fid.charCodeAt(e.fid.length - 1) % 7) - 3;
      const dot = document.createElementNS(ns, "circle");
      dot.setAttribute("cx", x);
      dot.setAttribute("cy", yC + jitter);
      dot.setAttribute("r", 4.5);
      dot.setAttribute("class",
        "sw-marker " + e.conf + (e.isArtifact ? "" : " ingest"));
      const ttl = document.createElementNS(ns, "title");
      ttl.textContent = `${e.ts}\n${e.agent}: ${e.claim}\n` +
        `${e.isArtifact ? "artifact time" : "ingest time (fallback)"}`;
      dot.appendChild(ttl);
      dot.addEventListener("click", () =>
        openDrawer(findingsById[e.fid]));
      svg.appendChild(dot);
    });

    // Off-axis annotation — when we dropped ingest-time fallback
    // events from the plot (because we have real artifact times to
    // anchor the axis), tell the analyst how many didn't land here
    // so they know the swimlane intentionally undercounts the full
    // finding set. Total count is in the timeline view below.
    if (droppedIngest > 0) {
      const tminLabel = new Date(tmin).toISOString().slice(0, 10);
      const tmaxLabel = new Date(tmax).toISOString().slice(0, 10);
      const note = document.createElementNS(ns, "text");
      note.setAttribute("x", LABEL_W);
      note.setAttribute("y", H - 4);
      note.setAttribute("class", "sw-axis-label");
      note.setAttribute("style",
        "fill:#8b949e; font-style:italic; font-size:10px");
      note.textContent =
        `Showing ${plotEvents.length} artifact-timestamped event(s) ` +
        `across ${tminLabel} → ${tmaxLabel}. ` +
        `${droppedIngest} additional finding(s) carry only EL ingest ` +
        `time (no real-world timestamp extracted) — see the Timeline ` +
        `view for the full set.`;
      svg.appendChild(note);
    }
  }

  // ----- Timeline / diagnostic / matrix (narrative) --------------------
  function renderTimeline() {
    const pane = document.getElementById("tl-list");
    if (!pane) return;
    // Sort key: prefer artifact time (evidence_time) when present,
    // fall back to EL wall clock (created_utc). On a 30-minute EL run
    // every created_utc clusters into a few minutes — the timeline
    // is forensically meaningless without the evidence_time fallback.
    const sortKey = f => f.evidence_time || f.created_utc || "";
    const ordered = [...data.findings].sort((a, b) =>
      sortKey(a).localeCompare(sortKey(b)) ||
      a.finding_id.localeCompare(b.finding_id));
    pane.innerHTML = ordered.map(f => {
      const t = f.evidence_time || f.created_utc || "";
      const tag = f.evidence_time ? "artifact" : "ingest";
      return `
      <div class="tl-item conf-${f.confidence}" data-fid="${esc(f.finding_id)}">
        <span class="ts" title="${tag} time">${esc(t.replace("T"," ").slice(0,19))}</span>
        <span class="agent">${esc(f.agent)}</span>
        <span class="cnf">${esc(f.confidence)}</span>
        <span class="cnf" style="background:#161b22;color:#8b949e">${tag}</span>
        <div class="claim">${esc(f.claim)}</div>
      </div>`;
    }).join("") ||
      '<div style="color:#8b949e">No findings to lay on a timeline yet.</div>';
    pane.querySelectorAll(".tl-item").forEach(el => {
      el.addEventListener("click", () =>
        openDrawer(findingsById[el.dataset.fid]));
    });
  }

  function renderAttackTimeline() {
    // Ordered by artifact time (evidence_time), NOT EL's wall clock.
    // Only includes findings that have a reconstructed artifact
    // timestamp in their extracted_facts — i.e. events we can place
    // on a real-world clock. Excludes insufficient-confidence
    // findings (those document gaps, not malicious events).
    const pane = document.getElementById("atl-list");
    if (!pane) return;
    const timed = data.findings
      .filter(f => f.evidence_time && f.confidence !== "insufficient")
      .sort((a, b) =>
        a.evidence_time.localeCompare(b.evidence_time) ||
        a.finding_id.localeCompare(b.finding_id));
    if (!timed.length) {
      pane.innerHTML = '<div class="atl-empty">No artifact-timestamped events found. Events that carry a real-world timestamp (EVTX EID records, file creation/modification times, lateral-movement sightings, email send times) land here once an agent extracts one.</div>';
      return;
    }
    pane.innerHTML = timed.map(f => `
      <div class="atl-item conf-${f.confidence}" data-fid="${esc(f.finding_id)}">
        <span class="evtime">${esc(f.evidence_time.replace("T"," ").replace(/\+.*$/, "").slice(0,19))}</span>
        <span class="agent">${esc(f.agent)}</span>
        <span class="cnf">${esc(f.confidence)}</span>
        <div class="claim">${esc(f.claim)}</div>
      </div>`).join("");
    pane.querySelectorAll(".atl-item").forEach(el => {
      el.addEventListener("click", () =>
        openDrawer(findingsById[el.dataset.fid]));
    });
  }

  function renderDiagnostic() {
    const pane = document.getElementById("diag-list");
    if (!pane) return;
    // Top-N findings by ACH score-delta spread (max(pos) - min(neg))
    // — Heuer's "most diagnostic" are the ones whose presence shifts
    // the ranking the hardest.
    const scored = data.findings.map(f => {
      const d = f.ach_score_delta || {};
      const vals = Object.values(d);
      if (!vals.length) return null;
      const spread = (Math.max(0, ...vals)) - (Math.min(0, ...vals));
      return {f, spread};
    }).filter(Boolean).sort((a,b) => b.spread - a.spread).slice(0, 10);
    if (!scored.length) {
      pane.innerHTML = '<div style="color:#8b949e">No ACH score-deltas recorded — diagnostic ranking populates once the ACH engine emits score-shift findings.</div>';
      return;
    }
    pane.innerHTML = scored.map(({f, spread}) => {
      const d = f.ach_score_delta || {};
      const deltas = Object.entries(d).sort()
        .map(([k, v]) => `<span class="delta ${v > 0 ? 'pos' : v < 0 ? 'neg' : ''}">${esc(k)} ${v > 0 ? '+' : ''}${v}</span>`).join(" ");
      return `<div class="diag-card" data-fid="${esc(f.finding_id)}">
        <div class="head"><span class="agent">${esc(f.agent)}</span>
          <span class="fid">${esc(f.finding_id)}</span>
          <span class="fid">spread=${spread}</span></div>
        <div class="claim">${esc(f.claim)}</div>
        <div class="deltas">${deltas}</div>
      </div>`;
    }).join("");
    pane.querySelectorAll(".diag-card").forEach(el => {
      el.addEventListener("click", () =>
        openDrawer(findingsById[el.dataset.fid]));
    });
  }

  function renderAchMatrix() {
    const pane = document.getElementById("ach-mat");
    if (!pane) return;
    const scoring = data.findings.filter(f =>
      f.ach_score_delta && Object.keys(f.ach_score_delta).length);
    if (!scoring.length) {
      pane.innerHTML = '<div style="color:#8b949e">No scoring deltas to matrix.</div>';
      return;
    }
    // Collect unique hypothesis ids across all scoring findings
    const hyps = Array.from(new Set(scoring.flatMap(f =>
      Object.keys(f.ach_score_delta)))).sort();
    // Limit to the top-20 most-diagnostic findings to keep the grid readable
    const ranked = scoring.map(f => {
      const v = Object.values(f.ach_score_delta);
      return {f, spread: Math.max(0, ...v) - Math.min(0, ...v)};
    }).sort((a,b) => b.spread - a.spread).slice(0, 20).map(x => x.f);
    const head = hyps.map(h => `<th class="hyp">${esc(h)}</th>`).join("");
    const rows = ranked.map(f => {
      const cells = hyps.map(h => {
        const v = (f.ach_score_delta || {})[h];
        if (v === undefined || v === 0) return '<td class="zero">·</td>';
        return `<td class="${v > 0 ? 'pos' : 'neg'}">${v > 0 ? '+' : ''}${v}</td>`;
      }).join("");
      return `<tr><th class="fid" data-fid="${esc(f.finding_id)}">${esc(f.claim).slice(0, 60)}…</th>${cells}</tr>`;
    }).join("");
    pane.innerHTML = `<table class="ach-mat"><thead><tr><th style="text-align:left">Finding ↓ / Hypothesis →</th>${head}</tr></thead><tbody>${rows}</tbody></table>`;
    pane.querySelectorAll("th.fid").forEach(el => {
      el.addEventListener("click", () =>
        openDrawer(findingsById[el.dataset.fid]));
    });
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

  // Technique-count click handlers — wire up every .tech-count anchor
  // emitted by the ATT&CK table + heatmap to open the rollup drawer.
  document.querySelectorAll(".tech-count").forEach(el => {
    el.addEventListener("click", e => {
      e.preventDefault();
      openTechniqueDrawer(el.dataset.tid);
    });
  });

  function openTechniqueDrawer(tid) {
    const tech = (data.techniques || {})[tid];
    const d = document.getElementById("drawer");
    const body = document.getElementById("drawer-body");
    if (!tech) {
      body.innerHTML = `<h3>${esc(tid)}</h3><div class="sub">Technique metadata not found in this case's data.</div>`;
      d.classList.add("open");
      return;
    }
    const fids = tech.evidence_finding_ids || [];
    const attackUrl = `https://attack.mitre.org/techniques/${tid.replace(".","/")}/`;
    const rows = fids.map(fid => {
      const f = findingsById[fid];
      if (!f) {
        return `<li><a class="cite" href="#${esc(fid)}" data-fid="${esc(fid)}">${esc(fid)}</a> <span style="color:#8b949e">(not in current ledger view)</span></li>`;
      }
      return `<li><a class="cite" href="#${esc(fid)}" data-fid="${esc(fid)}">${esc(fid)}</a> · <span style="color:#7ee787;font-family:monospace;font-size:11px">${esc(f.agent)}</span> · <span style="color:${f.confidence==="high"?"#f85149":f.confidence==="medium"?"#d29922":"#58a6ff"};font-size:11px;font-weight:600">${esc(f.confidence)}</span><div style="margin-top:3px;font-size:12px;color:#e6edf3">${esc(f.claim).slice(0, 220)}</div></li>`;
    }).join("");
    body.innerHTML = `
      <h3>${esc(tid)}${tech.name ? " — " + esc(tech.name) : ""}</h3>
      <div class="sub">ATT&amp;CK technique · ${fids.length} supporting finding(s) in this case</div>
      <div class="field"><div class="label">MITRE ATT&amp;CK</div><div class="val"><a class="cite" href="${esc(attackUrl)}" target="_blank" rel="noopener">${esc(attackUrl)}</a></div></div>
      <div class="field"><div class="label">Supporting findings</div><ul style="list-style-type:none;padding-left:0;margin-top:6px">${rows || '<li style="color:#8b949e">none</li>'}</ul></div>
      <div style="margin-top:16px;color:#8b949e;font-size:11px">Click any finding ID above to drill into its evidence drawer.</div>`;
    // Bind click-to-drill on every cite link in the list
    body.querySelectorAll("a.cite[data-fid]").forEach(el => {
      el.addEventListener("click", e => {
        const fid = el.dataset.fid;
        if (findingsById[fid]) {
          e.preventDefault();
          openDrawer(findingsById[fid]);
        }
      });
    });
    d.classList.add("open");
    history.replaceState(null, "", "#technique-" + tid);
  }

  renderFindings();
  renderGraph();
  renderSwimlane();
  renderTimeline();
  renderAttackTimeline();
  renderDiagnostic();
  renderAchMatrix();

  // Deep-link: case.html#<finding_id> opens drawer
  if (window.location.hash) {
    const fid = window.location.hash.slice(1);
    if (findingsById[fid]) openDrawer(findingsById[fid]);
  }
})();
"""


def _build_narrative_html(narrative) -> str:
    """Server-render the NarrativeReport. Each `[finding_id]` citation
    in the prose becomes a clickable anchor that opens the finding
    drawer via the existing hash-fragment handler."""
    if narrative is None:
        return '<p style="color:#8b949e">No narrative synthesized.</p>'
    parts: list[str] = []
    lead_html = (
        f'Leading hypothesis: <b>{html.escape(str(narrative.leading_hypothesis))}</b> '
        f'(score {narrative.leading_score})'
    )
    if narrative.runner_up_hypothesis:
        lead_html += (
            f', runner-up <b>{html.escape(str(narrative.runner_up_hypothesis))}</b> '
            f'(score {narrative.runner_up_score}, gap {narrative.leading_gap})'
        )
    parts.append(f'<div class="lead">{lead_html}.</div>')
    if narrative.leading_gap < 3 and narrative.runner_up_hypothesis:
        parts.append(
            '<div class="gap-warn">⚠ Hypothesis gap is small — evidence '
            'supports more than one theory. Both narratives render; a '
            'report that advocates only one is sycophantic.</div>')

    def _render_paragraph(text: str) -> str:
        # Turn [<finding_id>] citations into clickable anchors
        import re
        def _link(m):
            fid = m.group(1)
            return (f'<a class="cite" href="#{html.escape(fid)}" '
                    f'data-fid="{html.escape(fid)}">{html.escape(fid)}</a>')
        # Preserve markdown-ish bold + escape otherwise
        safe = html.escape(text)
        safe = re.sub(r'\[(01[A-Z0-9]{24})\]', _link, safe)
        safe = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', safe)
        # Newlines → <br>; bullet lines → list
        lines = safe.split("\n")
        out: list[str] = []
        in_ul = False
        for ln in lines:
            if ln.startswith("- "):
                if not in_ul:
                    out.append("<ul>"); in_ul = True
                out.append(f"<li>{ln[2:]}</li>")
            else:
                if in_ul:
                    out.append("</ul>"); in_ul = False
                if ln.strip():
                    out.append(f"<p>{ln}</p>")
        if in_ul:
            out.append("</ul>")
        return "\n".join(out)

    for block in narrative.beats:
        if block.finding_count == 0 and block.beat not in (
                "trigger", "impact"):
            continue
        parts.append(f'<h3>{html.escape(block.heading)}</h3>')
        if block.earliest:
            parts.append(f'<div class="earliest">Earliest evidence: '
                         f'{html.escape(block.earliest)}</div>')
        if not block.paragraph and block.beat in ("trigger", "impact"):
            # Honest gap statement for empty critical beats — surface
            # with distinct styling so the analyst sees the missing link
            parts.append(
                f'<div class="gap-statement">No findings in this beat — '
                f'the {html.escape(block.heading.lower())} step is not '
                f'reconstructible from the available evidence.</div>')
        elif block.paragraph:
            parts.append(_render_paragraph(block.paragraph))

    if narrative.alt_beats:
        parts.append('<div class="alt-section">')
        parts.append(
            f'<h2>Alternative narrative — '
            f'{html.escape(str(narrative.runner_up_hypothesis))}</h2>')
        parts.append(
            '<p style="color:#8b949e;font-size:13px">'
            'Evidence subset that would SUPPORT this runner-up hypothesis, '
            'had the analyst chosen it as the leading theory instead.</p>')
        for block in narrative.alt_beats:
            parts.append(f'<h3>{html.escape(block.heading)}</h3>')
            if block.paragraph:
                parts.append(_render_paragraph(block.paragraph))
        parts.append('</div>')

    if narrative.unresolved_count or narrative.insufficient_count:
        parts.append('<h3>Open questions</h3><ul>')
        if narrative.unresolved_count:
            parts.append(
                f'<li><b>{narrative.unresolved_count}</b> finding(s) '
                f'with red_review status = unresolved.</li>')
        if narrative.insufficient_count:
            parts.append(
                f'<li><b>{narrative.insufficient_count}</b> finding(s) '
                f'at confidence = insufficient — documented gaps.</li>')
        parts.append('</ul>')

    return f'<div class="narrative">{"".join(parts)}</div>'


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
            # Clickable count opens the Findings drawer with a
            # technique-rollup view (list of supporting finding_ids +
            # click-through to each). Zero-count cells stay static.
            count_html = (
                f'<a class="fcount {_heat_class(n)} tech-count" '
                f'href="#" data-tid="{html.escape(tid)}" '
                f'title="Click to list the {n} supporting finding(s)">'
                f'{n}</a>'
            ) if n else (
                f'<span class="fcount {_heat_class(n)}">{n}</span>'
            )
            rows.append(
                f'<div class="t-row">'
                f'<span class="tid"><a href="{html.escape(url)}" '
                f'target="_blank" rel="noopener">{html.escape(tid)}</a></span>'
                f'<span class="tname">{html.escape(name)}</span>'
                f'{count_html}'
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

    # Adversary email extraction — mirrors the markdown renderer in
    # diamond.py. External (non-local-domain) emails in supporting
    # findings' extracted_facts are the attacker's attribution
    # surface; prepended to the Adversary list so high-signal email
    # IOCs aren't crowded out by carved-domain noise.
    from el.reporting.diamond import (
        _EMAIL_RE, _infer_local_domains, _walk_fact_values,
    )
    local_domains = _infer_local_domains(findings)
    adversary_emails: set[str] = set()
    for f in supporting:
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            for s in _walk_fact_values(facts):
                for em in _EMAIL_RE.finditer(s):
                    addr = em.group(0).lower()
                    dom = addr.split("@", 1)[1]
                    if dom not in local_domains:
                        adversary_emails.add(addr)

    # Victim — same logic as the markdown renderer in diamond.py.
    # Shared helpers _infer_local_domains + _walk_fact_values + _EMAIL_RE
    # live in diamond.py so the two renderers stay in lockstep
    # (regression catch for M57-Jean: previously this block hard-
    # coded the case_id as a victim host even though the case_id is
    # just EL's internal handle, not a real victim).
    # Note: local_domains was already computed for the Adversary
    # email pass above — reuse it.
    victim_hosts: set[str] = set()
    victim_users: set[str] = set()
    if manifest and manifest.get("hostname"):
        victim_hosts.add(str(manifest["hostname"]))
    for f in supporting:
        for ev in f.evidence:
            facts = ev.extracted_facts or {}
            # (a) Legacy structured-principal lists (Kerberoasting +
            #     lateral-movement use these).
            for key in ("top_principals", "top_targets", "top_sources"):
                for item in facts.get(key) or []:
                    if isinstance(item, (list, tuple)) and item:
                        name = str(item[0])
                        nlow = name.lower()
                        if "@" in name:
                            dom = nlow.split("@", 1)[1]
                            if not local_domains or dom in local_domains:
                                victim_users.add(nlow)
                        elif "\\" in name or nlow.startswith("s-1-"):
                            victim_users.add(nlow)
            # (b) Free-text email regex over every scalar string value
            #     (sender / display_name / actual_recipient / from_smtp /
            #     etc.). Filtered to local domain.
            for s in _walk_fact_values(facts):
                for m in _EMAIL_RE.finditer(s):
                    addr = m.group(0).lower()
                    dom = addr.split("@", 1)[1]
                    if local_domains and dom in local_domains:
                        victim_users.add(addr)

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
    <div class="sub">public attribution surface — external IPs + domains + emails</div>
    {_ul(sorted(adversary_emails) + sorted(pub_ips | domains))}
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
    delta = getattr(f, "ach_score_delta", None) or {}
    rr = f.red_review
    return {
        "finding_id": f.finding_id,
        "case_id": f.case_id,
        "agent": f.agent,
        "claim": f.claim,
        "confidence": f.confidence,
        "evidence": [
            {"tool": e.tool, "version": e.version, "command": e.command,
             "output_sha256": e.output_sha256,
             "output_path": e.output_path,
             "extracted_facts": {
                 k: v for k, v in (e.extracted_facts or {}).items()
                 # Keep JSON small — only surface the lighter facts
                 if isinstance(v, (str, int, float, bool, list))
                 and len(str(v)) < 400
             }}
            for e in f.evidence
        ],
        "hypotheses_supported": list(f.hypotheses_supported),
        "hypotheses_refuted": list(f.hypotheses_refuted),
        "ach_score_delta": {k: int(v) for k, v in delta.items()},
        "red_review": {
            "status": rr.status,
            "challenger_notes": rr.challenger_notes or "",
            "disconfirming_checklist":
                list(rr.disconfirming_checklist or []),
        } if rr else None,
        "created_utc": f.created_utc.isoformat()
                          if getattr(f, "created_utc", None) else "",
        # Artifact time — when the evidence actually happened, mined
        # from extracted_facts (ts_utc / create_time / LoadTime / etc.).
        # Drives the Attack Timeline view (distinct from the
        # Discovery Timeline which uses created_utc above).
        "evidence_time": (_nar_evidence_time(f).isoformat()
                          if _nar_evidence_time(f) else ""),
        # Beat assignment — drives the per-case kill-chain swimlane.
        # Reuses the same classifier the Markdown narrative uses, so
        # both views stay in lockstep with one beat-routing rule.
        "beat": _nar_beat_from_finding(f),
        # Whether to plot on the kill-chain swimlane. Parse-confirmation
        # findings (windows_artifact "parsed successfully" notes) are
        # metadata about the parse, not discrete events — their per-key
        # / per-record children carry the real swimlane points. Keeping
        # them off the strip prevents a stray 1999 hive timestamp from
        # stretching the X axis across decades.
        "swimlane_eligible": not _nar_is_swimlane_metadata(f),
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
        # Beat lanes for the kill-chain swimlane — ordered list of
        # (beat_id, heading) pairs, drives the per-case SVG view that
        # converts "203 bullets" into a glance at attacker progression.
        "beat_lanes": [{"beat": b, "heading": _NAR_BEAT_HEADING[b]}
                       for b in _BEATS],
        # Serialisable technique map — `evidence_finding_ids` is already
        # a list of strings; include only the keys the JS renderer uses
        # to keep the embedded JSON tight.
        "techniques": {
            tid: {
                "name": info.get("name", ""),
                "evidence_finding_ids": list(
                    info.get("evidence_finding_ids", [])),
            }
            for tid, info in techniques.items()
        },
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
        count_cell = (
            f'<a class="tech-count" data-tid="{html.escape(tid)}" '
            f'href="#" title="Click to list the {n} supporting '
            f'finding(s)">{n}</a>'
        ) if n else f"{n}"
        att_rows.append(
            f'<tr><td class="tid"><a href="{html.escape(url)}" '
            f'target="_blank" rel="noopener">{html.escape(tid)}</a></td>'
            f'<td>{html.escape(info.get("name", ""))}</td>'
            f'<td>{count_cell}</td></tr>'
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

    # Tier 5: Executive Narrative — six-beat prose "what happened"
    try:
        narrative = _narrative_synth(
            case_id=case_id, findings=findings,
            ach_ranking=ach_ranking, iocs=iocs, manifest=manifest)
        narrative_html = _build_narrative_html(narrative)
    except Exception:
        narrative_html = ('<p style="color:#8b949e">narrative unavailable'
                          '</p>')

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
    <a href="#narrative">Narrative</a>
    <a href="#summary">Summary</a>
    <a href="#ach">ACH</a>
    <a href="#swimlane">Swimlane</a>
    <a href="#timeline">Timeline</a>
    <a href="#attack-timeline">Attack</a>
    <a href="#diagnostic">Diagnostic</a>
    <a href="#matrix">Matrix</a>
    <a href="#graph">Graph</a>
    <a href="#findings">Findings</a>
    <a href="#iocs">IOCs</a>
    <a href="#attack">ATT&amp;CK</a>
    <a href="#heatmap">Heatmap</a>
    <a href="#diamond">Diamond</a>
    <a href="executive.pdf" download class="pdf-download"
       title="Download the executive (non-expert) report as PDF"
       aria-label="Download executive PDF"
       ><svg width="13" height="13" viewBox="0 0 16 16" fill="none"
        stroke="currentColor" stroke-width="1.6" stroke-linecap="round"
        stroke-linejoin="round" aria-hidden="true"
        ><path d="M8 1v10M4 7.5l4 4 4-4M2 14.5h12"/></svg> PDF</a>
  </nav>
</header>
<main>

<section id="narrative">
  <h2>Executive Narrative <span class="count">(what happened, in prose — every factual claim cites the finding_id it rests on)</span></h2>
  {narrative_html}
</section>

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

<section id="swimlane">
  <h2>Kill-Chain Swimlane <span class="count">(Y=attacker phase · X=artifact time — solid markers = real-world event time, dashed-stroke markers = EL ingest time only. Click a marker to open the finding.)</span></h2>
  <div class="swimlane-wrap"><svg id="swimlane-svg"></svg></div>
  <div class="sw-legend">
    <span><span class="dot" style="background:#f85149"></span>high</span>
    <span><span class="dot" style="background:#d29922"></span>medium</span>
    <span><span class="dot" style="background:#58a6ff"></span>low</span>
    <span><span class="dot" style="background:#6e7681"></span>insufficient</span>
    <span style="margin-left:8px">○ dashed stroke = ingest-time fallback (no artifact time mined)</span>
  </div>
</section>

<section id="timeline">
  <h2>Discovery Timeline <span class="count">(findings in chronological order of discovery — click to open detail)</span></h2>
  <div class="timeline" id="tl-list"></div>
</section>

<section id="attack-timeline">
  <h2>Attack Event Timeline <span class="count">(ordered by artifact timestamp — when the event ACTUALLY happened, not when EL recorded it. Only findings with an extracted real-world time; insufficient-confidence rows excluded)</span></h2>
  <div class="attack-tl" id="atl-list"></div>
</section>

<section id="diagnostic">
  <h2>Most Diagnostic Findings <span class="count">(Heuer — top-10 by ACH score-delta spread; these are the findings whose presence or absence most shifts the hypothesis ranking)</span></h2>
  <div class="diagnostic-list" id="diag-list"></div>
</section>

<section id="matrix">
  <h2>ACH Consistency Matrix <span class="count">(finding × hypothesis score-delta grid — Heuer's standard view)</span></h2>
  <div class="ach-matrix" id="ach-mat"></div>
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

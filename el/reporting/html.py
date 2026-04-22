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

  // Deep-link: case.html#<finding_id> opens drawer
  if (window.location.hash) {
    const fid = window.location.hash.slice(1);
    if (findingsById[fid]) openDrawer(findingsById[fid]);
  }
})();
"""


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
) -> Path:
    case_dir = Path(case_dir)
    reports = case_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    out_path = reports / "case.html"

    ach_ranking = ach_ranking or []
    iocs = iocs or {}
    techniques = techniques or {}

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

    # ATT&CK table
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
    <a href="#findings">Findings</a>
    <a href="#iocs">IOCs</a>
    <a href="#attack">ATT&amp;CK</a>
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

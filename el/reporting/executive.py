"""Executive (non-expert) HTML report renderer.

Produces `cases/<id>/reports/executive.html` — a self-contained,
print-friendly HTML report aimed at stakeholders who don't read
ATT&CK T-IDs, ACH hypothesis tags, or DFIR detector codes. The
analyst report (`case.html`, `report.md`) is unchanged; both come
from the same `findings.sqlite`, so they cannot disagree.

Layout (6 sections — simplified from the canonical 9-component
forensic-report template per the engagement-level=CTF agreement):

  1. Case Details + Evidence Inventory (merged)
  2. Objective & Scope (only when supplied via --objective)
  3. Executive Summary (the synthesize_executive() digest)
  4. Findings (chronological, prose, no jargon)
  5. Conclusion & Recommendations
  6. Appendix (glossary of terms used, methodology blurb,
     reproducibility note, pointer to analyst report)

CSS is embedded; there is no JS. The document prints cleanly so
Phase 2's PDF export (WeasyPrint) renders without surprises.
"""
from __future__ import annotations

import html as _h
import json
from datetime import datetime, timezone
from pathlib import Path

from el.case_metadata import CaseMetadata, load as load_case_metadata
from el.evidence.ledger import list_findings
from el.intel.ach import score_findings
from el.reporting import glossary
from el.reporting.narrative import (
    ExecutiveDigest,
    evidence_time,
    synthesize,
    synthesize_executive,
)
from el.reporting.recommendations import (
    ADVISORY_DISCLAIMER,
    Recommendation,
    build_recommendations,
)
from el.schemas.finding import Finding


# ---------------------------------------------------------------------------
# CSS — print-friendly, single-column, serif. Targets a stakeholder who
# may print this or read it as PDF; no responsive grid, no JS hooks.
# ---------------------------------------------------------------------------

_CSS = """
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body {
  font-family: Georgia, "Times New Roman", serif;
  font-size: 11.5pt;
  line-height: 1.5;
  color: #1a1a1a;
  background: #fff;
  margin: 0 auto;
  max-width: 780px;
  padding: 28px 36px;
}
h1, h2, h3 { font-family: "Helvetica Neue", Arial, sans-serif; color: #14213d; }
h1 { font-size: 22pt; margin: 0 0 4pt 0; }
h2 { font-size: 14pt; margin: 24pt 0 6pt 0;
     border-bottom: 1px solid #ccc; padding-bottom: 4pt; }
h3 { font-size: 12pt; margin: 14pt 0 4pt 0; color: #2a3b5f; }
.meta { color: #666; font-size: 10pt; margin-bottom: 18pt; }
.subtitle { color: #444; font-style: italic; margin: 0 0 18pt 0; }
.section-lead { color: #444; font-style: italic; margin-bottom: 8pt; }
table.kv {
  width: 100%; border-collapse: collapse; margin: 4pt 0 12pt 0;
}
table.kv td {
  padding: 4pt 8pt; vertical-align: top; border-bottom: 1px solid #eee;
}
table.kv td.k { width: 30%; color: #555; font-weight: 600; }
.summary-box {
  background: #f4f6fa; border-left: 4px solid #14213d;
  padding: 12pt 14pt; margin: 8pt 0 14pt 0;
}
.confidence-tag {
  display: inline-block; padding: 1pt 8pt;
  font-size: 9pt; font-weight: 600; border-radius: 3pt;
  text-transform: uppercase; letter-spacing: 0.5pt;
}
.confidence-tag.strong { background: #d4edda; color: #155724; }
.confidence-tag.moderate { background: #fff3cd; color: #856404; }
.confidence-tag.preliminary { background: #f8d7da; color: #721c24; }
.confidence-tag.thin { background: #e2e3e5; color: #383d41; }
.finding-row {
  padding: 6pt 0; border-bottom: 1px dotted #ddd;
}
.finding-row .ts {
  color: #666; font-size: 9.5pt; font-family: "Courier New", monospace;
}
.finding-row .text { margin-top: 2pt; }
.recommendation {
  margin: 10pt 0; padding: 10pt 12pt;
  border-left: 3px solid #14213d; background: #fafbfc;
}
.recommendation .cat {
  font-size: 9pt; font-weight: 600; text-transform: uppercase;
  color: #14213d; letter-spacing: 0.5pt;
}
.recommendation .why {
  font-size: 10pt; color: #555; margin-top: 4pt; font-style: italic;
}
.recommendation .anchor {
  font-size: 9pt; color: #888; margin-top: 4pt;
  font-family: "Courier New", monospace;
}
.advisory {
  margin-top: 14pt; padding: 10pt 12pt;
  background: #fdfdfd; border: 1px dashed #aaa; font-size: 10pt;
  color: #444;
}
.glossary-entry {
  margin: 6pt 0; padding-left: 12pt; border-left: 2px solid #eee;
}
.glossary-entry .term {
  font-family: "Courier New", monospace; font-weight: 600; color: #14213d;
}
.glossary-entry .plain { color: #444; font-style: italic; }
.handoff {
  margin-top: 22pt; padding-top: 8pt; border-top: 1px solid #ccc;
  font-size: 10pt; color: #555;
}
.empty { color: #888; font-style: italic; }
@media print {
  h2, h3 { page-break-after: avoid; }
  .recommendation, .glossary-entry { page-break-inside: avoid; }
}
"""


# ---------------------------------------------------------------------------
# Small render helpers
# ---------------------------------------------------------------------------

def _e(s: str) -> str:
    """HTML-escape a value, defaulting empty to em-dash for cleaner cells."""
    if s is None or s == "":
        return "&mdash;"
    return _h.escape(str(s))


def _confidence_tag(score: int, gap: int) -> str:
    """CSS class for the confidence pill matching the digest's
    confidence_phrase logic."""
    if score <= 0:
        return "thin"
    if score >= 10 and gap >= 5:
        return "strong"
    if score >= 3 and gap >= 2:
        return "moderate"
    return "preliminary"


def _format_time(ts: str | None) -> str:
    if not ts:
        return ""
    # Trim sub-second + timezone for readability; full value is in
    # the analyst report.
    return ts[:19].replace("T", " ")


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_case_details(case_id: str, manifest: dict, meta: CaseMetadata) -> str:
    rows: list[tuple[str, str]] = []
    if meta.case_number:
        rows.append(("Case number", meta.case_number))
    rows.append(("Internal case ID", case_id))
    if meta.incident_date:
        rows.append(("Incident date", meta.incident_date.isoformat()))
    if meta.investigator_name:
        rows.append(("Investigator", meta.investigator_name))
    rows.append(("Report generated",
                 datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")))
    rows.append(("Evidence", manifest.get("input_path", "—").split("/")[-1]))
    sz = manifest.get("input_size_bytes")
    if sz:
        sz = int(sz)
        rows.append(("Evidence size",
                     f"{sz/1024/1024/1024:.2f} GiB" if sz > 1024**3
                     else f"{sz/1024/1024:.1f} MiB"))
    sha = manifest.get("input_sha256")
    if sha:
        rows.append(("Evidence SHA-256", f"{sha[:16]}…{sha[-8:]}"))
    parts = [f"<tr><td class='k'>{_e(k)}</td><td>{_e(v)}</td></tr>"
              for k, v in rows]
    return ("<h2>Case Details &amp; Evidence</h2>"
            f"<table class='kv'>{''.join(parts)}</table>")


def _render_objective(meta: CaseMetadata) -> str:
    if not meta.objective_statement:
        return ""
    return ("<h2>Objective</h2>"
            f"<p>{_e(meta.objective_statement)}</p>")


def _render_executive_summary(digest: ExecutiveDigest, score: int, gap: int) -> str:
    tag = _confidence_tag(score, gap)
    tag_label = {"strong": "Strong evidence",
                 "moderate": "Moderate evidence",
                 "preliminary": "Preliminary",
                 "thin": "Inconclusive"}[tag]
    paragraph = " ".join(_e(s) for s in digest.summary_sentences)
    # restore bold for the headline form (embedded as **headline**)
    paragraph = paragraph.replace(
        f"**{_h.escape(digest.headline)}**",
        f"<strong>{_h.escape(digest.headline)}</strong>",
    )
    return (
        "<h2>Executive Summary</h2>"
        f"<div class='summary-box'>"
        f"<span class='confidence-tag {tag}'>{tag_label}</span>"
        f"<p style='margin-top:8pt'>{paragraph}</p>"
        f"</div>"
    )


def _render_findings_chronological(findings: list[Finding], cap: int = 25) -> str:
    """Chronological list of findings ordered by artifact-time (when
    the event happened on the host), not EL ingest time. Drops
    insufficient findings (which by contract have no evidence) and
    knowledge_lookup chatter (Layer-3 cross-case context)."""
    keep: list[tuple[datetime, Finding]] = []
    for f in findings:
        if f.confidence == "insufficient":
            continue
        if (f.agent or "") == "knowledge_lookup":
            continue
        ts = evidence_time(f)
        if ts is None:
            continue
        keep.append((ts, f))
    keep.sort(key=lambda r: r[0])
    if not keep:
        return ("<h2>Findings</h2>"
                "<p class='empty'>No timestamped findings — see the "
                "analyst report for the full ledger.</p>")
    rows = []
    for ts, f in keep[:cap]:
        # Prefer agent-supplied human_summary on any evidence item;
        # fall back to glossary-translated claim.
        summary = next(
            (ev.human_summary for ev in (f.evidence or [])
             if ev.human_summary), None,
        )
        if not summary:
            from el.reporting.narrative import _strip_jargon
            summary = _strip_jargon(f.claim or "") or (f.claim or "")
        rows.append(
            "<div class='finding-row'>"
            f"<div class='ts'>{_e(_format_time(ts.isoformat()))}</div>"
            f"<div class='text'>{_e(summary)}</div>"
            "</div>"
        )
    head_extra = ""
    if len(keep) > cap:
        head_extra = (f"<p class='section-lead'>Showing the first "
                      f"{cap} findings in chronological order; "
                      f"{len(keep) - cap} more in the analyst report.</p>")
    return f"<h2>Findings (chronological)</h2>{head_extra}{''.join(rows)}"


def _render_conclusion(digest: ExecutiveDigest, leading_hyp: str | None) -> str:
    pieces = [f"<p>The leading theory is <strong>{_e(digest.headline)}</strong>; "
              f"{_e(digest.confidence_phrase)}.</p>"]
    if digest.time_range_phrase:
        pieces.append(
            f"<p>Activity window: {_e(digest.time_range_phrase)}.</p>"
        )
    if digest.affected_assets:
        items = ", ".join(_e(a) for a in digest.affected_assets)
        pieces.append(f"<p>Evidence considered: {items}.</p>")
    if digest.open_questions:
        ol = "".join(f"<li>{_e(q)}</li>" for q in digest.open_questions)
        pieces.append(
            f"<p>Open questions ({len(digest.open_questions)}):</p><ol>{ol}</ol>"
        )
    return f"<h2>Conclusion</h2>{''.join(pieces)}"


def _render_recommendations(recs: list[Recommendation]) -> str:
    if not recs:
        return ("<h2>Recommendations</h2>"
                "<p class='empty'>No specific recommendations are "
                "triggered by the current findings.</p>"
                f"<div class='advisory'>{_e(ADVISORY_DISCLAIMER)}</div>")
    blocks = []
    for r in recs:
        anchor = ""
        if r.triggered_by:
            cited = ", ".join(_e(fid) for fid in r.triggered_by[:3])
            anchor = f"<div class='anchor'>Cites: {cited}</div>"
        blocks.append(
            "<div class='recommendation'>"
            f"<div class='cat'>{_e(r.category)}</div>"
            f"<div>{_e(r.action)}</div>"
            f"<div class='why'>{_e(r.rationale)}</div>"
            f"{anchor}"
            "</div>"
        )
    return ("<h2>Recommendations</h2>"
            f"{''.join(blocks)}"
            f"<div class='advisory'>{_e(ADVISORY_DISCLAIMER)}</div>")


def _render_methodology(findings: list[Finding]) -> str:
    """One-paragraph methodology blurb plus a tools-and-versions list.
    The paragraph is fixed prose; the tool list is mined from the
    EvidenceItem.tool/version pairs across the ledger."""
    tools: dict[str, str] = {}
    for f in findings:
        for ev in (f.evidence or []):
            tools.setdefault(ev.tool, ev.version)
    rows = "".join(
        f"<tr><td class='k'>{_e(t)}</td><td>{_e(v)}</td></tr>"
        for t, v in sorted(tools.items())
    )
    return (
        "<h3>Methodology</h3>"
        "<p>This investigation used court-vetted command-line forensic "
        "tools to extract evidence from the source media. Every claim "
        "in the analyst report cites the tool, version, and command "
        "that produced it, and includes a SHA-256 hash of the raw "
        "tool output so a third party can re-run the same step and "
        "verify the result.</p>"
        f"<table class='kv'>{rows}</table>"
    )


def _render_glossary_appendix(findings: list[Finding],
                                hypotheses_seen: list[str]) -> str:
    """Build a glossary of every jargon term that surfaced in this
    case's source data — the raw claim text, evidence claims, and
    hypothesis tags. The rendered exec body translates these terms,
    so a stakeholder reading the body sees plain English; the
    appendix gives them the analyst-facing token + the explanation
    if they want to walk back into the analyst report."""
    # Aggregate all terms a curious reader might encounter when they
    # cross-reference back to case.html / report.md.
    haystack_parts: list[str] = list(hypotheses_seen)
    for f in findings:
        haystack_parts.append(f.claim or "")
        haystack_parts.extend(f.hypotheses_supported or [])
    haystack = " ".join(haystack_parts)
    used = glossary.entries_used(haystack)
    if not used:
        return ""
    items = "".join(
        "<div class='glossary-entry'>"
        f"<span class='term'>{_e(e.term)}</span>"
        f" — <span class='plain'>{_e(e.plain)}</span>"
        f"<div>{_e(e.explanation)}</div>"
        "</div>"
        for e in used
    )
    return f"<h3>Glossary of terms used</h3>{items}"


def _render_appendix(case_dir: Path, findings: list[Finding],
                      hypotheses_seen: list[str]) -> str:
    parts: list[str] = ["<h2>Appendix</h2>"]
    parts.append(_render_methodology(findings))
    parts.append(_render_glossary_appendix(findings, hypotheses_seen))
    # Pointer back to the analyst report
    case_html = case_dir / "reports" / "case.html"
    parts.append(
        "<h3>Analyst report</h3>"
        f"<p>Full technical detail (every finding, evidence chain, "
        f"ATT&amp;CK technique mapping, ACH consistency matrix, IOC "
        f"catalog) is preserved in <code>{_e(str(case_html))}</code>. "
        f"The analyst report and this executive report are both "
        f"deterministic projections of the same ledger and cannot "
        f"disagree about the same evidence.</p>"
    )
    return "".join(parts)


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def render_executive_html(
    case_dir: str | Path,
    case_id: str | None = None,
    manifest: dict | None = None,
) -> Path:
    """Render the executive HTML report for a case.

    Reads findings.sqlite, manifest.json, and case_metadata.json (if
    present); writes `reports/executive.html`. Returns the output path.

    `case_id` and `manifest` are read from disk when not supplied —
    matches the existing render.py / html.py call patterns.
    """
    case_dir = Path(case_dir)
    if manifest is None:
        m_path = case_dir / "manifest.json"
        manifest = json.loads(m_path.read_text()) if m_path.exists() else {}
    if case_id is None:
        case_id = manifest.get("case_id", case_dir.name)

    meta = load_case_metadata(case_dir)
    findings = list_findings(case_dir, case_id=case_id)
    ranking, _diag = score_findings(findings)
    nr = synthesize(case_id, findings, ach_ranking=ranking, manifest=manifest)
    digest = synthesize_executive(nr)
    recs = build_recommendations(nr, findings)

    body_sections: list[str] = []
    body_sections.append(_render_case_details(case_id, manifest, meta))
    body_sections.append(_render_objective(meta))
    body_sections.append(
        _render_executive_summary(digest, nr.leading_score, nr.leading_gap)
    )
    body_sections.append(_render_findings_chronological(findings))
    body_sections.append(_render_conclusion(digest, nr.leading_hypothesis))
    body_sections.append(_render_recommendations(recs))

    # Glossary scans the raw analyst data — claims + hypothesis tags —
    # not the post-translation body, because the body has already had
    # tokens swapped for plain English.
    hyps_seen = []
    if nr.leading_hypothesis:
        hyps_seen.append(nr.leading_hypothesis)
    if nr.runner_up_hypothesis:
        hyps_seen.append(nr.runner_up_hypothesis)
    body_sections.append(_render_appendix(case_dir, findings, hyps_seen))

    title_suffix = (f" — {meta.case_number}"
                     if meta.case_number else "")
    title = _h.escape(f"EL Executive Report — {case_id}{title_suffix}")

    html_doc = (
        "<!DOCTYPE html>"
        "<html lang='en'>"
        f"<head><meta charset='utf-8'><title>{title}</title>"
        f"<style>{_CSS}</style></head>"
        "<body>"
        f"<h1>{title}</h1>"
        f"<p class='meta'>Generated "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        " &middot; Executive (non-expert) report tier"
        "</p>"
        f"<p class='subtitle'>This report summarises the investigation "
        f"in plain language. Full technical detail is preserved in the "
        f"analyst report.</p>"
        f"{''.join(body_sections)}"
        "<div class='handoff'>"
        "End of executive report. For raw forensic evidence, ATT&amp;CK "
        "technique mappings, hypothesis-consistency matrices, and the "
        "complete IOC catalog, refer to the analyst report "
        "(<code>case.html</code> / <code>report.md</code>) in the same "
        "case directory."
        "</div>"
        "</body></html>"
    )

    out = case_dir / "reports" / "executive.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_doc)
    return out


__all__ = ["render_executive_html"]

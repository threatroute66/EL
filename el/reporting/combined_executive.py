"""Combined executive (non-expert) report — multi-host equivalent of
``executive.py`` for ``el combined-report`` outputs.

Single cases produce ``reports/executive.html`` + ``reports/executive.pdf``
aimed at non-technical stakeholders (the analyst report — ``case.html`` —
is the technical view). The multi-host equivalent stitches per-host
executive digests into one cross-host stakeholder report covering:

  1. Case identifier + scope (how many hosts, evidence-time span)
  2. Executive summary (cross-host attack story in plain English)
  3. Per-host attribution table (leading hypothesis + 1-line digest each)
  4. Cross-host recommendations
  5. Pointer to the technical combined.html for drill-down
  6. Glossary appendix

Output: ``<combined>/combined_executive.html`` + ``combined_executive.pdf``.
The combined.html dashboard gets a download icon linking to the PDF.

CSS is reused from executive.py for visual consistency — same look and
feel between single-case and multi-host stakeholder PDFs.
"""
from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from el.evidence.ledger import list_findings
from el.intel.ach import score_findings
from el.reporting import glossary
from el.reporting.executive import _CSS as _SINGLE_CSS
from el.reporting.executive import (
    _AI_BRIEF_SECTIONS,
    _confidence_tag,
    _e,
    _markdown_to_html,
)
from el.reporting.narrative import synthesize, synthesize_executive
from el.reporting.recommendations import build_recommendations


@dataclass
class _HostSlice:
    case_id: str
    case_dir: Path
    leading_hyp: str | None
    leading_score: int
    leading_gap: int
    high_count: int
    digest_text: str       # one-paragraph per-host plain-English summary
    ai_brief: dict | None  # cached six-section AI brief, if available


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _load_host_slice(case_dir: Path) -> _HostSlice:
    """Load the per-host slice we need — leading hypothesis, finding count,
    and the deterministic per-host digest from synthesize_executive()."""
    manifest_path = case_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    case_id = manifest.get("case_id", case_dir.name)
    findings = list_findings(case_dir, case_id=case_id)
    high = sum(1 for f in findings if f.confidence == "high")
    ranking, _diag = score_findings(findings)
    leading = ranking[0] if ranking else None
    runner = ranking[1] if len(ranking) >= 2 else None
    leading_score = leading.score if leading else 0
    runner_score = runner.score if runner else 0
    leading_gap = max(0, leading_score - runner_score)
    leading_hyp = leading.hyp_id if leading else None

    # Reuse the deterministic digest the single-case executive renderer
    # would have produced for this host. That gives us a consistent
    # plain-English summary across both single-case + multi-host outputs.
    nr = synthesize(case_id, findings, ach_ranking=ranking, manifest=manifest)
    digest = synthesize_executive(nr)
    # Headline + first 1-2 summary sentences as the per-host digest. The
    # ExecutiveDigest from narrative.synthesize_executive() exposes
    # headline + summary_sentences + confidence_phrase — we stitch them
    # into a compact paragraph the per-host table row can carry.
    parts: list[str] = []
    if digest.headline:
        parts.append(digest.headline.rstrip(". ") + ".")
    if digest.summary_sentences:
        parts.extend(s.rstrip(". ") + "." for s in digest.summary_sentences[:2])
    digest_text = " ".join(parts) or f"{leading_hyp} score={leading_score}"

    # Per-host AI brief — the same six-section JSON the single-case
    # executive renderer reads. When present, combined_executive surfaces
    # each host's brief verbatim so the stakeholder sees the rich
    # what-happened / what-was-taken / where-it-went / when / risk /
    # confidence narrative cross-host, not just one-line digests.
    ai_brief = _load_ai_brief(case_dir)

    return _HostSlice(
        case_id=case_id, case_dir=case_dir,
        leading_hyp=leading_hyp,
        leading_score=leading_score, leading_gap=leading_gap,
        high_count=high, digest_text=digest_text,
        ai_brief=ai_brief,
    )


def _load_ai_brief(case_dir: Path) -> dict | None:
    """Return the cached ExecutiveBrief dict from
    ``reports/executive_ai_brief.json`` (schema_version=2), or None if
    the file is missing / unparseable / wrong schema. The cache envelope
    wraps the brief under the ``brief`` key (mirrors the el-ai-brief
    skill output)."""
    cache_path = case_dir / "reports" / "executive_ai_brief.json"
    if not cache_path.is_file():
        return None
    try:
        payload = json.loads(cache_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    brief = payload.get("brief")
    if not isinstance(brief, dict):
        return None
    if brief.get("schema_version") != 2:
        return None
    return brief


def _render_header(name: str, slices: list[_HostSlice]) -> str:
    total_findings = sum(s.high_count for s in slices)
    case_count = len(slices)
    leaders = Counter(s.leading_hyp for s in slices if s.leading_hyp)
    dom = leaders.most_common(1)[0] if leaders else (None, 0)
    return (
        f"<h1>{_e(name)}</h1>"
        f"<p class='subtitle'>Combined executive report for non-technical "
        f"stakeholders, covering {case_count} host(s) and "
        f"{total_findings:,} high-confidence finding(s).</p>"
        f"<p class='meta'>Generated {_e(_now_iso())} UTC · Dominant pattern "
        f"across hosts: <b>{_e(dom[0] or 'mixed')}</b> "
        f"(lead in {dom[1]} of {case_count}).</p>"
    )


def _render_executive_summary(slices: list[_HostSlice]) -> str:
    """Cross-host attack story in plain English. Pulls the strongest
    per-host signal + cross-host commonality."""
    if not slices:
        return ""
    leaders = Counter(s.leading_hyp for s in slices if s.leading_hyp)
    dom_hyp, dom_count = leaders.most_common(1)[0] if leaders else (None, 0)
    top_score = max(slices, key=lambda s: s.leading_score)
    n = len(slices)

    strong = [s for s in slices if s.leading_score >= 20]
    parts = []
    score_label = _confidence_tag(top_score.leading_score, top_score.leading_gap)
    parts.append(
        f"<p>Across <b>{n}</b> host(s), the dominant compromise pattern "
        f"is <b>{_e(dom_hyp or 'mixed')}</b> — observed as the leading "
        f"hypothesis on <b>{dom_count} of {n}</b> hosts.</p>"
    )
    parts.append(
        f"<p>The strongest individual host signal comes from "
        f"<code>{_e(top_score.case_id)}</code>, with a score of "
        f"<b>{top_score.leading_score}</b> {score_label} for "
        f"<b>{_e(top_score.leading_hyp or '—')}</b>.</p>"
    )
    if len(strong) > 1:
        names = ", ".join(f"<code>{_e(s.case_id)}</code> ({s.leading_score})"
                            for s in sorted(
                                strong, key=lambda x: -x.leading_score)[:6])
        parts.append(
            f"<p>Hosts with substantive compromise indicators "
            f"(score ≥ 20): {names}.</p>"
        )
    return "<h2>Executive Summary</h2>" + "<div class='summary-box'>" + \
           "".join(parts) + "</div>"


def _render_per_host_ai_briefs(slices: list[_HostSlice]) -> str:
    """Surface each host's cached six-section AI brief verbatim. When a
    host has no brief on disk we silently skip it — the deterministic
    digest in the per-host table still carries the headline. Hosts are
    ordered by ACH score descending so the strongest signal leads."""
    briefs = [s for s in slices if s.ai_brief is not None]
    if not briefs:
        return ""
    blocks: list[str] = ["<h2>Per-Host Executive Narratives</h2>"]
    for s in sorted(briefs, key=lambda x: -x.leading_score):
        tag = _confidence_tag(s.leading_score, s.leading_gap)
        sections_html: list[str] = []
        for field_name, display_title in _AI_BRIEF_SECTIONS:
            body = (s.ai_brief or {}).get(field_name, "") or ""
            if not body.strip():
                continue
            sections_html.append(
                f"<section class='ai-section'>"
                f"<h4>{_e(display_title)}</h4>"
                f"{_markdown_to_html(body)}"
                f"</section>"
            )
        if not sections_html:
            continue
        blocks.append(
            f"<div class='summary-box ai-brief'>"
            f"<h3><code>{_e(s.case_id)}</code> "
            f"<span class='confidence-tag {tag}'>"
            f"{_e(s.leading_hyp or '—')} · score {s.leading_score}"
            f"</span></h3>"
            f"{''.join(sections_html)}"
            f"</div>"
        )
    if len(blocks) == 1:
        return ""
    return "".join(blocks)


def _render_per_host_table(slices: list[_HostSlice]) -> str:
    rows = []
    for s in sorted(slices, key=lambda x: -x.leading_score):
        tag = _confidence_tag(s.leading_score, s.leading_gap)
        digest = (s.digest_text or "").strip()
        if len(digest) > 280:
            digest = digest[:277] + "…"
        rows.append(
            f"<tr>"
            f"<td><code>{_e(s.case_id)}</code></td>"
            f"<td>{_e(s.leading_hyp or '—')}</td>"
            f"<td style='text-align:right'>{s.leading_score}</td>"
            f"<td>{tag}</td>"
            f"<td>{_e(digest)}</td>"
            f"</tr>"
        )
    return (
        "<h2>Per-Host Attribution</h2>"
        "<table class='kv'>"
        "<thead><tr>"
        "<th align='left'>Host</th>"
        "<th align='left'>Pattern</th>"
        "<th align='right'>Score</th>"
        "<th align='left'>Confidence</th>"
        "<th align='left'>Digest</th>"
        "</tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody>"
        "</table>"
    )


def _render_recommendations(slices: list[_HostSlice]) -> str:
    """Aggregate per-host recommendations; keep distinct ones."""
    seen: dict[tuple[str, str], dict] = {}
    for s in slices:
        try:
            findings = list_findings(s.case_dir, case_id=s.case_id)
            ranking, _ = score_findings(findings)
            nr = synthesize(s.case_id, findings, ach_ranking=ranking,
                              manifest={"case_id": s.case_id})
            recs = build_recommendations(nr, findings)
        except Exception:
            continue
        for r in recs:
            key = (r.category, r.action[:80])
            if key not in seen:
                seen[key] = {"rec": r, "hosts": [s.case_id]}
            else:
                seen[key]["hosts"].append(s.case_id)

    if not seen:
        return ""
    blocks: list[str] = ["<h2>Cross-Host Recommendations</h2>"]
    for entry in list(seen.values())[:15]:
        r = entry["rec"]
        hosts = entry["hosts"]
        blocks.append(
            "<div class='recommendation'>"
            f"<div class='cat'>{_e(r.category)}</div>"
            f"<div class='action'>{_e(r.action)}</div>"
            + (f"<div class='why'>{_e(r.rationale)}</div>"
                if r.rationale else "")
            + (f"<div class='anchor'>Applies to: "
                f"{', '.join(_e(h) for h in hosts[:8])}"
                f"{(' (+%d more)' % (len(hosts)-8)) if len(hosts) > 8 else ''}"
                f"</div>" if hosts else "")
            + "</div>"
        )
    return "".join(blocks)


def _render_handoff(name: str, output_dir: Path) -> str:
    return (
        "<h2>Drill-down to technical detail</h2>"
        f"<p>This is the executive (non-technical) view. The full "
        f"technical analysis — every finding, evidence chain, ATT&amp;CK "
        f"technique mapping, joint ACH consistency matrix, IOC catalog, "
        f"and cross-host signal heatmap — is preserved in "
        f"<code>combined.html</code> alongside this PDF "
        f"({_e(str(output_dir / 'combined.html'))}). The technical and "
        f"executive views are both deterministic projections of the same "
        f"per-host ledgers and cannot disagree about the same evidence.</p>"
    )


def _render_glossary(slices: list[_HostSlice]) -> str:
    """Glossary entries for whatever DFIR jargon ended up in the report."""
    # Build a string from the per-host digests + hypothesis tags so
    # glossary.entries_used() can scan it for terms it knows about.
    blob_parts: list[str] = []
    for s in slices:
        if s.leading_hyp:
            blob_parts.append(s.leading_hyp)
        if s.digest_text:
            blob_parts.append(s.digest_text)
    blob = " ".join(blob_parts)
    entries = glossary.entries_used(blob) if blob else []
    if not entries:
        return ""
    items = "".join(
        "<div class='glossary-entry'>"
        f"<span class='term'>{_e(e.term)}</span>"
        f" — <span class='plain'>{_e(e.plain)}</span>"
        f"<div>{_e(e.explanation)}</div>"
        "</div>"
        for e in entries
    )
    return "<h2>Glossary</h2>" + items


def render_combined_executive(
    case_dirs: list[Path],
    output_path: Path,
    *,
    name: str = "combined-case",
) -> Path:
    """Render the multi-host executive HTML for *case_dirs* into *output_path*.

    The output path SHOULD be ``<combined>/combined_executive.html``;
    callers can render it to PDF afterwards via WeasyPrint (see CLI).
    """
    case_dirs = [Path(d) for d in case_dirs]
    slices: list[_HostSlice] = []
    for d in case_dirs:
        try:
            slices.append(_load_host_slice(d))
        except Exception:
            # A malformed case dir shouldn't kill the executive report —
            # skip silently and proceed; the analyst can drill down via
            # combined.html if needed.
            continue

    body = (
        _render_header(name, slices)
        + _render_executive_summary(slices)
        + _render_per_host_ai_briefs(slices)
        + _render_per_host_table(slices)
        + _render_recommendations(slices)
        + _render_handoff(name, output_path.parent)
        + _render_glossary(slices)
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    document = (
        "<!doctype html>\n"
        f"<html lang='en'><head>"
        f"<meta charset='utf-8'>"
        f"<title>EL combined executive — {html.escape(name)}</title>"
        f"<style>{_SINGLE_CSS}</style>"
        f"</head><body>{body}</body></html>"
    )
    output_path.write_text(document)
    return output_path


def render_combined_executive_pdf(
    html_path: Path,
    pdf_path: Path | None = None,
) -> Path:
    """Render the combined executive HTML to PDF via WeasyPrint."""
    from weasyprint import HTML  # type: ignore
    pdf_path = pdf_path or html_path.with_suffix(".pdf")
    HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    return pdf_path

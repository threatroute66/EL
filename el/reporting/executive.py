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

from el.bundle import BundleManifest, is_bundle, load as load_bundle
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
.ai-disclaimer {
  background: #fff8e1; border: 1px dashed #d4a017;
  padding: 8pt 12pt; margin: 8pt 0 4pt 0;
  font-size: 9.5pt; color: #5b4400;
}
.ai-disclaimer strong { color: #5b4400; }
.ai-meta {
  font-size: 8.5pt; color: #888; margin-top: 8pt;
  font-family: "Helvetica Neue", Arial, sans-serif;
}
.ai-meta code { font-family: "Courier New", monospace; color: #555; }
.ai-brief section.ai-section { margin: 14pt 0 6pt 0; }
.ai-brief section.ai-section h3 {
  font-size: 12pt; margin: 0 0 6pt 0; color: #14213d;
  display: flex; align-items: center; gap: 8pt;
}
.ai-brief section.ai-section table {
  border-collapse: collapse; margin: 6pt 0; font-size: 9.5pt; width: 100%;
}
.ai-brief section.ai-section th,
.ai-brief section.ai-section td {
  border: 1px solid #ddd; padding: 4pt 7pt; text-align: left; vertical-align: top;
}
.ai-brief section.ai-section th { background: #ebeef3; font-weight: 600; }
.ai-brief section.ai-section ol,
.ai-brief section.ai-section ul { margin: 4pt 0 4pt 18pt; }
.ai-brief section.ai-section p { margin: 4pt 0; }
.ai-chip {
  display: inline-block; padding: 1pt 6pt;
  font-size: 8pt; font-weight: 600; border-radius: 3pt;
  background: #fff8e1; color: #5b4400; border: 1px dashed #d4a017;
  text-transform: uppercase; letter-spacing: 0.4pt;
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
.finding-row .device-chip {
  display: inline-block;
  margin-right: 6pt;
  padding: 0pt 6pt;
  font-size: 8.5pt;
  font-weight: 600;
  font-family: "Helvetica Neue", Arial, sans-serif;
  background: #14213d;
  color: #fff;
  border-radius: 2pt;
  letter-spacing: 0.4pt;
  vertical-align: middle;
}
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

def _format_size(sz_bytes: int | str | None) -> str:
    if not sz_bytes:
        return "—"
    sz = int(sz_bytes)
    return (f"{sz/1024/1024/1024:.2f} GiB" if sz > 1024**3
            else f"{sz/1024/1024:.1f} MiB")


def _render_case_details(case_id: str, manifest: dict, meta: CaseMetadata,
                          bundle: BundleManifest | None = None) -> str:
    """Case Details + Evidence section.

    Single-host: standard kv table with one evidence file.
    Bundle: kv table covers case-level metadata, then a per-device
    evidence table with one row per device. Same heading either way
    so the executive report's section count stays stable.
    """
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

    if bundle is None:
        # Single-host — inline evidence in the kv table as before.
        rows.append(("Evidence", manifest.get("input_path", "—").split("/")[-1]))
        sz = manifest.get("input_size_bytes")
        if sz:
            rows.append(("Evidence size", _format_size(sz)))
        sha = manifest.get("input_sha256")
        if sha:
            rows.append(("Evidence SHA-256", f"{sha[:16]}…{sha[-8:]}"))
        parts = [f"<tr><td class='k'>{_e(k)}</td><td>{_e(v)}</td></tr>"
                  for k, v in rows]
        return ("<h2>Case Details &amp; Evidence</h2>"
                f"<table class='kv'>{''.join(parts)}</table>")

    # Bundle — case-level metadata first, then per-device table.
    rows.append(("Bundle device count", str(len(bundle.devices))))
    rows.append(("Total evidence size",
                  _format_size(sum(d.input_size_bytes for d in bundle.devices))))
    kv_html = "".join(
        f"<tr><td class='k'>{_e(k)}</td><td>{_e(v)}</td></tr>"
        for k, v in rows
    )
    dev_rows = []
    for d in bundle.devices:
        sha_short = f"{d.input_sha256[:16]}…{d.input_sha256[-8:]}" if d.input_sha256 else "—"
        evidence_basename = d.input_path.split("/")[-1] if d.input_path else "—"
        dev_rows.append(
            f"<tr><td><strong>{_e(d.name)}</strong></td>"
            f"<td>{_e(evidence_basename)}</td>"
            f"<td>{_e(_format_size(d.input_size_bytes))}</td>"
            f"<td><code style='font-size:9pt'>{_e(sha_short)}</code></td></tr>"
        )
    devices_html = (
        "<h3>Devices in this bundle</h3>"
        "<table class='kv'>"
        "<tr><td class='k'>Device</td><td class='k'>Evidence</td>"
        "<td class='k'>Size</td><td class='k'>SHA-256</td></tr>"
        f"{''.join(dev_rows)}"
        "</table>"
    )
    return ("<h2>Case Details &amp; Evidence</h2>"
            f"<table class='kv'>{kv_html}</table>"
            f"{devices_html}")


def _render_objective(meta: CaseMetadata) -> str:
    if not meta.objective_statement:
        return ""
    return ("<h2>Objective</h2>"
            f"<p>{_e(meta.objective_statement)}</p>")


def _render_executive_summary(digest: ExecutiveDigest, score: int, gap: int,
                                ai_brief=None,
                                ai_metadata: dict | None = None) -> str:
    """Render the Executive Summary section.

    When `ai_brief` is an ``ExecutiveBrief`` (Phase 10 / schema_version=2),
    the brief's six sections render under the section header with a
    non-removable disclaimer banner above them and a per-section
    "AI-rendered" chip. The deterministic digest still feeds the
    confidence tag so the colour-coded badge stays grounded in the
    ACH score, not LLM judgement.

    When `ai_brief` is None (no API key, API call failed, model
    returned malformed JSON, or operator disabled it), the
    deterministic digest renders as before — no silent feature loss.
    """
    tag = _confidence_tag(score, gap)
    tag_label = {"strong": "Strong evidence",
                 "moderate": "Moderate evidence",
                 "preliminary": "Preliminary",
                 "thin": "Inconclusive"}[tag]
    if ai_brief is not None:
        return _render_ai_brief(ai_brief, tag, tag_label, ai_metadata)

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


# Section ordering + display titles for the AI-rendered brief. The
# tuple shape — (field_name, display_title) — keeps the renderer's
# section list authoritative even if the schema later grows extra
# fields the renderer doesn't yet know about.
_AI_BRIEF_SECTIONS: tuple[tuple[str, str], ...] = (
    ("what_happened", "What happened"),
    ("what_was_taken", "What was taken"),
    ("where_it_went", "Where it went"),
    ("when_timeline", "When"),
    ("risk_implications", "Risk implications"),
    ("confidence_and_limits", "Confidence and limits"),
)


def _markdown_to_html(text: str) -> str:
    """Render a markdown blob to HTML for one ExecutiveBrief section.
    Tables are enabled; raw HTML is enabled because the LLM may have
    embedded escape sequences for filenames containing < or > —
    the surrounding ``<div class='ai-section'>`` already isolates the
    payload from the page's structural elements."""
    try:
        import markdown_it
    except ImportError:
        # Defensive: if markdown_it is unavailable for some reason,
        # at least show the raw text — keeps the brief visible rather
        # than swallowing it. Wrap in <pre> so it's legible.
        return f"<pre>{_e(text)}</pre>"
    md = markdown_it.MarkdownIt("commonmark", {"html": True})
    md.enable("table")
    return md.render(text)


def _render_ai_brief(ai_brief, tag: str, tag_label: str,
                       ai_metadata: dict | None) -> str:
    """Render an ExecutiveBrief as the multi-section HTML payload.

    Each section gets a header + an "AI-rendered" chip + the
    markdown-converted body. A non-removable disclaimer banner sits
    above the whole block. Confidence pill stays grounded in ACH score.
    """
    from el.reporting.executive_ai import DISCLAIMER_LABEL, SECTION_AI_CHIP
    cache_status = (ai_metadata or {}).get("cache", "")
    model = (ai_metadata or {}).get("model", "")
    meta_line = ""
    if model:
        meta_line = (f"<div class='ai-meta'>Model: "
                     f"<code>{_e(model)}</code> · "
                     f"cache: {_e(cache_status)}</div>")

    section_html_parts: list[str] = []
    for field_name, display_title in _AI_BRIEF_SECTIONS:
        body = getattr(ai_brief, field_name, "") or ""
        if not body.strip():
            # Schema validator guarantees no empties at the brief level,
            # but we still defend so future per-field operator edits
            # to the cache file can't blank a section into a half-render.
            continue
        section_html_parts.append(
            f"<section class='ai-section'>"
            f"<h3>{_e(display_title)} "
            f"<span class='ai-chip' title='Generated by AI'>"
            f"{_e(SECTION_AI_CHIP)}</span></h3>"
            f"{_markdown_to_html(body)}"
            f"</section>"
        )

    return (
        "<h2>Executive Summary</h2>"
        f"<div class='ai-disclaimer' role='note'>"
        f"<strong>{_e(DISCLAIMER_LABEL)}</strong>"
        f"</div>"
        f"<div class='summary-box ai-brief'>"
        f"<span class='confidence-tag {tag}'>{tag_label}</span>"
        f"{''.join(section_html_parts)}"
        f"{meta_line}"
        f"</div>"
    )


def _render_findings_chronological(findings: list[Finding], cap: int = 25,
                                     show_device_tags: bool = False) -> str:
    """Chronological list of findings ordered by artifact-time (when
    the event happened on the host), not EL ingest time. Drops
    insufficient findings (which by contract have no evidence) and
    knowledge_lookup chatter (Layer-3 cross-case context).

    `show_device_tags=True` (bundle mode) prefixes each row with a
    coloured device chip so a stakeholder can see which device
    contributed which signal.
    """
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
        chip = ""
        if show_device_tags and f.device:
            chip = f"<span class='device-chip'>{_e(f.device)}</span>"
        rows.append(
            "<div class='finding-row'>"
            f"<div class='ts'>{_e(_format_time(ts.isoformat()))}</div>"
            f"<div class='text'>{chip}{_e(summary)}</div>"
            "</div>"
        )
    head_extra = ""
    if len(keep) > cap:
        head_extra = (f"<p class='section-lead'>Showing the first "
                      f"{cap} findings in chronological order; "
                      f"{len(keep) - cap} more in the analyst report.</p>")
    return f"<h2>Findings (chronological)</h2>{head_extra}{''.join(rows)}"


# Plain-English labels for IOC type keys used in iocs.json. Renders
# as the section header in the cross-device correlation table.
_IOC_TYPE_LABELS = {
    "ipv4": "IP addresses",
    "ipv6": "IPv6 addresses",
    "domain": "Domains",
    "url": "URLs",
    "email": "Email addresses",
    "hash_md5": "MD5 hashes",
    "hash_sha1": "SHA-1 hashes",
    "hash_sha256": "SHA-256 hashes",
}


def _render_cross_device_iocs(case_dir: Path, bundle: BundleManifest) -> str:
    """Cross-device IOC pivot.

    Reads each device's iocs.json and surfaces every indicator that
    appears on 2+ devices. This is the strongest cross-host signal
    in a bundle case — when the same IP / domain / hash shows up on
    both the laptop and the phone, that's correlation evidence the
    stakeholder needs to see called out, not buried in a per-device
    IOC list.

    Renders an empty string when no IOCs cross device boundaries —
    section disappears rather than emitting an empty placeholder.
    """
    by_value: dict[tuple[str, str], set[str]] = {}
    for d in bundle.devices:
        ioc_path = Path(d.case_dir) / "iocs.json"
        if not ioc_path.exists():
            continue
        try:
            data = json.loads(ioc_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        for ioc_type, values in (data or {}).items():
            if not isinstance(values, list):
                continue
            for v in values:
                if not isinstance(v, str) or not v:
                    continue
                key = (ioc_type, v)
                by_value.setdefault(key, set()).add(d.name)
    # Keep only IOCs that crossed devices.
    shared = {k: devs for k, devs in by_value.items() if len(devs) >= 2}
    if not shared:
        return ""

    # Group by IOC type for presentation.
    by_type: dict[str, list[tuple[str, list[str]]]] = {}
    for (ioc_type, value), devs in shared.items():
        by_type.setdefault(ioc_type, []).append(
            (value, sorted(devs))
        )
    # Stable order: known types first (per _IOC_TYPE_LABELS), then any
    # extras alphabetically.
    type_order = list(_IOC_TYPE_LABELS.keys())
    type_order += sorted(t for t in by_type if t not in type_order)

    sections = []
    for t in type_order:
        if t not in by_type:
            continue
        label = _IOC_TYPE_LABELS.get(t, t)
        rows = []
        # Limit per-type to 25 — long IOC lists belong in the analyst
        # iocs.json catalog, not the executive report.
        items = sorted(by_type[t])[:25]
        for value, devs in items:
            rows.append(
                f"<tr><td><code style='font-size:9.5pt'>{_e(value)}</code></td>"
                f"<td>{_e(', '.join(devs))}</td></tr>"
            )
        more = ""
        if len(by_type[t]) > 25:
            more = (f"<p class='section-lead'>"
                    f"{len(by_type[t]) - 25} more in the analyst IOC catalog.</p>")
        sections.append(
            f"<h3>{_e(label)}</h3>"
            "<table class='kv'>"
            "<tr><td class='k'>Indicator</td>"
            "<td class='k'>Devices</td></tr>"
            f"{''.join(rows)}"
            "</table>"
            f"{more}"
        )

    return (
        "<h2>Cross-device correlation</h2>"
        "<p class='section-lead'>The following indicators appeared on "
        "more than one device. Cross-device matches are the strongest "
        "evidence that the devices are part of the same incident.</p>"
        f"{''.join(sections)}"
    )


def _render_conclusion(digest: ExecutiveDigest, leading_hyp: str | None,
                        bundle: BundleManifest | None = None) -> str:
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
    # Bundle-only: per-device leading-hypothesis breakdown so a
    # stakeholder sees which device contributed which signal even
    # when the bundle-level theory dominates.
    if bundle is not None and bundle.devices:
        rows = []
        for d in bundle.devices:
            hyp_plain = (glossary.translate(d.leading_hypothesis)
                          if d.leading_hypothesis else "—")
            # Hide raw H_FOO if no glossary entry exists.
            if hyp_plain.startswith("H_"):
                hyp_plain = "—"
            rows.append(
                f"<tr><td><strong>{_e(d.name)}</strong></td>"
                f"<td>{_e(hyp_plain)}</td>"
                f"<td>{_e(str(d.leading_score) if d.leading_score else '—')}</td></tr>"
            )
        pieces.append(
            "<h3>Per-device summary</h3>"
            "<table class='kv'>"
            "<tr><td class='k'>Device</td>"
            "<td class='k'>Leading theory</td>"
            "<td class='k'>Score</td></tr>"
            f"{''.join(rows)}"
            "</table>"
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
    *,
    regenerate_ai_summary: bool = False,
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
    bundle = load_bundle(case_dir) if is_bundle(case_dir) else None
    findings = list_findings(case_dir, case_id=case_id)
    ranking, _diag = score_findings(findings)
    nr = synthesize(case_id, findings, ach_ranking=ranking, manifest=manifest)
    digest = synthesize_executive(nr)
    recs = build_recommendations(nr, findings)

    body_sections: list[str] = []
    body_sections.append(_render_case_details(case_id, manifest, meta, bundle))
    body_sections.append(_render_objective(meta))

    # Phase 10: AI-generated executive summary (gated on
    # ANTHROPIC_API_KEY). Falls back silently to the deterministic
    # digest when the API key is absent, the SDK can't import, or
    # the API call fails. The deterministic ExecutiveDigest still
    # feeds the confidence tag (the colour-coded pill stays grounded
    # in ACH score, not LLM judgement).
    ai_brief = None
    ai_meta: dict | None = None
    try:
        from el.reporting.executive_ai import synthesize_executive_ai
        result = synthesize_executive_ai(
            nr, findings, Path(case_dir),
            case_metadata=meta,
            regenerate=regenerate_ai_summary,
        )
        if result is not None:
            ai_brief, ai_meta = result
    except Exception:
        ai_brief = None
        ai_meta = None

    body_sections.append(
        _render_executive_summary(
            digest, nr.leading_score, nr.leading_gap,
            ai_brief=ai_brief, ai_metadata=ai_meta,
        )
    )
    body_sections.append(_render_findings_chronological(
        findings, show_device_tags=bundle is not None))
    if bundle is not None:
        cross = _render_cross_device_iocs(case_dir, bundle)
        if cross:
            body_sections.append(cross)
    body_sections.append(_render_conclusion(digest, nr.leading_hypothesis,
                                              bundle=bundle))
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

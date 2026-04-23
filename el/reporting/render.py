"""Reporter — turns the findings ledger into a human report + machine bundle.

No LLM. The report is a deterministic projection of structured Findings.
Every claim in the report has a finding_id pointer back to the ledger.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from el.evidence.ledger import list_findings
from el.schemas.finding import Finding


def render_report(
    case_dir: str | Path, case_id: str, manifest: dict,
    iocs: dict[str, list[str]] | None = None,
    techniques: dict[str, dict] | None = None,
    stix_path: Path | None = None,
    ach_ranking: list | None = None,
    diagnostic: list[Finding] | None = None,
) -> Path:
    case_dir = Path(case_dir)
    findings = list_findings(case_dir, case_id=case_id)
    reports = case_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    md_path = reports / "report.md"
    bundle_path = reports / "findings.json"

    by_conf: dict[str, list[Finding]] = {"high": [], "medium": [], "low": [], "insufficient": []}
    for f in findings:
        by_conf.setdefault(f.confidence, []).append(f)

    challenged = [f for f in findings if f.red_review.status == "challenged"]
    unresolved = [f for f in findings if f.red_review.status == "unresolved"]
    passed = [f for f in findings if f.red_review.status == "passed"]

    lines: list[str] = []
    lines.append(f"# EL Case Report — {case_id}")
    lines.append(f"_Generated {datetime.now(timezone.utc).isoformat()} UTC_")
    lines.append("")

    # Executive Narrative — six-beat story of what happened, prose
    # synthesised from the Findings + ACH ranking. Always renders
    # before the structured projections below, because the prose
    # version is what a non-DFIR stakeholder (legal / exec / IR lead)
    # reads first. Honest gap statements when a beat is empty.
    from el.reporting.narrative import synthesize as _nar_synth
    try:
        narrative = _nar_synth(
            case_id=case_id, findings=findings,
            ach_ranking=ach_ranking, iocs=iocs, manifest=manifest,
        )
        lines.append(narrative.as_markdown())
        lines.append("")
        lines.append("---")
        lines.append("")
        narrative_path = reports / "narrative.md"
        narrative_path.write_text(narrative.as_markdown())
    except Exception as e:
        lines.append(f"_(Narrative synthesis skipped: {e})_")
        lines.append("")

    # Agent execution log + traceability matrix (Find Evil 2026
    # submission requirement: 'Judges must be able to trace any
    # finding back to the specific tool execution that produced it.')
    # Writes reports/execution_log.{jsonl,md} + traceability_matrix.md
    # — aggregates existing audit log + Finding evidence items into a
    # chronological stream, no new instrumentation required.
    try:
        from el.reporting.execution_log import write_all as _exec_write
        _exec_write(case_dir)
    except Exception:
        pass

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Findings recorded: **{len(findings)}** "
                 f"(high={len(by_conf['high'])}, medium={len(by_conf['medium'])}, "
                 f"low={len(by_conf['low'])}, insufficient={len(by_conf['insufficient'])})")
    lines.append(f"- Adversarial review: passed={len(passed)}, "
                 f"challenged={len(challenged)}, unresolved={len(unresolved)}")
    if unresolved:
        lines.append("- ⚠ **SYNTHESIZE blocked**: one or more findings remain in red_review=unresolved.")
    lines.append("")

    lines.append("## Evidence Manifest")
    lines.append("")
    for k, v in manifest.items():
        lines.append(f"- **{k}**: `{v}`")
    lines.append("")

    if ach_ranking:
        lines.append("## Hypothesis Ranking (ACH)")
        lines.append("")
        lines.append("| Rank | Hypothesis | Score | Supporting | Refuting |")
        lines.append("|---:|---|---:|---:|---:|")
        for i, r in enumerate(ach_ranking, 1):
            lines.append(f"| {i} | {r.name} (`{r.hyp_id}`) | {r.score} "
                         f"| {len(r.supporting_findings)} | {len(r.refuting_findings)} |")
        lines.append("")
        lines.append("_Heuer's ACH: highest score is the leading hypothesis. EL never declares "
                     "the leader 'true' — it surfaces ranking, diagnostic findings, and open "
                     "disconfirmers and lets the analyst close._")
        lines.append("")

    if diagnostic:
        lines.append("## Most Diagnostic Findings")
        lines.append("")
        lines.append("Findings whose ACH score-deltas vary most across hypotheses — the ones whose "
                     "presence or absence shifts the ranking the hardest.")
        lines.append("")
        for f in diagnostic:
            if not f.ach_score_delta:
                continue
            lines.append(f"- `{f.finding_id}` ({f.agent}): {f.claim}")
            spread = ", ".join(f"{k}={v:+d}" for k, v in sorted(f.ach_score_delta.items()))
            lines.append(f"    - Δ: {spread}")
        lines.append("")

    # T4-1: formal Heuer ACH consistency matrix + Diamond Model view.
    # Both are lightweight projections of data already on the
    # findings ledger + IOC catalog — no extra queries, no per-case
    # tuning required.
    from el.reporting.ach_matrix import build_ach_matrix_markdown
    from el.reporting.diamond import build_diamond_markdown
    if ach_ranking:
        lines.extend(build_ach_matrix_markdown(findings, ach_ranking))
        lines.extend(build_diamond_markdown(findings, ach_ranking,
                                              iocs, manifest))

    lines.append("## Findings")
    lines.append("")
    for conf in ("high", "medium", "low", "insufficient"):
        if not by_conf.get(conf):
            continue
        lines.append(f"### Confidence: {conf}")
        lines.append("")
        for f in by_conf[conf]:
            lines.append(f"#### `{f.finding_id}` — {f.agent}")
            lines.append(f"- **Claim**: {f.claim}")
            if f.hypotheses_supported:
                lines.append(f"- **Supports**: {', '.join(f.hypotheses_supported)}")
            if f.hypotheses_refuted:
                lines.append(f"- **Refutes**: {', '.join(f.hypotheses_refuted)}")
            if f.evidence:
                lines.append("- **Evidence**:")
                for e in f.evidence:
                    lines.append(f"    - `{e.tool} {e.version}` — `{e.command}`")
                    lines.append(f"      sha256=`{e.output_sha256[:16]}…` path=`{e.output_path}`")
            if f.confidence != "insufficient" and f.agent != "red_reviewer":
                rr = f.red_review
                lines.append(f"- **Red review**: status={rr.status}")
                if rr.challenger_notes:
                    lines.append(f"    - notes: {rr.challenger_notes}")
                if rr.disconfirming_checklist:
                    lines.append(f"    - disconfirming checklist:")
                    for item in rr.disconfirming_checklist:
                        lines.append(f"        - [ ] {item}")
            lines.append("")

    if techniques:
        lines.append("## MITRE ATT&CK Techniques Implicated")
        lines.append("")
        for tid, info in sorted(techniques.items()):
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            lines.append(f"- [`{tid}`]({url}) — {info['name']} "
                         f"(supported by {len(info['evidence_finding_ids'])} finding(s))")
        lines.append("")

    if iocs:
        lines.append("## Indicators of Compromise")
        lines.append("")
        for kind, vals in sorted(iocs.items()):
            if not vals:
                continue
            lines.append(f"### {kind} ({len(vals)})")
            for v in vals[:200]:
                lines.append(f"- `{v}`")
            if len(vals) > 200:
                lines.append(f"- _… {len(vals)-200} more elided_")
            lines.append("")

    if stix_path:
        lines.append("## Machine Bundle")
        lines.append("")
        lines.append(f"- STIX 2.1 bundle: `{stix_path}`")
        lines.append(f"- Findings JSON: `{Path(case_dir) / 'reports' / 'findings.json'}`")
        lines.append(f"- IOC catalog: `{Path(case_dir) / 'iocs.json'}`")
        lines.append("")

    lines.append("## Reproducibility")
    lines.append("")
    lines.append("Every evidence entry above carries the exact command. To re-run:")
    lines.append("")
    seen = set()
    for f in findings:
        for e in f.evidence:
            if e.command in seen:
                continue
            seen.add(e.command)
            lines.append(f"```\n{e.command}\n```")
    md_path.write_text("\n".join(lines))

    bundle_path.write_text(json.dumps(
        [json.loads(f.model_dump_json()) for f in findings], indent=2,
    ))
    return md_path

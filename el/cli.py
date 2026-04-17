from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from el.evidence.intake import intake as run_intake
from el.evidence.graph import init_graph
from el.evidence.ledger import list_findings, open_ledger
from el.orchestrator.coordinator import Coordinator
from el.orchestrator.states import State
from el.tooling import survey

app = typer.Typer(add_completion=False, no_args_is_help=True, help="EL — Edmond Locard DFIR orchestrator")
console = Console()


@app.command()
def doctor() -> None:
    """Survey SIFT tooling and verify EL primitives are wired correctly."""
    table = Table(title="EL · Tool Survey", show_lines=False)
    table.add_column("Tool")
    table.add_column("Available")
    table.add_column("Version")
    table.add_column("Note")
    missing = 0
    for s in survey():
        marker = "[green]yes[/green]" if s.available else "[red]no[/red]"
        if not s.available:
            missing += 1
        table.add_row(s.name, marker, escape(s.version or "-"), escape(s.note))
    console.print(table)

    from el.schemas.finding import Finding, EvidenceItem
    try:
        Finding(case_id="x", agent="doctor", claim="schema-ok", confidence="insufficient")
        Finding(
            case_id="x", agent="doctor", claim="schema-ok", confidence="high",
            evidence=[EvidenceItem(tool="t", version="0", command="echo", output_sha256="0"*64, output_path="/tmp/x")],
        )
        console.print("[green]✓[/green] Finding schema validates (insufficient + grounded)")
    except Exception as e:
        console.print(f"[red]✗ Finding schema broken: {e}[/red]")
        raise typer.Exit(2)

    try:
        from el.evidence import graph as _g  # noqa: F401
        import kuzu  # noqa: F401
        console.print("[green]✓[/green] Kùzu graph engine importable")
    except Exception as e:
        console.print(f"[red]✗ Kùzu unavailable: {e}[/red]")

    if missing:
        console.print(f"[yellow]{missing} tool(s) missing — agents that need them will report 'insufficient evidence'.[/yellow]")


@app.command()
def intake(
    input_path: str = typer.Argument(..., help="Path to evidence file"),
    case_id: str = typer.Option(None, "--case-id", "-c", help="Optional case id"),
) -> None:
    """Hash an evidence input, create the case workspace, write manifest, init graph + ledger."""
    m = run_intake(input_path, case_id=case_id)
    init_graph(m.case_dir)
    with open_ledger(m.case_dir):
        pass
    console.print_json(json.dumps(m.__dict__))


@app.command("ledger")
def ledger_cmd(
    case_dir: str = typer.Argument(..., help="Path to a case directory"),
    case_id: str = typer.Option(None, "--case-id", "-c"),
) -> None:
    """List findings recorded for a case."""
    rows = list_findings(case_dir, case_id=case_id)
    if not rows:
        console.print("[dim]no findings yet[/dim]")
        return
    t = Table(title=f"Findings ({len(rows)})")
    for col in ("finding_id", "agent", "confidence", "claim"):
        t.add_column(col)
    for f in rows:
        t.add_row(f.finding_id[:10] + "…", f.agent, f.confidence, (f.claim[:80] + "…") if len(f.claim) > 80 else f.claim)
    console.print(t)


@app.command("provision-snapshot")
def provision_snapshot_cmd(
    label: str = typer.Option("manual", "--label", "-l",
                              help="Snapshot label (manual/pre-case/post-incident/...)"),
) -> None:
    """Capture a timestamped host-state snapshot for chain of custody.

    Records dpkg state, /opt contents, EL pip freeze, doctor output, and
    EL git rev. Each file is sha256-hashed in a manifest.json.
    """
    from el.provisioning import take_snapshot
    p = take_snapshot(label)
    console.print(f"[green]✓[/green] snapshot manifest: {p}")


@app.command("report")
def report_cmd(
    case_dir: str = typer.Argument(..., help="Path to a case directory"),
) -> None:
    """Re-render the human report + STIX bundle from the existing ledger.

    Deterministic projection — no agents are re-run, no LLM is invoked.
    Use after manually editing iocs.json, after Plaso runs out-of-band,
    or to refresh the report after the ledger has been augmented.
    """
    import json as _json
    from el.intel.ach import diagnostic_findings, score_findings, write_matrix
    from el.intel.attack_map import map_case
    from el.reporting.render import render_report
    from el.reporting.stix import emit_bundle

    cd = Path(case_dir)
    if not (cd / "manifest.json").exists():
        console.print(f"[red]not a case directory: missing manifest.json[/red]")
        raise typer.Exit(2)
    manifest = _json.loads((cd / "manifest.json").read_text())
    case_id = manifest["case_id"]
    rows = list_findings(cd, case_id=case_id)
    ranked, _ = score_findings(rows)
    matrix_path = write_matrix(cd, ranked, rows)
    techniques = map_case(rows)

    from el.skills import ioc_extract
    evidence_paths = [e.output_path for f in rows for e in f.evidence]
    ioc_sets = ioc_extract.extract_from_paths(evidence_paths)
    iocs = {k: sorted(v) for k, v in ioc_sets.items() if v}
    (cd / "iocs.json").write_text(_json.dumps(iocs, indent=2))

    stix_path = cd / "reports" / "stix-bundle.json"
    try:
        emit_bundle(case_id, rows, ioc_sets, stix_path)
    except Exception as e:
        console.print(f"[yellow]STIX emission failed: {e}[/yellow]")
        stix_path = None

    diag = diagnostic_findings(rows, top_n=5)
    p = render_report(cd, case_id, manifest, iocs=iocs,
                       techniques=techniques, stix_path=stix_path,
                       ach_ranking=ranked, diagnostic=diag)
    console.print(f"[bold]report[/bold]: {p}")
    if stix_path:
        console.print(f"[bold]stix[/bold]: {stix_path}")


@app.command("hunt")
def hunt_cmd(
    case_dir: str = typer.Argument(..., help="Path to a case directory"),
    rules: str = typer.Option(None, "--rules", "-r",
                              help="Path to an external YARA file. "
                                   "If omitted, generated from the case IOC catalog."),
) -> None:
    """Standalone YARA sweep over a case workspace.

    Generates a per-case rules file from iocs.json (or uses --rules),
    sweeps the input + analysis dir, appends Findings to the ledger.
    """
    import json as _json
    from el.agents.base import AgentContext
    from el.agents.threat_hunter import ThreatHunterAgent
    from el.skills import yara_hunt

    cd = Path(case_dir)
    if not (cd / "manifest.json").exists():
        console.print(f"[red]not a case directory: missing manifest.json[/red]")
        raise typer.Exit(2)
    manifest = _json.loads((cd / "manifest.json").read_text())
    ctx = AgentContext(
        case_id=manifest["case_id"], case_dir=cd,
        input_path=Path(manifest["input_path"]), manifest=manifest,
    )
    if rules:
        from el.schemas.finding import Finding
        analysis = cd / "analysis" / "threat_hunter"
        analysis.mkdir(parents=True, exist_ok=True)
        targets = [ctx.input_path, cd / "analysis"]
        for tgt in targets:
            if not tgt.exists():
                continue
            try:
                r = yara_hunt.scan_paths(Path(rules), tgt, analysis,
                                          recursive=tgt.is_dir(), threads=4,
                                          timeout=600)
            except yara_hunt.YaraError as e:
                console.print(f"[red]yara failed: {e}[/red]")
                raise typer.Exit(2)
            console.print(f"{tgt.name}: {r.hit_count} hit(s) "
                          f"across {len(r.rule_to_files)} rule(s)")
        return
    findings = ThreatHunterAgent().run(ctx)
    for f in findings:
        console.print(f"  [{f.confidence}] {f.claim[:120]}")


@app.command()
def investigate(
    input_path: str = typer.Argument(..., help="Path to evidence file"),
    case_id: str = typer.Option(None, "--case-id", "-c", help="Optional case id"),
    timeline: bool = typer.Option(False, "--timeline/--no-timeline",
                                  help="Run Plaso super-timeline (slow on real cases)"),
    baseline: str = typer.Option(None, "--baseline", "-b",
                                 help="Path to a baseline for Memory Baseliner — either a "
                                      "known-good memory image (.img/.raw/.mem) for direct "
                                      "diff, or a pre-built baseline JSON"),
) -> None:
    """Run the EL coordinator end-to-end on an evidence file."""
    result = Coordinator(run_timeline=timeline,
                         memory_baseline=baseline).investigate(input_path, case_id=case_id)
    console.print(f"[bold]case[/bold]: {result.case_id}")
    console.print(f"[bold]case_dir[/bold]: {result.case_dir}")
    console.print(f"[bold]investigator[/bold]: {result.investigator}")
    console.print(f"[bold]final_state[/bold]: {result.final_state.value}")
    if result.leading_hypothesis:
        console.print(f"[bold]leading_hypothesis[/bold]: {result.leading_hypothesis} "
                      f"(score={result.leading_hypothesis_score})")
    if result.report_path:
        console.print(f"[bold]report[/bold]: {result.report_path}")
    if result.stix_path:
        console.print(f"[bold]stix[/bold]: {result.stix_path}")
    if result.final_state == State.BLOCKED:
        console.print("[yellow]final state is BLOCKED — adversarial review left findings unresolved; "
                      "see report for the disconfirming-evidence checklist.[/yellow]")


if __name__ == "__main__":
    app()

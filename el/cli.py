from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from el.case_metadata import CaseMetadata, save as save_case_metadata
from el.evidence.intake import intake as run_intake
from el.evidence.graph import init_graph
from el.evidence.ledger import list_findings, open_ledger
from el.orchestrator.coordinator import Coordinator
from el.orchestrator.states import State
from el.tooling import survey

app = typer.Typer(add_completion=False, no_args_is_help=True, help="EL — Edmond Locard DFIR orchestrator")
console = Console()


def _maybe_detach(detach: bool, label: str) -> None:
    """Re-launch the current el invocation as a `systemd --user`
    transient service so it survives login-session teardown.

    Returns immediately (run in-process, foreground) when:
      * --detach was not requested, OR
      * we're ALREADY inside the detached unit (EL_DETACHED=1 guard
        prevents infinite re-exec), OR
      * systemd-run is unavailable (degrade to foreground + warn).

    Otherwise spawns the transient unit and raises typer.Exit(0).

    WHY this exists: a long EL bundle launched with `nohup … &` was
    killed when the operator's GUI session crashed and restarted —
    `nohup` only blocks SIGHUP, but systemd SIGKILLs every PID in a
    login-session cgroup when the session ends, regardless of signal
    disposition. A `systemd --user` service lives in its own unit
    OUTSIDE the session scope and, with lingering enabled, survives
    session restarts — the same mechanism that keeps el-serve.service
    alive across logouts. --detach gives long investigations that
    same durability without the operator hand-rolling systemd-run.
    """
    import os as _os
    if not detach or _os.environ.get("EL_DETACHED") == "1":
        return
    import shutil as _shutil
    import subprocess as _subprocess
    import sys as _sys

    systemd_run = _shutil.which("systemd-run")
    if not systemd_run:
        console.print(
            "[yellow]--detach requested but systemd-run is not "
            "available; running in the foreground instead. The run "
            "will NOT survive a session restart.[/yellow]")
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    unit = f"el-{label}-{ts}"
    el_bin = _sys.argv[0]
    cmd = [
        systemd_run, "--user", "--collect",
        f"--unit={unit}",
        "--setenv=EL_DETACHED=1",
        "-p", f"WorkingDirectory={_os.getcwd()}",
        # Inherit the API-key / defer env so the detached unit
        # behaves identically to a foreground run.
        "--", el_bin, *_sys.argv[1:],
    ]
    # Forward a small allowlist of env vars the detached unit needs
    # (systemd --user services don't inherit the caller's shell env).
    # CLAUDECODE + CLAUDE_CODE_SESSION_ID + AI_AGENT must ride along
    # so the detached run still recognises it's Claude-Code-orchestrated
    # and emits the deferred AI-brief request file — without them the
    # transient unit looks like a bare shell and silently skips the
    # brief (caught when an SRL-2015 --detach bundle produced no
    # _ai_brief_request.json).
    for _k in ("ANTHROPIC_API_KEY", "EL_AI_BRIEF_DEFER",
                "EL_AI_SUMMARY_MODEL", "EL_RED_MODEL",
                "EL_KNOWLEDGE_DB",
                "EL_MALWARE_TRIAGE_MAX_DUMPS",
                "EL_MALWARE_TRIAGE_MAX_DUMP_SIZE_MB",
                "EL_MALWARE_TRIAGE_BUDGET_SECONDS",
                "CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "AI_AGENT"):
        _v = _os.environ.get(_k)
        if _v:
            cmd.insert(cmd.index("--"), f"--setenv={_k}={_v}")
    try:
        _subprocess.run(cmd, check=True)
    except (_subprocess.CalledProcessError, OSError) as e:
        console.print(
            f"[red]--detach failed to launch transient unit ({e}); "
            f"falling back to foreground.[/red]")
        return
    console.print(
        f"[bold]detached[/bold]: launched as systemd --user unit "
        f"[cyan]{unit}[/cyan] — survives session restart / logout.")
    console.print(f"  follow:  journalctl --user -u {unit} -f")
    console.print(f"  status:  systemctl --user status {unit}")
    console.print(f"  stop:    systemctl --user stop {unit}")
    console.print(
        "  (the per-case analysis/forensic_audit.log is the canonical "
        "progress signal regardless of transport)")
    raise typer.Exit(0)


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


@app.command("seal-verify")
def seal_verify_cmd(
    case_dir: str = typer.Argument(..., help="Path to a sealed case directory"),
) -> None:
    """Re-hash a sealed case dir and confirm no drift since seal."""
    from el.seal import verify_seal
    ok, drift = verify_seal(Path(case_dir))
    if ok:
        console.print(f"[green]✓[/green] seal verified — no drift in {case_dir}")
    else:
        console.print(f"[red]✗[/red] seal drift detected in {case_dir}:")
        for d in drift:
            console.print(f"  - {d}")
        raise typer.Exit(1)


@app.command("knowledge")
def knowledge_cmd(
    action: str = typer.Argument(...,
        help="stats | lookup <value> | pull-feed --backend <misp|taxii>"),
    value: str = typer.Argument(None, help="IOC value (for lookup action)"),
    backend: str = typer.Option(None, "--backend",
        help="Feed backend (misp | taxii) for pull-feed action"),
    server: str = typer.Option(None, "--server",
        help="Feed server URL (else env EL_MISP_URL / EL_TAXII_URL)"),
    api_key: str = typer.Option(None, "--api-key",
        help="MISP API key (else env EL_MISP_KEY)"),
    collection: str = typer.Option(None, "--collection",
        help="TAXII collection ID (else env EL_TAXII_COLLECTION)"),
    username: str = typer.Option(None, "--username",
        help="TAXII basic-auth user (else env EL_TAXII_USER)"),
    password: str = typer.Option(None, "--password",
        help="TAXII basic-auth password (else env EL_TAXII_PASS)"),
    since_days: int = typer.Option(30, "--since-days",
        help="MISP: pull attributes from the last N days (default 30)"),
    limit: int = typer.Option(5000, "--limit",
        help="Max IOCs to pull per request (default 5000)"),
    insecure: bool = typer.Option(False, "--insecure",
        help="Skip TLS verification (self-signed internal feeds)"),
) -> None:
    """Query / write the institutional knowledge store
    (~/.el/knowledge.sqlite)."""
    from el import knowledge as kb
    if action == "stats":
        s = kb.stats()
        console.print_json(json.dumps(s))
        return
    if action == "lookup":
        if not value:
            console.print("[red]lookup requires a value argument[/red]")
            raise typer.Exit(2)
        results = kb.lookup_iocs([value], current_case_id="__cli__")
        if not results:
            console.print(f"[yellow]no prior observations of {value}[/yellow]")
            return
        for v, observations in results.items():
            console.print(f"[bold]{v}[/bold]")
            for o in observations:
                console.print(f"  - {o['observed_utc']} · case={o['case_id']} "
                              f"· type={o['ioc_type']} · agent={o['agent']}")
        return
    if action == "pull-feed":
        from el.skills import threat_feeds as tf
        if backend not in ("misp", "taxii"):
            console.print("[red]pull-feed requires --backend misp|taxii[/red]")
            raise typer.Exit(2)
        verify_tls = not insecure
        if backend == "misp":
            r = tf.pull_misp(
                server_url=server or "", api_key=api_key or "",
                since_days=since_days, limit=limit,
                verify_tls=verify_tls)
        else:
            r = tf.pull_taxii(
                discovery_url=server or "",
                collection_id=collection or "",
                username=username, password=password,
                limit=limit, verify_tls=verify_tls)
        if not r.ok:
            console.print(f"[red]{backend} pull failed: {r.error}[/red]")
            raise typer.Exit(1)
        n = tf.record(r)
        console.print(
            f"[green]{backend}[/green]: pulled "
            f"[bold]{len(r.iocs)}[/bold] IOC(s) from "
            f"[cyan]{r.server}[/cyan]; "
            f"[bold]{n}[/bold] new row(s) inserted under "
            f"case_id=[cyan]{r.case_id}[/cyan]"
        )
        return
    console.print(f"[red]unknown action: {action}[/red]")
    raise typer.Exit(2)


@app.command("stix")
def stix_cmd(
    action: str = typer.Argument(..., help="import"),
    path: str = typer.Argument(None, help="Path to STIX 2.1 bundle JSON"),
    case_id: str = typer.Option(None, "--case-id",
                                 help="Provenance tag for imported IOCs "
                                      "(default: stix-import-<file-stem>)"),
) -> None:
    """STIX 2.1 toolbox. V1: `stix import <bundle.json>` pulls
    indicators out of a STIX 2.1 bundle and into the cross-case
    knowledge store tagged with the supplied case_id. Output: counts
    per IOC type."""
    from el.skills import stix_import

    if action != "import":
        console.print(f"[red]unknown action: {action}[/red]")
        console.print("Supported: [bold]import[/bold]")
        raise typer.Exit(2)
    if not path:
        console.print("[red]stix import requires a bundle path[/red]")
        raise typer.Exit(2)

    bundle = Path(path)
    if not bundle.is_file():
        console.print(f"[red]bundle not found: {bundle}[/red]")
        raise typer.Exit(2)

    cid = case_id or f"stix-import-{bundle.stem}"
    total, per_type = stix_import.import_bundle(bundle, case_id=cid)
    if not total:
        console.print(f"[yellow]no indicators extracted from {bundle}[/yellow]")
        return
    console.print(f"[green]imported {total} IOC(s) → case_id={cid}[/green]")
    for t, n in sorted(per_type.items()):
        console.print(f"  {t}: {n}")


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


def _render_case_once(cd: Path, *, html: bool, executive: bool = False,
                       pdf: bool = False,
                       regenerate_ai_summary: bool = False,
                       quiet: bool = False) -> None:
    """Single-pass re-render: reads the ledger, recomputes ACH, IOC
    catalog, ATT&CK map, and writes report.md + findings.json +
    stix-bundle.json (+ case.html when html=True). Shared by `el
    report` and by the --watch loop."""
    import json as _json
    from el.intel.ach import diagnostic_findings, score_findings, write_matrix
    from el.intel.attack_map import map_case
    from el.reporting.render import render_report
    from el.reporting.stix import emit_bundle

    manifest = _json.loads((cd / "manifest.json").read_text())
    case_id = manifest["case_id"]
    rows = list_findings(cd, case_id=case_id)
    ranked, _ = score_findings(rows)
    write_matrix(cd, ranked, rows)
    techniques = map_case(rows)

    from el.skills import ioc_extract
    evidence_paths = [e.output_path for f in rows for e in f.evidence]
    ioc_sets = ioc_extract.extract_from_paths(evidence_paths)
    # Also surface structured-fact source IPs (lateral_movement_analyst
    # RDP/WinRM source IPs) that `_filter_ipv4` drops as RFC1918 — for
    # enterprise APT cases the internal-network pivot IPs are the
    # cross-host attribution signal, not noise.
    fact_iocs = ioc_extract.extract_from_finding_facts(rows)
    for k, v in fact_iocs.items():
        ioc_sets.setdefault(k, set()).update(v)
    iocs = {k: sorted(v) for k, v in ioc_sets.items() if v}
    (cd / "iocs.json").write_text(_json.dumps(iocs, indent=2))

    stix_path = cd / "reports" / "stix-bundle.json"
    try:
        emit_bundle(case_id, rows, ioc_sets, stix_path)
    except Exception as e:
        if not quiet:
            console.print(f"[yellow]STIX emission failed: {e}[/yellow]")
        stix_path = None

    diag = diagnostic_findings(rows, top_n=5)
    p = render_report(cd, case_id, manifest, iocs=iocs,
                      techniques=techniques, stix_path=stix_path,
                      ach_ranking=ranked, diagnostic=diag)
    if not quiet:
        console.print(f"[bold]report[/bold]: {p}")
        if stix_path:
            console.print(f"[bold]stix[/bold]: {stix_path}")
    if html:
        from el.reporting.html import render_html
        html_path = render_html(cd, case_id, manifest, findings=rows,
                                ach_ranking=ranked, iocs=iocs,
                                techniques=techniques)
        if not quiet:
            console.print(f"[bold]html[/bold]: {html_path}")
    if executive:
        from el.reporting.executive import render_executive_html
        exec_path = render_executive_html(
            cd, case_id=case_id, manifest=manifest,
            regenerate_ai_summary=regenerate_ai_summary,
        )
        if not quiet:
            console.print(f"[bold]executive[/bold]: {exec_path}")
        if pdf:
            from el.reporting.executive_pdf import (
                render_executive_pdf, WeasyPrintNotAvailable,
            )
            try:
                pdf_path = render_executive_pdf(exec_path)
                if not quiet:
                    console.print(f"[bold]executive_pdf[/bold]: {pdf_path}")
            except WeasyPrintNotAvailable as e:
                # Don't crash the report run — surface the gap.
                if not quiet:
                    console.print(
                        f"[yellow]executive PDF skipped: {e}[/yellow]")


@app.command("report")
def report_cmd(
    case_dir: str = typer.Argument(..., help="Path to a case directory"),
    html: bool = typer.Option(
        True, "--html/--no-html",
        help="Also render a self-contained case.html web view alongside "
             "the Markdown report (Tier 1 of docs/web-view-design.md). "
             "Default on; pass --no-html to skip."),
    executive: bool = typer.Option(
        True, "--executive/--no-executive",
        help="Also render reports/executive.html — a non-expert "
             "executive view (plain language, glossary, recommendations) "
             "alongside the analyst report. Default on; pass "
             "--no-executive to skip."),
    pdf: bool = typer.Option(
        True, "--pdf/--no-pdf",
        help="Also render reports/executive.pdf via WeasyPrint. The "
             "PDF is the printable form of the executive report. "
             "Default on (skipped automatically with a warning if "
             "WeasyPrint is not installed). Pass --no-pdf to skip."),
    regenerate_ai_summary: bool = typer.Option(
        False, "--regenerate-ai-summary",
        help="Force regeneration of the AI-generated executive "
             "brief (gated on ANTHROPIC_API_KEY OR on the deferred "
             "path via --defer-ai-brief). Default uses the cached "
             "brief at reports/executive_ai_brief.json when the "
             "underlying findings haven't changed."),
    defer_ai_brief: bool = typer.Option(
        False, "--defer-ai-brief",
        help="When ANTHROPIC_API_KEY is absent, write a request file "
             "(reports/_ai_brief_request.json) and let the Claude Code "
             "`el-ai-brief` skill fulfil it out-of-band. The next "
             "render picks up the cached response. Equivalent to "
             "exporting EL_AI_BRIEF_DEFER=1 for this run."),
    watch: bool = typer.Option(
        False, "--watch",
        help="Re-render whenever findings.sqlite changes; run until "
             "Ctrl-C (Tier 4 of docs/web-view-design.md). Open "
             "case.html?watch=1 in a browser for auto-reload."),
    poll: float = typer.Option(
        1.5, "--poll",
        help="--watch poll interval in seconds. Default 1.5."),
) -> None:
    """Re-render the human report + STIX bundle from the existing ledger.

    Deterministic projection — no agents are re-run, no LLM is invoked.
    Use after manually editing iocs.json, after Plaso runs out-of-band,
    or to refresh the report after the ledger has been augmented.
    """
    cd = Path(case_dir)
    if not (cd / "manifest.json").exists():
        console.print(f"[red]not a case directory: missing manifest.json[/red]")
        raise typer.Exit(2)

    if defer_ai_brief:
        import os as _os
        from el.reporting.executive_ai import DEFER_ENV as _DEFER_ENV
        _os.environ[_DEFER_ENV] = "1"

    _render_case_once(cd, html=html, executive=executive, pdf=pdf,
                       regenerate_ai_summary=regenerate_ai_summary)

    if not watch:
        return

    # --watch loop: follow findings.sqlite mtime and re-render on change.
    import time
    from datetime import datetime, timezone
    ledger = cd / "findings.sqlite"
    if not ledger.exists():
        console.print(f"[yellow]--watch: {ledger} does not exist yet; waiting…[/yellow]")
    console.print(
        f"[bold]watch[/bold]: polling {ledger.name} every {poll}s "
        f"(Ctrl-C to stop). Open "
        f"{cd}/reports/case.html?watch=1 for auto-reload.")
    last_mtime = ledger.stat().st_mtime if ledger.exists() else 0.0
    try:
        while True:
            time.sleep(poll)
            if not ledger.exists():
                continue
            mtime = ledger.stat().st_mtime
            if mtime == last_mtime:
                continue
            last_mtime = mtime
            try:
                _render_case_once(cd, html=html, executive=executive,
                                    pdf=pdf,
                                    regenerate_ai_summary=regenerate_ai_summary,
                                    quiet=True)
                ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                console.print(
                    f"[dim]{ts} UTC[/dim] · re-rendered on "
                    f"findings.sqlite change")
            except Exception as e:
                console.print(
                    f"[yellow]watch: re-render failed: {e}[/yellow]")
    except KeyboardInterrupt:
        console.print("\n[dim]watch stopped[/dim]")


@app.command("combined-report")
def combined_report_cmd(
    case_dirs: list[str] = typer.Argument(
        ..., help="Two or more case directories to stitch into one report."),
    out: str = typer.Option(
        None, "--out",
        help="Output markdown path. Defaults to "
             "/opt/EL/cases/_combined/<name>/report.md"),
    name: str = typer.Option(
        None, "--name",
        help="Combined case name. Defaults to longest common case_id prefix "
             "(e.g. 'srl2015') or 'combined-case'."),
    render_html: bool = typer.Option(
        True, "--html/--no-html",
        help="Render the combined.html multi-host dashboard alongside "
             "the markdown (default: on). Includes joint ACH matrix "
             "(heatmap), unified swim-lane timeline, merged cross-host "
             "graph, and per-case narrative blocks; links into each "
             "host's case.html for drill-down. Pass `--no-html` to "
             "skip the HTML render (Markdown-only output)."),
    render_pdf: bool = typer.Option(
        False, "--pdf/--no-pdf",
        help="Also render combined.pdf via WeasyPrint by paginating the "
             "combined.html dashboard. Off by default — large multi-host "
             "HTML can take minutes to paginate and adds a ~500KB-1MB "
             "PDF. Implies --html (the PDF is rendered FROM the HTML)."),
    regenerate_ai_summary: bool = typer.Option(
        False, "--regenerate-ai-summary",
        help="Bypass the cached cross-host AI brief at "
             "combined_executive_ai_brief.json and re-generate it. "
             "Costs an API call (or another skill round-trip in defer "
             "mode). Use after the bundle's per-case ledgers have "
             "materially changed."),
) -> None:
    """Stitch N per-case ledgers into a single multi-host report.

    Use this when a scenario spans multiple hosts (e.g. an enterprise
    APT intrusion with 4 host images) and the per-case reports — one
    per input — don't show the attacker's cross-host story. This
    command is a deterministic projection of the stitched ledgers
    (no LLM): it produces a single Markdown report with a per-host
    leading-hypothesis table, cross-host signal matrix, unified
    ATT&CK coverage, cross-case IOC overlap from the Layer-3
    knowledge DB, and compact per-host summaries.

    Example:
      el combined-report /opt/EL/cases/srl2015-dc-memory-r2 \\
                          /opt/EL/cases/srl2015-dc-disk \\
                          /opt/EL/cases/srl2015-nromanoff-memory \\
                          /opt/EL/cases/srl2015-nromanoff-disk \\
                          --name srl2015-enterprise
    """
    from el.reporting.combined import render_combined
    dirs = [Path(d) for d in case_dirs]
    missing = [d for d in dirs if not (d / "manifest.json").exists()]
    if missing:
        for d in missing:
            console.print(f"[red]not a case directory: {d}[/red]")
        raise typer.Exit(2)
    if len(dirs) < 2:
        console.print(
            "[yellow]Only one case supplied — combined report is designed "
            "for multi-host scenarios. Proceeding anyway.[/yellow]")
    if not name:
        ids = [json.loads((d/"manifest.json").read_text()).get("case_id", d.name)
               for d in dirs]
        common = os.path.commonprefix(ids).rstrip("-_")
        name = common or "combined-case"
    if not out:
        out = str(Path("/opt/EL/cases/_combined") / name / "report.md")
    out_path = Path(out)
    written = render_combined(dirs, out_path, name=name)
    console.print(
        f"[green]wrote combined report:[/green] {written}\n"
        f"  cases: {len(dirs)}")
    # Always emit the multi-host executive report (HTML + PDF) when
    # weasyprint is available. This is the equivalent of single-case
    # executive.html / executive.pdf — focused, non-technical,
    # stakeholder-friendly. Wired in by default so the combined dashboard
    # has something to link the "download executive PDF" icon to.
    exec_html_path = out_path.with_name("combined_executive.html")
    exec_pdf_path: Path | None = None
    try:
        from el.reporting.combined_executive import (
            render_combined_executive, render_combined_executive_pdf,
        )
        render_combined_executive(dirs, exec_html_path, name=name,
                                    regenerate_ai_summary=regenerate_ai_summary)
        console.print(
            f"[green]wrote combined executive HTML:[/green] {exec_html_path}")
        try:
            exec_pdf_path = render_combined_executive_pdf(exec_html_path)
            kb = exec_pdf_path.stat().st_size // 1024
            console.print(
                f"[green]wrote combined executive PDF:[/green] "
                f"{exec_pdf_path} ({kb} KB)")
        except ImportError:
            console.print(
                "[yellow]combined_executive.pdf skipped — "
                "weasyprint not installed[/yellow]")
        except Exception as e:
            console.print(
                f"[yellow]combined_executive.pdf render failed:[/yellow] "
                f"{e} — HTML at {exec_html_path} is still valid")
    except Exception as e:
        console.print(
            f"[yellow]combined executive report skipped:[/yellow] {e}")

    if render_html or render_pdf:
        from el.reporting.combined_html import render_combined_html
        html_path = out_path.with_name("combined.html")
        # Pass the executive PDF path so combined.html embeds a download
        # icon in its top nav (matching the per-case case.html pattern).
        try:
            render_combined_html(
                dirs, html_path, name=name,
                executive_pdf_path=exec_pdf_path,
            )
        except TypeError:
            # Older signature without executive_pdf_path — fall through.
            render_combined_html(dirs, html_path, name=name)
        console.print(f"[green]wrote combined HTML:[/green] {html_path}")
    if render_pdf:
        try:
            from weasyprint import HTML  # type: ignore
        except ImportError as e:
            console.print(
                f"[red]--pdf requires weasyprint:[/red] {e}\n"
                "  pip install weasyprint")
            raise typer.Exit(2)
        pdf_path = out_path.with_name("combined.pdf")
        try:
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        except Exception as e:
            console.print(
                f"[red]combined.pdf (full dashboard) render failed:[/red] "
                f"{e}\n  the combined.html at {html_path} is still valid")
            raise typer.Exit(2)
        size_kb = pdf_path.stat().st_size // 1024
        console.print(
            f"[green]wrote combined PDF (full dashboard):[/green] "
            f"{pdf_path} ({size_kb} KB)")


_SYSTEMD_UNIT_TEMPLATE = """\
[Unit]
Description=EL case-report viewer (local HTTP)
Documentation=https://github.com/threatroute66/EL
After=network.target

[Service]
Type=simple
ExecStart={exe} serve --bind {bind} --port {port} --root {root}
Restart=on-failure
RestartSec=5
# Loopback-only by default, but defense-in-depth: no new privileges,
# read-only access everywhere, no temp-dir isolation needed because
# http.server only reads --root.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadOnlyPaths={root}
ProtectHome=read-only

[Install]
WantedBy=default.target
"""


def _install_serve_service(exe: Path, root: Path, bind: str, port: int) -> int:
    """Install + enable a systemd --user service so `el serve` starts
    at login and survives reboots. Returns an exit code."""
    import os
    import shutil
    import subprocess
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / "el-serve.service"
    unit_path.write_text(_SYSTEMD_UNIT_TEMPLATE.format(
        exe=exe, root=root, bind=bind, port=port))
    if not shutil.which("systemctl"):
        console.print(
            f"[yellow]systemctl not found — wrote {unit_path} but could not "
            f"enable. Run `systemctl --user enable --now el-serve.service` "
            f"manually.[/yellow]")
        return 0
    for cmd in (
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", "el-serve.service"],
    ):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            console.print(f"[red]{' '.join(cmd)} failed:[/red]\n{r.stderr}")
            return r.returncode
    console.print(f"[green]installed + started[/green]: {unit_path}")
    console.print(
        f"  survives reboots when linger is enabled for this user. "
        f"If the service stops at logout, run: "
        f"`loginctl enable-linger {os.environ.get('USER', '$USER')}`")
    console.print(f"  status:  systemctl --user status el-serve.service")
    console.print(f"  logs:    journalctl --user -u el-serve.service -f")
    console.print(f"  url:     http://{bind}:{port}/")
    return 0


def _uninstall_serve_service() -> int:
    import shutil
    import subprocess
    unit_path = Path.home() / ".config" / "systemd" / "user" / "el-serve.service"
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "disable", "--now",
                         "el-serve.service"], capture_output=True)
        subprocess.run(["systemctl", "--user", "daemon-reload"],
                        capture_output=True)
    if unit_path.exists():
        unit_path.unlink()
        console.print(f"[green]removed[/green]: {unit_path}")
    else:
        console.print(f"[dim]nothing to remove at {unit_path}[/dim]")
    return 0


@app.command("serve")
def serve_cmd(
    root: str = typer.Option(
        "/opt/EL/cases", "--root", "-r",
        help="Directory to serve. Default: /opt/EL/cases."),
    port: int = typer.Option(
        8089, "--port", "-p",
        help="TCP port (default 8089)."),
    bind: str = typer.Option(
        "127.0.0.1", "--bind",
        help="Interface to bind. Default 127.0.0.1 (loopback only). "
             "DO NOT bind to 0.0.0.0 on an investigation host — "
             "case dirs contain evidence paths + IOCs."),
    install_service: bool = typer.Option(
        False, "--install-service",
        help="Install + enable a systemd --user unit so `el serve` "
             "auto-starts at login and survives reboots. Idempotent."),
    uninstall_service: bool = typer.Option(
        False, "--uninstall-service",
        help="Disable + remove the systemd user unit installed with "
             "--install-service."),
) -> None:
    """Serve case reports over HTTP (Ubuntu snap-confined browsers like
    Chromium can't read /opt/ from file:// — this is the workaround).

    Default: keep the process in the foreground; Ctrl-C stops it.
    Listens on loopback only. Files are served read-only.

    Install as a persistent service: `el serve --install-service` writes
    a systemd --user unit at ~/.config/systemd/user/el-serve.service
    and enables it so the server auto-starts at next login (and every
    reboot once linger is enabled).
    """
    import http.server
    import socketserver

    import sys
    exe = Path(sys.executable).parent / "el"
    if not exe.exists():
        exe = Path(sys.argv[0] if sys.argv else "el")

    if uninstall_service:
        raise typer.Exit(_uninstall_serve_service())
    if install_service:
        raise typer.Exit(_install_serve_service(
            exe=exe, root=Path(root), bind=bind, port=port))

    root_path = Path(root)
    if not root_path.is_dir():
        console.print(f"[red]not a directory: {root_path}[/red]")
        raise typer.Exit(2)

    # Quick per-case HTML index helps the analyst navigate
    index_cases = sorted(
        d.name for d in root_path.iterdir()
        if d.is_dir() and (d / "reports" / "case.html").is_file()
    )

    class CaseHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kw):
            super().__init__(*args, directory=str(root_path), **kw)

        def log_message(self, fmt, *args):
            # Quiet per-request logs; keep only errors
            return

        # Override the default SimpleHTTPRequestHandler index — by
        # default it emits one bare <a> per entry with no metadata,
        # which makes it impossible to tell multiple cases apart when
        # the names alone are similar (e.g. lonewolf vs lonewolf-mem).
        # We render a table with name + modified time, and at the case
        # root layer in intake_utc + investigator from case_metadata.json
        # / manifest.json so the cases sort chronologically and the
        # operator can pick the right one at a glance.
        def list_directory(self, path):
            import datetime as _dt
            import html as _html
            import io as _io
            import json as _json
            import os as _os
            import urllib.parse as _up

            try:
                entries = _os.listdir(path)
            except OSError:
                self.send_error(404, "No permission to list directory")
                return None
            entries.sort(key=lambda n: n.lower())

            is_case_root = _os.path.realpath(path) == _os.path.realpath(
                str(root_path))

            def _fmt_size(n: int) -> str:
                if n < 1024:
                    return f"{n} B"
                for unit in ("KB", "MB", "GB", "TB"):
                    n /= 1024.0
                    if n < 1024:
                        return f"{n:.1f} {unit}"
                return f"{n:.1f} PB"

            def _fmt_mtime(ts: float) -> str:
                return _dt.datetime.fromtimestamp(
                    ts, tz=_dt.timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S UTC")

            rows = []
            for name in entries:
                full = _os.path.join(path, name)
                display = name + ("/" if _os.path.isdir(full) else "")
                href = _up.quote(name + ("/" if _os.path.isdir(full) else ""))
                try:
                    st = _os.stat(full)
                except OSError:
                    continue
                mtime = _fmt_mtime(st.st_mtime)
                size = "" if _os.path.isdir(full) else _fmt_size(st.st_size)

                # At the case root, pull intake_utc + investigator from
                # case_metadata.json (preferred — has investigator name)
                # falling back to manifest.json (always present after
                # intake — has intake_utc). Empty cell when neither is
                # readable; never raises.
                intake_utc = ""
                investigator = ""
                report_link = ""
                if is_case_root and _os.path.isdir(full):
                    for src, keys in (
                        ("case_metadata.json",
                         ("created_utc", "investigator_name")),
                        ("manifest.json",
                         ("intake_utc", None)),
                    ):
                        meta_path = _os.path.join(full, src)
                        if not _os.path.isfile(meta_path):
                            continue
                        try:
                            meta = _json.loads(
                                Path(meta_path).read_text())
                        except (OSError, ValueError):
                            continue
                        if not intake_utc and keys[0]:
                            v = meta.get(keys[0])
                            if isinstance(v, str):
                                intake_utc = v[:19].replace("T", " ") + " UTC"
                        if not investigator and len(keys) > 1 and keys[1]:
                            v = meta.get(keys[1])
                            if isinstance(v, str):
                                investigator = v
                    case_html = _os.path.join(full, "reports", "case.html")
                    if _os.path.isfile(case_html):
                        case_url = (
                            f"{_up.quote(name)}/reports/case.html")
                        report_link = (
                            f'<a class="report" href="{case_url}">case</a>')
                        exec_html = _os.path.join(
                            full, "reports", "executive.html")
                        if _os.path.isfile(exec_html):
                            exec_url = (
                                f"{_up.quote(name)}/reports/executive.html")
                            report_link += (
                                f' &middot; <a class="report" '
                                f'href="{exec_url}">exec</a>')

                rows.append({
                    "href": href,
                    "display": display,
                    "mtime": mtime,
                    "size": size,
                    "intake_utc": intake_utc,
                    "investigator": investigator,
                    "report_link": report_link,
                })

            # Sort case-root by intake_utc desc (newest first) so the
            # most recent investigation lands at the top — for other
            # dirs keep name order, which is what SimpleHTTPRequestHandler
            # would have produced.
            if is_case_root:
                rows.sort(
                    key=lambda r: (r["intake_utc"] or r["mtime"]),
                    reverse=True)

            displaypath = _html.escape(
                _up.unquote(self.path), quote=False)
            title = (
                "EL cases" if is_case_root
                else f"Index of {displaypath}")
            header_cols = (
                "<th>case</th><th>intake (UTC)</th>"
                "<th>investigator</th><th>reports</th>"
                "<th>modified</th>"
                if is_case_root else
                "<th>name</th><th>modified</th><th>size</th>"
            )

            buf = _io.StringIO()
            buf.write("<!doctype html><html><head><meta charset='utf-8'>")
            buf.write(f"<title>{_html.escape(title)}</title>")
            buf.write("<style>"
                       "body{font-family:system-ui,-apple-system,"
                       "Segoe UI,Roboto,sans-serif;"
                       "background:#0d1117;color:#c9d1d9;padding:20px;"
                       "max-width:1200px;margin:0 auto}"
                       "h1{font-size:1.2em;color:#58a6ff;"
                       "border-bottom:1px solid #30363d;"
                       "padding-bottom:8px}"
                       "table{border-collapse:collapse;width:100%;"
                       "font-size:0.92em;margin-top:8px}"
                       "th,td{padding:6px 12px;text-align:left;"
                       "border-bottom:1px solid #21262d}"
                       "th{color:#8b949e;font-weight:600;"
                       "background:#161b22}"
                       "tr:hover td{background:#161b22}"
                       "a{color:#58a6ff;text-decoration:none}"
                       "a:hover{text-decoration:underline}"
                       "a.report{color:#7ee787;font-weight:500}"
                       ".muted{color:#6e7681;font-style:italic}"
                       "</style></head><body>")
            buf.write(f"<h1>{_html.escape(title)}</h1>")
            buf.write(f"<table><thead><tr>{header_cols}</tr></thead><tbody>")
            for r in rows:
                if is_case_root:
                    buf.write(
                        f"<tr><td><a href=\"{r['href']}\">"
                        f"{_html.escape(r['display'])}</a></td>"
                        f"<td>{_html.escape(r['intake_utc']) or '<span class=muted>—</span>'}</td>"
                        f"<td>{_html.escape(r['investigator']) or '<span class=muted>—</span>'}</td>"
                        f"<td>{r['report_link'] or '<span class=muted>—</span>'}</td>"
                        f"<td>{_html.escape(r['mtime'])}</td></tr>"
                    )
                else:
                    buf.write(
                        f"<tr><td><a href=\"{r['href']}\">"
                        f"{_html.escape(r['display'])}</a></td>"
                        f"<td>{_html.escape(r['mtime'])}</td>"
                        f"<td>{_html.escape(r['size'])}</td></tr>"
                    )
            if not rows:
                buf.write("<tr><td colspan='5' class='muted'>"
                          "(empty)</td></tr>")
            buf.write("</tbody></table></body></html>")
            encoded = buf.getvalue().encode("utf-8", "surrogateescape")

            f = _io.BytesIO()
            f.write(encoded)
            f.seek(0)
            self.send_response(200)
            self.send_header(
                "Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            return f

    console.print(f"[bold]serving[/bold]: {root_path}")
    console.print(f"[bold]  URL[/bold]: http://{bind}:{port}/")
    console.print(f"[bold]  cases with case.html[/bold]: "
                  f"{len(index_cases)}")
    if index_cases:
        console.print("  top 5 by directory name:")
        for n in index_cases[:5]:
            console.print(
                f"    http://{bind}:{port}/{n}/reports/case.html")
    console.print("[dim]Ctrl-C to stop[/dim]\n")

    with socketserver.ThreadingTCPServer((bind, port), CaseHandler) as s:
        s.allow_reuse_address = True
        try:
            s.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[dim]server stopped[/dim]")


@app.command("timeline-memory")
def timeline_memory_cmd(
    cases: list[str] = typer.Argument(
        ..., help="Two or more case directories (paths under /opt/EL/"
                 "cases/). The earliest (by intake_utc) becomes the "
                 "baseline when --baseline isn't given."),
    baseline: str = typer.Option(
        None, "--baseline", "-b",
        help="Explicit baseline case dir. If omitted, the "
             "chronologically earliest --cases entry is used."),
    out: str = typer.Option(
        None, "--out", "-o",
        help="Output Markdown path. Default: "
             "/tmp/el-memory-timeline-<ts>.md"),
    top_n: int = typer.Option(
        30, "--top-n",
        help="Max novel / removed modules shown per snapshot. "
             "Default 30 — full sets live in the source JSON."),
) -> None:
    """Diff memory-module inventories across cases (Roussev & Quates
    2012, M57 Case 2). Produces a chronological narrative of what
    executables / DLLs / drivers entered and left memory between
    snapshots — often enough to see attacker tooling land and
    disappear without any deep parsing.
    """
    from datetime import datetime, timezone
    from el.skills.memory_timeline import build_timeline, render_markdown
    if len(cases) < 2 and not baseline:
        console.print(
            "[red]need at least two case dirs (or one + --baseline)[/red]")
        raise typer.Exit(2)
    dirs = [Path(c) for c in cases]
    for d in dirs + ([Path(baseline)] if baseline else []):
        if not d.is_dir():
            console.print(f"[red]not a directory: {d}[/red]")
            raise typer.Exit(2)
    tl = build_timeline(dirs, baseline=baseline)
    md = render_markdown(tl, top_n=top_n)
    if not out:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = f"/tmp/el-memory-timeline-{ts}.md"
    Path(out).write_text(md)
    console.print(f"[bold]baseline[/bold]: {tl.baseline_case_id} "
                  f"({tl.baseline_count} modules)")
    console.print(f"[bold]snapshots[/bold]: {len(tl.entries)}")
    for e in tl.entries:
        console.print(
            f"  {e.case_id:<40} novel_vs_base={len(e.novel_vs_baseline):<5} "
            f"novel_vs_prev={len(e.novel_vs_previous):<4} "
            f"removed={len(e.removed_vs_previous)}")
    console.print(f"[bold]report[/bold]: {out}")


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
    investigator: str = typer.Option(None, "--investigator",
                                      help="Analyst/investigator name (recorded in case_metadata.json "
                                           "and surfaced in the executive report's Case Details section)"),
    objective: str = typer.Option(None, "--objective",
                                   help="One-sentence statement of what this investigation is meant to "
                                        "answer. Recorded in case_metadata.json."),
    case_number: str = typer.Option(None, "--case-number",
                                     help="External case/ticket number distinct from --case-id "
                                          "(which is EL's internal handle)."),
    incident_date: str = typer.Option(None, "--incident-date",
                                       help="ISO date (YYYY-MM-DD) when the incident is believed to "
                                            "have occurred, if known."),
    defer_ai_brief: bool = typer.Option(
        False, "--defer-ai-brief",
        help="When ANTHROPIC_API_KEY is absent, write a request file "
             "(reports/_ai_brief_request.json) at REPORT time and let "
             "the Claude Code `el-ai-brief` skill fulfil it out-of-band. "
             "On completion the CLI prints how to invoke the skill. "
             "Equivalent to exporting EL_AI_BRIEF_DEFER=1 for this run."),
    detach: bool = typer.Option(
        False, "--detach",
        help="Re-launch as a systemd --user transient service so the "
             "run survives a login-session crash / logout / terminal "
             "close (nohup does NOT — systemd kills the session "
             "cgroup). Prints the unit name + how to follow it, then "
             "returns the prompt. Requires systemd-run + user lingering."),
) -> None:
    """Run the EL coordinator end-to-end on an evidence file."""
    _maybe_detach(detach, f"investigate-{case_id or 'case'}")
    if defer_ai_brief:
        import os as _os
        from el.reporting.executive_ai import DEFER_ENV as _DEFER_ENV
        _os.environ[_DEFER_ENV] = "1"
    result = Coordinator(run_timeline=timeline,
                         memory_baseline=baseline).investigate(input_path, case_id=case_id)
    if any([investigator, objective, case_number, incident_date]):
        from datetime import date as _date
        meta = CaseMetadata(
            case_number=case_number,
            incident_date=_date.fromisoformat(incident_date) if incident_date else None,
            investigator_name=investigator,
            objective_statement=objective,
        )
        save_case_metadata(result.case_dir, meta)
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
    _notify_pending_ai_brief(result.case_dir)


def _notify_pending_ai_brief(case_dir: str | Path) -> None:
    """Print an end-of-run notification when an AI-brief request file
    is sitting on disk waiting to be fulfilled.

    Two readers in mind:
      1. **Inside Claude Code** — tell them to run `/el-ai-brief`;
         the skill picks the request up, generates the six-section
         brief using Claude Code's own auth, re-renders the report.
      2. **Outside Claude Code** — the same file is still actionable:
         a user can hand it to any AI / scripted responder that
         respects the schema. We surface the path either way.

    Silent when no request file is present. The file exists when
    EITHER the operator explicitly opted into the deferred path
    (`EL_AI_BRIEF_DEFER=1` / `el report --defer-ai-brief`) OR EL
    detected it was running inside a Claude Code session (CLAUDECODE
    env var set) — in both cases ANTHROPIC_API_KEY was absent. The
    message differs between the two so the operator knows whether
    the brief will be generated by the surrounding Claude Code
    session (path is "active") or whether it's truly waiting for an
    out-of-band responder.
    """
    import json as _json
    from el.reporting.executive_ai import _REQUEST_FILENAME
    req = Path(case_dir) / "reports" / _REQUEST_FILENAME
    if not req.is_file():
        return
    # Read the trigger annotation we wrote into the request payload
    # so the message reflects what actually fired.
    trigger = ""
    session_id = ""
    try:
        payload = _json.loads(req.read_text())
        trigger = payload.get("trigger") or ""
        session_id = payload.get("trigger_session_id") or ""
    except (OSError, ValueError):
        pass
    console.print()
    if trigger == "claude_code_session":
        sess_note = (f" (session [bold]{session_id}[/bold])"
                     if session_id else "")
        console.print(
            f"[cyan]AI executive brief — Claude Code path[/cyan]"
            f"{sess_note}\n"
            "  EL detected it was launched from a Claude Code session, "
            "so the six-section brief will be generated by the "
            "orchestrating assistant via the [bold]el-ai-brief[/bold] "
            "skill — Claude is the AI either way, just transported via "
            "this file rather than the Anthropic SDK.\n"
            f"  Request file: [bold]{req}[/bold]\n"
            "  The assistant should pick this up automatically; if not, "
            "run [bold]/el-ai-brief[/bold] inside the session."
        )
    else:
        console.print(
            "[cyan]Pending AI executive brief[/cyan] — the deterministic "
            "digest is in your report now; the six-section AI brief was "
            "deferred (no API key and no Claude Code session detected).\n"
            f"  Request file: [bold]{req}[/bold]\n"
            "  To fulfil it: run [bold]/el-ai-brief[/bold] inside a "
            "Claude Code session, or hand the request payload to any "
            "responder that respects the schema. The skill / responder "
            "writes the cache file, then `el report` picks it up."
        )


def _parse_device_spec(spec: str) -> tuple[str, str]:
    """Parse a `name:path` device flag value. Returns (name, path).
    Names allowed: alphanumeric + dash + underscore (so the device
    becomes a valid filesystem path under cases/<bundle>/devices/)."""
    if ":" not in spec:
        raise typer.BadParameter(
            f"--device must be NAME:PATH, got {spec!r}")
    name, _, path = spec.partition(":")
    name = name.strip()
    path = path.strip()
    if not name or not path:
        raise typer.BadParameter(
            f"--device NAME and PATH must both be non-empty: {spec!r}")
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9_\-]+", name):
        raise typer.BadParameter(
            f"--device NAME must be alphanumeric / dash / underscore: "
            f"{name!r}")
    return name, path


@app.command("investigate-bundle")
def investigate_bundle_cmd(
    bundle_id: str = typer.Argument(..., help="Case ID for the whole bundle"),
    device: list[str] = typer.Option(
        ..., "--device", "-d",
        help="Repeatable: NAME:PATH for each device in the bundle "
             "(e.g. --device laptop:/path/to/disk.E01 "
             "--device phone:/path/to/ios-fs/)"),
    timeline: bool = typer.Option(
        False, "--timeline/--no-timeline",
        help="Run Plaso super-timeline on each device (slow)."),
    investigator: str = typer.Option(None, "--investigator"),
    objective: str = typer.Option(None, "--objective"),
    case_number: str = typer.Option(None, "--case-number"),
    incident_date: str = typer.Option(None, "--incident-date"),
    detach: bool = typer.Option(
        False, "--detach",
        help="Re-launch as a systemd --user transient service so the "
             "multi-hour bundle survives a login-session crash / "
             "logout / terminal close. nohup does NOT survive session "
             "teardown (systemd kills the session cgroup); a --user "
             "service does. Strongly recommended for bundles. Requires "
             "systemd-run + user lingering."),
) -> None:
    """Investigate a multi-device case as a single bundle.

    Each --device runs through the existing single-host coordinator
    pipeline into cases/<bundle-id>/devices/<name>/. After all
    devices finish, a synthesis pass merges every finding into the
    bundle's top-level findings.sqlite, recomputes ACH on the union
    (so cross-device evidence sums into the same hypothesis), and
    writes bundle.json.
    """
    _maybe_detach(detach, f"bundle-{bundle_id}")
    from el.bundle import (
        BundleManifest, DeviceEntry, create_bundle_layout,
        create_device_layout, make_device_case_id, save as save_bundle,
    )
    from el.bundle_synth import synthesize_bundle
    from el.evidence.intake import CASE_ROOT

    if not device:
        console.print("[red]at least one --device is required[/red]")
        raise typer.Exit(2)

    parsed: list[tuple[str, str]] = [_parse_device_spec(s) for s in device]
    seen_names: set[str] = set()
    for name, _ in parsed:
        if name in seen_names:
            console.print(f"[red]duplicate device name: {name!r}[/red]")
            raise typer.Exit(2)
        seen_names.add(name)

    bundle_dir = create_bundle_layout(CASE_ROOT, bundle_id)
    bundle = BundleManifest(bundle_id=bundle_id)

    # Pair-detection (advisory v1) — scan the parsed device list for
    # A/B paired captures of the same host (same byte size + same
    # name-root after stripping acquisition suffixes). The detector
    # is read-only on the inputs; it just writes pair_candidates.json
    # and stamps a paired_with dict onto each affected device's
    # Coordinator. Two ACH hypotheses (H_PAIRED_CAPTURE_CANDIDATE,
    # H_NOT_CLEAN_BASELINE) consume the stamp at scoring time.
    from el.intel.pair_detection import detect_pairs, write_candidates
    pair_candidates = detect_pairs(parsed)
    write_candidates(bundle_dir, pair_candidates)
    paired_meta: dict[str, dict] = {}
    if pair_candidates:
        console.print(
            f"[bold]pair_detection[/bold]: {len(pair_candidates)} "
            f"paired-capture candidate(s) detected — see "
            f"{bundle_dir / 'pair_candidates.json'}")
        for pc in pair_candidates:
            console.print(
                f"  [bold]{pc.authoritative_name}[/bold] "
                f"↔ {pc.baseline_name} (root={pc.name_root!r}, "
                f"size={pc.size_bytes}B) — {pc.reason}")
            paired_meta[pc.authoritative_name] = {
                "role": "authoritative",
                "peer_name": pc.baseline_name,
                "peer_path": pc.baseline_path,
                "name_root": pc.name_root,
                "size_bytes": pc.size_bytes,
                "reason": pc.reason,
            }
            paired_meta[pc.baseline_name] = {
                "role": "baseline",
                "peer_name": pc.authoritative_name,
                "peer_path": pc.authoritative_path,
                "name_root": pc.name_root,
                "size_bytes": pc.size_bytes,
                "reason": pc.reason,
            }

    for dev_name, dev_path in parsed:
        dev_dir = create_device_layout(bundle_dir, dev_name)
        dev_case_id = make_device_case_id(bundle_id, dev_name)
        console.print(
            f"[bold]device[/bold] {dev_name}: investigating "
            f"{dev_path} → {dev_dir}")
        try:
            # Fresh Coordinator per device — the state machine
            # (self.state) starts at INTAKE and ends at DONE; reusing
            # one instance across devices would attempt an illegal
            # DONE->TRIAGE transition on the second device.
            coordinator = Coordinator(
                run_timeline=timeline,
                paired_with=paired_meta.get(dev_name),
            )
            result = coordinator.investigate(
                dev_path, case_id=dev_case_id, case_dir=dev_dir)
        except Exception as e:
            console.print(
                f"[red]device {dev_name} failed: {e}[/red] — continuing "
                f"with remaining devices so the bundle can still synthesise.")
            continue
        # Build the device manifest entry
        import json as _json
        dev_manifest = _json.loads((dev_dir / "manifest.json").read_text())
        bundle.devices.append(DeviceEntry(
            name=dev_name, case_id=dev_case_id,
            input_path=dev_manifest["input_path"],
            input_size_bytes=dev_manifest["input_size_bytes"],
            input_sha256=dev_manifest["input_sha256"],
            case_dir=str(dev_dir),
            investigated_utc=datetime.now(timezone.utc),
            leading_hypothesis=result.leading_hypothesis,
            leading_score=result.leading_hypothesis_score or 0,
        ))

    save_bundle(bundle_dir, bundle)

    if investigator or objective or case_number or incident_date:
        from datetime import date as _date
        meta = CaseMetadata(
            case_number=case_number,
            incident_date=_date.fromisoformat(incident_date) if incident_date else None,
            investigator_name=investigator,
            objective_statement=objective,
        )
        save_case_metadata(bundle_dir, meta)

    if not bundle.devices:
        console.print(
            "[red]bundle has zero successful devices — skipping synthesis.[/red]")
        raise typer.Exit(2)

    console.print(f"[bold]synthesising[/bold] {len(bundle.devices)} "
                  f"device(s) into the bundle ledger…")
    bundle = synthesize_bundle(bundle_dir)

    # Auto-render the bundle's reports — analyst case.html + executive
    # HTML/PDF — so the bundle command is self-contained. Falls back
    # to a yellow note on failure rather than raising; the per-device
    # reports inside devices/<name>/reports/ still render via the
    # coordinator regardless.
    try:
        _render_case_once(bundle_dir, html=True, executive=True, pdf=True)
    except Exception as e:
        console.print(
            f"[yellow]bundle report render failed: {e}[/yellow]")

    _notify_pending_ai_brief(bundle_dir)

    # Bundle-level seal — covers everything under cases/<bundle>/,
    # including per-device subcases (which skipped their own seal
    # under Phase 9 to avoid redundant archives). One merkle root
    # for the whole investigation.
    try:
        from el import seal as case_seal
        seal_manifest = case_seal.seal_case(
            bundle_dir, bundle_id, archive=True,
        )
        console.print(
            f"[bold]bundle_seal[/bold]: merkle="
            f"{seal_manifest['merkle_root'][:16]}… "
            f"archive={seal_manifest.get('archive_path', '—')}")
    except Exception as e:
        console.print(f"[yellow]bundle seal failed: {e}[/yellow]")

    console.print(f"[bold]bundle[/bold]: {bundle_dir}")
    console.print(f"[bold]devices[/bold]: "
                  f"{', '.join(d.name for d in bundle.devices)}")
    console.print(f"[bold]total_findings[/bold]: {bundle.total_findings}")
    if bundle.leading_hypothesis:
        console.print(
            f"[bold]bundle_leading_hypothesis[/bold]: "
            f"{bundle.leading_hypothesis} (score={bundle.leading_score})")


if __name__ == "__main__":
    app()

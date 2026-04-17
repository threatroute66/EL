"""Memory Forensicator — runs vol3 plugins, parses, emits Findings.

Mostly deterministic. Tool output IS the evidence. The claim text is a
factual summary of parsed rows; confidence is grounded in plugin success.
Suspicious-pattern flagging is rule-based (no LLM) — Red Reviewer + ACH
handle the reasoning layer.
"""
from __future__ import annotations

from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.evidence.graph import open_graph
from el.schemas.finding import Finding
from el.skills import memory_baseliner, vol3


SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "wmic.exe",
}
SUSPICIOUS_CHILDREN = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "bitsadmin.exe",
}

WIN_PLUGINS = [
    "windows.pslist.PsList",
    "windows.psscan.PsScan",       # SKILL: pool-tag scan finds hidden + exited
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.netstat.NetStat",     # SKILL: netstat = current state
    "windows.netscan.NetScan",     # SKILL: netscan = historical (pool-tag)
    "windows.dlllist.DllList",
    "windows.svcscan.SvcScan",
]

# malfind runs separately with --dump so suspicious regions hit disk as files
# (per memory-analysis SKILL: `windows.malfind --dump --output-dir ./exports/malfind/`)
WIN_DUMP_PLUGINS = [("windows.malfind.Malfind", ["--dump"])]
LIN_PLUGINS = [
    "linux.pslist.PsList",
    "linux.pstree.PsTree",
    "linux.bash.Bash",
    "linux.malfind.Malfind",
]


class MemoryForensicatorAgent(Agent):
    name = "memory_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        family = ctx.shared.get("mem_os")
        if not family:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="Skipping memory analysis — Triage did not establish an OS family",
            ))]

        plugins = WIN_PLUGINS if family == "windows" else LIN_PLUGINS if family == "linux" else []
        if not plugins:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"No plugin set wired for OS family '{family}' yet",
            ))]

        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        runs = {}
        plugin_specs: list[tuple[str, list[str] | None]] = [(p, None) for p in plugins]
        if family == "windows":
            plugin_specs.extend(WIN_DUMP_PLUGINS)

        for plugin, extra in plugin_specs:
            try:
                r = vol3.run_plugin(ctx.input_path, plugin, analysis,
                                     extra_args=extra, timeout=900)
                runs[plugin] = r
                ev = r.as_evidence()
                if r.rc == 0 and r.rows:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        claim=f"{plugin}: {len(r.rows)} row(s) parsed",
                        confidence="high", evidence=[ev],
                    )))
                elif r.rc == 0:
                    out.append(self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        claim=f"{plugin} ran but returned no rows",
                        confidence="low", evidence=[ev],
                    )))
                else:
                    err_text = ""
                    try:
                        err_text = r.stderr_path.read_text(errors="ignore")
                    except Exception:
                        pass
                    if "Unable to locate symbols" in err_text or "ISF" in err_text:
                        out.append(self.emit(ctx, Finding(
                            case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                            claim=(f"{plugin} blocked by Vol3 symbol mismatch — the image's module "
                                   "(typically tcpip.sys / a Windows version-specific PDB) is not in "
                                   "the local symbol cache. Per memory-analysis SKILL: pre-download "
                                   "ISF from downloads.volatilityfoundation.org/volatility3/symbols/ "
                                   "into volatility3/symbols/windows/, or run with internet access "
                                   "for auto-fetch."),
                        )))
                    else:
                        out.append(self.emit(ctx, Finding(
                            case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                            claim=f"{plugin} failed (rc={r.rc}) — see {r.stderr_path}",
                        )))
            except vol3.Vol3Error as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"{plugin}: {e}",
                )))

        if family == "windows" and "windows.pslist.PsList" in runs:
            out.extend(self._analyze_pslist_windows(ctx, runs["windows.pslist.PsList"]))
        if family == "windows" and {"windows.pslist.PsList", "windows.psscan.PsScan"} <= runs.keys():
            out.extend(self._diff_hidden_processes(
                ctx, runs["windows.pslist.PsList"], runs["windows.psscan.PsScan"]))
        if "windows.malfind.Malfind" in runs and runs["windows.malfind.Malfind"].rows:
            out.extend(self._flag_malfind(ctx, runs["windows.malfind.Malfind"]))
            out.extend(self._flag_pe_headers(ctx, runs["windows.malfind.Malfind"]))
            out.extend(self._report_dumped_regions(ctx, runs["windows.malfind.Malfind"]))

        if family == "windows" and "windows.pslist.PsList" in runs and runs["windows.pslist.PsList"].rows:
            out.extend(self._process_anomalies(ctx, runs["windows.pslist.PsList"]))

        baseline_path = ctx.shared.get("memory_baseline_json")
        if baseline_path:
            out.extend(self._run_baseline(ctx, Path(baseline_path)))

        return out

    def _run_baseline(self, ctx: AgentContext, baseline_json: Path) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name / "baseliner"
        for mode in ("proc", "drv", "svc"):
            try:
                r = memory_baseliner.compare(mode, ctx.input_path, baseline_json,
                                             analysis, timeout=3600)
            except memory_baseliner.BaselinerError as e:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"Memory Baseliner ({mode}) unavailable: {e}",
                )))
                continue
            ev = r.as_evidence()
            if r.rc != 0:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                    claim=f"Memory Baseliner {mode} returned rc={r.rc}; see {r.stderr_path.name}",
                )))
                continue
            if r.nonbaseline_count == 0:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=f"Baseline comparison ({mode}): no non-baseline items observed",
                    evidence=[ev],
                )))
            else:
                hyp = {"proc": "H_PROCESS_INJECTION", "drv": "H_ROOTKIT",
                       "svc": "H_PERSISTENCE_SERVICE"}[mode]
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim=f"Baseline comparison ({mode}): {r.nonbaseline_count} item(s) "
                          f"present in suspect image but absent from baseline — review {r.output_csv.name}",
                    evidence=[ev], hypotheses_supported=[hyp],
                )))
        return out

    def _diff_hidden_processes(self, ctx: AgentContext, pslist: vol3.PluginRun,
                                psscan: vol3.PluginRun) -> list[Finding]:
        """Per memory-analysis SKILL: PIDs present in psscan but NOT pslist =
        hidden (unlinked) processes — strong injection / rootkit indicator.

        Guard: if pslist returned no rows at all, the diff is meaningless
        (it would flag every psscan PID as 'hidden'). That's a tool-failure
        condition, not an injection signal — we surface it as such.
        """
        if not pslist.rows:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=("Hidden-process diff skipped — pslist returned 0 rows "
                       "(likely a Vol3 symbol/structure mismatch for this Windows version; "
                       "psscan succeeded so the image itself is parseable). "
                       "Cannot distinguish 'all processes hidden' from 'pslist tool failure'."),
            ))]
        listed = {row.get("PID") for row in pslist.rows if isinstance(row, dict)}
        scanned = {row.get("PID") for row in psscan.rows if isinstance(row, dict)}
        hidden_pids = sorted(p for p in (scanned - listed) if p is not None)
        if not hidden_pids:
            return []
        ev = psscan.as_evidence({"hidden_pids": hidden_pids})
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Hidden processes detected — {len(hidden_pids)} PID(s) in psscan but absent "
                   f"from pslist (likely unlinked / rootkit / injection): {hidden_pids[:20]}"),
            evidence=[ev],
            hypotheses_supported=["H_PROCESS_INJECTION", "H_ROOTKIT"],
        ))]

    def _analyze_pslist_windows(self, ctx: AgentContext, run: vol3.PluginRun) -> list[Finding]:
        findings: list[Finding] = []
        ev = run.as_evidence()
        by_pid = {row.get("PID"): row for row in run.rows if isinstance(row, dict) and "PID" in row}
        suspicious_pairs = []
        for row in run.rows:
            if not isinstance(row, dict):
                continue
            child = (row.get("ImageFileName") or "").lower()
            ppid = row.get("PPID")
            parent_row = by_pid.get(ppid)
            parent = (parent_row.get("ImageFileName") or "").lower() if parent_row else ""
            if parent in SUSPICIOUS_PARENTS and child in SUSPICIOUS_CHILDREN:
                suspicious_pairs.append((parent, row.get("PID"), child, ppid))

        if suspicious_pairs:
            details = "; ".join(f"{p}->[pid {cpid}] {c}" for p, cpid, c, _ in suspicious_pairs)
            findings.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                claim=f"Suspicious parent->child process pair(s) observed: {details}",
                confidence="high", evidence=[ev],
                hypotheses_supported=["H_INITIAL_ACCESS_DOC_MACRO", "H_LIVING_OFF_THE_LAND"],
            )))

        try:
            db, conn = open_graph(ctx.case_dir)
            host = "host_unknown"
            conn.execute(f"MERGE (:Host {{name: '{host}', os: 'windows'}})")
            for row in run.rows:
                if not isinstance(row, dict):
                    continue
                pid = row.get("PID")
                ppid = row.get("PPID")
                name = (row.get("ImageFileName") or "").replace("'", "''")
                if pid is None:
                    continue
                conn.execute(
                    f"MERGE (p:Process {{pid: {int(pid)}}}) "
                    f"SET p.ppid = {int(ppid) if ppid is not None else 0}, "
                    f"p.name = '{name}', p.host = '{host}'"
                )
            for row in run.rows:
                if not isinstance(row, dict):
                    continue
                pid = row.get("PID"); ppid = row.get("PPID")
                if pid is None or ppid is None:
                    continue
                conn.execute(
                    f"MATCH (c:Process {{pid:{int(pid)}}}), (p:Process {{pid:{int(ppid)}}}) "
                    f"MERGE (c)-[:CHILD_OF]->(p)"
                )
        except Exception as e:
            findings.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"Process graph population partially failed: {e}",
                evidence=[ev],
            )))
        return findings

    CREDENTIAL_ACCESS_TARGETS = {
        "lsass.exe", "winlogon.exe", "services.exe", "wininit.exe",
        "csrss.exe", "smss.exe", "lsaiso.exe",
    }

    def _flag_pe_headers(self, ctx: AgentContext, run: vol3.PluginRun) -> list[Finding]:
        """Per memory-analysis SKILL: malfind Hexdump rows starting with MZ
        are reflectively-loaded PE images not backed by a disk file — a
        classic hollowing / injection indicator stronger than raw shellcode."""
        mz_hits: list[dict] = []
        for row in run.rows:
            if not isinstance(row, dict):
                continue
            hexdump = (row.get("Hexdump") or "").strip()
            # Hexdump starts with "4d 5a" (MZ) — a DOS/PE executable header
            if hexdump[:5].lower().replace(" ", "").startswith("4d5a"):
                mz_hits.append({
                    "pid": row.get("PID"),
                    "process": (row.get("Process") or "").lower(),
                    "start_vpn": row.get("Start VPN") or row.get("StartVPN"),
                })
        if not mz_hits:
            return []
        procs = sorted({h["process"] for h in mz_hits})
        ev = run.as_evidence({"pe_header_hits": mz_hits[:20]})
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Reflectively-loaded PE image(s) detected — {len(mz_hits)} malfind region(s) "
                   f"begin with MZ header in process(es): {', '.join(procs)}. "
                   "Per memory-analysis SKILL: 'classic hollowing indicator'."),
            evidence=[ev],
            hypotheses_supported=["H_PROCESS_INJECTION", "H_PROCESS_HOLLOWING"],
        ))]

    def _report_dumped_regions(self, ctx: AgentContext, run: vol3.PluginRun) -> list[Finding]:
        """Enumerate --dump outputs sitting next to the malfind JSON.
        ThreatHunter then YARA-sweeps these as part of the analysis dir."""
        dump_dir = run.stdout_path.parent
        dumps = sorted(dump_dir.glob("pid.*.dmp")) + sorted(dump_dir.glob("*.vad.dmp"))
        if not dumps:
            return []
        total_bytes = sum(p.stat().st_size for p in dumps)
        ev = run.as_evidence({"dumped_files": [p.name for p in dumps[:20]],
                               "total_bytes": total_bytes})
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"malfind --dump produced {len(dumps)} region file(s) "
                   f"({total_bytes} bytes total) into {dump_dir.name}/ — "
                   "ThreatHunter will YARA-sweep these alongside the analysis dir"),
            evidence=[ev], hypotheses_supported=["H_PROCESS_INJECTION"],
        ))]

    def _process_anomalies(self, ctx: AgentContext, run: vol3.PluginRun) -> list[Finding]:
        """SKILL-documented process anomalies from pslist:
          - Orphaned: PPID not present in the process list (possible hollowing
            or attacker-parent that has exited)
          - Very short-lived: exited within 5 seconds of creation (atomic
            actions or AV termination)
        """
        out: list[Finding] = []
        rows = [r for r in run.rows if isinstance(r, dict)]
        pids = {r.get("PID") for r in rows if r.get("PID") is not None}
        ev = run.as_evidence({"phase": "process_anomaly_scan"})

        # Orphaned: PPID not in the live PID set (but not 0 / 4, which are system)
        orphans = []
        for r in rows:
            ppid = r.get("PPID")
            if ppid in (None, 0, 4):
                continue
            if ppid not in pids:
                orphans.append({"pid": r.get("PID"),
                                "ppid": ppid,
                                "name": (r.get("ImageFileName") or "").lower()})
        if orphans:
            names = sorted({o["name"] for o in orphans})
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"Orphaned processes — {len(orphans)} PID(s) with PPID not in pslist: "
                       f"{', '.join(names)}. Parent may have exited (benign) or never "
                       "existed in linked-list walk (suspicious; possible hollowing)."),
                evidence=[ev],
                hypotheses_supported=["H_PROCESS_INJECTION"],
            )))

        # Very short-lived: exited in < 5 seconds
        from datetime import datetime
        short: list[dict] = []
        for r in rows:
            ct = r.get("CreateTime"); et = r.get("ExitTime")
            if not ct or not et:
                continue
            try:
                a = datetime.fromisoformat(ct.replace("Z", "+00:00"))
                b = datetime.fromisoformat(et.replace("Z", "+00:00"))
            except Exception:
                continue
            delta = (b - a).total_seconds()
            if 0 < delta < 5.0:
                short.append({"pid": r.get("PID"),
                              "name": (r.get("ImageFileName") or "").lower(),
                              "dt": delta})
        if short:
            # Filter noise: conhost.exe and consent.exe routinely short-lived
            noisy = {"conhost.exe", "consent.exe", "backgroundtaskhost.exe"}
            signal = [s for s in short if s["name"] not in noisy]
            if signal:
                names = sorted({s["name"] for s in signal})
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="low",
                    claim=(f"Very short-lived process(es) (<5s exit): {len(signal)} — {', '.join(names)}. "
                           "May be atomic actions, AV termination, or short exploit runs."),
                    evidence=[ev],
                )))
        return out

    def _flag_malfind(self, ctx: AgentContext, run: vol3.PluginRun) -> list[Finding]:
        out: list[Finding] = []
        ev = run.as_evidence()
        names = sorted({(r.get("Process") or "").lower()
                        for r in run.rows if isinstance(r, dict)})
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name,
            claim=f"malfind flagged {len(run.rows)} region(s) across processes: "
                  f"{', '.join(filter(None, names))}",
            confidence="high", evidence=[ev],
            hypotheses_supported=["H_PROCESS_INJECTION", "H_CODE_EXECUTION"],
        )))

        # Credential-access carve-out: RWX in a critical system process (lsass,
        # winlogon, services, csrss, wininit, smss) is NOT explainable by JIT
        # runtimes — these processes don't run managed code. A malfind hit
        # here is high-signal for credential theft (mimikatz-class).
        cred_hits: dict[str, int] = {}
        for row in run.rows:
            if not isinstance(row, dict):
                continue
            proc = (row.get("Process") or "").lower()
            if proc in self.CREDENTIAL_ACCESS_TARGETS:
                cred_hits[proc] = cred_hits.get(proc, 0) + 1

        if cred_hits:
            detail = ", ".join(f"{p}×{n}" for p, n in sorted(cred_hits.items()))
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                claim=f"Code-injection in credential-access target process(es): {detail}. "
                      "These system processes do not run JIT-compiled code; RWX regions "
                      "here are strong indicators of credential-dumping (mimikatz-class) "
                      "or privilege-escalation malware.",
                confidence="high", evidence=[ev],
                hypotheses_supported=["H_CREDENTIAL_ACCESS", "H_PROCESS_INJECTION"],
            )))
        return out

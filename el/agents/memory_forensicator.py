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
from el.skills import memory_baseliner, netscan_triage, process_profile, vol3


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
    # T3-1: kernel-driver + handle + SID visibility. modules vs modscan
    # diff reveals unlinked drivers (rootkit). ldrmodules three-list
    # diff reveals unlinked DLLs (reflective injection). handles
    # identifies which process holds a staging file or named pipe.
    # getsids completes the process-anomaly matrix's user-account
    # check that PR-H explicitly deferred.
    "windows.modules.Modules",
    "windows.modscan.ModScan",
    "windows.ldrmodules.LdrModules",
    "windows.handles.Handles",
    "windows.getsids.GetSIDs",
    # vol3 extras — kernel-hook + in-memory-file carving visibility.
    # ssdt + driverirp expose syscall-table / IRP-dispatch hooks
    # (rootkit primitive). filescan + mftscan give disk-less file
    # visibility for exfil / staged-payload reconstruction. yarascan
    # sweeps the raw memory image with the per-case YARA catalog
    # that ThreatHunter already builds — complements malfind-based
    # region scanning with image-wide match surface.
    "windows.ssdt.SSDT",
    "windows.driverirp.DriverIrp",
    "windows.filescan.FileScan",
    "windows.mftscan.MFTScan",
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
            # Carve mapped file objects from the suspicious PIDs malfind
            # flagged. Per-PID is the right granularity here — running
            # vol3 windows.dumpfiles WITHOUT a PID filter dumps every
            # mapped file in memory (10k+ on a busy workstation), which
            # is forensically pointless. Targeted carving from a malfind
            # PID gives the analyst the on-disk DLLs / EXEs the process
            # was holding open at acquisition time.
            out.extend(self._carve_dumpfiles(
                ctx, runs["windows.malfind.Malfind"], analysis))

        if family == "windows" and "windows.pslist.PsList" in runs and runs["windows.pslist.PsList"].rows:
            out.extend(self._process_anomalies(ctx, runs["windows.pslist.PsList"]))
        # PR-H: Hunt-Evil "Know Normal" expected-profile matrix
        # (parent + count checks for the 12 core Windows processes).
        # Orthogonal to _process_anomalies (which checks orphans +
        # short-lived) — every anomaly class fires its own finding.
        # Fallback: on Win10/11 builds where vol3 has an EPROCESS symbol
        # mismatch, pslist returns 0 rows but psscan (pool-tag scan) still
        # works. Pass both — the matrix uses psscan rows filtered to
        # ExitTime=None when pslist is empty.
        if family == "windows" and "windows.pslist.PsList" in runs:
            out.extend(self._hunt_evil_process_matrix(
                ctx, runs["windows.pslist.PsList"],
                runs.get("windows.psscan.PsScan")))

        # PR-C: netscan beacon + lateral-admin-port triage. vol3 netscan
        # survives the Win10 EPROCESS/tcpip symbol-mismatch that takes
        # out netstat, so it's frequently the only network visibility
        # available on a memory capture. Turn clusters of outbound
        # connections into hypothesis-lifting findings.
        if family == "windows" and "windows.netscan.NetScan" in runs:
            out.extend(self._netscan_triage(
                ctx, runs["windows.netscan.NetScan"]))

        # T3-1: kernel-driver rootkit detection via modules-vs-modscan diff.
        if (family == "windows"
                and {"windows.modules.Modules",
                     "windows.modscan.ModScan"} <= runs.keys()):
            out.extend(self._diff_hidden_drivers(
                ctx, runs["windows.modules.Modules"],
                runs["windows.modscan.ModScan"]))

        # T3-1: unlinked-DLL detection via ldrmodules InLoad/InInit/InMem diff.
        if ("windows.ldrmodules.LdrModules" in runs
                and runs["windows.ldrmodules.LdrModules"].rows):
            out.extend(self._flag_unlinked_dlls(
                ctx, runs["windows.ldrmodules.LdrModules"]))

        # vol3 extras: syscall-table and driver-IRP hook detection.
        # Each row in ssdt / driverirp exposes an Address + owning
        # Module; legitimate entries point at ntoskrnl / hal / win32k.
        # Anything else is a hook.
        for plugin in ("windows.ssdt.SSDT", "windows.driverirp.DriverIrp"):
            if plugin in runs and runs[plugin].rows:
                out.extend(self._flag_kernel_hooks(
                    ctx, plugin, runs[plugin]))

        baseline_path = (ctx.shared.get("memory_baseline")
                          or ctx.shared.get("memory_baseline_json"))
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

    def _diff_hidden_drivers(self, ctx: AgentContext,
                              modules: vol3.PluginRun,
                              modscan: vol3.PluginRun) -> list[Finding]:
        """T3-1: kernel-driver rootkit detection. modules walks the
        PsLoadedModuleList (the normal kernel driver registry);
        modscan finds drivers via pool-tag scanning. A driver in
        modscan but not in modules is unlinked — classic rootkit
        trick to hide from standard enumeration.
        """
        if not modules.rows:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=("Driver rootkit diff skipped — modules returned 0 rows "
                       "(vol3 symbol mismatch). Cannot distinguish "
                       "'all drivers unlinked' from 'tool failure'."),
            ))]

        def _key(row: dict) -> str:
            # Normalise on module name; offset varies across plugins.
            return ((row.get("Name") or row.get("FullDllName")
                      or row.get("Path") or "") or "").strip().lower()

        listed = {_key(r) for r in modules.rows
                  if isinstance(r, dict)}
        scanned = {_key(r) for r in modscan.rows
                   if isinstance(r, dict)}
        hidden = sorted(n for n in (scanned - listed)
                        if n and n != "")
        if not hidden:
            return []
        ev = modscan.as_evidence({"hidden_drivers": hidden[:50]})
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Hidden kernel driver(s) detected — {len(hidden)} "
                   f"module name(s) in modscan (pool-tag scan) but "
                   f"absent from modules (PsLoadedModuleList walk). "
                   f"Unlinked drivers are a classic rootkit "
                   f"hide-from-enumeration trick. Samples: "
                   f"{', '.join(hidden[:5])}"
                   f"{' …' if len(hidden) > 5 else ''}."),
            evidence=[ev],
            hypotheses_supported=["H_ROOTKIT", "H_APT_ESPIONAGE"],
        ))]

    def _flag_kernel_hooks(self, ctx: AgentContext,
                            plugin: str,
                            run: vol3.PluginRun) -> list[Finding]:
        """vol3 extras: ssdt + driverirp expose kernel syscall / IRP
        dispatch tables. A legitimate entry points at ntoskrnl.exe,
        hal.dll, or win32k.sys (and variants). An entry pointing at
        ANY other module is a kernel hook — near-unambiguous rootkit
        primitive (SSDT hook for anti-AV / stealth; IRP hook for
        file/registry interception)."""
        legit_modules = {"ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe",
                         "ntoskrnl", "hal.dll", "hal", "halmacpi.dll",
                         "win32k.sys", "win32k", "win32kbase.sys",
                         "win32kfull.sys"}
        hooks: list[dict] = []
        for r in run.rows:
            if not isinstance(r, dict):
                continue
            # Column names vary by plugin: SSDT uses "Module", DriverIrp
            # uses "Module" too but sometimes "Owner". Check both.
            module = ((r.get("Module") or r.get("Owner")
                        or r.get("ModuleName") or "") or "").strip().lower()
            if not module:
                continue
            # "UNKNOWN" / empty means vol3 couldn't resolve the address
            # to a driver — suggestive of hook in unlinked memory.
            if module in ("unknown", "n/a", "-"):
                hooks.append(r)
                continue
            if module not in legit_modules:
                hooks.append(r)

        if not hooks:
            return []
        # Group by module name for the claim
        from collections import Counter
        by_module: Counter = Counter(
            (r.get("Module") or r.get("Owner") or "unknown")
            for r in hooks
        )
        sample = ", ".join(f"{m} ×{n}"
                            for m, n in by_module.most_common(5))
        ev = run.as_evidence({"hook_count": len(hooks),
                               "by_module": dict(by_module)})
        plugin_short = plugin.split(".")[-1]
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Kernel hook(s) in {plugin_short}: {len(hooks)} "
                   f"entry(ies) owned by non-core module(s) "
                   f"({sample}). Expected owners are ntoskrnl / hal / "
                   f"win32k only; anything else is a syscall-table or "
                   f"IRP-dispatch hook — classic rootkit primitive."),
            evidence=[ev],
            hypotheses_supported=["H_ROOTKIT", "H_APT_ESPIONAGE"],
        ))]

    def _flag_unlinked_dlls(self, ctx: AgentContext,
                             run: vol3.PluginRun) -> list[Finding]:
        """T3-1: unlinked-DLL detection via ldrmodules three-list diff.
        The Windows loader tracks loaded DLLs in three linked lists
        (InLoad / InInit / InMem). A DLL present in some lists but not
        others is hiding — the signature of reflectively-injected
        modules (Metasploit reflective DLL injection,
        Invoke-ReflectivePEInjection, Cobalt Strike's default module
        loader). Flag processes where any DLL has InLoad=False
        OR InInit=False OR InMem=False while at least one list
        recorded it."""
        rows = [r for r in run.rows if isinstance(r, dict)]
        if not rows:
            return []

        unlinked: list[dict] = []
        for r in rows:
            il = r.get("InLoad")
            ii = r.get("InInit")
            im = r.get("InMem")
            # Each column may be bool/"True"/"False"/None in vol3 JSON
            def _is_false(v):
                if v is None:
                    return True
                if isinstance(v, bool):
                    return not v
                s = str(v).strip().lower()
                return s in ("false", "0", "no", "none", "")
            false_count = sum(1 for v in (il, ii, im) if _is_false(v))
            # Only flag if ≥1 list was true but ≥1 was false — symmetric
            # all-true or all-false patterns are either normal or tool-
            # failure, not injection signals.
            if 1 <= false_count <= 2:
                unlinked.append(r)
        if not unlinked:
            return []

        # Group by (Pid, Process) to report per-process counts
        from collections import Counter
        by_proc: Counter = Counter()
        for r in unlinked:
            key = (r.get("Pid") or r.get("PID") or 0,
                   r.get("Process") or r.get("ImageFileName") or "?")
            by_proc[key] += 1
        top = by_proc.most_common(5)
        sample = ", ".join(f"PID {pid} {name}: {n} DLL(s)"
                            for (pid, name), n in top)
        ev = run.as_evidence({"unlinked_dll_count": len(unlinked),
                               "top_processes": [[k[0], k[1], n]
                                                   for k, n in top]})
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Unlinked DLL(s) detected via ldrmodules three-list "
                   f"diff: {len(unlinked)} DLL(s) present in some but "
                   f"not all of InLoad / InInit / InMem across "
                   f"{len(by_proc)} process(es). Reflective-injection "
                   f"signature (Metasploit / Cobalt Strike / "
                   f"Invoke-ReflectivePEInjection). Top: {sample}."),
            evidence=[ev],
            hypotheses_supported=["H_PROCESS_INJECTION", "H_APT_ESPIONAGE",
                                    "H_ROOTKIT"],
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

    def _carve_dumpfiles(self, ctx: AgentContext,
                          malfind_run: vol3.PluginRun,
                          analysis: Path) -> list[Finding]:
        """Run `vol3 windows.dumpfiles` against the suspicious PIDs
        malfind flagged. Carved DLLs / EXEs / handles land under
        `<analysis>/dumpfiles/` so the threat_hunter YARA sweep picks
        them up alongside the malfind region dumps."""
        # Enumerate distinct PIDs from malfind's JSON output. Cap at
        # 8 — running dumpfiles per-PID against more than that on a
        # large image starts hitting hours of runtime.
        pids: list[int] = []
        seen = set()
        for row in malfind_run.rows or []:
            pid = row.get("PID") or row.get("pid")
            if pid is None:
                continue
            try:
                pid_i = int(pid)
            except (TypeError, ValueError):
                continue
            if pid_i in seen:
                continue
            seen.add(pid_i)
            pids.append(pid_i)
            if len(pids) >= 8:
                break
        if not pids:
            return []
        dump_root = analysis / "dumpfiles"
        try:
            r = vol3.dumpfiles(ctx.input_path, dump_root,
                                pids=pids, timeout=1800)
        except vol3.Vol3Error as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"vol3 windows.dumpfiles failed: {e}"),
            ))]
        carved = sorted(dump_root.rglob("file.*"))
        if not carved:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"windows.dumpfiles ran against {len(pids)} "
                       f"malfind-flagged PID(s) "
                       f"({', '.join(str(p) for p in pids[:5])}"
                       f"{' …' if len(pids) > 5 else ''}) but carved "
                       "no file objects (process may have closed all "
                       "handles before acquisition, or rc != 0)."),
                evidence=[r.as_evidence({"pids": pids})],
            ))]
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=(f"windows.dumpfiles carved {len(carved)} file "
                   f"object(s) from {len(pids)} malfind-flagged PID(s) "
                   f"({', '.join(str(p) for p in pids[:5])}"
                   f"{' …' if len(pids) > 5 else ''}). Each carved file "
                   "is a DLL / EXE / handle the suspicious process held "
                   "open at acquisition time. ThreatHunter's YARA sweep "
                   "will scan them as part of the analysis-dir pass."),
            evidence=[r.as_evidence({"pids": pids,
                                       "carved_files": len(carved)})],
            hypotheses_supported=["H_PROCESS_INJECTION"],
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

    def _hunt_evil_process_matrix(self, ctx: AgentContext,
                                    pslist_run: vol3.PluginRun,
                                    psscan_run: vol3.PluginRun | None = None,
                                    ) -> list[Finding]:
        """PR-H: per Hunt Evil page 1, check the 12 core Windows processes
        against their expected (parent, count) profile. Emits one Finding
        per anomaly class, with confidence escalated for lsass.exe / core
        singletons because a masquerade there is unambiguous.

        PR-B (SRL-2018 shakedown): on images where vol3 can't resolve the
        EPROCESS symbols (common on Win10 1709+/Win11 with no matching
        ISF), pslist returns 0 rows but psscan's pool-tag scan still
        works. When that happens, fall back to psscan filtered on
        ExitTime=None (still-running only — psscan otherwise includes
        exited processes that would falsify count checks), and cap
        confidence at medium to reflect the weaker data source.
        """
        out: list[Finding] = []
        rows = [r for r in pslist_run.rows if isinstance(r, dict)]
        source_run = pslist_run
        source_note = ""

        if not rows and psscan_run is not None:
            # Fallback. psscan includes exited procs → filter them out
            # so count checks don't get poisoned by pool-resident corpses.
            rows = [r for r in psscan_run.rows
                    if isinstance(r, dict) and r.get("ExitTime") in (None, "")]
            if rows:
                source_run = psscan_run
                source_note = (" [data source: windows.psscan.PsScan + ExitTime=None; "
                               "pslist returned 0 rows due to Vol3 symbol mismatch]")

        if not rows:
            return out

        anomalies = process_profile.analyze(rows)
        if not anomalies:
            return out

        ev = source_run.as_evidence({"phase": "hunt_evil_process_matrix",
                                      "source": source_run.plugin,
                                      "anomaly_count": len(anomalies)})
        psscan_fallback = source_run is not pslist_run
        for a in anomalies:
            # Credential-access core processes (lsass/wininit/services/csrss)
            # masqueraded or duplicated is an unambiguous high-confidence
            # finding. svchost-and-friends with wrong parent can legitimately
            # occur on clean systems (e.g., during service-pack install) →
            # medium.
            core_singletons = {"lsass.exe", "wininit.exe", "services.exe",
                                "csrss.exe", "lsaiso.exe", "smss.exe",
                                "winlogon.exe"}
            if a.image_name in core_singletons:
                confidence = "high"
            elif a.reason == "unexpected_parent":
                confidence = "medium"
            else:
                confidence = "medium"
            if psscan_fallback and confidence == "high":
                confidence = "medium"

            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"Process-tree anomaly [{a.image_name}/{a.reason}]: "
                       f"{a.details}{source_note}"),
                evidence=[ev],
                hypotheses_supported=a.hypotheses,
            )))
        return out

    def _netscan_triage(self, ctx: AgentContext,
                         run: vol3.PluginRun) -> list[Finding]:
        """PR-C: promote netscan row clusters into Findings.

        Two detectors from `el.skills.netscan_triage`:
          - repeat-endpoint beacon → H_C2_BEACONING
          - lateral admin-port session → H_LATERAL_MOVEMENT

        Confidence ladder:
          - Beacon with ≥10 hits to a single (addr, port) → high
          - Beacon with ≥4 hits → medium
          - Lateral with at least one ESTABLISHED session → high
          - Lateral with only CLOSED sockets → medium
        """
        out: list[Finding] = []
        rows = [r for r in run.rows if isinstance(r, dict)]
        if not rows:
            return out

        beacons = netscan_triage.detect_repeat_endpoint_beacon(rows)
        laterals = netscan_triage.detect_lateral_admin_port_session(rows)
        if not beacons and not laterals:
            return out

        ev = run.as_evidence({
            "phase": "netscan_triage",
            "beacon_count": len(beacons),
            "lateral_count": len(laterals),
        })

        for b in beacons[:10]:  # cap to avoid report spam
            # Unregistered destination ports (e.g. SRL-2018 base-sp →
            # 172.16.4.7:22233) are meaningfully more suspicious than
            # beacons to well-known services like http_alt — surface
            # that distinction in the claim so the analyst sees it.
            is_unregistered = b.port_category in ("registered", "ephemeral") \
                and b.port_label.startswith(("unregistered", "ephemeral"))
            base_conf = "high" if b.count >= 10 else "medium"
            confidence = base_conf
            if is_unregistered and confidence == "medium" and b.count >= 6:
                confidence = "high"
            states = ", ".join(f"{k or '?'}={v}" for k, v in b.states.items())
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"Netscan beacon pattern: {b.count} connection(s) from "
                       f"this host to {b.foreign_addr}:{b.foreign_port} "
                       f"[{b.port_label}] "
                       f"({b.proto}; states: {states}). "
                       f"Repeated contact with the same (IP, port) is the "
                       f"signature shape of periodic C2 beaconing."
                       + (" Unregistered destination port elevates suspicion — "
                          "no legitimate service documented."
                          if is_unregistered else "")),
                evidence=[ev],
                hypotheses_supported=["H_C2_BEACONING"],
            )))

        for l in laterals[:10]:
            confidence = "high" if l.established else "medium"
            states = ", ".join(f"{k or '?'}={v}" for k, v in l.states.items())
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"Netscan lateral-admin-port session: "
                       f"{l.count} connection(s) from this host to "
                       f"{l.foreign_addr}:{l.foreign_port} "
                       f"({l.service}; {l.proto}; states: {states}; "
                       f"established={l.established}). "
                       f"Outbound traffic to an admin / remote-exec port is "
                       f"a Hunt-Evil lateral-movement signature."),
                evidence=[ev],
                hypotheses_supported=["H_LATERAL_MOVEMENT"],
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

"""Coordinator — drives the EL state machine.

Triage runs first. Triage's evidence_kind determines which primary
investigator runs in PARALLEL_INVESTIGATE. If no kind matched, the
memory path is tried (vol3 banners may have detected an OS family).
"""
from __future__ import annotations

import json
import signal
from dataclasses import dataclass, field
from pathlib import Path

from el.audit import AuditLog
from el.case_template import render as render_case_claude_md
from el import knowledge as kb
from el import seal as case_seal
from el.agents.base import Agent, AgentContext
from el.agents.cloud_forensicator import CloudForensicatorAgent
from el.agents.correlator import CorrelatorAgent
from el.agents.browser_forensicator import BrowserForensicatorAgent
from el.agents.credential_analyst import CredentialAnalystAgent
from el.agents.powershell_analyst import PowerShellAnalystAgent
from el.agents.sigma_analyst import SigmaAnalystAgent
from el.agents.disk_forensicator import DiskForensicatorAgent
from el.agents.email_forensicator import EmailForensicatorAgent
from el.agents.bulk_extractor_features_agent import BulkExtractorFeaturesAgent
from el.agents.endpoint_analyst import EndpointAnalystAgent
from el.agents.linux_forensicator import LinuxForensicatorAgent
from el.agents.macos_forensicator import MacOSForensicatorAgent
from el.agents.execution_corroborator import ExecutionCorroboratorAgent
from el.agents.lateral_movement_analyst import LateralMovementAnalystAgent
from el.agents.log_analyst import LogAnalystAgent
from el.agents.malware_triage import MalwareTriageAgent
from el.agents.windows_artifact import WindowsArtifactAgent
from el.agents.memory_forensicator import MemoryForensicatorAgent
from el.agents.network_analyst import NetworkAnalystAgent
from el.agents.red_reviewer import RedReviewerAgent
from el.agents.threat_hunter import ThreatHunterAgent
from el.agents.timeline_synthesist import TimelineSynthesistAgent
from el.agents.triage import TriageAgent
from el.evidence.graph import init_graph
from el.evidence.intake import intake as run_intake
from el.evidence.ledger import list_findings, open_ledger
from el.intel.ach import (
    diagnostic_findings, emit_leading_hypothesis_finding, score_findings, write_matrix,
)
from el.intel.attack_map import map_case
from el.orchestrator.states import State, can_transition
from el.reporting.html import render_html
from el.reporting.render import render_report
from el.reporting.stix import emit_bundle
from el.skills import ioc_extract


from el.agents.android_forensicator import AndroidForensicatorAgent
from el.agents.ios_forensicator import IOSForensicatorAgent
from el.agents.k8s_audit_analyst import K8sAuditAnalystAgent

KIND_TO_AGENT: dict[str, type[Agent]] = {
    "pcap (libpcap)": NetworkAnalystAgent,
    "pcap (libpcap, big-endian)": NetworkAnalystAgent,
    "pcapng": NetworkAnalystAgent,
    # Multi-pcap capture series (directory of .pcap/.pcapng files).
    # Triage merges them with mergecap and rewrites ctx.input_path
    # so NetworkAnalystAgent sees a single normal pcap.
    "pcap-collection": NetworkAnalystAgent,
    "EWF (E01)": DiskForensicatorAgent,
    # VM disk wrappers — DiskForensicator converts to raw via qemu-img
    # then runs the normal mmls + fls pipeline.
    "vhdx": DiskForensicatorAgent,
    "vhd": DiskForensicatorAgent,
    "vmdk (sparse)": DiskForensicatorAgent,
    "vmdk (descriptor)": DiskForensicatorAgent,
    "EVTX (Windows Event Log)": LogAnalystAgent,
    "windows-artifacts-dir": WindowsArtifactAgent,
    "velociraptor-collection": EndpointAnalystAgent,
    "android-fs-dir": AndroidForensicatorAgent,
    # Magnet/UFED Android extraction archive (.tar/.zip with the
    # canonical /data layout) — same agent, ALEAPP wrap takes over
    # from the FS-walk path.
    "android-archive": AndroidForensicatorAgent,
    # Old-Android MTD/YAFFS2 bundle (pre-Android-4 phones,
    # mtdN.dd raw partition dumps) — same agent, YAFFS2 extract
    # path chains into the standard android-artifacts walker.
    "android-mtd-bundle": AndroidForensicatorAgent,
    "ios-fs-dir": IOSForensicatorAgent,
    # iTunes/Finder backup directory (Manifest.plist + Manifest.db)
    "itunes-backup": IOSForensicatorAgent,
    # iOS sysdiagnose tarball (sysdiagnose_*.tar.gz)
    "ios-sysdiagnose": IOSForensicatorAgent,
    "linux-fs-dir": LinuxForensicatorAgent,
    "qnap-nas-dir": LinuxForensicatorAgent,
    "macos-fs-dir": MacOSForensicatorAgent,
    "bulk-extractor-output": BulkExtractorFeaturesAgent,
    "k8s-audit-log": K8sAuditAnalystAgent,
}


def _sample_head(path: Path, n: int = 8192) -> bytes:
    """Read up to *n* bytes from *path*, or from the first .json/.gz
    child if *path* is a directory. Returns b"" on any failure."""
    try:
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_file() and child.suffix in (".json", ".gz",
                                                          ".log", ".ndjson"):
                    return child.read_bytes()[:n]
            return b""
        return path.read_bytes()[:n]
    except Exception:
        return b""


def _looks_like_cloudtrail(path: Path) -> bool:
    head = _sample_head(path)
    return b'"eventName"' in head or b'"eventSource"' in head


def _looks_like_k8s_audit(path: Path) -> bool:
    head = _sample_head(path)
    return b'"audit.k8s.io/' in head and b'"auditID"' in head


@dataclass
class RunResult:
    case_id: str
    case_dir: Path
    final_state: State
    report_path: Path | None
    stix_path: Path | None
    investigator: str | None
    leading_hypothesis: str | None = None
    leading_hypothesis_score: int | None = None
    techniques: dict[str, dict] = field(default_factory=dict)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    transitions: list[tuple[State, State]] = field(default_factory=list)


class Coordinator:
    def __init__(self, run_timeline: bool = False,
                 timeline_l2t_timeout: int = 7200,
                 timeline_psort_timeout: int = 3600,
                 memory_baseline: str | None = None):
        self.state = State.INTAKE
        self.transitions: list[tuple[State, State]] = []
        self.run_timeline = run_timeline
        self.timeline_l2t_timeout = timeline_l2t_timeout
        self.timeline_psort_timeout = timeline_psort_timeout
        self.memory_baseline = memory_baseline
        self.audit: AuditLog | None = None
        self._current_agent: str | None = None
        self._signal_prev: dict[int, object] = {}

    def _go(self, dst: State) -> None:
        if not can_transition(self.state, dst):
            raise RuntimeError(f"illegal transition {self.state} -> {dst}")
        self.transitions.append((self.state, dst))
        if self.audit:
            self.audit.info("state_transition", from_=self.state.value, to=dst.value)
        self.state = dst

    def _emit_cross_case_findings(self, ctx: AgentContext,
                                    prior: dict[str, list[dict]],
                                    ioc_sets: dict) -> None:
        """For each IOC seen previously in another case, write one Finding
        per (value, prior_case) pair into the ledger. Confidence is 'low'
        because cross-case overlap is suggestive context, not evidence
        for any hypothesis in this case."""
        from el.evidence.ledger import insert as ledger_insert
        from el.schemas.finding import EvidenceItem, Finding
        import hashlib
        # Group prior observations by (value, ioc_type) to keep findings tidy
        from el.intel.long_tail import (
            score as rarity_score, bucket_for_case_count)
        for value, observations in prior.items():
            ioc_type = observations[0]["ioc_type"]
            cases = sorted({o["case_id"] for o in observations})
            rarity = rarity_score(value, observations)
            # Ubiquitous IOCs are almost always benign infrastructure
            # (8.8.8.8, fonts.googleapis.com, time.windows.com). Suppress
            # the finding entirely — writing a ledger row per one of
            # these every case just adds noise to the report.
            if rarity.bucket == "ubiquitous":
                continue
            # Partition prior observations into real EL cases vs
            # external-feed pulls (case_id starts with "feed:"). Both
            # surface in the Finding, but the claim text and
            # extracted_facts call out feed provenance separately so
            # the analyst doesn't read "observed in N cases" when
            # really the source is a MISP/TAXII curator's list.
            feed_cases = [c for c in cases if c.startswith("feed:")]
            real_cases = [c for c in cases if not c.startswith("feed:")]
            ev = EvidenceItem(
                tool="el.knowledge", version="0.1.0",
                command=f"kb.lookup_iocs([{value}])",
                output_sha256=hashlib.sha256(value.encode()).hexdigest(),
                output_path=str(Path.home() / ".el" / "knowledge.sqlite"),
                extracted_facts={
                    "ioc_value": value,
                    "ioc_type": ioc_type,
                    "previously_seen_in_cases": real_cases,
                    "external_feed_sources": feed_cases,
                    "first_seen_utc": min(
                        o["observed_utc"] for o in observations),
                    "rarity_bucket": rarity.bucket,
                    "prior_case_count": rarity.case_count,
                },
                # Feed-sourced priors carry the threat_feeds tier (C2 —
                # fairly reliable, probably true). Real-case priors
                # inherit the original analyst-vetted tier (B2).
                source_reliability="C" if feed_cases and not real_cases else "B",
                info_credibility="2",
            )
            if feed_cases and not real_cases:
                # Feed-only prior — name the feed source, not the
                # case count.
                feed_label = ", ".join(c[len("feed:"):] for c in feed_cases[:2])
                claim = (
                    f"External-feed match [{rarity.bucket}]: {ioc_type} "
                    f"`{value[:80]}` listed by {feed_label}"
                    f"{' …' if len(feed_cases) > 2 else ''}. "
                    "External threat-intel feeds are reputable curators "
                    "but EL did not observe this IOC directly in another "
                    "case — confidence stays 'low' for the same reason "
                    "real cross-case overlap does."
                )
                agent_name = "knowledge_lookup"
            else:
                hybrid = (f", plus {len(feed_cases)} external feed(s)"
                          if feed_cases else "")
                claim = (
                    f"Cross-case overlap [{rarity.bucket}]: {ioc_type} "
                    f"`{value[:80]}` previously observed in "
                    f"{len(real_cases)} case(s) "
                    f"({', '.join(real_cases[:3])}"
                    f"{' …' if len(real_cases) > 3 else ''}{hybrid}). "
                    "Suggestive only — confidence stays 'low' because "
                    "cross-case overlap is context, not evidence for this "
                    "case's hypotheses."
                )
                agent_name = "knowledge_lookup"
            f = Finding(
                case_id=ctx.case_id, agent=agent_name,
                claim=claim, confidence="low", evidence=[ev],
            )
            ledger_insert(ctx.case_dir, f)

    def _run_agent(self, agent: Agent, ctx: AgentContext) -> None:
        if self.audit:
            self.audit.info("agent_start", agent=agent.name, state=self.state.value)
        self._current_agent = agent.name
        try:
            findings = agent.run(ctx)
            if self.audit:
                self.audit.info("agent_done", agent=agent.name,
                                findings_emitted=len(findings))
        except Exception as e:
            if self.audit:
                self.audit.error("agent_failed", agent=agent.name, err=str(e))
            raise
        finally:
            self._current_agent = None

    # ----- signal handling -----
    # SIGTERM/SIGINT arriving during a long agent (e.g. vol3 on a large
    # memory image) would otherwise die silently — the audit log would
    # stop mid-state with no `agent_failed` entry. We install handlers
    # that log `coordinator_signalled` with the last-known state + agent
    # before letting the default handler terminate the process.
    #
    # NOTE: SIGKILL (signal 9, used by the Linux OOM-killer) cannot be
    # trapped — the kernel delivers it unhandleable. Silent OOM deaths
    # must be detected out-of-band (e.g. by scanning dmesg for the
    # affected PID).
    def _install_signal_handlers(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                self._signal_prev[sig] = signal.signal(sig, self._on_signal)
            except (ValueError, OSError):
                # not in main thread, or unsupported — skip silently
                pass

    def _uninstall_signal_handlers(self) -> None:
        for sig, prev in self._signal_prev.items():
            try:
                signal.signal(sig, prev)
            except (ValueError, OSError):
                pass
        self._signal_prev.clear()

    def _on_signal(self, signum: int, frame) -> None:
        try:
            sig_name = signal.Signals(signum).name
        except Exception:
            sig_name = str(signum)
        if self.audit:
            self.audit.error(
                "coordinator_signalled",
                signal=sig_name,
                state=self.state.value,
                agent=self._current_agent or "(between agents)",
            )
        if signum == signal.SIGINT:
            raise KeyboardInterrupt()
        raise SystemExit(128 + signum)

    def _pick_investigator(self, ctx: AgentContext) -> Agent:
        kind = ctx.shared.get("evidence_kind")
        if kind and kind in KIND_TO_AGENT:
            return KIND_TO_AGENT[kind]()
        if _looks_like_k8s_audit(ctx.input_path):
            ctx.shared["evidence_kind"] = "k8s-audit-log"
            return K8sAuditAnalystAgent()
        if _looks_like_cloudtrail(ctx.input_path):
            ctx.shared["evidence_kind"] = "AWS CloudTrail"
            return CloudForensicatorAgent()
        if ctx.shared.get("mem_os"):
            return MemoryForensicatorAgent()
        return MemoryForensicatorAgent()

    def investigate(self, input_path: str | Path, case_id: str | None = None,
                     case_dir: str | Path | None = None) -> RunResult:
        """Run the coordinator end-to-end on `input_path`.

        `case_dir` overrides the default cases/<case_id>/ placement —
        used by the bundle pipeline to put each device's sub-case
        under cases/<bundle>/devices/<name>/.
        """
        self._install_signal_handlers()
        try:
            return self._investigate_main(input_path, case_id=case_id,
                                           case_dir=case_dir)
        finally:
            self._uninstall_signal_handlers()

    def _investigate_main(self, input_path: str | Path,
                          case_id: str | None = None,
                          case_dir: str | Path | None = None) -> RunResult:
        manifest = run_intake(input_path, case_id=case_id, case_dir=case_dir)
        init_graph(manifest.case_dir)
        with open_ledger(manifest.case_dir):
            pass

        self.audit = AuditLog(Path(manifest.case_dir), manifest.case_id)
        self.audit.info("intake_complete",
                        input_path=manifest.input_path,
                        input_sha256=manifest.input_sha256,
                        input_size_bytes=manifest.input_size_bytes)

        ctx = AgentContext(
            case_id=manifest.case_id,
            case_dir=Path(manifest.case_dir),
            input_path=Path(manifest.input_path),
            manifest=manifest.__dict__,
        )
        if self.memory_baseline:
            ctx.shared["memory_baseline"] = self.memory_baseline

        self._go(State.TRIAGE)
        self._run_agent(TriageAgent(), ctx)

        self._go(State.HYPOTHESIS_GEN)
        self._go(State.PARALLEL_INVESTIGATE)
        investigator = self._pick_investigator(ctx)
        self.audit.info("investigator_selected", name=type(investigator).__name__,
                        evidence_kind=ctx.shared.get("evidence_kind"))
        self._run_agent(investigator, ctx)

        # MalwareTriage covers two evidence pools: memory dumps (preferred)
        # and text-extractable analysis outputs (pcap summaries, EVTX CSVs,
        # fls bodyfiles). Always run — it'll emit insufficient if neither
        # pool has anything to attribute.
        self._run_agent(MalwareTriageAgent(), ctx)

        # If DiskForensicator extracted Linux artifacts (ext2/3/4), chain
        # LinuxForensicatorAgent for the triage-detector sweep.
        if ctx.shared.get("linux_artifacts_dir"):
            self._run_agent(LinuxForensicatorAgent(), ctx)

        # If DiskForensicator extracted macOS artifacts (APFS Data
        # volume), chain MacOSForensicatorAgent.
        if ctx.shared.get("macos_artifacts_dir"):
            self._run_agent(MacOSForensicatorAgent(), ctx)

        # If the primary investigator extracted Windows artifacts (DiskForensicator
        # on an NTFS partition), chain WindowsArtifactAgent against them.
        if ctx.shared.get("artifacts_dir"):
            artifacts_path = Path(ctx.shared["artifacts_dir"])
            if artifacts_path.exists() and artifacts_path.is_dir():
                artifact_ctx = AgentContext(
                    case_id=ctx.case_id, case_dir=ctx.case_dir,
                    input_path=artifacts_path, manifest=ctx.manifest,
                    shared=ctx.shared,
                )
                self._run_agent(WindowsArtifactAgent(), artifact_ctx)

                # If WindowsArtifactAgent produced an EvtxECmd CSV, chain
                # LateralMovementAnalyst (Hunt-Evil 7-technique detector).
                # Agent itself short-circuits with 'insufficient' if the
                # CSV is missing, so always safe to run here.
                self._run_agent(LateralMovementAnalystAgent(), ctx)
                # Execution-artifact correlator — cross-references
                # Shimcache/Prefetch/Amcache/UserAssist CSVs to corroborate
                # which binaries actually ran. Same short-circuit pattern.
                self._run_agent(ExecutionCorroboratorAgent(), ctx)
                # Credential-access / brute-force detectors over the same
                # EvtxECmd CSV — 4625 bursts + 4769 RC4-Kerberoasting +
                # 4776 NTLM spray. Disjoint from LM detectors; runs here
                # so the EVTX CSV is already on disk.
                self._run_agent(CredentialAnalystAgent(), ctx)
                # PowerShell 4104 decoded-payload triage: extracts
                # ScriptBlockText, base64/gzip-decodes inline blobs,
                # pattern-matches against mimikatz / AMSI bypass /
                # encoded-cradle / C2-framework family markers.
                self._run_agent(PowerShellAnalystAgent(), ctx)
                # Community SIGMA rule pack over the same EvtxECmd CSV.
                # Short-circuits insufficient when no rule pack is
                # configured; otherwise emits one Finding per matched
                # rule with the ATT&CK technique IDs from the rule's
                # tags wired into hypotheses_supported.
                self._run_agent(SigmaAnalystAgent(), ctx)

                # If PSTs were also extracted (extract_windows_artifacts
                # drops them under exports/windows-artifacts/mail/), triage
                # the mailbox for display-name spoofing + sensitive-
                # attachment-to-external patterns. Skipped silently when
                # no mail/ subdir exists.
                mail_dir = artifacts_path / "mail"
                if mail_dir.is_dir() and any(mail_dir.iterdir()):
                    mail_ctx = AgentContext(
                        case_id=ctx.case_id, case_dir=ctx.case_dir,
                        input_path=mail_dir, manifest=ctx.manifest,
                        shared=ctx.shared,
                    )
                    self._run_agent(EmailForensicatorAgent(), mail_ctx)

                # Firefox profiles (and later IE index.dat) land under
                # exports/windows-artifacts/browser/. Triage browser
                # history for anon-share / forum-post / webmail destinations.
                browser_dir = artifacts_path / "browser"
                if browser_dir.is_dir() and any(browser_dir.rglob("places.sqlite")):
                    browser_ctx = AgentContext(
                        case_id=ctx.case_id, case_dir=ctx.case_dir,
                        input_path=browser_dir, manifest=ctx.manifest,
                        shared=ctx.shared,
                    )
                    self._run_agent(BrowserForensicatorAgent(), browser_ctx)

        if self.run_timeline:
            self._run_agent(TimelineSynthesistAgent(
                log2timeline_timeout=self.timeline_l2t_timeout,
                psort_timeout=self.timeline_psort_timeout,
            ), ctx)

        # Recovery pass: when DiskForensicator surfaced anti-forensic
        # signals (timestomp / wiped binaries / cleared logs / VSS
        # deletion), automatically run tsk_recover + bulk_extractor
        # on the same image. Self-gating — the agent returns silently
        # when no triggers fire, so this is a no-op for clean cases.
        # Only meaningful when partitions metadata exists (set by
        # DiskForensicator after a successful mmls).
        if ctx.shared.get("partitions"):
            from el.agents.recovery import RecoveryAgent
            self._run_agent(RecoveryAgent(), ctx)

        self._go(State.CORRELATE)
        self._run_agent(CorrelatorAgent(), ctx)

        rows = list_findings(ctx.case_dir, case_id=ctx.case_id)
        evidence_paths_pre = [e.output_path for f in rows for e in f.evidence]
        ioc_sets_pre = ioc_extract.extract_from_paths(evidence_paths_pre)
        iocs_pre = {k: sorted(v) for k, v in ioc_sets_pre.items() if v}
        (ctx.case_dir / "iocs.json").write_text(json.dumps(iocs_pre, indent=2))

        # Cross-case knowledge lookup (Layer 3): for each IOC, query the
        # global knowledge store for prior observations from OTHER cases.
        # Emits SUGGESTIVE Findings (low confidence, informational) — does
        # not lift hypotheses. Forensic conclusions stay grounded in this
        # case's evidence.
        all_values = [v for vs in iocs_pre.values() for v in vs]
        try:
            prior = kb.lookup_iocs(all_values, current_case_id=ctx.case_id)
        except Exception as e:
            prior = {}
            if self.audit:
                self.audit.warn("knowledge_lookup_failed", err=str(e))
        if prior:
            self._emit_cross_case_findings(ctx, prior, ioc_sets_pre)
        # Always RECORD what this case extracted (write happens regardless of lookup outcome)
        try:
            new_rows = kb.record_iocs(ctx.case_id, "coordinator_post_pass", ioc_sets_pre)
            if self.audit:
                self.audit.info("knowledge_iocs_recorded", new_rows=new_rows,
                                total_iocs=len(all_values))
        except Exception as e:
            if self.audit:
                self.audit.error("knowledge_record_failed", err=str(e))

        self._run_agent(ThreatHunterAgent(), ctx)

        rows = list_findings(ctx.case_dir, case_id=ctx.case_id)
        ranked, _ = score_findings(rows)
        for f in rows:
            from el.evidence.ledger import insert as _ins
            _ins(ctx.case_dir, f)
        matrix_path = write_matrix(ctx.case_dir, ranked, rows)
        emit_leading_hypothesis_finding(ctx.case_id, ctx.case_dir, ranked, matrix_path)

        self._go(State.ADVERSARIAL_REVIEW)
        self._run_agent(RedReviewerAgent(), ctx)

        rows = list_findings(ctx.case_dir, case_id=ctx.case_id)
        unresolved = [f for f in rows if f.red_review.status == "unresolved"]

        evidence_paths = [e.output_path for f in rows for e in f.evidence]
        ioc_sets = ioc_extract.extract_from_paths(evidence_paths)
        # Structured-fact pass: pull source IPs from finding facts that
        # the path-level extractor's RFC1918 filter drops. See
        # `extract_from_finding_facts` for the rationale (enterprise
        # APT internal pivots are load-bearing IOCs, not noise).
        fact_iocs = ioc_extract.extract_from_finding_facts(rows)
        for k, v in fact_iocs.items():
            ioc_sets.setdefault(k, set()).update(v)
        iocs = {k: sorted(v) for k, v in ioc_sets.items() if v}
        (ctx.case_dir / "iocs.json").write_text(json.dumps(iocs, indent=2))

        techniques = map_case(rows)

        stix_path = ctx.case_dir / "reports" / "stix-bundle.json"
        try:
            emit_bundle(ctx.case_id, rows, ioc_sets, stix_path)
        except Exception as e:
            (ctx.case_dir / "reports" / "stix-error.txt").write_text(str(e))
            stix_path = None

        diag = diagnostic_findings(rows, top_n=5)

        if unresolved:
            self._go(State.BLOCKED)
            report_path = render_report(ctx.case_dir, ctx.case_id, manifest.__dict__,
                                        iocs=iocs, techniques=techniques, stix_path=stix_path,
                                        ach_ranking=ranked, diagnostic=diag)
        else:
            self._go(State.SYNTHESIZE)
            self._go(State.REPORT)
            report_path = render_report(ctx.case_dir, ctx.case_id, manifest.__dict__,
                                        iocs=iocs, techniques=techniques, stix_path=stix_path,
                                        ach_ranking=ranked, diagnostic=diag)
            self._go(State.DONE)

        try:
            render_html(ctx.case_dir, ctx.case_id, manifest.__dict__,
                        findings=rows, ach_ranking=ranked, iocs=iocs,
                        techniques=techniques)
        except Exception as e:
            if self.audit:
                self.audit.warn("case_html_render_failed", err=str(e))

        # Executive (non-expert) tier: HTML + PDF, both projections of
        # the same ledger as the analyst report. Failure on either
        # path is non-fatal — the analyst report is the source of
        # truth; the executive deliverables are derived.
        try:
            from el.reporting.executive import render_executive_html
            exec_html = render_executive_html(
                ctx.case_dir, case_id=ctx.case_id,
                manifest=manifest.__dict__,
            )
        except Exception as e:
            exec_html = None
            if self.audit:
                self.audit.warn("executive_html_render_failed", err=str(e))
        if exec_html is not None:
            try:
                from el.reporting.executive_pdf import (
                    render_executive_pdf, WeasyPrintNotAvailable,
                )
                render_executive_pdf(exec_html)
            except WeasyPrintNotAvailable as e:
                if self.audit:
                    self.audit.info("executive_pdf_skipped", err=str(e))
            except Exception as e:
                if self.audit:
                    self.audit.warn("executive_pdf_render_failed", err=str(e))

        (ctx.case_dir / "transitions.json").write_text(
            json.dumps([(a.value, b.value) for a, b in self.transitions], indent=2)
        )
        leader = ranked[0] if ranked else None
        try:
            manifest_with_kind = dict(manifest.__dict__)
            manifest_with_kind["evidence_kind"] = ctx.shared.get("evidence_kind")
            render_case_claude_md(
                ctx.case_dir, manifest_with_kind,
                investigator=type(investigator).__name__,
                final_state=self.state.value,
                leading_hypothesis=leader.hyp_id if leader else None,
                leading_hypothesis_score=leader.score if leader else None,
                ach_ranking=ranked,
                findings=rows,
            )
        except Exception as e:
            if self.audit:
                self.audit.error("case_claude_md_render_failed", err=str(e))
        # Seal the case at terminal state (Layer 2: chain-of-custody bundle).
        # Marks knowledge-store rows for this case as sealed.
        seal_manifest = None
        if self.state == State.DONE:
            try:
                seal_manifest = case_seal.seal_case(ctx.case_dir, ctx.case_id, archive=True)
                kb.mark_case_sealed(ctx.case_id)
                if self.audit:
                    self.audit.info("case_sealed",
                                    merkle_root=seal_manifest["merkle_root"],
                                    archive_path=seal_manifest.get("archive_path"))
            except Exception as e:
                if self.audit:
                    self.audit.error("case_seal_failed", err=str(e))

        if self.audit:
            self.audit.info("case_complete", final_state=self.state.value,
                            leading_hypothesis=leader.hyp_id if leader else None,
                            leading_score=leader.score if leader else None,
                            report_path=str(report_path) if report_path else None)
        return RunResult(
            case_id=ctx.case_id, case_dir=ctx.case_dir,
            final_state=self.state, report_path=report_path, stix_path=stix_path,
            investigator=type(investigator).__name__,
            leading_hypothesis=leader.hyp_id if leader else None,
            leading_hypothesis_score=leader.score if leader else None,
            techniques=techniques, iocs=iocs,
            transitions=self.transitions,
        )

"""Coordinator — drives the EL state machine.

Triage runs first. Triage's evidence_kind determines which primary
investigator runs in PARALLEL_INVESTIGATE. If no kind matched, the
memory path is tried (vol3 banners may have detected an OS family).
"""
from __future__ import annotations

import json
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
from el.agents.endpoint_analyst import EndpointAnalystAgent
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
from el.reporting.render import render_report
from el.reporting.stix import emit_bundle
from el.skills import ioc_extract


KIND_TO_AGENT: dict[str, type[Agent]] = {
    "pcap (libpcap)": NetworkAnalystAgent,
    "pcap (libpcap, big-endian)": NetworkAnalystAgent,
    "pcapng": NetworkAnalystAgent,
    "EWF (E01)": DiskForensicatorAgent,
    "EVTX (Windows Event Log)": LogAnalystAgent,
    "windows-artifacts-dir": WindowsArtifactAgent,
    "velociraptor-collection": EndpointAnalystAgent,
}


def _looks_like_cloudtrail(path: Path) -> bool:
    try:
        head = path.read_bytes()[:8192]
    except Exception:
        return False
    return b'"eventName"' in head or b'"eventSource"' in head


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
        for value, observations in prior.items():
            ioc_type = observations[0]["ioc_type"]
            cases = sorted({o["case_id"] for o in observations})
            ev = EvidenceItem(
                tool="el.knowledge", version="0.1.0",
                command=f"kb.lookup_iocs([{value}])",
                output_sha256=hashlib.sha256(value.encode()).hexdigest(),
                output_path=str(Path.home() / ".el" / "knowledge.sqlite"),
                extracted_facts={
                    "ioc_value": value,
                    "ioc_type": ioc_type,
                    "previously_seen_in_cases": cases,
                    "first_seen_utc": min(o["observed_utc"] for o in observations),
                },
            )
            f = Finding(
                case_id=ctx.case_id, agent="knowledge_lookup",
                claim=(f"Cross-case overlap: {ioc_type} `{value[:80]}` previously "
                       f"observed in case(s) {', '.join(cases[:3])}"
                       f"{' …' if len(cases) > 3 else ''}. "
                       "Suggestive only — confidence stays 'low' because cross-case "
                       "overlap is context, not evidence for this case's hypotheses."),
                confidence="low", evidence=[ev],
            )
            ledger_insert(ctx.case_dir, f)

    def _run_agent(self, agent: Agent, ctx: AgentContext) -> None:
        if self.audit:
            self.audit.info("agent_start", agent=agent.name, state=self.state.value)
        try:
            findings = agent.run(ctx)
            if self.audit:
                self.audit.info("agent_done", agent=agent.name,
                                findings_emitted=len(findings))
        except Exception as e:
            if self.audit:
                self.audit.error("agent_failed", agent=agent.name, err=str(e))
            raise

    def _pick_investigator(self, ctx: AgentContext) -> Agent:
        kind = ctx.shared.get("evidence_kind")
        if kind and kind in KIND_TO_AGENT:
            return KIND_TO_AGENT[kind]()
        if _looks_like_cloudtrail(ctx.input_path):
            ctx.shared["evidence_kind"] = "AWS CloudTrail"
            return CloudForensicatorAgent()
        if ctx.shared.get("mem_os"):
            return MemoryForensicatorAgent()
        return MemoryForensicatorAgent()

    def investigate(self, input_path: str | Path, case_id: str | None = None) -> RunResult:
        manifest = run_intake(input_path, case_id=case_id)
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

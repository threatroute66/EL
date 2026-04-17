"""Timeline Synthesist — builds Plaso super-timeline.

Applicable to disk images, log corpora, EVTX, or directories.
log2timeline followed by psort. Heavy on real cases — caller controls
whether to invoke via the coordinator (currently disabled by default;
the user opts in via CLI flag).
"""
from __future__ import annotations

from el.agents.base import Agent, AgentContext
from el.schemas.finding import Finding
from el.skills import plaso


class TimelineSynthesistAgent(Agent):
    name = "timeline_synthesist"

    def __init__(self, log2timeline_timeout: int = 7200, psort_timeout: int = 3600,
                 parsers: str = "win10", vss: bool = True):
        self.log2timeline_timeout = log2timeline_timeout
        self.psort_timeout = psort_timeout
        self.parsers = parsers
        self.vss = vss

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name
        analysis.mkdir(parents=True, exist_ok=True)

        try:
            l2t = plaso.log2timeline(ctx.input_path, analysis,
                                     timeout=self.log2timeline_timeout,
                                     parsers=self.parsers, vss=self.vss)
        except plaso.PlasoError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"log2timeline.py unavailable or failed: {e}",
            ))]

        if l2t.rc != 0 or not l2t.output_path.exists() or l2t.output_path.stat().st_size == 0:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"log2timeline produced no usable storage file (rc={l2t.rc})",
            ))]

        ev = l2t.as_evidence({"phase": "extract", "parsers": self.parsers,
                              "vss": self.vss})
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"Plaso events extracted to {l2t.output_path.name} "
                  f"({l2t.output_path.stat().st_size} bytes) "
                  f"using --parsers {self.parsers} "
                  f"{'--vss-stores all' if self.vss else ''}",
            evidence=[ev], hypotheses_supported=["H_TIMELINE_AVAILABLE"],
        )))

        try:
            info = plaso.pinfo(l2t.output_path, analysis, timeout=120)
            txt = info.output_path.read_text(errors="ignore")
            if "Number of events" in txt and " 0\n" in txt.split("Number of events", 1)[1][:200]:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="medium",
                    claim="pinfo reports zero events — per plaso-timeline SKILL, this is a config error "
                          "(wrong parser set or mount problem), not a clean system",
                    evidence=[info.as_evidence({"phase": "pinfo"})],
                )))
            else:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name, confidence="high",
                    claim="pinfo confirms parser hits across the storage",
                    evidence=[info.as_evidence({"phase": "pinfo"})],
                )))
        except plaso.PlasoError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=f"pinfo verification failed: {e}", evidence=[ev],
            )))

        try:
            ps = plaso.psort(l2t.output_path, analysis, timeout=self.psort_timeout)
        except plaso.PlasoError as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"psort.py failed: {e}",
            )))
            return out

        if ps.rc != 0 or not ps.output_path.exists():
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim=f"psort produced no timeline (rc={ps.rc})",
            )))
            return out

        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=f"Super-timeline rendered: {ps.output_path.name}",
            evidence=[ps.as_evidence({"phase": "render"})],
        )))
        return out

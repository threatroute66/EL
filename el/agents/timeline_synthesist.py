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
                 parsers: str = "win_gen", vss: bool = True):
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

        # Mine first / last event time from psort output so the
        # super-timeline lands on the kill-chain swimlane. l2tcsv
        # column 0 is `date` (MM/DD/YYYY), column 1 is `time` (HH:MM:SS),
        # column 2 is timezone. Header row is the first line. We scan
        # forward + backward for the first / last parseable timestamp
        # rather than loading the whole CSV.
        first_ts, last_ts = _l2tcsv_time_range(ps.output_path)
        ts_facts: dict = {"phase": "render"}
        if first_ts:
            ts_facts["first_ts_utc"] = first_ts
        if last_ts and last_ts != first_ts:
            ts_facts["last_ts_utc"] = last_ts
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Super-timeline rendered: {ps.output_path.name}"
                   + (f" — events span {first_ts} → {last_ts}"
                      if first_ts else "")),
            evidence=[ps.as_evidence(ts_facts)],
        )))
        return out


def _l2tcsv_time_range(csv_path) -> tuple[str | None, str | None]:
    """Scan an l2tcsv for the earliest + latest event timestamps.
    Reads forward through the head and backward through the tail
    rather than loading the whole CSV — Plaso super-timelines are
    typically hundreds of MB to multi-GB."""
    from datetime import datetime, timezone
    def _parse(date_field: str, time_field: str) -> str | None:
        try:
            dt = datetime.strptime(
                f"{date_field.strip()} {time_field.strip()}",
                "%m/%d/%Y %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            return None
    first_ts: str | None = None
    last_ts: str | None = None
    try:
        with open(csv_path, "r", errors="ignore") as f:
            header = f.readline()
            del header
            for line in f:
                parts = line.split(",", 3)
                if len(parts) < 2:
                    continue
                t = _parse(parts[0], parts[1])
                if t:
                    first_ts = t
                    break
        # Tail scan — walk back for the last parseable line.
        with open(csv_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(64 * 1024, size)
            f.seek(size - chunk)
            tail = f.read().decode("utf-8", errors="ignore")
            for line in reversed(tail.splitlines()):
                parts = line.split(",", 3)
                if len(parts) < 2:
                    continue
                t = _parse(parts[0], parts[1])
                if t:
                    last_ts = t
                    break
    except Exception:
        return (None, None)
    return (first_ts, last_ts)

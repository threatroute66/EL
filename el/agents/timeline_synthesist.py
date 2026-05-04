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
from el.skills import timesketch as tsk


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

        # Optional Timesketch upload — closes the analyst-review loop. Opt-in
        # via EL_TIMESKETCH_URL + EL_TIMESKETCH_TOKEN (or USERNAME+PASSWORD).
        # Pushes the .plaso storage file (l2t.output_path) into a sketch
        # named after the case so multi-analyst review can begin without
        # the operator manually re-uploading.
        out.extend(self._maybe_push_to_timesketch(ctx, l2t.output_path))
        return out

    def _maybe_push_to_timesketch(self, ctx: AgentContext,
                                    plaso_path) -> list[Finding]:
        """Push the .plaso storage to Timesketch if configured. No-op otherwise."""
        out: list[Finding] = []
        if not tsk.is_configured():
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("Timesketch push skipped — set EL_TIMESKETCH_URL + "
                       "EL_TIMESKETCH_TOKEN (or USERNAME+PASSWORD) to enable"),
            )))
            return out

        try:
            upload = tsk.push(plaso_path, sketch_name=ctx.case_id)
        except (tsk.TimesketchError, OSError, TypeError, ValueError) as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"Timesketch push failed: {e}",
            )))
            return out

        ev = upload.as_evidence()
        if upload.sketch_url:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"Timesketch sketch ready for review: "
                       f"{upload.sketch_url} "
                       f"({upload.plaso_size_bytes:,} bytes uploaded in "
                       f"{upload.duration_seconds:.1f}s)"),
                evidence=[ev],
            )))
        else:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=("Timesketch upload completed but server returned no "
                       "sketch URL; check the sketch list manually"),
                evidence=[ev],
            )))
        return out


def _l2tcsv_time_range(csv_path) -> tuple[str | None, str | None]:
    """Scan an l2tcsv for the earliest + latest plausible event timestamps.

    Plaso reads literally everything including manufacturing dates baked
    into Windows install media (often 1990s) and NTFS records with
    overflow timestamps (2106-02-07 is the classic Y2038-cousin
    artifact). Both are real evidence-derived data but useless for
    narrative time-range — they'd present a 100-year case span.
    Filter to a plausible analyst-relevant window: 1995-01-01 .. now+1d.
    """
    from datetime import datetime, timezone, timedelta
    def _parse(date_field: str, time_field: str) -> datetime | None:
        try:
            dt = datetime.strptime(
                f"{date_field.strip()} {time_field.strip()}",
                "%m/%d/%Y %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    floor = datetime(1995, 1, 1, tzinfo=timezone.utc)
    ceiling = datetime.now(timezone.utc) + timedelta(days=1)
    def _plausible(dt: datetime) -> bool:
        return floor <= dt <= ceiling
    first_dt: datetime | None = None
    last_dt: datetime | None = None
    # Single forward pass. Tail-scan was clean in theory but l2tcsv is
    # time-sorted ascending, and the m57-jean reference run had 54 k
    # overflow rows (2106-02-07, 44227-08-27 — FAT/NTFS records with
    # 0xff…ff timestamps) clustered at the end, beyond any reasonable
    # tail window. One forward sweep through a 1 GB CSV is ~30-60 s,
    # which is rounding error on a 12-min Plaso run.
    try:
        with open(csv_path, "r", errors="ignore") as f:
            f.readline()  # header
            for line in f:
                parts = line.split(",", 3)
                if len(parts) < 2:
                    continue
                dt = _parse(parts[0], parts[1])
                if dt and _plausible(dt):
                    if first_dt is None:
                        first_dt = dt
                    last_dt = dt
    except Exception:
        return (None, None)
    return (first_dt.isoformat() if first_dt else None,
            last_dt.isoformat() if last_dt else None)

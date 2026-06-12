"""Agent execution log + traceability matrix — Find Evil 2026 submission
requirement: 'Judges must be able to trace any finding back to the
specific tool execution that produced it.'

Three artefacts, all deterministic projections of existing state:

  reports/execution_log.jsonl   One JSON object per line, chronologically
                                ordered, covering:
                                  · state_transition events (coordinator)
                                  · agent_start / agent_done (audit log)
                                  · tool_execution (one per EvidenceItem
                                    attached to a Finding)
                                  · finding_emitted (one per Finding)
                                Every event carries a case_id + ts_utc;
                                tool_execution + finding_emitted cross-
                                reference via `finding_id`.

  reports/execution_log.md      Human-readable roll-up grouped by
                                state-machine phase + agent, with
                                per-finding tool citations.

  reports/traceability_matrix.md  Finding × tool execution grid. For each
                                Finding: finding_id, agent, confidence,
                                claim (head), tool, command, output
                                sha256, output path. Exactly the table
                                judges need to trace a claim to the
                                specific subprocess that produced it.

No new instrumentation — all data already captured during the run:
  · forensic_audit.log is append-only, grep-friendly
  · findings.sqlite holds Findings + EvidenceItems with the tool,
    version, command, output_sha256, output_path schema fields
EL's existing contract already guarantees every claim is backed by
tool-grounded evidence; this module just aggregates + presents it.
"""
from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from el.evidence.ledger import list_findings


_AUDIT_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+\[(?P<level>[A-Z]+)\]\s+(?P<rest>.*)$")


def _parse_audit_line(line: str) -> dict | None:
    """Parse one line of the audit log into a {ts, level, ...} dict.
    Values containing spaces are single-quoted by audit.py — shlex
    handles that unambiguously."""
    m = _AUDIT_LINE_RE.match(line.rstrip("\n"))
    if not m:
        return None
    try:
        kv_parts = shlex.split(m.group("rest"))
    except ValueError:
        return None
    rec: dict = {"ts_utc": m.group("ts"), "level": m.group("level")}
    for part in kv_parts:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        rec[k] = v
    return rec


def _read_audit(case_dir: Path) -> list[dict]:
    path = case_dir / "analysis" / "forensic_audit.log"
    if not path.is_file():
        return []
    out: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = _parse_audit_line(line)
            if rec is not None:
                out.append(rec)
    return out


@dataclass
class ExecutionEvent:
    ts_utc: str
    event_type: str           # state_transition | agent_start | agent_done
                              # | finding_emitted | tool_execution | other
    case_id: str
    agent: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    command: str | None = None
    output_sha256: str | None = None
    output_path: str | None = None
    finding_id: str | None = None
    confidence: str | None = None
    fields: dict = field(default_factory=dict)     # remaining key=value pairs

    def to_json_dict(self) -> dict:
        d = {
            "ts_utc": self.ts_utc,
            "event": self.event_type,
            "case_id": self.case_id,
        }
        for k in ("agent", "tool", "tool_version", "command",
                  "output_sha256", "output_path",
                  "finding_id", "confidence"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if self.fields:
            d["extra"] = self.fields
        return d


def _audit_rec_to_event(rec: dict) -> ExecutionEvent:
    ev = rec.get("event", "other")
    case_id = rec.get("case", "")
    # Carry remaining structured fields through as `extra` for
    # judges who want the full audit record context (pid, state,
    # input_sha256, etc.)
    known = {"ts_utc", "level", "event", "case", "agent"}
    extra = {k: v for k, v in rec.items() if k not in known}
    return ExecutionEvent(
        ts_utc=rec.get("ts_utc", ""),
        event_type=ev,
        case_id=case_id,
        agent=rec.get("agent"),
        fields=extra,
    )


def build_events(case_dir: str | Path) -> list[ExecutionEvent]:
    """Merge the audit log + Finding ledger into a single chronological
    event stream."""
    case_dir = Path(case_dir)
    events: list[ExecutionEvent] = []

    # Audit-log events
    for rec in _read_audit(case_dir):
        events.append(_audit_rec_to_event(rec))

    # Finding + tool-execution events
    manifest_path = case_dir / "manifest.json"
    case_id = case_dir.name
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text())
            case_id = manifest.get("case_id", case_id)
        except Exception:
            pass
    try:
        findings = list_findings(case_dir, case_id=case_id)
    except Exception:
        findings = []
    for f in findings:
        ts = (f.created_utc.isoformat(timespec="seconds")
              if getattr(f, "created_utc", None) else "")
        # One tool_execution per EvidenceItem — the core traceability row
        for e in f.evidence:
            events.append(ExecutionEvent(
                ts_utc=ts,
                event_type="tool_execution",
                case_id=case_id,
                agent=f.agent,
                tool=e.tool,
                tool_version=e.version,
                command=e.command,
                output_sha256=e.output_sha256,
                output_path=e.output_path,
                finding_id=f.finding_id,
                confidence=f.confidence,
            ))
        # One finding_emitted per Finding — links the claim to the
        # tool executions above via shared finding_id
        events.append(ExecutionEvent(
            ts_utc=ts,
            event_type="finding_emitted",
            case_id=case_id,
            agent=f.agent,
            finding_id=f.finding_id,
            confidence=f.confidence,
            fields={
                "claim": f.claim,
                "hypotheses_supported": list(f.hypotheses_supported),
                "hypotheses_refuted": list(f.hypotheses_refuted),
                "red_review_status": (f.red_review.status
                                       if f.red_review else ""),
                "evidence_count": len(f.evidence),
            },
        ))

    # Sort: ts_utc first, then a stable secondary key so repeat runs are
    # deterministic. tool_execution before finding_emitted for the same
    # ts (conceptually the tool fires first, then the finding is
    # emitted).
    _type_order = {
        "state_transition": 0, "investigator_selected": 1,
        "agent_start": 2, "tool_execution": 3,
        "finding_emitted": 4, "self_correction": 5,
        "agent_handoff": 6, "agent_done": 7,
    }
    events.sort(key=lambda e: (
        e.ts_utc,
        _type_order.get(e.event_type, 99),
        e.finding_id or "",
    ))
    return events


def write_jsonl(events: list[ExecutionEvent], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev.to_json_dict(),
                                separators=(",", ":")) + "\n")
    return out_path


def write_markdown(events: list[ExecutionEvent], out_path: Path,
                    case_id: str) -> Path:
    """Human-readable roll-up. Groups by state-machine phase, then
    by agent, with tool executions indented under each finding."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append(f"# Agent Execution Log — {case_id}")
    lines.append("")
    lines.append("_Chronological trace of coordinator state transitions, "
                 "agent invocations, tool executions, and emitted "
                 "Findings. Every tool_execution row is linked to the "
                 "Finding it produced via a shared finding_id, so any "
                 "claim can be traced back to the exact subprocess "
                 "that generated its supporting evidence._")
    lines.append("")

    summary = {
        "state_transition": 0, "agent_start": 0, "agent_done": 0,
        "tool_execution": 0, "finding_emitted": 0, "investigator_selected": 0,
        "agent_handoff": 0, "llm_call": 0, "self_correction": 0,
    }
    for ev in events:
        if ev.event_type in summary:
            summary[ev.event_type] += 1

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- State transitions: **{summary['state_transition']}**")
    lines.append(f"- Investigators selected: **{summary['investigator_selected']}**")
    lines.append(f"- Agent invocations: **{summary['agent_start']}**")
    lines.append(f"- Agent-to-agent handoffs: **{summary['agent_handoff']}**")
    lines.append(f"- Tool executions: **{summary['tool_execution']}**")
    lines.append(f"- LLM calls (token-metered): **{summary['llm_call']}**")
    lines.append(f"- Findings emitted: **{summary['finding_emitted']}**")
    lines.append(f"- Runtime self-corrections: **{summary['self_correction']}**")
    lines.append("")

    # Group events by (state, agent). We track the current state /
    # agent as we iterate so prose reads like a trace.
    current_state = "—"
    current_agent = "—"
    for ev in events:
        if ev.event_type == "state_transition":
            frm = ev.fields.get("from_", "?")
            to = ev.fields.get("to", "?")
            lines.append(f"### State: {frm} → **{to}**")
            lines.append(f"_{ev.ts_utc}_")
            lines.append("")
            current_state = to
            continue
        if ev.event_type == "investigator_selected":
            name = ev.fields.get("name", "?")
            kind = ev.fields.get("evidence_kind", "?")
            lines.append(f"- _{ev.ts_utc}_ · **investigator selected**: "
                          f"`{name}` (evidence_kind={kind})")
            continue
        if ev.event_type == "agent_start":
            lines.append(f"#### {ev.agent} — start  ·  _{ev.ts_utc}_")
            current_agent = ev.agent or "—"
            continue
        if ev.event_type == "agent_handoff":
            pub = ev.fields.get("published", "")
            lines.append(f"- _{ev.ts_utc}_ · **{ev.agent} → shared context**: "
                          f"published `{pub}`")
            continue
        if ev.event_type == "agent_done":
            n = ev.fields.get("findings_emitted", "?")
            lines.append(f"#### {ev.agent} — done ({n} finding(s))  ·  "
                          f"_{ev.ts_utc}_")
            lines.append("")
            continue
        if ev.event_type == "llm_call":
            comp = ev.fields.get("component", "?")
            model = ev.fields.get("model", "?")
            it = ev.fields.get("input_tokens", "?")
            ot = ev.fields.get("output_tokens", "?")
            lines.append(f"- _{ev.ts_utc}_ · **LLM call** ({comp}) `{model}` "
                          f"— tokens in={it} out={ot}")
            continue
        if ev.event_type == "tool_execution":
            sha = (ev.output_sha256 or "")[:16] + "…" if ev.output_sha256 else "—"
            lines.append(f"- _{ev.ts_utc}_ · tool `{ev.tool}`"
                          f"{' ' + ev.tool_version if ev.tool_version else ''}  "
                          f"→  finding [`{ev.finding_id}`] ({ev.confidence})")
            if ev.command:
                lines.append(f"    - cmd: `{ev.command[:200]}`")
            lines.append(f"    - sha256: `{sha}`  path: `{ev.output_path or ''}`")
            continue
        if ev.event_type == "finding_emitted":
            claim = ev.fields.get("claim", "")[:180]
            hs = ev.fields.get("hypotheses_supported") or []
            if isinstance(hs, str):
                try:
                    hs = json.loads(hs)
                except Exception:
                    hs = [hs]
            hs_txt = (", ".join(hs) if hs else "—")
            lines.append(f"- _{ev.ts_utc}_ · **finding** [`{ev.finding_id}`] "
                          f"({ev.confidence}) `{ev.agent}`: "
                          f"{claim}")
            if hs:
                lines.append(f"    - supports: {hs_txt}")
            lines.append("")
            continue
        if ev.event_type == "self_correction":
            mech = ev.fields.get("mechanism", "?")
            lines.append(f"- _{ev.ts_utc}_ · ⟳ **SELF-CORRECTION** "
                          f"(`{mech}`) by `{ev.fields.get('agent', ev.agent or '?')}`")
            for k in ("trigger", "detection", "correction", "outcome"):
                v = ev.fields.get(k)
                if v:
                    lines.append(f"    - {k}: {v}")
            continue
        # Other audit events — surface as a dim bullet so the trace is
        # complete even for intake_complete, etc.
        lines.append(f"- _{ev.ts_utc}_ · _{ev.event_type}_ "
                      f"{json.dumps(ev.fields) if ev.fields else ''}")

    out_path.write_text("\n".join(lines))
    return out_path


def write_traceability_matrix(events: list[ExecutionEvent],
                                out_path: Path, case_id: str) -> Path:
    """Flat table: one row per tool_execution. Columns judges need to
    walk from a claim back to the subprocess that produced its
    evidence."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append(f"# Traceability Matrix — {case_id}")
    lines.append("")
    lines.append("_Finding → tool → command → output sha256 → output path. "
                 "Required for the Find Evil submission: 'Judges must be "
                 "able to trace any finding back to the specific tool "
                 "execution that produced it.' Every row here is one "
                 "EvidenceItem attached to a Finding; the finding_id column "
                 "anchors the reverse-lookup._")
    lines.append("")
    lines.append("| finding_id | agent | conf | tool | command | output sha256 | output path |")
    lines.append("|---|---|---|---|---|---|---|")
    for ev in events:
        if ev.event_type != "tool_execution":
            continue
        cmd = (ev.command or "")[:100].replace("|", "\\|")
        sha = (ev.output_sha256 or "")[:16] + "…" if ev.output_sha256 else "—"
        path = (ev.output_path or "")[-70:]
        lines.append(
            f"| `{ev.finding_id}` | {ev.agent} | {ev.confidence} | "
            f"`{ev.tool}{' ' + ev.tool_version if ev.tool_version else ''}` | "
            f"`{cmd}` | `{sha}` | `{path}` |"
        )
    out_path.write_text("\n".join(lines))
    return out_path


def write_all(case_dir: str | Path) -> dict:
    """Entry point called by `el report`. Writes all three artefacts;
    returns {jsonl, md, traceability} as Path objects."""
    case_dir = Path(case_dir)
    reports = case_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    case_id = case_dir.name
    manifest = case_dir / "manifest.json"
    if manifest.is_file():
        try:
            case_id = json.loads(manifest.read_text()).get(
                "case_id", case_id)
        except Exception:
            pass
    events = build_events(case_dir)
    jsonl = write_jsonl(events, reports / "execution_log.jsonl")
    md = write_markdown(events, reports / "execution_log.md", case_id)
    tm = write_traceability_matrix(
        events, reports / "traceability_matrix.md", case_id)
    return {"jsonl": jsonl, "md": md, "traceability": tm,
            "event_count": len(events)}


__all__ = [
    "ExecutionEvent", "build_events",
    "write_jsonl", "write_markdown", "write_traceability_matrix",
    "write_all",
]

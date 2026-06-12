"""Self-correction recorder — capture genuine within-run auto-corrections.

EL self-corrects at runtime in several places: it commits to a first
interpretation or tool route, then *detects* that the route is wrong,
contradicted, or unreachable, corrects course, and continues. Examples that
already exist in the codebase, each wired to call ``record_self_correction``:

  * ``memory_truncated_acquisition_fallback`` — vol3 automagic builds no
    kernel layer; a raw-byte ntoskrnl banner scan confirms the input IS
    Windows memory but the DTB sits above a truncated capture, so triage
    re-routes the image to the carve pipeline instead of dead-ending
    (``el/agents/triage.py``).
  * ``memory_symbol_healing`` — ``windows.pslist`` returns 0 rows while
    ``windows.psscan`` finds processes (the symbol-degradation signature);
    a pslist retry after symbol recovery repopulates the list and re-enables
    the process-context plugins (``el/agents/memory_forensicator.py``).
  * ``paired_baseline_rescore`` — a zero-diff baseline comparison would
    normally lift the benign/null hypothesis, but on a *paired* capture a
    zero-diff means the baseline carries the same persistence, so EL tags
    ``H_NOT_CLEAN_BASELINE`` and the benign lift is suppressed
    (``el/agents/memory_forensicator.py``).
  * ``adversarial_review_downgrade`` — the Red Reviewer's challenger
    escalates a finding the system had emitted as actionable
    (``el/agents/red_reviewer.py``).

The point of this module is to make those corrections *first-class
recordable artifacts* — the before/after captured with a UTC timestamp —
rather than only implicit in the surrounding Findings. It is NOT a narrator:
it is only ever called from a code path that genuinely performed a
correction, so the record is grounded in real tool/observation state.

Output per case:
  ``<case_dir>/analysis/self_corrections.jsonl`` — one JSON object per
  correction (the authoritative structured store the CLI/report read).
And a compact ``event=self_correction`` line in the forensic audit log,
which ``el.reporting.execution_log`` lifts into
``reports/execution_log.jsonl`` automatically.

The recorder is deliberately decoupled from the coordinator: it
reconstructs an :class:`~el.audit.AuditLog` from the ``AgentContext`` so any
agent can call it without the coordinator threading an audit handle through
``AgentContext``. It is best-effort — a recorder failure must never abort an
investigation.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from el.audit import AuditLog

# Mechanism registry. Keys are stable identifiers that appear in
# execution_log.jsonl and the case report; each maps to ONE real runtime
# correction point in the code. Add a key here only when a new genuine
# correction site is wired — never as decoration.
MECHANISMS: dict[str, str] = {
    "memory_truncated_acquisition_fallback":
        "Memory truncated-acquisition fallback (vol3 no-kernel → carve)",
    "memory_symbol_healing":
        "Memory symbol healing (pslist retry repopulates process list)",
    "paired_baseline_rescore":
        "Paired-baseline re-score (clean-diff ≠ benign on a paired capture)",
    "adversarial_review_downgrade":
        "Adversarial-review downgrade (challenger escalated a finding)",
}

_FILENAME = "self_corrections.jsonl"


@dataclass
class SelfCorrection:
    """One genuine runtime self-correction: EL's before/after on a re-think."""

    utc: str                       # ISO-8601 UTC, seconds precision
    case_id: str
    agent: str                     # the agent that made the correction
    mechanism: str                 # a key of MECHANISMS
    trigger: str                   # the observation that forced a re-think
    initial_interpretation: str    # the path/claim EL was about to take
    detection: str                 # how EL noticed the first read was wrong
    correction: str                # what EL did instead
    outcome: str                   # what the corrected path yielded / continued
    evidence_sha256: str | None = None   # sha256 of the grounding tool output
    refs: list[str] = field(default_factory=list)   # finding_ids / paths

    def to_json(self) -> dict:
        return asdict(self)

    def mechanism_label(self) -> str:
        return MECHANISMS.get(self.mechanism, self.mechanism)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record_self_correction(
    ctx,
    agent: str,
    *,
    mechanism: str,
    trigger: str,
    initial: str,
    detection: str,
    correction: str,
    outcome: str,
    evidence_sha256: str | None = None,
    refs: list[str] | None = None,
) -> SelfCorrection | None:
    """Record one runtime self-correction for ``ctx``'s case.

    Best-effort: writes a JSONL row under ``analysis/`` and a compact
    ``event=self_correction`` audit line, and returns the record. Never
    raises into the caller — a recorder failure logs nothing and returns
    ``None`` rather than aborting the investigation.
    """
    sc = SelfCorrection(
        utc=_now_utc(),
        case_id=getattr(ctx, "case_id", "") or "",
        agent=agent,
        mechanism=mechanism,
        trigger=trigger,
        initial_interpretation=initial,
        detection=detection,
        correction=correction,
        outcome=outcome,
        evidence_sha256=evidence_sha256,
        refs=list(refs or []),
    )
    try:
        case_dir = Path(ctx.case_dir)
        out = case_dir / "analysis" / _FILENAME
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(sc.to_json(), separators=(",", ":")) + "\n")
        # Compact audit event → picked up by the execution-log builder and
        # surfaced in reports/execution_log.{jsonl,md}. Keep field values
        # short; the full record lives in self_corrections.jsonl.
        AuditLog(case_dir, sc.case_id).info(
            "self_correction",
            mechanism=mechanism,
            agent=agent,
            trigger=trigger,
            detection=detection,
            correction=correction,
            outcome=outcome,
            evidence_sha256=evidence_sha256,
        )
    except Exception:
        return None
    return sc


def load_self_corrections(case_dir: str | Path) -> list[SelfCorrection]:
    """Load all self-corrections for a case, sorted chronologically.

    Aggregates bundle device sub-cases: each device writes its own
    ``devices/<name>/analysis/self_corrections.jsonl``, so a bundle report
    sees every device's corrections in one stream.
    """
    case_dir = Path(case_dir)
    paths = [case_dir / "analysis" / _FILENAME]
    devices = case_dir / "devices"
    if devices.is_dir():
        paths += sorted(devices.glob(f"*/analysis/{_FILENAME}"))

    out: list[SelfCorrection] = []
    known = set(SelfCorrection.__dataclass_fields__)
    for p in paths:
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            # Tolerate schema drift: drop unknown keys, default missing ones.
            out.append(SelfCorrection(**{k: rec.get(k) for k in known
                                         if k != "refs"},
                                      refs=list(rec.get("refs") or [])))
    out.sort(key=lambda s: s.utc or "")
    return out

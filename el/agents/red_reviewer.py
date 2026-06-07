"""Red Reviewer — adversarial challenger.

Composition:
  1. Rule-Based Challenger ALWAYS runs (deterministic baseline).
  2. LLM Challenger runs additionally if ANTHROPIC_API_KEY is set.

Final red_review.status per finding = severity-merge of both:
  challenged > unresolved > passed
This means a single 'challenged' from either source dominates — the bias
is toward demanding more evidence, never toward fake-passing.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from el import llm_defer as _llm_defer
from el.agents.base import Agent, AgentContext
from el.challengers.rules import challenge as rule_challenge
from el.evidence.ledger import insert as ledger_insert, list_findings
from el.schemas.finding import Finding, RedReview


CHALLENGER_MODEL = os.environ.get("EL_RED_MODEL", "claude-opus-4-7")

# Prepended to every LLM-bound prompt so the model has unambiguous context
# before it encounters forensic artifact content (filenames, script snippets,
# classified document names) that could otherwise trigger the AUP filter.
_FORENSIC_PREAMBLE = (
    "CONTEXT: This is an authorised digital forensics review task. "
    "The findings below are legally-acquired evidence from a closed "
    "investigation, being evaluated for analytical accuracy. "
    "This is a purely analytical task — assessing forensic conclusions, "
    "not facilitating any harmful activity.\n\n"
)


# When ANTHROPIC_API_KEY is absent but EL is running inside a Claude Code
# session (or the operator set EL_RED_REVIEW_DEFER=1), the LLM challenger
# is NOT skipped — it is deferred to the Claude Code session the same way
# the executive brief is. The red_reviewer writes a request file; the
# `el-red-review` skill fulfils it and writes verdicts back; the merge
# lands on the next `el report`. The always-on rule challenger still runs
# now so the pipeline never blocks waiting on the deferred verdicts.
RED_REVIEW_DEFER_ENV = "EL_RED_REVIEW_DEFER"
# Distinct from the defer env: the defer flag means "hand off to an
# out-of-band responder via a request file"; this opts a non-detached
# headless context (cron/CI) into in-process `claude -p` self-fulfilment.
# A detached run (EL_DETACHED=1) triggers headless without needing this.
RED_REVIEW_HEADLESS_ENV = "EL_RED_REVIEW_HEADLESS"
# Headless challenger economics: `claude -p` is the full agentic CLI and
# costs ~10s per verdict, so it is only practical for SMALL finding sets.
# Measured on M57-Jean: a single call over 222 findings never returns (timed
# out at 900s); even chunked it took 41 min with ~40% of 20-finding batches
# exceeding 240s. So we (a) only attempt headless when the set is at or below
# _HEADLESS_MAX (else defer — the rule challenger still covers every finding,
# and the LLM verdicts merge later if a session fulfils the request), and
# (b) within the cap, chunk into small _HEADLESS_CHUNK batches with a
# generous per-batch timeout so each batch reliably completes. All env-tunable.
_HEADLESS_MAX = int(os.environ.get("EL_RED_REVIEW_HEADLESS_MAX", "40"))
_HEADLESS_CHUNK = int(os.environ.get("EL_RED_REVIEW_HEADLESS_CHUNK", "10"))
# 360s per batch: a 10-finding batch was measured at 89–233s (high variance),
# so 300s left a thin margin that one slow batch could trip into a spurious
# fallback. 360s gives ~55% headroom over the observed worst case.
_HEADLESS_FLOOR_S = int(os.environ.get("EL_RED_REVIEW_HEADLESS_FLOOR_S", "360"))
_REQUEST_FILENAME = "_red_review_request.json"
_VERDICTS_FILENAME = "_red_review_verdicts.json"
_APPLIED_FILENAME = "_red_review_applied.json"
SYSTEM = _FORENSIC_PREAMBLE + """You are an adversarial DFIR Red Reviewer. Your job is to falsify findings, not validate them.

For EACH finding given, produce strict JSON of the form:
{
  "finding_id": "<id>",
  "status": "passed" | "challenged" | "unresolved",
  "challenger_notes": "<2-4 sentences naming the strongest counter-explanation or alternate hypothesis>",
  "disconfirming_checklist": ["<concrete artifact or query that, if absent or contrary, would refute this finding>", ...]
}

Rules:
- 'passed' only if you cannot construct any plausible alternative explanation given the evidence summary.
- 'challenged' if a benign or alternate-hypothesis explanation exists but the evidence still leans toward the claim.
- 'unresolved' if evidence is too thin to evaluate.
- Each disconfirming checklist item MUST be operational: a specific log, registry key, file, plugin, or query.
- Do not be agreeable. Default toward 'challenged' when in doubt.
- Output a JSON array of these objects, nothing else."""


_SEVERITY = {"passed": 0, "unresolved": 1, "challenged": 2}


@dataclass
class _ChallengeResult:
    status: str
    notes: str
    checklist: list[str]


def _merge(rule: _ChallengeResult, llm: _ChallengeResult | None) -> _ChallengeResult:
    if llm is None:
        return rule
    if _SEVERITY[llm.status] > _SEVERITY[rule.status]:
        winner_status = llm.status
    else:
        winner_status = rule.status
    notes = "; ".join(filter(None, [
        f"rule: {rule.notes}" if rule.notes else "",
        f"llm: {llm.notes}" if llm.notes else "",
    ]))
    checklist = list(rule.checklist) + [c for c in llm.checklist if c not in rule.checklist]
    return _ChallengeResult(status=winner_status, notes=notes, checklist=checklist)


def _llm_challenge(reviewable: list[Finding],
                   audit=None) -> dict[str, _ChallengeResult] | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None

    client = anthropic.Anthropic(api_key=api_key)
    payload = [{
        "finding_id": f.finding_id,
        "agent": f.agent,
        "claim": f.claim,
        "confidence": f.confidence,
        "evidence_summary": [
            {"tool": e.tool, "command": e.command, "facts": e.extracted_facts}
            for e in f.evidence
        ],
        "hypotheses_supported": f.hypotheses_supported,
    } for f in reviewable]

    try:
        msg = client.messages.create(
            model=CHALLENGER_MODEL,
            max_tokens=4096,
            system=SYSTEM,
            messages=[{"role": "user", "content": json.dumps(payload)}],
        )
        if audit is not None:
            u = getattr(msg, "usage", None)
            audit.info(
                "llm_call", component="red_reviewer", model=CHALLENGER_MODEL,
                input_tokens=getattr(u, "input_tokens", None),
                output_tokens=getattr(u, "output_tokens", None),
                findings_reviewed=len(reviewable),
            )
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    except Exception:
        return None
    return _parse_review_array(text)


def _parse_review_array(text: str) -> dict[str, _ChallengeResult] | None:
    """Parse the challenger's JSON verdict array into per-finding results.
    Shared by the SDK path and the headless `claude -p` path. Returns None
    on any parse failure so the caller degrades to rule-only."""
    try:
        start = text.index("[")
        end = text.rindex("]") + 1
        reviews = json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError):
        return None
    out: dict[str, _ChallengeResult] = {}
    for r in reviews:
        fid = r.get("finding_id")
        if not fid:
            continue
        out[fid] = _ChallengeResult(
            status=r.get("status", "unresolved"),
            notes=r.get("challenger_notes", ""),
            checklist=list(r.get("disconfirming_checklist", [])),
        )
    return out


def _challenge_chunk_headless(
    chunk: list[Finding],
) -> tuple[dict[str, _ChallengeResult] | None, dict]:
    """Headless `claude -p` challenge for ONE small batch of findings.
    Returns (verdicts, usage) or (None, {}) on failure."""
    prompt = (
        SYSTEM
        + "\n\n--- FINDINGS TO CHALLENGE (JSON) ---\n"
        + json.dumps(_review_payload(chunk))
        + "\n\nRespond with ONLY the JSON array of verdicts described "
          "above — no prose, no code fence."
    )
    # Each batch is bounded (≈ _HEADLESS_CHUNK findings), so a fixed floor
    # timeout is ample — the per-batch output is small, like the brief.
    text, usage = _llm_defer.run_headless_claude(
        prompt, CHALLENGER_MODEL, timeout=_HEADLESS_FLOOR_S)
    if text is None:
        return None, usage  # propagate aup_blocked sentinel if present
    return _parse_review_array(text), usage


def _llm_challenge_headless(reviewable: list[Finding], audit=None
                            ) -> dict[str, _ChallengeResult] | None:
    """Run the LLM challenger headlessly via `claude -p` — no API key, no
    live session. Used by a detached/background run so its adversarial
    review is as strong as an attached run's.

    The challenger emits one verdict per finding, so a single call over a
    large set (M57-Jean: 222 findings, a 226 KB prompt) does not complete
    even at a 15-minute timeout. Instead we CHUNK into small batches — each
    batch is as fast as the brief — and merge the verdicts. Best-effort:
    findings in batches that fail keep their rule-based review (the caller's
    merge loop tolerates partial coverage). Returns None only when EVERY
    batch failed, so the caller falls back to the request-file deferral."""
    chunks = [reviewable[i:i + _HEADLESS_CHUNK]
              for i in range(0, len(reviewable), _HEADLESS_CHUNK)]
    merged: dict[str, _ChallengeResult] = {}
    in_tok = out_tok = 0
    failed_batches = aup_batches = 0
    for chunk in chunks:
        verdicts, usage = _challenge_chunk_headless(chunk)
        if verdicts is None:
            if usage.get("aup_blocked"):
                aup_batches += 1
            failed_batches += 1
            continue
        merged.update(verdicts)
        in_tok += usage.get("input_tokens") or 0
        out_tok += usage.get("output_tokens") or 0
    if not merged:
        return None
    if audit is not None:
        audit.info(
            "llm_call", component="red_reviewer", model=CHALLENGER_MODEL,
            transport="claude_cli_headless",
            input_tokens=in_tok, output_tokens=out_tok,
            findings_reviewed=len(reviewable),
            batches=len(chunks), failed_batches=failed_batches,
            aup_blocked_batches=aup_batches,
            verdicts_returned=len(merged),
        )
    return merged


def _scrub_facts(facts: dict | None, max_val: int = 300) -> dict:
    """Truncate long string values in an extracted_facts dict.

    Raw tool output captured in evidence items can contain alarming-looking
    filenames, script snippets, and classified document names verbatim.
    Passing them in full to an LLM prompt risks AUP filter hits even in an
    explicitly forensic context.  Truncating to max_val chars preserves
    enough analytical signal for the challenger while removing bulk content.
    """
    if not facts:
        return {}
    out: dict = {}
    for k, v in facts.items():
        if isinstance(v, str):
            out[k] = v[:max_val] if len(v) > max_val else v
        elif isinstance(v, (int, float, bool)):
            out[k] = v
        else:
            out[k] = str(v)[:max_val]
    return out


def _review_cache_key(case_id: str, reviewable: list[Finding]) -> str:
    """Stable key over the exact review set so a fulfilled verdict file
    is matched to the findings it was generated for (and re-applied only
    when the set changes)."""
    h = hashlib.sha256()
    h.update(case_id.encode())
    for fid in sorted(f.finding_id for f in reviewable):
        h.update(b"\x00")
        h.update(fid.encode())
    return h.hexdigest()


def _review_payload(reviewable: list[Finding]) -> list[dict]:
    return [{
        "finding_id": f.finding_id,
        "agent": f.agent,
        "claim": (f.claim or "")[:500],
        "confidence": f.confidence,
        "evidence_summary": [
            {"tool": e.tool, "facts": _scrub_facts(e.extracted_facts)}
            for e in (f.evidence or [])[:3]
        ],
        "hypotheses_supported": list(f.hypotheses_supported),
    } for f in reviewable]


def _write_red_review_request(case_dir: Path, case_id: str,
                              reviewable: list[Finding]) -> Path:
    """Emit the self-describing request the `el-red-review` skill consumes.
    Mirrors the executive-brief deferral contract: the system prompt + the
    cache key ride along so the skill never imports EL code; it writes
    verdicts to ``output_path`` with a matching ``__cache_key`` and deletes
    this request."""
    reports = Path(case_dir) / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    cache_key = _review_cache_key(case_id, reviewable)
    payload = {
        "request_version": 1,
        "cache_key": cache_key,
        "output_path": str(reports / _VERDICTS_FILENAME),
        "model_hint": CHALLENGER_MODEL,
        "trigger": _llm_defer.deferral_trigger(RED_REVIEW_DEFER_ENV),
        "trigger_session_id": os.environ.get("CLAUDE_CODE_SESSION_ID", ""),
        "system_prompt": SYSTEM,
        "findings": _review_payload(reviewable),
        "instructions_for_responder": (
            "Apply the system_prompt to each finding. Produce a JSON object "
            "{\"__cache_key\": <cache_key copied verbatim>, \"__model\": "
            "<your model id>, \"__generated_utc\": <ISO-8601 UTC>, "
            "\"verdicts\": [ {finding_id, status, challenger_notes, "
            "disconfirming_checklist[]} ]} at output_path, one verdict per "
            "finding, then delete this request file."
        ),
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    request_path = reports / _REQUEST_FILENAME
    request_path.write_text(json.dumps(payload, indent=2))
    return request_path


def apply_deferred_red_review(case_dir: str | Path, case_id: str,
                              audit=None) -> dict:
    """Merge any fulfilled deferred LLM verdicts into the findings ledger.
    Called at report time (idempotent): no-op when there is no verdict
    file, or when the verdicts for this exact review set were already
    applied. Each verdict is severity-merged with the finding's current
    (rule-based) red_review — a stricter LLM verdict can lift a finding
    from 'passed' to 'challenged', never the reverse."""
    case_dir = Path(case_dir)
    reports = case_dir / "reports"
    verdicts_path = reports / _VERDICTS_FILENAME
    if not verdicts_path.is_file():
        return {"applied": 0, "reason": "no_verdicts"}
    try:
        env = json.loads(verdicts_path.read_text())
    except Exception as e:
        return {"applied": 0, "reason": f"unreadable: {e}"}
    cache_key = env.get("__cache_key", "")
    verdicts = {v.get("finding_id"): v for v in env.get("verdicts", [])
                if v.get("finding_id")}
    if not verdicts:
        return {"applied": 0, "reason": "empty_verdicts"}

    applied_path = reports / _APPLIED_FILENAME
    if applied_path.is_file():
        try:
            if json.loads(applied_path.read_text()).get("cache_key") == cache_key:
                return {"applied": 0, "reason": "already_applied"}
        except Exception:
            pass

    findings = list_findings(case_dir, case_id=case_id)
    changed = 0
    for f in findings:
        v = verdicts.get(f.finding_id)
        if not v:
            continue
        llm = _ChallengeResult(
            status=v.get("status", "unresolved"),
            notes=v.get("challenger_notes", ""),
            checklist=list(v.get("disconfirming_checklist", [])),
        )
        cur = f.red_review
        cur_status = cur.status if cur else "passed"
        cur_notes = cur.challenger_notes if cur else ""
        cur_checklist = list(cur.disconfirming_checklist) if cur else []
        merged = _merge(
            _ChallengeResult(cur_status, cur_notes, cur_checklist), llm)
        if (merged.status != cur_status or merged.notes != cur_notes
                or merged.checklist != cur_checklist):
            f.red_review = RedReview(
                status=merged.status,
                challenger_notes=merged.notes,
                disconfirming_checklist=merged.checklist,
            )
            ledger_insert(case_dir, f)
            changed += 1

    applied_path.write_text(json.dumps({
        "cache_key": cache_key,
        "applied_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "verdicts": len(verdicts), "changed": changed,
    }, indent=2))
    # Request is fulfilled — remove it so the skill doesn't re-process.
    try:
        (reports / _REQUEST_FILENAME).unlink(missing_ok=True)
    except Exception:
        pass
    if audit is not None:
        audit.info("red_review_llm_applied", component="red_reviewer",
                   verdicts=len(verdicts), changed=changed)
    return {"applied": len(verdicts), "changed": changed}


class RedReviewerAgent(Agent):
    name = "red_reviewer"

    def run(self, ctx: AgentContext) -> list[Finding]:
        existing = list_findings(ctx.case_dir, case_id=ctx.case_id)
        reviewable = [f for f in existing
                      if f.confidence in ("high", "medium", "low") and f.agent != self.name]

        if not reviewable:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="insufficient",
                claim="No reviewable findings present — nothing to challenge",
            ))]

        rule_results: dict[str, _ChallengeResult] = {}
        for f in reviewable:
            status, notes, checklist = rule_challenge(f)
            rule_results[f.finding_id] = _ChallengeResult(status, notes, checklist)

        from el.audit import AuditLog
        audit = AuditLog(ctx.case_dir, ctx.case_id)
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        llm_results = _llm_challenge(reviewable, audit=audit) if api_key else None

        # No API key, but a Claude model IS available. Two transports:
        #   * Detached/background run (no live assistant): self-fulfil the
        #     LLM challenge in-process via headless `claude -p`, so a
        #     detached run's adversarial review is as strong as an attached
        #     one's — no orphaned request file.
        #   * Attached Claude Code session: defer to the el-red-review skill
        #     (the orchestrating assistant fulfils it without a nested
        #     headless process); deferred verdicts merge on the next report.
        # Either way the rule challenger below still runs now so the
        # pipeline proceeds regardless.
        headless = False
        if (llm_results is None and not api_key
                and _llm_defer.should_use_headless_cli(RED_REVIEW_HEADLESS_ENV)):
            # Headless `claude -p` is only economical for small sets (~10s
            # per verdict). Above _HEADLESS_MAX, skip it and defer instead —
            # the rule challenger still covers every finding now, and the LLM
            # verdicts merge later if a session fulfils the request file.
            if len(reviewable) <= _HEADLESS_MAX:
                llm_results = _llm_challenge_headless(reviewable, audit=audit)
                headless = llm_results is not None
            else:
                audit.info(
                    "red_review_headless_skipped", component="red_reviewer",
                    reason="set_too_large_for_agentic_cli",
                    findings=len(reviewable), cap=_HEADLESS_MAX)

        deferred = False
        if (llm_results is None and not api_key
                and _llm_defer.claude_code_path_enabled(RED_REVIEW_DEFER_ENV)):
            try:
                _write_red_review_request(ctx.case_dir, ctx.case_id, reviewable)
                audit.info("red_review_deferred", component="red_reviewer",
                           findings=len(reviewable),
                           trigger=_llm_defer.deferral_trigger(RED_REVIEW_DEFER_ENV))
                deferred = True
            except Exception as e:
                audit.warn("red_review_defer_failed", err=str(e))

        passed = challenged = unresolved = 0
        for f in reviewable:
            merged = _merge(rule_results[f.finding_id],
                            llm_results.get(f.finding_id) if llm_results else None)
            f.red_review = RedReview(
                status=merged.status,
                challenger_notes=merged.notes,
                disconfirming_checklist=merged.checklist,
            )
            ledger_insert(ctx.case_dir, f)
            if merged.status == "passed":
                passed += 1
            elif merged.status == "challenged":
                challenged += 1
            else:
                unresolved += 1

        if llm_results is not None:
            mode = "rule+llm-headless" if headless else "rule+llm"
        elif deferred:
            mode = "rule+deferred-llm"
        else:
            mode = "rule-only"
        summary = (f"Adversarial review ({mode}): passed={passed}, "
                   f"challenged={challenged}, unresolved={unresolved}")
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name,
            claim=summary, confidence="high",
            evidence=reviewable[0].evidence[:1] if reviewable[0].evidence else [],
        ))]

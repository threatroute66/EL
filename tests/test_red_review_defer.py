"""Red Reviewer Claude Code deferral — when ANTHROPIC_API_KEY is absent
but EL runs inside a Claude Code session, the LLM challenger is deferred
(request file written, fulfilled out-of-band by the el-red-review skill,
verdicts merged at report time) rather than silently skipped.

Mirrors the executive-brief deferral contract in executive_ai.py."""
import json
from pathlib import Path

from el.agents.base import AgentContext
from el.agents.red_reviewer import (
    RedReviewerAgent, apply_deferred_red_review,
    _REQUEST_FILENAME, _VERDICTS_FILENAME, _APPLIED_FILENAME,
)
from el.evidence import intake as intake_mod
from el.evidence.ledger import insert as ledger_insert, list_findings
from el.schemas.finding import EvidenceItem, Finding


def _mk_case(tmp_path, monkeypatch, case_id="rr-defer-t"):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "evidence.bin"
    src.write_bytes(b"evidence\n")
    m = intake_mod.intake(src, case_id=case_id)
    return Path(m.case_dir)


def _seed_reviewable(case_dir, case_id):
    f = Finding(
        case_id=case_id, agent="disk_forensicator",
        claim="Executable in user Temp directory — dropper pattern",
        confidence="high",
        evidence=[EvidenceItem(
            tool="sleuthkit/fls", version="4.12", command="fls -r image.E01",
            output_sha256="0" * 64, output_path="/tmp/fls.txt")],
        hypotheses_supported=["H_OPPORTUNISTIC_COMMODITY"],
    )
    ledger_insert(case_dir, f)
    return f


def _no_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("EL_RED_REVIEW_DEFER", raising=False)
    monkeypatch.delenv("AI_AGENT", raising=False)
    monkeypatch.delenv("CLAUDECODE", raising=False)


# ---------------------------------------------------------------------------

def test_defer_writes_request_inside_claude_code(tmp_path, monkeypatch):
    case_dir = _mk_case(tmp_path, monkeypatch)
    _seed_reviewable(case_dir, "rr-defer-t")
    _no_key(monkeypatch)
    monkeypatch.setenv("CLAUDECODE", "1")

    ctx = AgentContext(case_id="rr-defer-t", case_dir=case_dir,
                       input_path=case_dir, manifest={})
    out = RedReviewerAgent().run(ctx)

    # Pipeline still produced its summary finding (rule challenger ran now)
    assert out and out[0].agent == "red_reviewer"
    assert "deferred-llm" in out[0].claim

    # Request file written with the contract the el-red-review skill needs
    req = case_dir / "reports" / _REQUEST_FILENAME
    assert req.is_file()
    payload = json.loads(req.read_text())
    assert payload["cache_key"]
    assert payload["system_prompt"]
    assert payload["trigger"] == "claude_code_session"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["claim"].startswith("Executable in user Temp")

    # The reviewed finding still got a (rule-based) red_review now — not blocked
    fs = list_findings(case_dir, case_id="rr-defer-t")
    reviewed = [f for f in fs if f.agent == "disk_forensicator"][0]
    assert reviewed.red_review.status in ("passed", "challenged", "unresolved")


def test_no_defer_when_not_in_claude_code(tmp_path, monkeypatch):
    case_dir = _mk_case(tmp_path, monkeypatch, case_id="rr-nodefer-t")
    _seed_reviewable(case_dir, "rr-nodefer-t")
    _no_key(monkeypatch)  # no key, no CLAUDECODE, no defer flag

    ctx = AgentContext(case_id="rr-nodefer-t", case_dir=case_dir,
                       input_path=case_dir, manifest={})
    out = RedReviewerAgent().run(ctx)

    assert "rule-only" in out[0].claim
    assert not (case_dir / "reports" / _REQUEST_FILENAME).exists()


def test_explicit_defer_flag_writes_request(tmp_path, monkeypatch):
    case_dir = _mk_case(tmp_path, monkeypatch, case_id="rr-flag-t")
    _seed_reviewable(case_dir, "rr-flag-t")
    _no_key(monkeypatch)
    monkeypatch.setenv("EL_RED_REVIEW_DEFER", "1")

    ctx = AgentContext(case_id="rr-flag-t", case_dir=case_dir,
                       input_path=case_dir, manifest={})
    RedReviewerAgent().run(ctx)
    req = case_dir / "reports" / _REQUEST_FILENAME
    assert req.is_file()
    assert json.loads(req.read_text())["trigger"] == "explicit_defer_flag"


def test_apply_merges_and_is_idempotent(tmp_path, monkeypatch):
    case_dir = _mk_case(tmp_path, monkeypatch, case_id="rr-apply-t")
    _seed_reviewable(case_dir, "rr-apply-t")
    _no_key(monkeypatch)
    monkeypatch.setenv("CLAUDECODE", "1")

    ctx = AgentContext(case_id="rr-apply-t", case_dir=case_dir,
                       input_path=case_dir, manifest={})
    RedReviewerAgent().run(ctx)
    req = json.loads((case_dir / "reports" / _REQUEST_FILENAME).read_text())

    # Simulate the el-red-review skill fulfilling the request: a stricter
    # 'challenged' verdict for the seeded finding.
    fid = req["findings"][0]["finding_id"]
    (case_dir / "reports" / _VERDICTS_FILENAME).write_text(json.dumps({
        "__cache_key": req["cache_key"],
        "__model": "claude-opus-4-8",
        "__generated_utc": "2026-05-31T00:00:00+00:00",
        "verdicts": [{
            "finding_id": fid, "status": "challenged",
            "challenger_notes": "A scheduled-install or admin action could explain a binary in Temp.",
            "disconfirming_checklist": ["Prefetch entry for the binary", "Amcache first-run timestamp"],
        }],
    }))

    res = apply_deferred_red_review(case_dir, "rr-apply-t")
    assert res["applied"] == 1 and res["changed"] == 1

    fs = list_findings(case_dir, case_id="rr-apply-t")
    reviewed = [f for f in fs if f.finding_id == fid][0]
    assert reviewed.red_review.status == "challenged"
    assert "scheduled-install" in reviewed.red_review.challenger_notes
    assert "Prefetch entry for the binary" in reviewed.red_review.disconfirming_checklist

    # Applied marker written; request consumed
    assert (case_dir / "reports" / _APPLIED_FILENAME).is_file()
    assert not (case_dir / "reports" / _REQUEST_FILENAME).exists()

    # Idempotent: second apply is a no-op for the same cache_key
    res2 = apply_deferred_red_review(case_dir, "rr-apply-t")
    assert res2["applied"] == 0 and res2["reason"] == "already_applied"


def test_apply_noop_without_verdicts(tmp_path, monkeypatch):
    case_dir = _mk_case(tmp_path, monkeypatch, case_id="rr-empty-t")
    res = apply_deferred_red_review(case_dir, "rr-empty-t")
    assert res["applied"] == 0 and res["reason"] == "no_verdicts"

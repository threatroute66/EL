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


# ---------------------------------------------------------------------------
# Headless self-fulfilment — a detached run runs the LLM challenger in-process
# via `claude -p` instead of orphaning a request file.
# ---------------------------------------------------------------------------

def _stub_headless(monkeypatch, verdicts):
    """Stub el.llm_defer's headless backend to return `verdicts` (a list of
    per-finding verdict dicts) wrapped in the `claude -p --output-format json`
    envelope. Returns the recorded calls list."""
    from el import llm_defer as ld
    calls = []
    envelope = json.dumps({"is_error": False,
                           "result": json.dumps(verdicts),
                           "usage": {"input_tokens": 50, "output_tokens": 20}})

    class _Proc:
        returncode = 0
        stdout = envelope
        stderr = ""

    def _fake(argv, input=None, **kw):
        calls.append({"argv": argv, "input": input})
        return _Proc()

    monkeypatch.setattr(ld, "headless_cli_path", lambda: "/fake/bin/claude")
    monkeypatch.setattr(ld.subprocess, "run", _fake)
    return calls


def test_detached_run_self_fulfils_red_review_headless(tmp_path, monkeypatch):
    case_dir = _mk_case(tmp_path, monkeypatch, case_id="rr-headless-t")
    f = _seed_reviewable(case_dir, "rr-headless-t")
    _no_key(monkeypatch)
    monkeypatch.setenv("EL_DETACHED", "1")
    monkeypatch.setenv("CLAUDECODE", "1")   # rides along in the unit env
    calls = _stub_headless(monkeypatch, [{
        "finding_id": f.finding_id,
        "status": "challenged",
        "challenger_notes": "Temp-dir executables are common for installers.",
        "disconfirming_checklist": ["Check digital signature", "Check parent process"],
    }])

    ctx = AgentContext(case_id="rr-headless-t", case_dir=case_dir,
                       input_path=case_dir, manifest={})
    out = RedReviewerAgent().run(ctx)

    # LLM challenger ran in-process — mode reflects the headless transport
    assert out and "rule+llm-headless" in out[0].claim
    # No orphaned request file (self-fulfilled, not deferred)
    assert not (case_dir / "reports" / _REQUEST_FILENAME).exists()
    # The headless CLI was actually invoked
    assert len(calls) == 1
    # The LLM verdict merged into the finding's red_review
    reviewed = [x for x in list_findings(case_dir, case_id="rr-headless-t")
                if x.agent == "disk_forensicator"][0]
    assert reviewed.red_review.status in ("challenged", "unresolved")


def test_headless_failure_falls_back_to_red_review_request(tmp_path, monkeypatch):
    """If the headless challenger fails, the run falls back to the
    request-file deferral — the LLM review is transported, never skipped."""
    from el import llm_defer as ld
    case_dir = _mk_case(tmp_path, monkeypatch, case_id="rr-hfail-t")
    _seed_reviewable(case_dir, "rr-hfail-t")
    _no_key(monkeypatch)
    monkeypatch.setenv("EL_DETACHED", "1")
    monkeypatch.setenv("CLAUDECODE", "1")

    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "boom"

    monkeypatch.setattr(ld, "headless_cli_path", lambda: "/fake/bin/claude")
    monkeypatch.setattr(ld.subprocess, "run", lambda *a, **k: _Proc())

    ctx = AgentContext(case_id="rr-hfail-t", case_dir=case_dir,
                       input_path=case_dir, manifest={})
    out = RedReviewerAgent().run(ctx)

    assert out and "deferred-llm" in out[0].claim
    assert (case_dir / "reports" / _REQUEST_FILENAME).is_file()


def _mk_findings(n):
    return [Finding(case_id="t", agent="a", claim=f"c{i}",
                    confidence="high",
                    evidence=[EvidenceItem(tool="x", version="1",
                              command="x", output_sha256="0"*64,
                              output_path="/tmp/x")])
            for i in range(n)]


def test_headless_chunks_large_finding_sets(monkeypatch):
    """A single call over a large set never completes (M57-Jean's 222
    findings timed out even at 900s), so the headless challenger batches
    into _HEADLESS_CHUNK-sized calls and merges. Verify a 222-finding set
    is split into ceil(222/chunk) bounded calls, each at the per-batch
    floor timeout, and every verdict is merged back."""
    from el.agents import red_reviewer as rr
    import math

    batch_sizes = []
    timeouts = []

    def _fake_run_headless(prompt, model, timeout=None):
        timeouts.append(timeout)
        # Echo back one verdict per finding_id embedded in the prompt
        import json as _json
        payload = _json.loads(prompt.split("--- FINDINGS TO CHALLENGE (JSON) ---\n", 1)[1]
                              .rsplit("\n\nRespond", 1)[0])
        batch_sizes.append(len(payload))
        verdicts = [{"finding_id": f["finding_id"], "status": "passed",
                     "challenger_notes": "ok", "disconfirming_checklist": []}
                    for f in payload]
        return _json.dumps(verdicts), {"input_tokens": 1, "output_tokens": 1}

    monkeypatch.setattr(rr._llm_defer, "run_headless_claude", _fake_run_headless)

    findings = _mk_findings(222)
    result = rr._llm_challenge_headless(findings)

    chunk = rr._HEADLESS_CHUNK
    assert len(batch_sizes) == math.ceil(222 / chunk)       # chunked, not one call
    assert max(batch_sizes) <= chunk                         # every batch bounded
    assert sum(batch_sizes) == 222
    assert all(t == rr._HEADLESS_FLOOR_S for t in timeouts)  # per-batch floor timeout
    assert result is not None and len(result) == 222         # all verdicts merged


def test_headless_partial_batch_failure_keeps_coverage(monkeypatch):
    """If some batches fail, the successful ones still merge (the caller's
    merge loop tolerates partial coverage) — only an all-batches-fail set
    returns None to trigger the request-file fallback."""
    from el.agents import red_reviewer as rr
    import json as _json

    calls = {"n": 0}

    def _fake_run_headless(prompt, model, timeout=None):
        calls["n"] += 1
        if calls["n"] == 2:                 # second batch fails
            return None, {}
        payload = _json.loads(prompt.split("--- FINDINGS TO CHALLENGE (JSON) ---\n", 1)[1]
                              .rsplit("\n\nRespond", 1)[0])
        verdicts = [{"finding_id": f["finding_id"], "status": "challenged",
                     "challenger_notes": "n", "disconfirming_checklist": []}
                    for f in payload]
        return _json.dumps(verdicts), {}

    monkeypatch.setattr(rr._llm_defer, "run_headless_claude", _fake_run_headless)

    findings = _mk_findings(rr._HEADLESS_CHUNK * 3)   # exactly 3 batches
    result = rr._llm_challenge_headless(findings)
    assert result is not None
    # 2 of 3 batches succeeded → partial coverage, not None
    assert len(result) == rr._HEADLESS_CHUNK * 2


def test_headless_all_batches_fail_returns_none(monkeypatch):
    from el.agents import red_reviewer as rr
    monkeypatch.setattr(rr._llm_defer, "run_headless_claude",
                        lambda *a, **k: (None, {}))
    assert rr._llm_challenge_headless(_mk_findings(50)) is None

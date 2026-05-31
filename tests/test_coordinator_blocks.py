"""Coordinator contract tests.

Under the rule+llm challenger composition, the coordinator should:
  - Reach DONE on synthetic inputs without an API key (rule challenger
    runs successfully and surfaces challenges in the report).
  - Never advance through SYNTHESIZE while there are unresolved findings.
  - Mark every reviewable finding with a non-default red_review status —
    'pending' must never appear post-review on a reviewable finding.
"""
from pathlib import Path

import pytest

from el.evidence import intake as intake_mod
from el.evidence.ledger import list_findings
from el.orchestrator.coordinator import Coordinator
from el.orchestrator.states import State


@pytest.fixture
def isolated_cases(tmp_path, monkeypatch):
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    yield tmp_path


def test_completes_with_rule_challenger_when_no_api_key(isolated_cases, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Pin the environment to the pure rule-only path: no key AND no Claude
    # Code deferral. (Inside a Claude Code session — CLAUDECODE=1 — the
    # red_reviewer instead defers the LLM challenger; that path is covered
    # in tests/test_red_review_defer.py. Here we assert the no-key,
    # no-deferral baseline so the test is deterministic regardless of where
    # pytest runs.)
    monkeypatch.delenv("CLAUDECODE", raising=False)
    monkeypatch.delenv("AI_AGENT", raising=False)
    monkeypatch.delenv("EL_RED_REVIEW_DEFER", raising=False)
    src = isolated_cases / "fake.bin"
    src.write_bytes(b"not a real memory image")

    result = Coordinator().investigate(src, case_id="t-rule-only")

    assert result.final_state == State.DONE
    rows = list_findings(Path(result.case_dir), case_id="t-rule-only")
    reviewable = [f for f in rows if f.confidence in ("high", "medium", "low") and f.agent != "red_reviewer"]
    assert reviewable, "expected at least one reviewable finding"
    for f in reviewable:
        assert f.red_review.status in ("passed", "challenged"), \
            f"reviewable finding {f.finding_id} left at {f.red_review.status}"
        if f.red_review.status == "challenged":
            assert f.red_review.disconfirming_checklist, "challenged finding must include checklist"

    summary = next(f for f in rows if f.agent == "red_reviewer")
    assert "rule-only" in summary.claim


def test_defers_llm_challenger_inside_claude_code_when_no_api_key(isolated_cases, monkeypatch):
    """Inside a Claude Code session with no API key, the coordinator still
    reaches DONE, but the red_reviewer defers the LLM challenger (writes a
    request file) instead of skipping it silently."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("EL_RED_REVIEW_DEFER", raising=False)
    monkeypatch.setenv("CLAUDECODE", "1")
    src = isolated_cases / "fake.bin"
    src.write_bytes(b"not a real memory image")

    result = Coordinator().investigate(src, case_id="t-defer")
    assert result.final_state == State.DONE
    rows = list_findings(Path(result.case_dir), case_id="t-defer")
    summary = next(f for f in rows if f.agent == "red_reviewer")
    assert "deferred-llm" in summary.claim
    # The request file the el-red-review skill consumes was written.
    assert (Path(result.case_dir) / "reports" / "_red_review_request.json").is_file()

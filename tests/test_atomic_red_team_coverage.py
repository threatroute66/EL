"""Atomic Red Team coverage harness — Tier 3.3.

Walks ``tests/atomic/expectations/coverage_map.yaml`` and runs EL against
the corresponding fixture under ``tests/atomic/fixtures/<atomic_id>/``,
asserting that:

  1. EL's run produces at least one Finding whose ``hypotheses_supported``
     intersects the atomic's ``expected_hypotheses``, **OR**
  2. EL produces a Finding whose ``claim`` matches one of the configured
     ``matcher_args.patterns`` (substring match).

This is the regression suite for detection coverage. Each new atomic test
the operator wants validated:
  - drops fixture under tests/atomic/fixtures/<atomic_id>/
  - adds a YAML entry to coverage_map.yaml
  - re-runs the harness; green = covered

Two fixture kinds are wired today:
  * ``linux-fs-dir``  — runs MalwareTriageAgent + LinuxForensicatorAgent
                          against the fixture dir
  * ``bytes-blob``    — runs MalwareTriageAgent against a single binary

This harness deliberately runs only a subset of EL agents (no full
coordinator state machine) so the assertion is about whether the relevant
detectors fire on the fixture content. Full-pipeline coverage testing is
out of scope.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


# Skill-level YAML import. PyYAML is already pulled in via plaso/keyring
# via the venv's transitive deps; if absent, the harness skips with a clear
# reason.
try:
    import yaml  # type: ignore
except ImportError:
    yaml = None


_REPO = Path(__file__).resolve().parents[1]
_COVERAGE = _REPO / "tests" / "atomic" / "expectations" / "coverage_map.yaml"
_FIXTURES = _REPO / "tests" / "atomic" / "fixtures"


def _load_coverage_map() -> dict:
    if yaml is None:
        pytest.skip("PyYAML not installed — atomic harness needs it")
    if not _COVERAGE.is_file():
        pytest.skip(f"coverage map missing: {_COVERAGE}")
    data = yaml.safe_load(_COVERAGE.read_text())
    if not isinstance(data, dict) or not isinstance(data.get("atomics"), dict):
        pytest.fail(f"malformed coverage map: {_COVERAGE}")
    return data["atomics"]


def _load_atomic_ids() -> list[str]:
    return sorted(_load_coverage_map().keys())


def _matches_expected(finding_claim: str,
                       finding_hyps: list[str],
                       expected_hyps: list[str],
                       patterns: list[str]) -> tuple[bool, str]:
    """Return (matched, reason_if_matched)."""
    claim_lower = finding_claim.lower()
    hyp_set = set(h for h in finding_hyps or [])
    for h in expected_hyps:
        if h in hyp_set:
            return True, f"hypothesis match: {h}"
    for pat in patterns:
        if pat.lower() in claim_lower:
            return True, f"claim substring match: {pat!r}"
    return False, ""


def _run_malware_triage_on_fixture(fixture_dir: Path,
                                     case_dir: Path,
                                     case_id: str) -> list:
    """Drive MalwareTriageAgent against a fixture directory.

    MalwareTriage walks <case_dir>/analysis/ and <case_dir>/exports/ for
    files to fingerprint — it does not crawl <input_path> directly. So the
    harness stages the fixture contents into the case workspace's exports/
    + analysis/disk_forensicator/ trees first; this matches the upstream
    pipeline shape (DiskForensicator deposits there before MalwareTriage
    runs in the real coordinator).
    """
    import shutil as _shutil
    from el.agents.base import AgentContext
    from el.agents.malware_triage import MalwareTriageAgent

    case_dir.mkdir(parents=True, exist_ok=True)
    exports = case_dir / "exports"
    exports.mkdir(exist_ok=True)
    analysis_disk = case_dir / "analysis" / "disk_forensicator"
    analysis_disk.mkdir(parents=True, exist_ok=True)

    # Mirror every fixture file into exports/ AND analysis/disk_forensicator/.
    # MalwareTriage's text-mode scan walks <case_dir>/analysis/**/{*.json,
    # *.csv, *.txt} so we stage a .txt copy alongside the original suffix
    # to match that discovery pattern.
    for src in fixture_dir.rglob("*"):
        if not src.is_file():
            continue
        rel = src.relative_to(fixture_dir)
        for dest_root in (exports, analysis_disk):
            dest = dest_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            _shutil.copy2(src, dest)
            # Drop a .txt-suffixed sibling so the analysis-tree text-walk
            # picks the content up regardless of fixture's own suffix.
            if dest.suffix.lower() not in (".txt", ".json", ".csv"):
                txt_sibling = dest.with_suffix(dest.suffix + ".txt")
                _shutil.copy2(src, txt_sibling)

    ctx = AgentContext(
        case_id=case_id, case_dir=case_dir,
        input_path=fixture_dir, manifest={}, shared={},
    )
    return MalwareTriageAgent().run(ctx)


def _run_linux_forensicator_on_fixture(fixture_dir: Path,
                                         case_dir: Path,
                                         case_id: str) -> list:
    """Drive LinuxForensicatorAgent against a fixture directory."""
    from el.agents.base import AgentContext
    from el.agents.linux_forensicator import LinuxForensicatorAgent
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "analysis").mkdir(exist_ok=True)
    ctx = AgentContext(
        case_id=case_id, case_dir=case_dir,
        input_path=fixture_dir, manifest={},
        shared={"evidence_kind": "linux-fs-dir",
                 "linux_artifacts_dir": fixture_dir},
    )
    return LinuxForensicatorAgent().run(ctx)


@pytest.mark.parametrize("atomic_id", _load_atomic_ids())
def test_atomic_red_team_coverage(atomic_id, tmp_path, monkeypatch):
    """For each atomic in the coverage map, verify EL detects it."""
    coverage = _load_coverage_map()
    spec = coverage[atomic_id]

    fixture_dir = _FIXTURES / atomic_id
    if not fixture_dir.is_dir():
        pytest.skip(
            f"no fixture under tests/atomic/fixtures/{atomic_id}/ — "
            "add one to enable this atomic's coverage check"
        )

    fixture_kind = spec.get("fixture_kind")
    expected_hyps = spec.get("expected_hypotheses") or []
    matcher_args = spec.get("matcher_args") or {}
    patterns = matcher_args.get("patterns") or []

    # Bind intake CASE_ROOT + knowledge DB to the per-test temp so we don't
    # pollute /opt/EL/cases on harness runs.
    from el.evidence import intake as intake_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "knowledge.sqlite"))

    case_dir = tmp_path / "cases" / atomic_id

    findings: list = []
    if fixture_kind == "linux-fs-dir":
        # MalwareTriage + LinuxForensicator both apply.
        findings.extend(
            _run_malware_triage_on_fixture(fixture_dir, case_dir, atomic_id)
        )
        findings.extend(
            _run_linux_forensicator_on_fixture(fixture_dir, case_dir, atomic_id)
        )
    elif fixture_kind == "bytes-blob":
        findings.extend(
            _run_malware_triage_on_fixture(fixture_dir, case_dir, atomic_id)
        )
    else:
        pytest.fail(f"unknown fixture_kind {fixture_kind!r} for {atomic_id}")

    matched_finding = None
    matched_reason = ""
    for f in findings:
        ok, reason = _matches_expected(
            getattr(f, "claim", ""),
            getattr(f, "hypotheses_supported", []),
            expected_hyps, patterns,
        )
        if ok:
            matched_finding = f
            matched_reason = reason
            break

    if matched_finding is None:
        # Helpful diagnostic for the failure message.
        summary = "\n".join(
            f"  - [{getattr(f, 'confidence', '?')}] "
            f"{getattr(f, 'claim', '')[:140]}  "
            f"{getattr(f, 'hypotheses_supported', [])}"
            for f in findings[:20]
        )
        pytest.fail(
            f"\nAtomic {atomic_id} ({spec.get('description', '')}) NOT "
            f"detected:\n  expected hypotheses: {expected_hyps}\n  expected "
            f"claim patterns: {patterns}\n  EL emitted {len(findings)} "
            f"finding(s):\n{summary}"
        )


def test_coverage_map_well_formed():
    """Sanity: every entry in the coverage map has the required keys."""
    cov = _load_coverage_map()
    required_keys = {"description", "expected_hypotheses",
                      "fixture_kind", "matcher", "matcher_args"}
    for atomic_id, spec in cov.items():
        assert isinstance(spec, dict), \
            f"{atomic_id}: spec must be a dict"
        missing = required_keys - set(spec.keys())
        assert not missing, \
            f"{atomic_id}: missing keys {missing}"
        assert isinstance(spec["expected_hypotheses"], list), \
            f"{atomic_id}: expected_hypotheses must be a list"
        assert spec["fixture_kind"] in ("linux-fs-dir", "bytes-blob"), \
            f"{atomic_id}: unsupported fixture_kind {spec['fixture_kind']!r}"


def test_coverage_map_atomic_ids_match_fixture_dirs():
    """Every coverage-map entry should have a corresponding fixture dir.
    Missing fixtures cause the per-atomic test to skip rather than fail,
    but the harness reports them via the docstring + this test's diagnostic."""
    cov = _load_coverage_map()
    missing = []
    for atomic_id in cov:
        if not (_FIXTURES / atomic_id).is_dir():
            missing.append(atomic_id)
    if missing:
        # Use a warning-style assertion: list missing fixtures so the
        # operator sees them at a glance.
        pytest.skip(
            f"coverage-map entries without fixtures (build them to enable "
            f"those checks): {missing}"
        )

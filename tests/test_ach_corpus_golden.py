"""Corpus-level ACH regression.

Locks in the leading hypothesis + score for every case we have on disk
under /opt/EL/cases/. If the scoring logic in el.intel.ach or the
hypothesis scorers in el.intel.hypotheses silently shifts, M57's leader
will drift off H_BEC_ACCOUNT_TAKEOVER (or tdungan-memory off
H_APT_ESPIONAGE, etc.) and this test will catch it.

Case directories live under /opt/EL/cases/ which is gitignored. If the
corpus isn't present (CI, fresh checkout), the test skips per-entry —
the golden still serves as documentation of the last-known-good state.

To refresh the golden after a deliberate scoring change, regenerate
tests/fixtures/ach_golden.json via:

    for each case under /opt/EL/cases/<case_id>:
        rows = list_findings(case_dir, case_id=case_id)
        ranked, _ = score_findings(rows)
"""
import json
from pathlib import Path

import pytest

from el.evidence.ledger import list_findings
from el.intel.ach import score_findings


_CASES_ROOT = Path("/opt/EL/cases")
_GOLDEN_PATH = Path(__file__).parent / "fixtures" / "ach_golden.json"


def _golden() -> dict:
    return json.loads(_GOLDEN_PATH.read_text())


def test_golden_file_exists_and_nonempty():
    assert _GOLDEN_PATH.exists(), f"missing {_GOLDEN_PATH}"
    g = _golden()
    assert len(g) >= 1, "golden must pin at least one case"


@pytest.mark.parametrize("case_id", sorted(_golden().keys()) if _GOLDEN_PATH.exists() else [])
def test_leading_hypothesis_matches_golden(case_id):
    case_dir = _CASES_ROOT / case_id
    if not (case_dir / "findings.sqlite").exists():
        pytest.skip(f"case corpus not present on this host: {case_dir}")

    rows = list_findings(case_dir, case_id=case_id)
    ranked, _ = score_findings(rows)
    assert ranked, f"{case_id}: no ranked hypotheses"

    expected = _golden()[case_id]
    leader = ranked[0]

    assert leader.hyp_id == expected["leader_hyp"], (
        f"{case_id}: leading hypothesis drifted "
        f"{expected['leader_hyp']} → {leader.hyp_id}"
    )
    assert int(leader.score) == expected["leader_score"], (
        f"{case_id}: leading score drifted "
        f"{expected['leader_score']} → {int(leader.score)} "
        f"(leader={leader.hyp_id})"
    )

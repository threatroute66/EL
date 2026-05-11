"""UserActivityAgent — agent-level + hypothesis-scoring contract.

These tests deliberately bypass vol3 by patching
``user_activity_memory.run_for_user`` to return a synthetic
``UserActivityRun``, so the agent contract (Finding emission, tag
propagation, ACH scoring) is testable without a real memory image.

The skill-level decoders are exercised separately in
``test_user_activity_memory.py``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from el.agents.base import AgentContext
from el.agents.user_activity import UserActivityAgent
from el.intel.ach import score_findings
from el.schemas.finding import EvidenceItem, Finding
from el.skills import user_activity_memory as ua


def _make_run(case_dir: Path, *, with_staging: bool) -> ua.UserActivityRun:
    """Build a synthetic UserActivityRun with one Office MRU + the
    requested staging-signal posture."""
    out_dir = case_dir / "analysis" / "user_activity" / "user_fredr"
    out_dir.mkdir(parents=True, exist_ok=True)
    office_json = out_dir / "windows_registry_printkey.json"
    office_json.write_text("[]")          # sha256-anchorable file
    typed_json = out_dir / "typedpaths.json"
    typed_json.write_text("[]")
    md_json = out_dir / "mounted.json"
    md_json.write_text("[]")

    entry_corp = ua.OfficeMRUEntry(
        app="Word", account="ADAL", account_id="ADAL_X", kind="File",
        path=r"F:\Files of interest\SRL-Projects - Megaforce\x.docx",
        opened_utc="2020-11-14T04:30:00+00:00",
    )
    entry_benign = ua.OfficeMRUEntry(
        app="Word", account="LiveId", account_id="LiveId_X", kind="File",
        path=r"C:\Users\fredr\Documents\notes.docx",
        opened_utc="2020-11-10T14:00:00+00:00",
    )
    drive_map = [
        ua.DriveLetterMapping(letter="C", backing="internal / non-USB"),
        ua.DriveLetterMapping(
            letter="F", backing="USB Lexar Flash [SN1]",
            usb_vendor="Lexar", usb_product="USB Flash Drive",
            usb_serial="SN1",
        ),
    ]
    staging = []
    if with_staging:
        staging = ua.detect_removable_staging(
            [entry_corp, entry_benign],
            ua.removable_drive_letters(drive_map),
        )
    return ua.UserActivityRun(
        user="fredr", ntuser_offset=0xdeadbeef, out_dir=out_dir,
        office_mru_path=office_json,
        typedpaths_path=typed_json,
        mounted_devices_path=md_json,
        office_mru=[entry_corp, entry_benign],
        typedpaths=[r"G:\My Drive\STARK-RESEARCH-LABS FOLDER"],
        drive_map=drive_map,
        staging_signals=staging,
    )


@pytest.fixture
def isolated_case(tmp_path, monkeypatch):
    """Standard EL test-isolation fixture: redirect CASE_ROOT and the
    knowledge DB into tmp_path so a real ``cases/`` is never touched.
    """
    from el.evidence import intake as intake_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    monkeypatch.setenv("EL_KNOWLEDGE_DB", str(tmp_path / "knowledge.sqlite"))
    case_dir = tmp_path / "cases" / "test-case"
    (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    return case_dir


@pytest.fixture
def ctx(isolated_case):
    from el.evidence.ledger import open_ledger
    with open_ledger(isolated_case):
        pass
    return AgentContext(
        case_id="test-case",
        case_dir=isolated_case,
        input_path=Path("/dev/null"),    # never actually read
        manifest={},
        shared={"mem_os": "windows"},
    )


def test_agent_skips_when_not_windows_memory(ctx):
    ctx.shared["mem_os"] = "linux"
    out = UserActivityAgent().run(ctx)
    assert len(out) == 1
    assert out[0].confidence == "insufficient"


def test_agent_emits_findings_and_staging_tag(monkeypatch, ctx):
    # Synthesize a hive list (one user) so the agent doesn't call vol3.
    fake_hive = ua.HiveSummary(
        file_full_path=r"\??\C:\Users\fredr\ntuser.dat",
        offset=0xdeadbeef, user="fredr",
    )
    # No real hivelist.json present in the case dir → the agent will try
    # to run vol3.hivelist; intercept that. Patching `run_plugin` returns
    # a stub PluginRun-shaped object with .rows.
    class _Fake:
        rows = [
            {"FileFullPath": fake_hive.file_full_path,
             "Offset": fake_hive.offset}
        ]
    monkeypatch.setattr(ua.vol3, "run_plugin",
                         lambda *a, **kw: _Fake())
    monkeypatch.setattr(ua, "run_for_user",
                         lambda *a, **kw: _make_run(ctx.case_dir,
                                                     with_staging=True))

    findings = UserActivityAgent().run(ctx)
    claims = [f.claim for f in findings]
    assert any("Office MRU timeline" in c for c in claims)
    assert any("Drive-letter map" in c for c in claims)
    assert any("TypedPaths" in c for c in claims)

    staging = [f for f in findings if "staging signal" in f.claim.lower()]
    assert len(staging) == 1
    assert "H_INSIDER_DATA_STAGING" in staging[0].hypotheses_supported
    assert "H_INSIDER_DATA_EXFIL" in staging[0].hypotheses_supported


def test_ach_lifts_insider_exfil_on_staging_finding(ctx):
    # The whole point of the new tag — verify it scores.
    staging = Finding(
        case_id=ctx.case_id, agent="user_activity",
        claim=("Removable-media staging signal for user 'fredr': "
               "1 corporate-project file(s) opened from USB letter F"),
        confidence="high",
        evidence=[EvidenceItem(
            tool="vol3+user_activity_memory", version="2.27",
            command="vol --offset 0xdeadbeef windows.registry.printkey",
            output_sha256="0" * 64,
            output_path=str(ctx.case_dir / "stub.json"),
        )],
        hypotheses_supported=["H_INSIDER_DATA_STAGING",
                                "H_INSIDER_DATA_EXFIL"],
    )
    ranked, _ = score_findings([staging])
    by_id = {row.hyp_id: row for row in ranked}
    # Tag-driven +3 (H_INSIDER_DATA_STAGING) + keyword-driven +3
    # ('usb', 'removable', 'stage' all in the claim) = +6.
    assert by_id["H_INSIDER_DATA_EXFIL"].score >= 3, (
        f"insider-exfil score too low: {by_id['H_INSIDER_DATA_EXFIL']}"
    )

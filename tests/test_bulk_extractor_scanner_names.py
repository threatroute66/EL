"""Regression test for the bulk_extractor scanner-name bug.

Previously, `disk_forensicator` called `be.scan(..., features=['email', 'url',
'domain', 'ip', 'ccn', 'json'])`. Of those, only 'email' and 'json' are real
scanner names — 'url', 'domain', 'ip', 'ccn' are feature-output categories
produced by other scanners ('email' emits url/domain, 'net' emits ip, 'accts'
emits ccn). Passing a feature category to `-e` makes bulk_extractor exit with
"Invalid scanner name" before writing any output, which silently broke BE
carving on every disk case.

Fix: validate against the published scanner list before exec. These tests
lock that validation in.
"""
from pathlib import Path

import pytest


def test_valid_scanner_names_accepted(tmp_path, monkeypatch):
    from el.skills import bulk_extractor as be

    target = tmp_path / "x.bin"
    target.write_bytes(b"x")
    out = tmp_path / "out"

    captured: dict = {}
    class _Proc:
        returncode = 0
    def _fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        return _Proc()
    monkeypatch.setattr("subprocess.run", _fake_run)
    monkeypatch.setattr(be, "_bin", lambda: "/usr/bin/bulk_extractor")

    be.scan(target, out,
            enable_scanners=["outlook", "email"],
            disable_scanners=["pdf"])
    cmd = captured["cmd"]
    assert "-e" in cmd and "outlook" in cmd and "email" in cmd
    assert "-x" in cmd and "pdf" in cmd


def test_invalid_enable_scanner_name_raises_early(tmp_path, monkeypatch):
    from el.skills import bulk_extractor as be

    target = tmp_path / "x.bin"
    target.write_bytes(b"x")
    out = tmp_path / "out"

    monkeypatch.setattr(be, "_bin", lambda: "/usr/bin/bulk_extractor")

    # 'url' is a feature category, not a scanner — this is exactly the bug
    # that silently produced zero features on every disk case.
    with pytest.raises(be.BulkExtractorError, match="invalid.*scanner.*url"):
        be.scan(target, out, enable_scanners=["url"])
    # 'domain' / 'ip' / 'ccn' likewise:
    for bad in ("domain", "ip", "ccn"):
        with pytest.raises(be.BulkExtractorError, match=f"invalid.*scanner.*{bad}"):
            be.scan(target, out, enable_scanners=[bad])


def test_invalid_disable_scanner_name_raises_early(tmp_path, monkeypatch):
    from el.skills import bulk_extractor as be

    target = tmp_path / "x.bin"
    target.write_bytes(b"x")
    out = tmp_path / "out"

    monkeypatch.setattr(be, "_bin", lambda: "/usr/bin/bulk_extractor")

    with pytest.raises(be.BulkExtractorError, match="invalid.*scanner"):
        be.scan(target, out, disable_scanners=["nonsense-scanner-42"])


def test_disk_forensicator_passes_valid_scanner_names(tmp_path, monkeypatch):
    """The disk_forensicator call site must stay in sync with the skill
    contract — catch the regression at the call-site level too."""
    from el.skills import bulk_extractor as be
    from el.agents.disk_forensicator import DiskForensicatorAgent
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")

    src = tmp_path / "x.bin"
    src.write_bytes(b"x" * 100)
    m = intake_mod.intake(src, case_id="t-be-names")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-be-names", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    captured: dict = {}
    def _fake_scan(target, out_dir, enable_scanners=None,
                   disable_scanners=None, threads=4, timeout=3600):
        captured["enable_scanners"] = enable_scanners or []
        captured["disable_scanners"] = disable_scanners or []
        # Validate against the real skill contract — raises if invalid
        for name in (enable_scanners or []) + (disable_scanners or []):
            if name not in be.VALID_SCANNERS:
                raise be.BulkExtractorError(
                    f"invalid bulk_extractor scanner name: {name!r}")
        return be.BulkRun(target=target, out_dir=out_dir, rc=0,
                          feature_files=[], command=["bulk_extractor"])
    monkeypatch.setattr(be, "scan", _fake_scan)

    # Should not raise — every name DiskForensicator passes must be valid.
    DiskForensicatorAgent()._run_bulk_extractor(ctx, src, tmp_path)

    for name in captured["enable_scanners"]:
        assert name in be.VALID_SCANNERS, (
            f"disk_forensicator passed invalid scanner {name!r} to "
            f"bulk_extractor (not in VALID_SCANNERS)")

"""SIGMA rule export skill — unit tests."""
from pathlib import Path

import pytest

from el.skills import sigma_export as sx


_TEST_RULE = """
title: Suspicious Logon Type 3 from Workstation
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: Test rule
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
    condition: selection
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.002
"""


# --- is_available -----------------------------------------------------

def test_is_available_when_pysigma_installed():
    ok, reason = sx.is_available()
    if not ok:
        pytest.skip(f"pysigma not installed: {reason}")
    assert ok
    assert reason == ""


def test_is_available_false_when_pysigma_missing(monkeypatch):
    """If pysigma can't be imported, is_available reports it."""
    import sys
    # Sentinel: remove from sys.modules so the next import raises.
    backup = {}
    for mod in list(sys.modules.keys()):
        if mod == "sigma" or mod.startswith("sigma."):
            backup[mod] = sys.modules[mod]

    # Replace the import with one that fails.
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) \
        else __import__

    def fail_sigma_import(name, *args, **kwargs):
        if name == "sigma" or name.startswith("sigma."):
            raise ImportError("simulated pysigma absence")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fail_sigma_import)
    try:
        ok, reason = sx.is_available()
        assert ok is False
        assert "pysigma" in reason.lower()
    finally:
        # Restore for other tests.
        for mod, val in backup.items():
            sys.modules[mod] = val


# --- _resolve_backends ----------------------------------------------

def test_resolve_backends_returns_dict():
    backends = sx._resolve_backends()
    # At least one of the four ought to be installed in this venv.
    assert isinstance(backends, dict)


# --- export_pack: end-to-end -----------------------------------------

def test_export_pack_returns_unavailable_without_pysigma(tmp_path,
                                                            monkeypatch):
    """When pysigma can't be loaded, export_pack short-circuits with a note."""
    monkeypatch.setattr(sx, "is_available",
                          lambda: (False, "pip install pysigma"))
    rules = tmp_path / "rules"
    rules.mkdir()
    out = tmp_path / "out"
    result = sx.export_pack(rules, out)
    assert result.rule_count == 0
    assert "skipped" in result.note.lower()


def test_export_pack_raises_for_non_directory(tmp_path):
    if not sx.is_available()[0]:
        pytest.skip("pysigma not installed")
    with pytest.raises(sx.SigmaExportError):
        sx.export_pack(tmp_path / "missing", tmp_path / "out")


def test_export_pack_converts_one_rule_across_all_backends(tmp_path):
    if not sx.is_available()[0]:
        pytest.skip("pysigma not installed")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test.yml").write_text(_TEST_RULE)
    out = tmp_path / "out"
    result = sx.export_pack(rules, out)

    assert result.rule_count == 1
    assert result.converted_count == 1
    assert len(result.backends_run) >= 1
    # Every wired backend should have produced an output file.
    for backend in result.backends_run:
        assert backend in result.output_files
        path = result.output_files[backend]
        assert path.is_file()
        assert path.stat().st_size > 0
        text = path.read_text()
        # Each line either a comment header or a converted query.
        # The rule's title text appears in the comment.
        assert "Suspicious Logon Type 3" in text
        # And the EventID literal survives the conversion.
        assert "4624" in text


def test_export_pack_writes_manifest(tmp_path):
    if not sx.is_available()[0]:
        pytest.skip("pysigma not installed")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test.yml").write_text(_TEST_RULE)
    out = tmp_path / "out"
    sx.export_pack(rules, out)
    manifest = (out / "manifest.txt").read_text()
    assert "rules_walked" in manifest
    assert "rules_converted" in manifest


def test_export_pack_handles_invalid_yaml(tmp_path):
    if not sx.is_available()[0]:
        pytest.skip("pysigma not installed")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "broken.yml").write_text("not: valid: sigma:\n  detection: blah")
    (rules / "good.yml").write_text(_TEST_RULE)
    out = tmp_path / "out"
    result = sx.export_pack(rules, out)
    assert result.rule_count == 2
    # Broken rule is skipped, good one converts.
    assert result.skipped_count >= 1
    assert result.converted_count >= 1


def test_export_pack_handles_empty_dir(tmp_path):
    if not sx.is_available()[0]:
        pytest.skip("pysigma not installed")
    rules = tmp_path / "rules"
    rules.mkdir()
    out = tmp_path / "out"
    result = sx.export_pack(rules, out)
    assert result.rule_count == 0
    assert result.converted_count == 0


# --- as_evidence shape ----------------------------------------------

def test_as_evidence_shape(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    run = sx.SigmaExportRun(
        rules_root=tmp_path / "rules", output_dir=out,
        rule_count=10, converted_count=8, skipped_count=2,
        backends_run=["splunk", "kusto"],
        output_files={"splunk": out / "x.spl", "kusto": out / "y.kql"},
        output_sha256="h" * 64,
    )
    ev = run.as_evidence()
    assert ev.tool == "sigma_export"
    assert ev.output_sha256 == "h" * 64
    assert ev.extracted_facts["rule_count"] == 10
    assert ev.extracted_facts["converted_count"] == 8
    assert "splunk" in ev.extracted_facts["backends"]


def test_unavailable_run_zero_pads_evidence(tmp_path):
    run = sx.SigmaExportRun(
        rules_root=tmp_path, output_dir=tmp_path,
        note="pysigma not installed",
    )
    ev = run.as_evidence()
    assert ev.output_sha256 == "0" * 64

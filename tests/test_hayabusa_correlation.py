"""Hayabusa Sigma correlation parsing — Tier 4.4.

Synthetic CSV-timeline outputs verify that rows whose RuleFile path
indicates a correlation rule are tracked in HayabusaRun.correlation_hits
separately from base-rule hits.
"""
import csv
from pathlib import Path
from unittest.mock import patch

import pytest

from el.skills import hayabusa as hb


def _write_csv(path: Path, rows: list[dict]):
    """Write a CSV with the columns Hayabusa's csv-timeline emits."""
    fields = [
        "Timestamp", "Computer", "Channel", "EventID", "Level",
        "RuleTitle", "RuleFile", "MitreTactics", "MitreTags",
    ]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def _make_run(tmp_path, rows):
    """Synthesize a HayabusaRun object via the CSV parsing path."""
    csv_path = tmp_path / "hayabusa-detections.csv"
    _write_csv(csv_path, rows)

    # Patch the binary + rules so csv_timeline doesn't actually try to run.
    fake_target = tmp_path / "fake.evtx"; fake_target.write_bytes(b"\x00")
    out_dir = tmp_path / "out"; out_dir.mkdir()
    # Move our pre-written CSV into the location csv_timeline expects.
    expected_csv = out_dir / "hayabusa-detections.csv"
    csv_path.replace(expected_csv)

    with patch.object(hb, "_bin", lambda: "/usr/bin/echo"), \
            patch.object(hb, "_rules_dir",
                          lambda: tmp_path / "rules"), \
            patch.object(hb, "_version", lambda: "test"):
        # Make _rules_dir succeed
        (tmp_path / "rules").mkdir(exist_ok=True)
        # Skip the actual subprocess by stubbing it out.
        import subprocess as _sp
        with patch.object(hb.subprocess, "run") as fake_run:
            fake_run.return_value = _sp.CompletedProcess(
                args=[], returncode=0, stdout="", stderr="",
            )
            run = hb.csv_timeline(fake_target, out_dir)
    return run


def test_csv_timeline_separates_base_from_correlation_rules(tmp_path):
    rows = [
        {"RuleTitle": "Suspicious PowerShell",
         "RuleFile": "rules/sigma/builtin/windows/process_creation/proc_susp_ps.yml",
         "Level": "high", "MitreTactics": "T1059.001"},
        {"RuleTitle": "Failed logon (4625)",
         "RuleFile": "rules/sigma/builtin/windows/security/win_failed_logon.yml",
         "Level": "low", "MitreTactics": ""},
        # Correlation rule — RuleFile path includes correlation_rules
        {"RuleTitle": "Brute force from many failed logons + 1 success",
         "RuleFile": "rules/sigma/correlation_rules/brute_force_correlation.yml",
         "Level": "critical", "MitreTactics": "T1110"},
        {"RuleTitle": "Brute force from many failed logons + 1 success",
         "RuleFile": "rules/sigma/correlation_rules/brute_force_correlation.yml",
         "Level": "critical", "MitreTactics": "T1110"},
        {"RuleTitle": "Lateral movement chain (psexec → wmiprvse)",
         "RuleFile": "rules/sigma/correlation_rule/lateral_chain.yml",
         "Level": "high", "MitreTactics": "T1021"},
    ]
    run = _make_run(tmp_path, rows)

    # Total detections = all 5 CSV rows.
    assert run.detection_count == 5
    # Base-rule hits cover all 3 distinct rules.
    assert "Suspicious PowerShell" in run.rule_hits
    assert "Failed logon (4625)" in run.rule_hits
    # Correlation hits track only the correlation-rule-file rows.
    assert "Brute force from many failed logons + 1 success" in run.correlation_hits
    assert run.correlation_hits[
        "Brute force from many failed logons + 1 success"
    ] == 2
    assert "Lateral movement chain (psexec → wmiprvse)" in run.correlation_hits
    assert "Suspicious PowerShell" not in run.correlation_hits


def test_csv_timeline_no_correlation_rules(tmp_path):
    rows = [
        {"RuleTitle": "x", "RuleFile": "rules/sigma/builtin/x.yml",
         "Level": "high", "MitreTactics": "T1059"},
    ]
    run = _make_run(tmp_path, rows)
    assert run.correlation_hits == {}
    assert not run.has_correlation_hits()


def test_correlation_samples_capped_at_five(tmp_path):
    rows = [
        {"RuleTitle": f"Correlation rule {i}",
         "RuleFile": "rules/sigma/correlation_rules/test.yml",
         "Level": "high", "MitreTactics": ""}
        for i in range(10)
    ]
    run = _make_run(tmp_path, rows)
    assert len(run.correlation_samples) == 5
    # The first sample should retain the rule + RuleFile.
    assert "Correlation rule 0" in run.correlation_samples[0]["rule"]
    assert "correlation_rules" in run.correlation_samples[0]["rule_file"]


def test_has_correlation_hits():
    run = hb.HayabusaRun(
        target=Path("/x"), rc=0,
        csv_path=Path("/y"), stderr_path=Path("/z"),
        command=[],
    )
    assert not run.has_correlation_hits()
    run.correlation_hits["x"] = 1
    assert run.has_correlation_hits()


def test_evidence_payload_includes_correlation_fields(tmp_path):
    csv_path = tmp_path / "h.csv"
    csv_path.write_text("dummy")
    run = hb.HayabusaRun(
        target=Path("/x"), rc=0,
        csv_path=csv_path, stderr_path=Path("/z"),
        command=[],
        detection_count=10,
        rule_hits={"r1": 5, "r2": 3},
        correlation_hits={"corr_a": 2, "corr_b": 1},
    )
    ev = run.as_evidence()
    facts = ev.extracted_facts
    assert facts["correlation_rule_count"] == 2
    assert facts["correlation_total_hits"] == 3
    top = dict(facts["top_correlation_rules"])
    assert top["corr_a"] == 2

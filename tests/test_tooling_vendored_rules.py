"""`el doctor` probe for vendored YARA rule packs (el/skills/rules/)."""
from pathlib import Path

from el import tooling
from el.skills import yara_hunt


def test_probe_reports_present_packs():
    s = tooling.probe_vendored_yara_rules()
    assert s.name == "vendored-yara-rules"
    assert s.available is True
    # ships at least the FALLCHILL + HIDDEN COBRA packs
    assert "pack(s)" in s.version and "rule(s)" in s.version
    assert "MALW_FALLCHILL.yar" in s.note
    assert "hiddencobra_uscert.yar" in s.note


def test_probe_registered_in_survey():
    names = {st.name for st in tooling.survey()}
    assert "vendored-yara-rules" in names


def test_probe_graceful_when_dir_absent(tmp_path, monkeypatch):
    # Point the rules dir at a non-existent path: probe must report
    # unavailable (not raise) — yara_hunt degrades gracefully too.
    monkeypatch.setattr(yara_hunt, "_RULES_DIR", tmp_path / "nope")
    s = tooling.probe_vendored_yara_rules()
    assert s.available is False
    assert "absent" in s.note


def test_probe_empty_dir_reports_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(yara_hunt, "_RULES_DIR", tmp_path)
    s = tooling.probe_vendored_yara_rules()
    assert s.available is False
    assert "0 packs" in s.version

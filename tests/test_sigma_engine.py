"""PR: SIGMA rule engine + SigmaAnalystAgent tests.

Covers the parts that are most likely to drift:
  - Rule parsing (logsource / detection / tags / level)
  - Modifier matching (contains, startswith, endswith, regex, all, cased)
  - Condition parser (and / or / not / parens / "1 of X" / "all of X"
    with wildcards)
  - EventID pre-filter extraction (tighter index, negative-branch bail)
  - Agent wiring against a synthetic EvtxECmd CSV + fixture rule pack
"""
import csv
import textwrap
from pathlib import Path

import pytest

from el.skills import sigma_engine as se


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------

def _write_rule(path: Path, yaml_text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(yaml_text).lstrip())


def test_load_parses_basic_rule(tmp_path):
    _write_rule(tmp_path / "r.yml", """
        title: Test Rule
        id: 11111111-aaaa-bbbb-cccc-222222222222
        status: experimental
        description: example
        author: me
        logsource:
          product: windows
          service: security
        detection:
          selection:
            EventID: 4104
            ScriptBlockText|contains: 'IEX'
          condition: selection
        tags:
          - attack.execution
          - attack.t1059.001
        level: high
    """)
    rules = se.load_rules(tmp_path)
    assert len(rules) == 1
    r = rules[0]
    assert r.id == "11111111-aaaa-bbbb-cccc-222222222222"
    assert r.level == "high"
    assert "attack.execution" in r.tags
    assert r.logsource["product"] == "windows"
    assert r._target_eids == {4104}


def test_load_ignores_non_rule_docs(tmp_path):
    """README snippets sometimes live in the rules tree — they shouldn't
    crash parsing, just be skipped."""
    (tmp_path / "note.yaml").write_text("# not-a-rule\n")
    (tmp_path / "empty.yml").write_text("")
    rules = se.load_rules(tmp_path)
    assert rules == []


def test_load_records_yaml_error(tmp_path):
    (tmp_path / "bad.yml").write_text("!!!:\n  - [unterminated\n")
    rules = se.load_rules(tmp_path)
    assert len(rules) == 1
    assert "yaml parse error" in rules[0].skipped_reason


# ---------------------------------------------------------------------------
# Modifier matching — direct CSV column + payload fallback
# ---------------------------------------------------------------------------

def _row(eid: int = 4104, **payload) -> dict:
    """Synthetic EvtxECmd row. Extra kwargs become PayloadData1..6."""
    base = {
        "EventId": str(eid),
        "Channel": "Security",
        "Computer": "HOST1",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "TimeCreated": "2024-01-01T10:00:00Z",
        "Level": "Information",
        "UserName": "SYSTEM",
        "MapDescription": "",
    }
    for i, (k, v) in enumerate(payload.items(), start=1):
        base[f"PayloadData{i}"] = f"{k}: {v}"
    return base


def _compile(expr: str, body: dict) -> se.SigmaRule:
    """Minimal rule factory: one selection, one condition."""
    rule = se.SigmaRule(
        id="r", title="t", level="high", description="", author="",
        tags=[], logsource={"product": "windows"},
        detection={"selection": body, "condition": "selection"},
        file_path=Path("/tmp/r.yml"),
    )
    rule._condition_fn = se._compile_condition(
        "selection", [k for k in rule.detection if k != "condition"])
    rule._target_eids = se._extract_eid_filter(
        rule.detection,
        [k for k in rule.detection if k != "condition"],
        "selection")
    _ = expr   # unused — keeps API surface
    return rule


def test_eventid_exact_match_hits():
    r = _compile("selection", {"EventID": 4104})
    assert se.evaluate_rule(r, _row(eid=4104))
    assert not se.evaluate_rule(r, _row(eid=4625))


def test_contains_hits_against_payload_blob():
    r = _compile("selection",
                 {"EventID": 4104, "ScriptBlockText|contains": "IEX"})
    assert se.evaluate_rule(r, _row(eid=4104, script="powershell -c IEX(...)"))
    assert not se.evaluate_rule(r, _row(eid=4104, script="Get-Process"))


def test_startswith_endswith():
    r = _compile("selection", {"Image|startswith": "C:\\Windows\\Temp\\"})
    assert se.evaluate_rule(r, _row(path="C:\\Windows\\Temp\\dropper.exe"))
    assert not se.evaluate_rule(r, _row(path="C:\\Windows\\System32\\cmd.exe"))
    r = _compile("selection", {"Image|endswith": ".tmp"})
    assert se.evaluate_rule(r, _row(path="C:\\foo\\x.tmp"))
    assert not se.evaluate_rule(r, _row(path="C:\\foo\\x.exe"))


def test_regex_modifier():
    r = _compile("selection",
                 {"ScriptBlockText|re": r"\bInvoke-Mimikatz\b"})
    assert se.evaluate_rule(r, _row(script="running Invoke-Mimikatz -d"))
    assert not se.evaluate_rule(r, _row(script="running MimikatzLib"))


def test_contains_with_list_is_any():
    r = _compile("selection",
                 {"ScriptBlockText|contains": ["IEX", "DownloadString", "AMSI"]})
    assert se.evaluate_rule(r, _row(script="AMSI bypass attempt"))
    assert not se.evaluate_rule(r, _row(script="nothing interesting"))


def test_contains_all_modifier():
    r = _compile("selection",
                 {"ScriptBlockText|contains|all": ["IEX", "DownloadString"]})
    assert se.evaluate_rule(r, _row(script="IEX(New-Object Net.WebClient).DownloadString('...')"))
    assert not se.evaluate_rule(r, _row(script="IEX Get-Foo"))


def test_cased_modifier_defaults_insensitive():
    r = _compile("selection", {"Computer": "HOST1"})
    assert se.evaluate_rule(r, _row())                # HOST1 matches HOST1
    r_lower = _row(); r_lower["Computer"] = "host1"
    assert se.evaluate_rule(r, r_lower)               # HOST1 matches host1 (case-insensitive)
    # With |cased, the match is strict
    r2 = _compile("selection", {"Computer|cased": "HOST1"})
    assert se.evaluate_rule(r2, _row())
    assert not se.evaluate_rule(r2, r_lower)


# ---------------------------------------------------------------------------
# Condition parser
# ---------------------------------------------------------------------------

def _sels(state: dict[str, bool], condition: str,
          keys: list[str] | None = None) -> bool:
    keys = keys or list(state.keys())
    fn = se._compile_condition(condition, keys)
    return fn(state)


def test_condition_identifier():
    assert _sels({"selection": True}, "selection")
    assert not _sels({"selection": False}, "selection")


def test_condition_and_or_not():
    assert _sels({"a": True, "b": True}, "a and b")
    assert not _sels({"a": True, "b": False}, "a and b")
    assert _sels({"a": True, "b": False}, "a or b")
    assert not _sels({"a": False, "b": False}, "a or b")
    assert _sels({"a": False}, "not a")
    assert not _sels({"a": True}, "not a")


def test_condition_parens():
    assert _sels({"a": True, "b": False, "c": True},
                 "a and (b or c)")
    assert not _sels({"a": True, "b": False, "c": False},
                 "a and (b or c)")


def test_condition_1_of_them():
    assert _sels({"s1": False, "s2": True, "s3": False}, "1 of them")
    assert not _sels({"s1": False, "s2": False, "s3": False}, "1 of them")


def test_condition_all_of_them():
    assert _sels({"s1": True, "s2": True}, "all of them")
    assert not _sels({"s1": True, "s2": False}, "all of them")


def test_condition_wildcard():
    state = {"selection_one": True, "selection_two": False, "filter": True}
    assert _sels(state, "1 of selection_*", list(state.keys()))
    assert not _sels(state, "all of selection_*", list(state.keys()))


def test_condition_combined_form():
    state = {"attack_a": True, "attack_b": False, "filter": True}
    # Classic SIGMA pattern — one of attacks AND NOT filter
    assert not _sels(state, "1 of attack_* and not filter",
                     list(state.keys()))
    state["filter"] = False
    assert _sels(state, "1 of attack_* and not filter",
                 list(state.keys()))


def test_condition_rejects_garbage():
    with pytest.raises(se.SigmaError):
        se._compile_condition("a and and b", ["a", "b"])


# ---------------------------------------------------------------------------
# EventID pre-filter extraction
# ---------------------------------------------------------------------------

def test_eid_filter_pins_from_single_selection():
    det = {"selection": {"EventID": 4104}, "condition": "selection"}
    assert se._extract_eid_filter(det, ["selection"], "selection") == {4104}


def test_eid_filter_union_over_selections():
    det = {
        "sel_a": {"EventID": 4625},
        "sel_b": {"EventID": [4769, 4776]},
        "condition": "sel_a or sel_b",
    }
    pins = se._extract_eid_filter(det, ["sel_a", "sel_b"], "sel_a or sel_b")
    assert pins == {4625, 4769, 4776}


def test_eid_filter_bails_on_negation():
    det = {
        "sel": {"EventID": 4625},
        "filter": {"UserName": "SYSTEM"},
        "condition": "sel and not filter",
    }
    # filter has no EID pin; the whole rule must fall back to generic.
    assert se._extract_eid_filter(det, ["sel", "filter"],
                                    "sel and not filter") is None


def test_eid_filter_bails_on_modifier():
    det = {"s": {"EventID|gte": 4000}, "condition": "s"}
    assert se._extract_eid_filter(det, ["s"], "s") is None


def test_index_by_eid_splits_indexed_and_generic():
    det1 = {"selection": {"EventID": 4104}, "condition": "selection"}
    det2 = {"selection": {"UserName": "admin"}, "condition": "selection"}
    r1 = se._parse_rule({"title": "x", "detection": det1, "level": "low"},
                        Path("/tmp/r1.yml"))
    r2 = se._parse_rule({"title": "y", "detection": det2, "level": "low"},
                        Path("/tmp/r2.yml"))
    by_eid, generic = se.index_rules_by_eid([r1, r2])
    assert r1 in by_eid.get(4104, [])
    assert r2 in generic


# ---------------------------------------------------------------------------
# Agent wiring
# ---------------------------------------------------------------------------

_EVTX_COLS = [
    "RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
    "Provider", "Channel", "ProcessId", "ThreadId", "Computer",
    "ChunkNumber", "UserId", "MapDescription", "UserName", "RemoteHost",
    "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
    "PayloadData5", "PayloadData6", "SourceFile",
]


def _write_evtx_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=_EVTX_COLS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in _EVTX_COLS})


def test_agent_emits_findings_for_matched_rules(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.sigma_analyst import SigmaAnalystAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-sigma")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-sigma", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)

    rules_dir = tmp_path / "sigma_rules"
    _write_rule(rules_dir / "mimikatz.yml", """
        title: PowerShell Mimikatz Invocation
        id: rule-mimikatz-001
        description: detects Invoke-Mimikatz pattern
        logsource:
          product: windows
          service: powershell
        detection:
          selection:
            EventID: 4104
            ScriptBlockText|contains: 'Invoke-Mimikatz'
          condition: selection
        tags:
          - attack.credential_access
          - attack.t1003
        level: high
    """)
    _write_rule(rules_dir / "noise.yml", """
        title: Unrelated Rule
        id: rule-noise
        logsource:
          product: windows
        detection:
          selection:
            EventID: 9999
          condition: selection
        level: medium
    """)
    ctx.shared["sigma_rules_dir"] = str(rules_dir)

    csv_path = (Path(m.case_dir) / "analysis" / "windows_artifact"
                / "evtx" / "evtx_parsed.csv")
    _write_evtx_csv(csv_path, [
        {"TimeCreated": "2024-01-01T10:00:00Z", "EventId": "4104",
         "Channel": "Microsoft-Windows-PowerShell/Operational",
         "PayloadData1": "ScriptBlockText: Invoke-Mimikatz -Command sekurlsa::logonpasswords"},
        {"TimeCreated": "2024-01-01T10:05:00Z", "EventId": "4104",
         "Channel": "Microsoft-Windows-PowerShell/Operational",
         "PayloadData1": "ScriptBlockText: Get-Process"},
        {"TimeCreated": "2024-01-01T10:10:00Z", "EventId": "4625",
         "Channel": "Security",
         "PayloadData1": "Target: guest"},
    ])

    findings = SigmaAnalystAgent().run(ctx)
    # Summary + one per matched rule
    assert any("SigmaAnalyst summary" in f.claim for f in findings)
    # Per-rule findings start with "SIGMA rule [<level>]"; the summary
    # starts with "SigmaAnalyst summary:". Filter so we only inspect
    # per-rule findings here.
    per_rule = [f for f in findings if f.claim.startswith("SIGMA rule")]
    matched = [f for f in per_rule if "rule-mimikatz-001" in f.claim]
    assert matched, f"expected mimikatz rule to match, got {[f.claim for f in per_rule]}"
    assert matched[0].confidence == "high"
    assert "H_CREDENTIAL_ACCESS" in matched[0].hypotheses_supported
    # Noise rule should not have produced a per-rule finding
    assert not any("Unrelated Rule" in f.claim for f in per_rule)


def test_agent_insufficient_when_no_rules_configured(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.sigma_analyst import SigmaAnalystAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    # Point resolution at an empty path
    monkeypatch.setenv("EL_SIGMA_RULES", str(tmp_path / "nope"))
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-sigma-empty")
    with open_ledger(m.case_dir):
        pass
    csv_path = (Path(m.case_dir) / "analysis" / "windows_artifact"
                / "evtx" / "evtx_parsed.csv")
    _write_evtx_csv(csv_path, [])

    # Need a non-existing default too — override the module constant
    from el.agents import sigma_analyst as sa
    original_resolver = sa._resolve_rules_dir
    monkeypatch.setattr(sa, "_resolve_rules_dir", lambda ctx: None)

    ctx = AgentContext(case_id="t-sigma-empty", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = SigmaAnalystAgent().run(ctx)
    sa._resolve_rules_dir = original_resolver
    assert findings
    assert findings[0].confidence == "insufficient"
    assert "no rule pack found" in findings[0].claim.lower()


def test_agent_insufficient_when_no_csv(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.sigma_analyst import SigmaAnalystAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "x.bin"; src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-sigma-nocsv")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-sigma-nocsv", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = SigmaAnalystAgent().run(ctx)
    assert findings and findings[0].confidence == "insufficient"
    assert "no evtxecmd csv" in findings[0].claim.lower()


# ---------------------------------------------------------------------------
# ATT&CK technique extraction
# ---------------------------------------------------------------------------

def test_attack_techniques_extracted_from_tags():
    rule = se.SigmaRule(
        id="x", title="y", level="high", description="", author="",
        tags=["attack.credential_access", "attack.t1003", "attack.T1059.001"],
        logsource={}, detection={}, file_path=Path("/tmp/x.yml"),
    )
    hit = se.SigmaHit(rule=rule, event_count=1)
    assert hit.attack_techniques() == ["T1003", "T1059.001"]

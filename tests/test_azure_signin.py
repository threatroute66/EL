"""Azure AD / Entra sign-in log detector tests.

Synthetic Graph-shaped records drive each detector; an integration
test confirms CloudForensicatorAgent dispatches Azure sign-in inputs
to the right skill.
"""
import json
from pathlib import Path

import pytest

from el.skills import azure_signin as asl


# ---------------------------------------------------------------------------
# Record factory + writer
# ---------------------------------------------------------------------------

def _record(**kwargs) -> dict:
    base = {
        "id": kwargs.pop("id", "guid-abc"),
        "createdDateTime": kwargs.pop("createdDateTime",
                                        "2024-01-01T10:00:00Z"),
        "userPrincipalName": kwargs.pop("userPrincipalName",
                                           "alice@corp.example"),
        "userId": kwargs.pop("userId", "uid-alice"),
        "appDisplayName": kwargs.pop("appDisplayName",
                                       "Microsoft Teams"),
        "clientAppUsed": kwargs.pop("clientAppUsed", "Browser"),
        "ipAddress": kwargs.pop("ipAddress", "203.0.113.10"),
        "location": kwargs.pop("location",
                                {"countryOrRegion": "US"}),
        "status": kwargs.pop("status", {"errorCode": 0}),
        "riskLevelAggregated": kwargs.pop("riskLevelAggregated", "none"),
        "riskLevelDuringSignIn": kwargs.pop("riskLevelDuringSignIn", "none"),
        "riskState": kwargs.pop("riskState", "none"),
        "conditionalAccessStatus": kwargs.pop("conditionalAccessStatus",
                                                "success"),
    }
    base.update(kwargs)
    return base


def _failure(**kwargs) -> dict:
    kwargs.setdefault("status", {"errorCode": 50126,
                                  "failureReason": "Invalid username or password"})
    return _record(**kwargs)


def _write_log(path: Path, records: list[dict],
                wrap_in_value: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"value": records} if wrap_in_value else records
    path.write_text(json.dumps(payload))


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

def test_parse_bare_array(tmp_path):
    p = tmp_path / "signins.json"
    _write_log(p, [_record(userPrincipalName="x@y.z")])
    assert len(asl.parse_signin_log(p)) == 1


def test_parse_graph_wrapper(tmp_path):
    p = tmp_path / "signins.json"
    _write_log(p, [_record(), _record()], wrap_in_value=True)
    assert len(asl.parse_signin_log(p)) == 2


def test_parse_missing_file():
    assert asl.parse_signin_log(Path("/nope")) == []


def test_parse_bad_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not json")
    assert asl.parse_signin_log(p) == []


# ---------------------------------------------------------------------------
# Detector 1: signin brute / spray
# ---------------------------------------------------------------------------

def test_signin_brute_fires_on_10_failures_same_user():
    rows = [_failure(userPrincipalName="ceo@corp.example") for _ in range(12)]
    hits = asl.detect_signin_failure_burst(rows)
    brute = [h for h in hits if h.technique == "signin_brute"]
    assert brute
    assert brute[0].top_principals[0] == ("ceo@corp.example", 12)


def test_signin_spray_fires_on_5_users_one_source():
    rows = [_failure(userPrincipalName=f"u{i}@corp.example",
                      ipAddress="198.51.100.7")
            for i in range(6)]
    hits = asl.detect_signin_failure_burst(rows)
    spray = [h for h in hits if h.technique == "signin_spray"]
    assert spray
    assert spray[0].top_sources[0] == ("198.51.100.7", 6)


def test_signin_success_not_counted():
    rows = [_record() for _ in range(50)]
    assert asl.detect_signin_failure_burst(rows) == []


def test_signin_brute_below_threshold_silent():
    rows = [_failure(userPrincipalName="ceo@corp.example") for _ in range(9)]
    assert asl.detect_signin_failure_burst(rows) == []


# ---------------------------------------------------------------------------
# Detector 2: legacy auth
# ---------------------------------------------------------------------------

def test_legacy_auth_fires_on_successful_imap():
    rows = [_record(clientAppUsed="IMAP4",
                     userPrincipalName="svc@corp.example")
            for _ in range(2)]
    hits = asl.detect_legacy_auth_bypass(rows)
    assert hits
    assert hits[0].technique == "legacy_auth"
    assert ("T1556.006", "Modify Authentication Process: MFA") in hits[0].attack


def test_legacy_auth_ignores_failures():
    rows = [_failure(clientAppUsed="IMAP4") for _ in range(5)]
    assert asl.detect_legacy_auth_bypass(rows) == []


def test_legacy_auth_ignores_browser_and_modern_client():
    rows = [_record(clientAppUsed="Browser") for _ in range(5)]
    rows += [_record(clientAppUsed="Mobile Apps and Desktop clients")
             for _ in range(5)]
    assert asl.detect_legacy_auth_bypass(rows) == []


def test_legacy_auth_recognises_multiple_variants():
    for app in ("POP3", "Authenticated SMTP", "Exchange ActiveSync",
                "MAPI Over HTTP"):
        hits = asl.detect_legacy_auth_bypass(
            [_record(clientAppUsed=app) for _ in range(1)])
        assert hits, f"legacy auth detector missed {app!r}"


# ---------------------------------------------------------------------------
# Detector 3: risky sign-in
# ---------------------------------------------------------------------------

def test_risky_signin_fires_on_risk_level_high():
    rows = [_record(riskLevelAggregated="high",
                     userPrincipalName="risky@corp.example")]
    hits = asl.detect_risky_signin(rows)
    assert hits


def test_risky_signin_fires_on_risk_state_at_risk():
    rows = [_record(riskState="atRisk")]
    assert asl.detect_risky_signin(rows)


def test_risky_signin_silent_on_none_risk():
    assert asl.detect_risky_signin([_record() for _ in range(50)]) == []


# ---------------------------------------------------------------------------
# Detector 4: impossible travel
# ---------------------------------------------------------------------------

def test_impossible_travel_fires_across_countries_within_hour():
    rows = [
        _record(createdDateTime="2024-01-01T10:00:00Z",
                 location={"countryOrRegion": "US"}),
        _record(createdDateTime="2024-01-01T10:30:00Z",
                 location={"countryOrRegion": "RU"}),
    ]
    hits = asl.detect_impossible_travel(rows)
    assert hits
    assert hits[0].technique == "impossible_travel"


def test_impossible_travel_silent_same_country():
    rows = [
        _record(createdDateTime="2024-01-01T10:00:00Z",
                 location={"countryOrRegion": "US"}),
        _record(createdDateTime="2024-01-01T10:30:00Z",
                 location={"countryOrRegion": "US"}),
    ]
    assert asl.detect_impossible_travel(rows) == []


def test_impossible_travel_silent_outside_window():
    rows = [
        _record(createdDateTime="2024-01-01T10:00:00Z",
                 location={"countryOrRegion": "US"}),
        _record(createdDateTime="2024-01-01T14:30:00Z",   # 4.5h later
                 location={"countryOrRegion": "RU"}),
    ]
    assert asl.detect_impossible_travel(rows) == []


def test_impossible_travel_silent_on_failures():
    rows = [
        _failure(createdDateTime="2024-01-01T10:00:00Z",
                  location={"countryOrRegion": "US"}),
        _failure(createdDateTime="2024-01-01T10:30:00Z",
                  location={"countryOrRegion": "RU"}),
    ]
    assert asl.detect_impossible_travel(rows) == []


# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------

def test_looks_like_signin_log_positive():
    sample = b'[{"userPrincipalName":"x","appDisplayName":"Teams"}]'
    assert asl.looks_like_signin_log(sample)


def test_looks_like_signin_log_negative_for_cloudtrail():
    sample = b'{"Records":[{"eventName":"ConsoleLogin","eventSource":"x"}]}'
    assert not asl.looks_like_signin_log(sample)


# ---------------------------------------------------------------------------
# Agent dispatch — CloudForensicatorAgent handles sign-in input
# ---------------------------------------------------------------------------

def test_agent_routes_signin_log_to_azure_skill(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.cloud_forensicator import CloudForensicatorAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "signins.json"
    _write_log(src, [
        _failure(userPrincipalName="ceo@corp.example") for _ in range(12)
    ])
    m = intake_mod.intake(src, case_id="t-signin")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-signin", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = CloudForensicatorAgent().run(ctx)
    claims = [f.claim for f in findings]
    assert any("Azure sign-in record" in c for c in claims)
    assert any("signin_brute" in c.lower() for c in claims)
    assert any("H_BRUTE_FORCE" in f.hypotheses_supported for f in findings)


def test_agent_insufficient_for_unknown_cloud_kind(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.cloud_forensicator import CloudForensicatorAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "random.json"
    src.write_text('{"nothing":"usable"}')
    m = intake_mod.intake(src, case_id="t-unknown")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-unknown", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    findings = CloudForensicatorAgent().run(ctx)
    assert findings[0].confidence == "insufficient"
    assert "cloud-log shape" in findings[0].claim

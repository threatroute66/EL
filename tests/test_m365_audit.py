"""Microsoft 365 Unified Audit Log detector tests.

Exchange / SharePoint / OneDrive / AzureActiveDirectory / MicrosoftTeams
events share the UAL envelope; detectors target specific Operation
values inside AuditData. Fixtures mirror the real export shape where
AuditData is a JSON STRING inside each outer record (the PowerShell
`Search-UnifiedAuditLog` default).
"""
import json
from pathlib import Path

import pytest

from el.skills import m365_audit as ual


# ---------------------------------------------------------------------------
# Record factory
# ---------------------------------------------------------------------------

def _ual_record(operation: str, user_id: str = "user@corp.example",
                client_ip: str = "203.0.113.10",
                audit_data: dict | None = None,
                workload: str = "Exchange",
                creation_time: str = "2024-01-01T10:00:00Z",
                audit_data_as_string: bool = False) -> dict:
    ad = dict(audit_data or {})
    ad.setdefault("Operation", operation)
    ad.setdefault("Workload", workload)
    ad.setdefault("ObjectId", "obj-1")
    rec = {
        "CreationTime": creation_time,
        "Id": f"rec-{operation}-{user_id}",
        "Operation": operation,
        "OrganizationId": "org-guid",
        "RecordType": 15,
        "ResultStatus": "Succeeded",
        "UserKey": user_id,
        "UserType": 0,
        "UserId": user_id,
        "ClientIP": client_ip,
        "Workload": workload,
    }
    rec["AuditData"] = json.dumps(ad) if audit_data_as_string else ad
    return rec


def _write_log(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records))


# ---------------------------------------------------------------------------
# Parse + AuditData string unpack
# ---------------------------------------------------------------------------

def test_parse_unpacks_auditdata_json_string(tmp_path):
    p = tmp_path / "ual.json"
    _write_log(p, [_ual_record("MailItemsAccessed",
                                  audit_data_as_string=True)])
    rows = ual.parse_ual_log(p)
    assert rows
    assert isinstance(rows[0]["AuditData"], dict)
    assert rows[0]["AuditData"]["Operation"] == "MailItemsAccessed"


def test_parse_accepts_graph_wrapper(tmp_path):
    p = tmp_path / "ual.json"
    p.write_text(json.dumps({"value": [_ual_record("UserLoggedIn")]}))
    assert len(ual.parse_ual_log(p)) == 1


def test_parse_bad_json_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not json")
    assert ual.parse_ual_log(p) == []


# ---------------------------------------------------------------------------
# Detector 1: inbox-rule external forward
# ---------------------------------------------------------------------------

def _rule_record(forward_to: str,
                  user: str = "victim@corp.example",
                  op: str = "New-InboxRule") -> dict:
    return _ual_record(op, user_id=user, audit_data={
        "Operation": op,
        "Parameters": [
            {"Name": "Name", "Value": "auto-forward"},
            {"Name": "ForwardTo", "Value": forward_to},
        ],
    })


def test_inbox_rule_external_fires_without_tenant_anchor():
    rows = [_rule_record("attacker@evil.example")]
    hits = ual.detect_inbox_rule_external_forward(rows)
    assert hits
    assert hits[0].technique == "inbox_rule_forward_external"
    assert ("T1114.003", "Email Collection: Email Forwarding Rule") in hits[0].attack


def test_inbox_rule_respects_tenant_allowlist():
    """With tenant_domains configured, only truly external targets fire."""
    tenant = {"corp.example"}
    internal = [_rule_record("teammate@corp.example")]
    external = [_rule_record("attacker@evil.example")]
    assert not ual.detect_inbox_rule_external_forward(internal, tenant)
    assert ual.detect_inbox_rule_external_forward(external, tenant)


def test_inbox_rule_redirect_param_also_flags():
    rows = [_ual_record("Set-InboxRule", audit_data={
        "Parameters": [
            {"Name": "RedirectTo", "Value": "attacker@evil.example"},
        ],
    })]
    assert ual.detect_inbox_rule_external_forward(rows)


def test_inbox_rule_silent_without_forward_param():
    rows = [_ual_record("New-InboxRule", audit_data={
        "Parameters": [
            {"Name": "Name", "Value": "flag-marketing"},
            {"Name": "MarkAsRead", "Value": "True"},
        ],
    })]
    assert ual.detect_inbox_rule_external_forward(rows) == []


# ---------------------------------------------------------------------------
# Detector 2: MailItemsAccessed bulk
# ---------------------------------------------------------------------------

def test_mail_items_accessed_bulk_fires_at_50_per_user():
    rows = [_ual_record("MailItemsAccessed",
                         user_id="target@corp.example")
            for _ in range(55)]
    hits = ual.detect_mail_items_accessed_bulk(rows)
    assert hits
    assert hits[0].top_principals[0] == ("target@corp.example", 55)


def test_mail_items_accessed_below_threshold_silent():
    rows = [_ual_record("MailItemsAccessed") for _ in range(10)]
    assert ual.detect_mail_items_accessed_bulk(rows) == []


def test_mail_items_accessed_spread_across_users_silent():
    """50 events total but spread across 50 users = normal org
    activity, not post-compromise scraping."""
    rows = [_ual_record("MailItemsAccessed",
                         user_id=f"user{i}@corp.example")
            for i in range(50)]
    assert ual.detect_mail_items_accessed_bulk(rows) == []


# ---------------------------------------------------------------------------
# Detector 3: OAuth consent grant
# ---------------------------------------------------------------------------

def test_oauth_consent_fires_on_consent_operation():
    rows = [_ual_record("Consent to application",
                         workload="AzureActiveDirectory")]
    hits = ual.detect_oauth_consent_grant(rows)
    assert hits
    assert ("T1528", "Steal Application Access Token") in hits[0].attack


def test_oauth_consent_fires_on_permission_grant_variants():
    for op in ("Add OAuth2PermissionGrant",
                "Add delegated permission grant"):
        rows = [_ual_record(op, workload="AzureActiveDirectory")]
        assert ual.detect_oauth_consent_grant(rows), \
            f"detector missed {op!r}"


def test_oauth_consent_silent_on_normal_ops():
    rows = [_ual_record("FileAccessed"),
            _ual_record("UserLoggedIn"),
            _ual_record("MailItemsAccessed")]
    assert ual.detect_oauth_consent_grant(rows) == []


# ---------------------------------------------------------------------------
# Detector 4: UserLoginFailed burst
# ---------------------------------------------------------------------------

def test_userloginfailed_brute_fires_per_user():
    rows = [_ual_record("UserLoginFailed", user_id="ceo@corp.example")
            for _ in range(12)]
    hits = ual.detect_userlogin_failed_burst(rows)
    assert any(h.technique == "signin_brute" for h in hits)


def test_userloginfailed_spray_fires_per_source_ip():
    rows = [_ual_record("UserLoginFailed",
                         user_id=f"u{i}@corp.example",
                         client_ip="198.51.100.7")
            for i in range(6)]
    hits = ual.detect_userlogin_failed_burst(rows)
    spray = [h for h in hits if h.technique == "signin_spray"]
    assert spray


# ---------------------------------------------------------------------------
# run_all + sniffer + agent dispatch
# ---------------------------------------------------------------------------

def test_run_all_combines(tmp_path):
    p = tmp_path / "ual.json"
    _write_log(p, [
        _rule_record("attacker@evil.example"),
        *[_ual_record("MailItemsAccessed", user_id="victim@corp.example")
          for _ in range(55)],
        _ual_record("Consent to application"),
        *[_ual_record("UserLoginFailed", user_id="ceo@corp.example")
          for _ in range(12)],
    ])
    records, hits = ual.run_all(p, tenant_domains={"corp.example"})
    techniques = {h.technique for h in hits}
    assert "inbox_rule_forward_external" in techniques
    assert "mail_items_accessed_bulk" in techniques
    assert "oauth_consent_grant" in techniques
    assert "signin_brute" in techniques


def test_looks_like_ual_positive():
    sample = b'[{"Operation":"UserLoggedIn","Workload":"AzureActiveDirectory","AuditData":"{}"}]'
    assert ual.looks_like_ual(sample)


def test_looks_like_ual_negative_for_cloudtrail():
    sample = b'{"Records":[{"eventName":"ConsoleLogin","eventSource":"x"}]}'
    assert not ual.looks_like_ual(sample)


def test_agent_routes_ual_input(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.cloud_forensicator import CloudForensicatorAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ual.json"
    _write_log(src, [
        _rule_record("attacker@evil.example"),
        _ual_record("Consent to application"),
    ])
    m = intake_mod.intake(src, case_id="t-ual")
    with open_ledger(m.case_dir):
        pass
    ctx = AgentContext(case_id="t-ual", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__)
    ctx.shared["tenant_domains"] = ["corp.example"]
    findings = CloudForensicatorAgent().run(ctx)
    claims = [f.claim for f in findings]
    assert any("M365 UAL record" in c for c in claims)
    assert any("inbox_rule_forward_external" in c.lower() for c in claims)
    # BEC persistence hypothesis lifted
    assert any("H_BEC_ACCOUNT_TAKEOVER" in f.hypotheses_supported
               for f in findings)

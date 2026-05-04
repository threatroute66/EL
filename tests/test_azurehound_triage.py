"""AzureHound triage skill — unit tests.

Synthetic AzureHound JSON fixtures verify role-assignment detection,
external-guest flagging, OAuth-grant scope screening, and dump-shape
heuristics.
"""
import json
import zipfile
from pathlib import Path

import pytest

from el.skills import azurehound_triage as ah


# --- _iter_records: top-level forms -------------------------------------

def test_iter_records_array_form(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps([
        {"kind": "AZUser", "data": {"id": "u1"}},
        {"kind": "AZGroup", "data": {"id": "g1"}},
    ]))
    out = list(ah._iter_records(p))
    assert len(out) == 2
    assert out[0]["kind"] == "AZUser"


def test_iter_records_data_wrapped_dict(tmp_path):
    """AzureHound's `{"data": [...], "meta": {...}}` form."""
    p = tmp_path / "b.json"
    p.write_text(json.dumps({
        "data": [{"kind": "AZUser", "data": {"id": "u1"}}],
        "meta": {"count": 1},
    }))
    out = list(ah._iter_records(p))
    assert len(out) == 1
    assert out[0]["kind"] == "AZUser"


def test_iter_records_jsonl_form(tmp_path):
    p = tmp_path / "c.jsonl"
    p.write_text(
        json.dumps({"kind": "AZUser", "data": {"id": "u1"}}) + "\n"
        + json.dumps({"kind": "AZGroup", "data": {"id": "g1"}}) + "\n"
    )
    out = list(ah._iter_records(p))
    assert len(out) == 2


def test_iter_records_directory(tmp_path):
    (tmp_path / "users.json").write_text(json.dumps(
        [{"kind": "AZUser", "data": {"id": "u1"}}]))
    (tmp_path / "groups.json").write_text(json.dumps(
        [{"kind": "AZGroup", "data": {"id": "g1"}}]))
    out = sorted((r["kind"] for r in ah._iter_records(tmp_path)))
    assert out == ["AZGroup", "AZUser"]


def test_iter_records_zip_archive(tmp_path):
    archive = tmp_path / "ah.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("users.json", json.dumps([
            {"kind": "AZUser", "data": {"id": "u1"}},
        ]))
        zf.writestr("groups.json", json.dumps([
            {"kind": "AZGroup", "data": {"id": "g1"}},
        ]))
    out = sorted((r["kind"] for r in ah._iter_records(archive)))
    assert out == ["AZGroup", "AZUser"]


def test_iter_records_returns_nothing_for_missing_path(tmp_path):
    assert list(ah._iter_records(tmp_path / "nope.json")) == []


# --- _is_external_guest ------------------------------------------------

def test_is_external_guest_via_user_type():
    assert ah._is_external_guest({"userType": "Guest"})
    assert not ah._is_external_guest({"userType": "Member"})


def test_is_external_guest_via_upn():
    assert ah._is_external_guest({
        "userPrincipalName": "alice_contoso.com#EXT#@example.onmicrosoft.com"
    })


# --- triage: privileged role assignment detection -----------------------

def test_triage_detects_global_admin(tmp_path):
    records = [
        {"kind": "AZUser", "data": {"id": "u1", "displayName": "Alice",
                                       "userPrincipalName": "alice@e.com"}},
        {"kind": "AZRoleAssignment", "data": {
            "principalId": "u1",
            "roleName": "Global Administrator",
            "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10",
        }},
    ]
    dump = tmp_path / "dump.json"
    dump.write_text(json.dumps(records))
    result = ah.triage(dump)
    assert result.record_count == 2
    assert len(result.privileged_assignments) == 1
    a = result.privileged_assignments[0]
    assert a.principal_id == "u1"
    assert a.role_name == "Global Administrator"
    assert a.principal_kind == "user"
    assert a.is_external_guest is False


def test_triage_flags_external_guest_admin(tmp_path):
    records = [
        {"kind": "AZUser", "data": {
            "id": "u_guest", "displayName": "Mallory",
            "userPrincipalName": "mallory_external.com#EXT#@e.onmicrosoft.com",
            "userType": "Guest",
        }},
        {"kind": "AZRoleAssignment", "data": {
            "principalId": "u_guest",
            "roleName": "Application Administrator",
        }},
    ]
    dump = tmp_path / "guest.json"
    dump.write_text(json.dumps(records))
    result = ah.triage(dump)
    assert len(result.privileged_assignments) == 1
    a = result.privileged_assignments[0]
    assert a.is_external_guest


def test_triage_ignores_non_privileged_roles(tmp_path):
    records = [
        {"kind": "AZUser", "data": {"id": "u1"}},
        {"kind": "AZRoleAssignment", "data": {
            "principalId": "u1",
            "roleName": "Reports Reader",   # not on privileged list
        }},
    ]
    dump = tmp_path / "low.json"
    dump.write_text(json.dumps(records))
    result = ah.triage(dump)
    assert result.privileged_assignments == []


def test_triage_dedupes_repeated_assignments(tmp_path):
    records = [
        {"kind": "AZUser", "data": {"id": "u1"}},
        {"kind": "AZRoleAssignment", "data": {
            "principalId": "u1", "roleName": "Global Administrator"}},
        {"kind": "AZRoleAssignment", "data": {
            "principalId": "u1", "roleName": "Global Administrator"}},
    ]
    dump = tmp_path / "dup.json"
    dump.write_text(json.dumps(records))
    result = ah.triage(dump)
    assert len(result.privileged_assignments) == 1


# --- triage: risky OAuth grants ----------------------------------------

def test_triage_detects_high_risk_oauth(tmp_path):
    records = [
        {"kind": "AZOAuth2PermissionGrant", "data": {
            "clientId": "app-evil",
            "displayName": "EvilApp",
            "consentType": "AllPrincipals",
            "scope": "Mail.Read Mail.ReadWrite User.Read",
        }},
    ]
    dump = tmp_path / "oauth.json"
    dump.write_text(json.dumps(records))
    result = ah.triage(dump)
    assert len(result.risky_oauth_grants) == 1
    g = result.risky_oauth_grants[0]
    assert "Mail.Read" in g.high_risk_scopes
    assert "Mail.ReadWrite" in g.high_risk_scopes
    assert "User.Read" not in g.high_risk_scopes  # not on the high-risk list


def test_triage_skips_low_risk_oauth(tmp_path):
    records = [
        {"kind": "AZOAuth2PermissionGrant", "data": {
            "clientId": "app-benign",
            "scope": "User.Read profile email openid",
        }},
    ]
    dump = tmp_path / "benign.json"
    dump.write_text(json.dumps(records))
    result = ah.triage(dump)
    assert result.risky_oauth_grants == []


# --- looks_like_azurehound_dump ----------------------------------------

def test_looks_like_dump_for_real_shape(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps([
        {"kind": "AZUser", "data": {"id": "u1"}},
    ]))
    assert ah.looks_like_azurehound_dump(p)


def test_looks_like_dump_false_for_other_json(tmp_path):
    p = tmp_path / "rando.json"
    p.write_text(json.dumps({"hello": "world"}))
    assert not ah.looks_like_azurehound_dump(p)


def test_looks_like_dump_directory(tmp_path):
    (tmp_path / "x.json").write_text(json.dumps([
        {"kind": "AZGroup", "data": {"id": "g1"}}
    ]))
    assert ah.looks_like_azurehound_dump(tmp_path)


# --- as_evidence shape -------------------------------------------------

def test_result_as_evidence_shape(tmp_path):
    dump = tmp_path / "dump.json"
    dump.write_text(json.dumps([{"kind": "AZUser", "data": {"id": "u"}}]))
    result = ah.AzureHoundResult(
        input_path=dump, record_count=1,
        privileged_assignments=[
            ah.PrivilegedAssignment(
                principal_id="u", principal_name="Alice",
                principal_kind="user", role_name="Global Administrator",
            ),
        ],
        risky_oauth_grants=[],
        distinct_kinds={"AZUser": 1},
        output_sha256="d" * 64,
    )
    ev = result.as_evidence()
    assert ev.tool == "azurehound_triage"
    assert ev.output_sha256 == "d" * 64
    assert ev.extracted_facts["privileged_assignment_count"] == 1
    assert ev.extracted_facts["external_guest_admin_count"] == 0


def test_triage_raises_for_missing_input(tmp_path):
    with pytest.raises(ah.AzureHoundError):
        ah.triage(tmp_path / "nope.json")

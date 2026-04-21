"""Cloud-breadth tests: Azure Activity + GCP Cloud Audit + AWS VPC
Flow parsers, detectors, and cloud_forensicator dispatch."""
import json
from pathlib import Path

import pytest

from el.skills import azure_activity as az_act
from el.skills import gcp_audit as gcp
from el.skills import vpc_flow_log as vpc


# ---------------------------------------------------------------------------
# Azure Activity Logs
# ---------------------------------------------------------------------------

def _az_activity_record(operation: str, **kw) -> dict:
    rec = {
        "eventTimestamp": kw.pop("ts", "2024-01-01T10:00:00Z"),
        "operationName": {"value": operation,
                           "localizedValue": operation},
        "caller": kw.pop("caller", "admin@corp.example"),
        "properties": kw.pop("properties", {}),
        "resourceProviderName": {"value": "Microsoft.Example"},
        "subscriptionId": "sub-guid",
    }
    rec.update(kw)
    return rec


def _write(path: Path, records) -> None:
    path.write_text(json.dumps(records))


def test_az_privileged_role_assignment_fires(tmp_path):
    p = tmp_path / "a.json"
    _write(p, [
        _az_activity_record(
            "Microsoft.Authorization/roleAssignments/write",
            properties={"roleName": "Global Administrator"}),
    ])
    _, hits = az_act.run_all(p)
    assert any(h.technique == "privileged_role_assignment" for h in hits)


def test_az_nsg_open_to_world_fires_on_any_source(tmp_path):
    p = tmp_path / "a.json"
    _write(p, [
        _az_activity_record(
            "Microsoft.Network/networkSecurityGroups/securityRules/write",
            properties={"requestBody": json.dumps({
                "sourceAddressPrefix": "*",
                "destinationPortRange": "3389",
            })}),
    ])
    _, hits = az_act.run_all(p)
    assert any(h.technique == "nsg_open_to_world" for h in hits)


def test_az_keyvault_bulk_access_requires_many_secrets(tmp_path):
    records = [
        _az_activity_record(
            "Microsoft.KeyVault/vaults/secrets/read",
            caller="attacker@corp.example",
            properties={"id": f"https://vault/secrets/s{i}"})
        for i in range(12)
    ]
    p = tmp_path / "a.json"
    _write(p, records)
    _, hits = az_act.run_all(p)
    assert any(h.technique == "keyvault_bulk_access" for h in hits)


def test_az_resource_mass_delete_aggregates_by_principal(tmp_path):
    records = [
        _az_activity_record(
            "Microsoft.Compute/virtualMachines/delete",
            caller="wiper@corp.example")
        for _ in range(25)
    ]
    p = tmp_path / "a.json"
    _write(p, records)
    _, hits = az_act.run_all(p)
    mass = [h for h in hits if h.technique == "resource_mass_delete"]
    assert mass and mass[0].top_principals[0] == ("wiper@corp.example", 25)


def test_az_looks_like_signature_disambiguates_signin():
    # Activity log field combo
    assert az_act.looks_like_azure_activity(
        b'[{"operationName":{"value":"x"},"resourceProviderName":{"value":"y"}}]')
    # Sign-in log field combo — must NOT match activity
    assert not az_act.looks_like_azure_activity(
        b'[{"userPrincipalName":"x","appDisplayName":"y"}]')


# ---------------------------------------------------------------------------
# GCP Cloud Audit Logs
# ---------------------------------------------------------------------------

def _gcp_record(method: str, **kw) -> dict:
    rec = {
        "timestamp": kw.pop("ts", "2024-01-01T10:00:00Z"),
        "logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
        "protoPayload": {
            "methodName": method,
            "authenticationInfo": {
                "principalEmail": kw.pop("principal", "admin@corp.example")
            },
            "resourceName": kw.pop("resource", "projects/p/serviceAccount/x"),
            "request": kw.pop("request", {}),
            "status": kw.pop("status", {}),
        },
    }
    rec.update(kw)
    return rec


def test_gcp_sa_key_creation_fires(tmp_path):
    p = tmp_path / "g.json"
    _write(p, [_gcp_record(
        "google.iam.admin.v1.CreateServiceAccountKey")])
    _, hits = gcp.run_all(p)
    assert any(h.technique == "service_account_key_creation" for h in hits)


def test_gcp_iam_privileged_grant_fires(tmp_path):
    p = tmp_path / "g.json"
    _write(p, [_gcp_record(
        "SetIamPolicy",
        request={"policy": {"bindings": [
            {"role": "roles/owner", "members": ["user:attacker@corp.example"]}
        ]}}
    )])
    _, hits = gcp.run_all(p)
    assert any(h.technique == "iam_privileged_grant" for h in hits)


def test_gcp_policy_denied_burst_aggregates_by_principal(tmp_path):
    records = []
    for i in range(25):
        rec = _gcp_record("storage.objects.get",
                           principal="attacker@corp.example",
                           status={"code": "7"})
        rec["logName"] = "policy_denied"
        records.append(rec)
    p = tmp_path / "g.json"
    _write(p, records)
    _, hits = gcp.run_all(p)
    assert any(h.technique == "policy_denied_burst" for h in hits)


def test_gcp_storage_bucket_public_fires(tmp_path):
    p = tmp_path / "g.json"
    _write(p, [_gcp_record(
        "storage.setIamPermissions",
        resource="projects/_/buckets/sensitive",
        request={"policy": {"bindings": [
            {"role": "roles/storage.objectViewer",
             "members": ["allUsers"]}
        ]}}
    )])
    _, hits = gcp.run_all(p)
    assert any(h.technique == "storage_bucket_public_open" for h in hits)


def test_gcp_parser_accepts_jsonl(tmp_path):
    p = tmp_path / "g.jsonl"
    rec = _gcp_record("google.iam.admin.v1.CreateServiceAccountKey")
    p.write_text(json.dumps(rec) + "\n" + json.dumps(rec) + "\n")
    rows = gcp.parse_audit_log(p)
    assert len(rows) == 2


# ---------------------------------------------------------------------------
# AWS VPC Flow Logs
# ---------------------------------------------------------------------------

def _vpc_line(src="10.0.0.5", dst="203.0.113.10",
                srcport="54321", dstport="443",
                action="ACCEPT", bytes_="1000") -> str:
    return (f"2 123456789012 eni-abc {src} {dst} {srcport} {dstport} "
            f"6 10 {bytes_} 1700000000 1700000060 {action} OK")


def test_vpc_parses_v2_format(tmp_path):
    p = tmp_path / "vpc.txt"
    p.write_text(_vpc_line() + "\n")
    rows = vpc.parse_vpc_flow_log(p)
    assert rows
    assert rows[0]["srcaddr"] == "10.0.0.5"


def test_vpc_denied_inbound_scan_fires(tmp_path):
    lines = [_vpc_line(src="185.220.101.7",
                         dst="10.0.0.10",
                         dstport=str(p),
                         action="REJECT")
             for p in range(1000, 1025)]
    p = tmp_path / "vpc.txt"
    p.write_text("\n".join(lines))
    _, hits = vpc.run_all(p)
    assert any(h.technique == "denied_inbound_scan" for h in hits)


def test_vpc_exfil_large_bytes_fires_per_pair(tmp_path):
    p = tmp_path / "vpc.txt"
    big = 20 * 1024 * 1024      # 20 MB per flow
    p.write_text(_vpc_line(src="10.0.0.5", dst="185.220.101.7",
                              bytes_=str(big)) + "\n")
    _, hits = vpc.run_all(p)
    assert any(h.technique == "exfil_large_bytes" for h in hits)


def test_vpc_outbound_admin_port_fires_on_ssh_to_external(tmp_path):
    p = tmp_path / "vpc.txt"
    p.write_text(_vpc_line(src="10.0.0.5", dst="185.220.101.7",
                              dstport="22", action="ACCEPT") + "\n")
    _, hits = vpc.run_all(p)
    assert any(h.technique == "outbound_admin_port" for h in hits)


def test_vpc_internal_to_internal_not_flagged_as_exfil(tmp_path):
    """Internal→internal large transfer is normal replication, not exfil."""
    p = tmp_path / "vpc.txt"
    p.write_text(_vpc_line(src="10.0.0.5", dst="10.0.0.99",
                              bytes_=str(100 * 1024 * 1024)) + "\n")
    _, hits = vpc.run_all(p)
    assert not any(h.technique == "exfil_large_bytes" for h in hits)


def test_vpc_looks_like_positive_and_negative():
    assert vpc.looks_like_vpc_flow_log(
        b"2 123 eni-abc 10.0.0.5 203.0.113.1 54321 443 6 10 1000 1 2 ACCEPT OK\n")
    # CloudTrail-looking input must not misroute
    assert not vpc.looks_like_vpc_flow_log(
        b'{"Records":[{"eventName":"ConsoleLogin"}]}')


# ---------------------------------------------------------------------------
# Agent dispatch — cloud_forensicator routes each input correctly
# ---------------------------------------------------------------------------

def _make_ctx(tmp_path, monkeypatch, case_id, input_path: Path):
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    m = intake_mod.intake(input_path, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=input_path, manifest=m.__dict__)


def test_agent_routes_azure_activity(tmp_path, monkeypatch):
    from el.agents.cloud_forensicator import CloudForensicatorAgent

    src = tmp_path / "azure_act.json"
    _write(src, [_az_activity_record(
        "Microsoft.Authorization/roleAssignments/write",
        properties={"roleName": "Global Administrator"})])
    ctx = _make_ctx(tmp_path, monkeypatch, "t-az-act", src)
    findings = CloudForensicatorAgent().run(ctx)
    claims = [f.claim for f in findings]
    assert any("Azure Activity Log record" in c for c in claims)
    assert any("privileged_role_assignment" in c.lower() for c in claims)


def test_agent_routes_gcp_audit(tmp_path, monkeypatch):
    from el.agents.cloud_forensicator import CloudForensicatorAgent

    src = tmp_path / "gcp.json"
    _write(src, [_gcp_record(
        "google.iam.admin.v1.CreateServiceAccountKey")])
    ctx = _make_ctx(tmp_path, monkeypatch, "t-gcp", src)
    findings = CloudForensicatorAgent().run(ctx)
    claims = [f.claim for f in findings]
    assert any("GCP Cloud Audit Log record" in c for c in claims)
    assert any("service_account_key_creation" in c.lower() for c in claims)


def test_agent_routes_vpc_flow(tmp_path, monkeypatch):
    from el.agents.cloud_forensicator import CloudForensicatorAgent

    src = tmp_path / "vpc.txt"
    lines = [_vpc_line(src="185.220.101.7", dst="10.0.0.10",
                         dstport=str(p), action="REJECT")
             for p in range(1000, 1030)]
    src.write_text("\n".join(lines))
    ctx = _make_ctx(tmp_path, monkeypatch, "t-vpc", src)
    findings = CloudForensicatorAgent().run(ctx)
    claims = [f.claim for f in findings]
    assert any("AWS VPC Flow Log" in c for c in claims)
    assert any("denied_inbound_scan" in c.lower() for c in claims)

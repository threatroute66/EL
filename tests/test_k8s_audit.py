"""Tests for the Kubernetes audit-log triage skill."""
from __future__ import annotations

import json
from pathlib import Path

from el.skills import k8s_audit as k8s


def _write_ndjson(path: Path, events: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")


def _event(**kw) -> dict:
    base = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "Metadata",
        "auditID": kw.pop("auditID", "auid-test"),
        "stage": "ResponseComplete",
        "requestURI": "/api/v1/pods",
        "verb": "get",
        "user": {"username": "system:node:n1", "groups": []},
        "sourceIPs": ["192.168.1.10"],
        "userAgent": "kubectl/v1.26",
        "objectRef": {"resource": "pods"},
        "responseStatus": {"code": 200},
        "requestReceivedTimestamp": "2026-04-23T00:00:00Z",
        "stageTimestamp": "2026-04-23T00:00:00.1Z",
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# Triage sniffer
# ---------------------------------------------------------------------------

def test_looks_like_k8s_audit_positive(tmp_path):
    p = tmp_path / "a.log"
    _write_ndjson(p, [_event()])
    assert k8s.looks_like_k8s_audit(p)


def test_looks_like_k8s_audit_negative_cloudtrail(tmp_path):
    p = tmp_path / "ct.json"
    p.write_text(json.dumps({"eventVersion": "1.08",
                              "eventName": "AssumeRole",
                              "eventSource": "sts.amazonaws.com"}))
    assert not k8s.looks_like_k8s_audit(p)


def test_looks_like_k8s_audit_negative_empty(tmp_path):
    p = tmp_path / "x.log"
    p.write_text("")
    assert not k8s.looks_like_k8s_audit(p)


# ---------------------------------------------------------------------------
# Anomaly detectors
# ---------------------------------------------------------------------------

def test_anonymous_probe_alone_does_not_fire(tmp_path):
    """Health-check probes from system:anonymous are benign."""
    p = tmp_path / "a.log"
    _write_ndjson(p, [
        _event(user={"username": "system:anonymous"},
                requestURI="/livez", objectRef={}, auditID="a1"),
        _event(user={"username": "system:anonymous"},
                requestURI="/readyz", objectRef={}, auditID="a2"),
    ])
    run = k8s.run_all(p)
    assert not any(a.anomaly_id == "ANONYMOUS_NON_PROBE"
                    for a in run.anomalies)


def test_anonymous_to_non_probe_endpoint_fires(tmp_path):
    p = tmp_path / "a.log"
    _write_ndjson(p, [
        _event(user={"username": "system:anonymous"},
                requestURI="/api/v1/secrets",
                objectRef={"resource": "secrets"},
                auditID="a1"),
    ])
    run = k8s.run_all(p)
    hit = next((a for a in run.anomalies
                if a.anomaly_id == "ANONYMOUS_NON_PROBE"), None)
    assert hit is not None
    assert hit.confidence == "high"


def test_pod_exec_fires(tmp_path):
    p = tmp_path / "a.log"
    _write_ndjson(p, [
        _event(verb="create",
                objectRef={"resource": "pods", "subresource": "exec",
                            "namespace": "prod", "name": "web-7"},
                auditID="a1"),
    ])
    run = k8s.run_all(p)
    hit = next((a for a in run.anomalies if a.anomaly_id == "POD_EXEC"),
                None)
    assert hit is not None
    assert "T1609" in [t for t, _ in hit.attack]


def test_cluster_admin_binding_fires(tmp_path):
    p = tmp_path / "a.log"
    _write_ndjson(p, [
        _event(verb="create",
                objectRef={"resource": "clusterrolebindings",
                            "name": "evil-crb"},
                requestObject={
                    "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                    "subjects": [{"kind": "ServiceAccount",
                                   "namespace": "default",
                                   "name": "pwn"}],
                },
                auditID="crb-1"),
    ])
    run = k8s.run_all(p)
    hit = next((a for a in run.anomalies
                if a.anomaly_id == "CLUSTER_ADMIN_BINDING"), None)
    assert hit is not None
    assert "ServiceAccount:default/pwn" in hit.facts["targets"]


def test_impersonation_fires(tmp_path):
    p = tmp_path / "a.log"
    _write_ndjson(p, [
        _event(user={"username": "alice"},
                impersonatedUser={"username": "admin"},
                auditID="imp-1"),
    ])
    run = k8s.run_all(p)
    hit = next((a for a in run.anomalies if a.anomaly_id == "IMPERSONATION"),
                None)
    assert hit is not None
    assert hit.confidence == "high"


def test_bulk_secret_access_fires_on_human_identity(tmp_path):
    p = tmp_path / "a.log"
    events = [_event(user={"username": "attacker"}, verb="get",
                      objectRef={"resource": "secrets",
                                  "namespace": "default",
                                  "name": f"sec-{i}"},
                      auditID=f"s{i}")
              for i in range(60)]
    _write_ndjson(p, events)
    run = k8s.run_all(p)
    hit = next((a for a in run.anomalies
                if a.anomaly_id == "BULK_SECRET_ACCESS"), None)
    assert hit is not None
    assert hit.confidence == "high"


def test_bulk_secret_access_downgraded_during_rbac_provisioning(tmp_path):
    """kubernetes-admin reading many secrets WHILE simultaneously doing
    heavy RBAC mutation is Helm install/uninstall — not credential access.
    Cross-signal suppression should drop confidence to medium."""
    p = tmp_path / "a.log"
    events = []
    # Heavy RBAC mutation window
    for i in range(40):
        events.append(_event(user={"username": "kubernetes-admin"},
                              verb="create",
                              objectRef={"resource": "clusterroles",
                                          "name": f"r-{i}"},
                              auditID=f"rbac{i}"))
    # Wide secret read
    for i in range(60):
        events.append(_event(user={"username": "kubernetes-admin"},
                              verb="get",
                              objectRef={"resource": "secrets",
                                          "namespace": "default",
                                          "name": f"sec-{i}"},
                              auditID=f"sec{i}"))
    _write_ndjson(p, events)
    run = k8s.run_all(p)
    hit = next((a for a in run.anomalies
                if a.anomaly_id == "BULK_SECRET_ACCESS"), None)
    assert hit is not None
    assert hit.confidence == "medium"


def test_bulk_secret_access_operator_confidence_medium(tmp_path):
    """Operator/controller reading many secrets is lower-confidence —
    reconciliation loops legitimately read lots of TLS assets."""
    p = tmp_path / "a.log"
    events = [_event(
        user={"username": "system:serviceaccount:ns:prometheus-operator"},
        verb="get",
        objectRef={"resource": "secrets",
                    "namespace": "monitoring",
                    "name": f"tls-asset-{i}"},
        auditID=f"o{i}")
        for i in range(60)]
    _write_ndjson(p, events)
    run = k8s.run_all(p)
    hit = next((a for a in run.anomalies
                if a.anomaly_id == "BULK_SECRET_ACCESS"), None)
    assert hit is not None
    assert hit.confidence == "medium"


def test_rbac_balanced_churn_does_not_fire(tmp_path):
    """Benign Helm install+uninstall = balanced create/delete — suppress."""
    p = tmp_path / "a.log"
    events = []
    for i in range(60):
        events.append(_event(user={"username": "kubernetes-admin"},
                              verb="create",
                              objectRef={"resource": "clusterroles",
                                          "name": f"r-{i}"},
                              auditID=f"c{i}"))
        events.append(_event(user={"username": "kubernetes-admin"},
                              verb="delete",
                              objectRef={"resource": "clusterroles",
                                          "name": f"r-{i}"},
                              auditID=f"d{i}"))
    _write_ndjson(p, events)
    run = k8s.run_all(p)
    assert not any(a.anomaly_id == "RBAC_MUTATION_SPIKE"
                    for a in run.anomalies)


def test_rbac_net_create_domination_fires(tmp_path):
    """Net-create dominance = persistence establishment."""
    p = tmp_path / "a.log"
    events = [_event(user={"username": "attacker"}, verb="create",
                      objectRef={"resource": "clusterrolebindings",
                                  "name": f"binding-{i}"},
                      auditID=f"c{i}")
              for i in range(150)]
    _write_ndjson(p, events)
    run = k8s.run_all(p)
    hit = next((a for a in run.anomalies
                if a.anomaly_id == "RBAC_MUTATION_SPIKE"), None)
    assert hit is not None


def test_external_source_ip_fires(tmp_path):
    p = tmp_path / "a.log"
    _write_ndjson(p, [
        _event(sourceIPs=["203.0.113.99"], auditID="ext-1"),
    ])
    run = k8s.run_all(p)
    hit = next((a for a in run.anomalies
                if a.anomaly_id == "EXTERNAL_SOURCE_IP"), None)
    assert hit is not None


def test_internal_source_ip_does_not_fire(tmp_path):
    p = tmp_path / "a.log"
    _write_ndjson(p, [
        _event(sourceIPs=["10.0.0.5"], auditID="int-1"),
        _event(sourceIPs=["192.168.1.20"], auditID="int-2"),
        _event(sourceIPs=["127.0.0.1"], auditID="int-3"),
    ])
    run = k8s.run_all(p)
    assert not any(a.anomaly_id == "EXTERNAL_SOURCE_IP"
                    for a in run.anomalies)


def test_forbidden_spike_fires(tmp_path):
    p = tmp_path / "a.log"
    events = [_event(user={"username": "prober"},
                      responseStatus={"code": 403},
                      auditID=f"f{i}")
              for i in range(60)]
    _write_ndjson(p, events)
    run = k8s.run_all(p)
    hit = next((a for a in run.anomalies
                if a.anomaly_id == "FORBIDDEN_SPIKE"), None)
    assert hit is not None


def test_run_all_populates_counts_and_time_range(tmp_path):
    p = tmp_path / "a.log"
    _write_ndjson(p, [_event(auditID=f"x{i}") for i in range(3)])
    run = k8s.run_all(p)
    assert run.total_events == 3
    assert run.time_min is not None
    assert run.time_max is not None
    assert "pods" in run.resource_counts

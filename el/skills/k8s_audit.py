"""Skill: Kubernetes API-server audit-log (audit.k8s.io/v1) triage.

Parses NDJSON streams of audit events and surfaces the handful of
cluster-abuse signals that matter for DFIR:

  - ANONYMOUS_NON_PROBE     system:anonymous hitting endpoints other than
                             /livez/readyz/healthz (auth bypass attempt)
  - POD_EXEC                verb exec/attach/portforward on pods (shell
                             access to workloads)
  - CLUSTER_ADMIN_BINDING   ClusterRoleBinding create tied to cluster-admin
  - IMPERSONATION           Impersonate-User / Impersonate-Group headers
  - BULK_SECRET_ACCESS      one identity reading many distinct secrets in
                             a short time (credential-access shape)
  - RBAC_MUTATION_SPIKE     many RBAC create/delete events from a single
                             identity (persistence establishment / teardown)
  - SA_TOKEN_CREATE         ServiceAccount /token subresource creation
                             (post-exploit token fabrication)
  - EXTERNAL_SOURCE_IP      sourceIP outside RFC1918 / localhost / cluster
                             CIDRs (unexpected external control-plane reach)
  - FORBIDDEN_SPIKE         403 spray by a single user (recon / probing)

Every hit carries the matching ATT&CK technique (T1078.004, T1098,
T1552, T1133, T1609) and maps to EL hypotheses. Intentionally NARROW
— stays quiet on normal cluster bootstrap churn so real incidents
stand out.
"""
from __future__ import annotations

import collections
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

from el.schemas.finding import EvidenceItem


# --- JSON signature check for triage routing ---------------------------------

def looks_like_k8s_audit(path: Path, max_bytes: int = 16384) -> bool:
    """Cheap detector for triage. Reads up to max_bytes and returns True
    if the stream contains an audit.k8s.io/v1 envelope.
    """
    try:
        head = path.read_bytes()[:max_bytes]
    except OSError:
        return False
    if b'"audit.k8s.io/' not in head:
        return False
    # Avoid false positives on CRD manifests (YAML-as-JSON) by also
    # requiring an auditID field (present on every Event).
    return b'"auditID"' in head and b'"apiVersion"' in head


# --- Core dataclasses --------------------------------------------------------

@dataclass
class K8sAuditAnomaly:
    anomaly_id: str
    summary: str
    confidence: str               # "high" / "medium" / "low"
    hypotheses: list[str] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)
    facts: dict = field(default_factory=dict)
    sample_audit_ids: list[str] = field(default_factory=list)


@dataclass
class K8sAuditRun:
    log_path: Path
    total_events: int
    time_min: str | None
    time_max: str | None
    anomalies: list[K8sAuditAnomaly]
    user_counts: dict[str, int]
    verb_counts: dict[str, int]
    resource_counts: dict[str, int]

    def as_evidence(self, facts: dict | None = None) -> EvidenceItem:
        seed = (f"{self.log_path}|{self.total_events}|"
                f"{self.time_min}|{self.time_max}").encode()
        sha = hashlib.sha256(seed).hexdigest()
        f = {"log_path": str(self.log_path),
             "total_events": self.total_events,
             "time_min_utc": self.time_min,
             "time_max_utc": self.time_max,
             "anomaly_count": len(self.anomalies),
             "anomalies_by_id": {a.anomaly_id: len(a.sample_audit_ids)
                                   for a in self.anomalies},
             "top_users": dict(list(self.user_counts.items())[:10]),
             "top_verbs": dict(list(self.verb_counts.items())[:10]),
             "top_resources": dict(list(self.resource_counts.items())[:10])}
        if facts:
            f.update(facts)
        return EvidenceItem(
            tool="el.k8s_audit", version="0.1.0",
            command=f"run_all({self.log_path.name})",
            output_sha256=sha, output_path=str(self.log_path),
            extracted_facts=f,
        )


# --- Helpers -----------------------------------------------------------------

_HEALTH_PATHS = ("/livez", "/readyz", "/healthz", "/version")
_RFC1918 = (
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^::1$"),
    re.compile(r"^fe80:"),
)


def _is_internal(ip: str) -> bool:
    return any(r.match(ip or "") for r in _RFC1918)


def _user(e: dict) -> str:
    return (e.get("user") or {}).get("username") or ""


def _resource(e: dict) -> str:
    ref = e.get("objectRef") or {}
    r = ref.get("resource", "")
    if ref.get("subresource"):
        r += f"/{ref['subresource']}"
    return r


def _iter_events(path: Path) -> Iterable[dict]:
    with path.open() as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# --- Individual detectors ----------------------------------------------------

def _detect_anonymous_non_probe(events: list[dict]) -> K8sAuditAnomaly | None:
    hits: list[dict] = []
    for e in events:
        if _user(e) != "system:anonymous":
            continue
        uri = (e.get("requestURI") or "").split("?")[0]
        if any(uri.startswith(p) or uri == p for p in _HEALTH_PATHS):
            continue
        hits.append(e)
    if not hits:
        return None
    return K8sAuditAnomaly(
        anomaly_id="ANONYMOUS_NON_PROBE",
        summary=(f"{len(hits)} anonymous request(s) to non-probe endpoint(s). "
                 f"Health probes (/livez, /readyz) are benign; anything else "
                 f"from system:anonymous is an auth-bypass attempt."),
        confidence="high",
        hypotheses=["H_C2_OR_REVERSE_SHELL"],
        attack=[("T1078.004", "Valid Accounts: Cloud Accounts")],
        facts={"hit_count": len(hits),
                "sample_uris": sorted({(h.get("requestURI") or "")[:120]
                                         for h in hits})[:5]},
        sample_audit_ids=[h.get("auditID","") for h in hits[:10]],
    )


def _detect_pod_exec(events: list[dict]) -> K8sAuditAnomaly | None:
    hits = [e for e in events
            if _resource(e) in {"pods/exec", "pods/attach",
                                 "pods/portforward"}]
    if not hits:
        return None
    pods = sorted({
        f"{(e.get('objectRef') or {}).get('namespace','-')}/"
        f"{(e.get('objectRef') or {}).get('name','?')}"
        for e in hits
    })
    users = sorted({_user(e) for e in hits})
    return K8sAuditAnomaly(
        anomaly_id="POD_EXEC",
        summary=(f"{len(hits)} pod exec/attach/portforward event(s) — "
                 f"interactive shell into workload. Users: "
                 f"{', '.join(users[:5])}. Pods: {', '.join(pods[:5])}"),
        confidence="high",
        hypotheses=["H_C2_OR_REVERSE_SHELL", "H_LATERAL_MOVEMENT"],
        attack=[("T1609", "Container Administration Command")],
        facts={"hit_count": len(hits), "users": users[:10],
                "pods": pods[:10]},
        sample_audit_ids=[e.get("auditID","") for e in hits[:10]],
    )


def _detect_cluster_admin_binding(events: list[dict]) -> K8sAuditAnomaly | None:
    hits: list[dict] = []
    for e in events:
        if _resource(e) != "clusterrolebindings":
            continue
        if e.get("verb") != "create":
            continue
        req = e.get("requestObject") or {}
        ref = (req.get("roleRef") or {})
        if ref.get("name") == "cluster-admin":
            hits.append(e)
    if not hits:
        return None
    targets = []
    for e in hits:
        req = e.get("requestObject") or {}
        for s in (req.get("subjects") or []):
            targets.append(f"{s.get('kind','?')}:{s.get('namespace','-')}/{s.get('name','?')}")
    return K8sAuditAnomaly(
        anomaly_id="CLUSTER_ADMIN_BINDING",
        summary=(f"{len(hits)} ClusterRoleBinding(s) created tying subjects "
                 f"to cluster-admin. Targets: {', '.join(targets[:5])}"),
        confidence="high",
        hypotheses=["H_CLOUD_PERSISTENCE", "H_APT_ESPIONAGE"],
        attack=[("T1098", "Account Manipulation"),
                ("T1078.004", "Valid Accounts: Cloud Accounts")],
        facts={"hit_count": len(hits), "targets": targets[:20]},
        sample_audit_ids=[e.get("auditID","") for e in hits[:10]],
    )


def _detect_impersonation(events: list[dict]) -> K8sAuditAnomaly | None:
    hits = [e for e in events if e.get("impersonatedUser")]
    if not hits:
        return None
    impersonated = sorted({
        (e.get("impersonatedUser") or {}).get("username","?") for e in hits
    })
    actors = sorted({_user(e) for e in hits})
    return K8sAuditAnomaly(
        anomaly_id="IMPERSONATION",
        summary=(f"{len(hits)} impersonated request(s). Actors: "
                 f"{', '.join(actors[:5])} → {', '.join(impersonated[:5])}. "
                 f"Impersonation is rare in normal operation; verify RBAC "
                 f"allows and the workflow is expected."),
        confidence="high",
        hypotheses=["H_APT_ESPIONAGE", "H_CLOUD_PERSISTENCE"],
        attack=[("T1078.004", "Valid Accounts: Cloud Accounts")],
        facts={"hit_count": len(hits),
                "actors": actors[:10],
                "impersonated_as": impersonated[:10]},
        sample_audit_ids=[e.get("auditID","") for e in hits[:10]],
    )


def _detect_bulk_secret_access(events: list[dict],
                                 threshold: int = 50
                                 ) -> K8sAuditAnomaly | None:
    """A single identity reading ≥ threshold DISTINCT secrets is a
    credential-access fingerprint."""
    per_user_secrets: dict[str, set[str]] = collections.defaultdict(set)
    per_user_sample: dict[str, list[str]] = collections.defaultdict(list)
    for e in events:
        if _resource(e) != "secrets":
            continue
        if e.get("verb") not in {"get", "list", "watch"}:
            continue
        u = _user(e)
        if not u:
            continue
        ref = e.get("objectRef") or {}
        key = f"{ref.get('namespace','-')}/{ref.get('name','-')}"
        per_user_secrets[u].add(key)
        if len(per_user_sample[u]) < 10:
            per_user_sample[u].append(e.get("auditID",""))
    offenders = {u: s for u, s in per_user_secrets.items()
                  if len(s) >= threshold}
    # Exclude the common operator identities whose job IS to reconcile many
    # secrets. Skim — if the offender is explicitly a controller/operator
    # SA with 'operator' or 'controller' in the name, mark medium not high.
    if not offenders:
        return None
    rows = [(u, len(s)) for u, s in offenders.items()]
    rows.sort(key=lambda r: -r[1])
    worst_user = rows[0][0]
    is_operator = ("operator" in worst_user.lower()
                    or "controller" in worst_user.lower()
                    or "cert-manager" in worst_user.lower()
                    or "prometheus" in worst_user.lower())
    # Cross-signal suppression: the same identity doing heavy RBAC mutation
    # (≥ 30 create/delete events on roles/bindings) is almost certainly
    # running cluster bootstrap / teardown — Helm install/uninstall pattern.
    # Secret reads in that window are template-rendering side effects, not
    # credential access.
    rbac_count = sum(
        1 for e in events
        if _user(e) == worst_user
        and _resource(e) in {"clusterroles", "clusterrolebindings",
                              "roles", "rolebindings"}
        and e.get("verb") in {"create", "update", "patch", "delete"}
    )
    is_provisioning = rbac_count >= 30
    if is_operator or is_provisioning:
        conf = "medium"
    else:
        conf = "high"
    if is_provisioning:
        why = (f"Same identity issued {rbac_count} RBAC mutations — "
               f"cluster bootstrap/teardown pattern, not credential access.")
    elif is_operator:
        why = "Likely operator reconcile — confidence medium."
    else:
        why = "Not an operator-shaped identity — credential-access shape."
    return K8sAuditAnomaly(
        anomaly_id="BULK_SECRET_ACCESS",
        summary=(f"{len(offenders)} identity/-ies read ≥ {threshold} "
                 f"distinct secret(s). Worst: {worst_user} "
                 f"({rows[0][1]} secrets). " + why),
        confidence=conf,
        hypotheses=["H_CREDENTIAL_ACCESS"],
        attack=[("T1552.007", "Unsecured Credentials: Container API")],
        facts={"offenders": {u: len(s) for u, s in offenders.items()},
                "threshold": threshold},
        sample_audit_ids=per_user_sample[worst_user][:10],
    )


def _detect_rbac_mutation_spike(events: list[dict],
                                  threshold: int = 100
                                  ) -> K8sAuditAnomaly | None:
    """One identity issuing ≥ threshold RBAC create/delete events is a
    persistence-establishment signal. Stays quiet on install-churn cases
    (benign Helm/charts), which typically show balanced create+delete."""
    per_user: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    per_user_audits: dict[str, list[str]] = collections.defaultdict(list)
    for e in events:
        if _resource(e) not in {"clusterrolebindings", "rolebindings",
                                 "clusterroles", "roles"}:
            continue
        verb = e.get("verb","")
        if verb not in {"create", "update", "patch", "delete"}:
            continue
        u = _user(e)
        if not u:
            continue
        per_user[u][verb] += 1
        if len(per_user_audits[u]) < 10:
            per_user_audits[u].append(e.get("auditID",""))
    offenders = {u: cnt for u, cnt in per_user.items()
                  if sum(cnt.values()) >= threshold}
    if not offenders:
        return None
    # Rule-based suppression: kubernetes-admin doing balanced create+delete
    # at equal scale is Helm install/uninstall churn, not attack. Suppress
    # when |create - delete| < 0.3 * total.
    # Only surface where the imbalance is meaningful (net-create or net-
    # delete domination).
    surfaced = {}
    for u, c in offenders.items():
        cr = c.get("create", 0) + c.get("patch", 0) + c.get("update", 0)
        de = c.get("delete", 0)
        total = cr + de
        if total < threshold:
            continue
        imbalance = abs(cr - de) / total if total else 0
        if imbalance >= 0.3:
            surfaced[u] = (cr, de, imbalance)
    if not surfaced:
        return None
    worst = max(surfaced.items(), key=lambda kv: kv[1][2])[0]
    cr, de, imb = surfaced[worst]
    return K8sAuditAnomaly(
        anomaly_id="RBAC_MUTATION_SPIKE",
        summary=(f"{len(surfaced)} identity/-ies issued imbalanced RBAC "
                 f"mutations. Worst: {worst} — {cr} create/update/patch "
                 f"vs {de} delete (imbalance {imb:.0%}). "
                 f"Net-create dominance can indicate persistence "
                 f"establishment."),
        confidence="medium",
        hypotheses=["H_CLOUD_PERSISTENCE"],
        attack=[("T1098", "Account Manipulation")],
        facts={"surfaced": {u: {"create_update_patch": v[0],
                                 "delete": v[1],
                                 "imbalance": round(v[2], 2)}
                             for u, v in surfaced.items()}},
        sample_audit_ids=per_user_audits[worst][:10],
    )


def _detect_sa_token_create(events: list[dict]) -> K8sAuditAnomaly | None:
    hits = []
    for e in events:
        ref = e.get("objectRef") or {}
        if (ref.get("resource") == "serviceaccounts"
                and ref.get("subresource") == "token"
                and e.get("verb") in {"create", "update"}):
            hits.append(e)
    if not hits:
        return None
    return K8sAuditAnomaly(
        anomaly_id="SA_TOKEN_CREATE",
        summary=(f"{len(hits)} ServiceAccount /token event(s). Normal "
                 f"during pod scheduling; bursts from a human identity "
                 f"or outside scheduler context are token-fabrication."),
        confidence="low",
        hypotheses=["H_CREDENTIAL_ACCESS"],
        attack=[("T1552.007", "Unsecured Credentials: Container API")],
        facts={"hit_count": len(hits),
                "users": sorted({_user(e) for e in hits})[:10]},
        sample_audit_ids=[e.get("auditID","") for e in hits[:10]],
    )


def _detect_external_source_ip(events: list[dict]) -> K8sAuditAnomaly | None:
    # Allow cluster-internal CIDRs (10.x is common for pod networks).
    # Only flag if the source IP is a fully public address.
    hits: list[tuple[dict, str]] = []
    for e in events:
        for ip in (e.get("sourceIPs") or []):
            if not _is_internal(ip):
                hits.append((e, ip))
                break
    if not hits:
        return None
    ips = sorted({ip for _, ip in hits})
    users = sorted({_user(e) for e, _ in hits})
    return K8sAuditAnomaly(
        anomaly_id="EXTERNAL_SOURCE_IP",
        summary=(f"{len(hits)} audit event(s) from {len(ips)} external "
                 f"IP(s). Kubernetes control-plane reachable from the "
                 f"public internet. IPs: {', '.join(ips[:5])}. "
                 f"Users: {', '.join(users[:5])}"),
        confidence="medium",
        hypotheses=["H_C2_OR_REVERSE_SHELL"],
        attack=[("T1133", "External Remote Services")],
        facts={"hit_count": len(hits),
                "external_ips": ips[:20],
                "users": users[:10]},
        sample_audit_ids=[e.get("auditID","") for e, _ in hits[:10]],
    )


def _detect_forbidden_spike(events: list[dict],
                              threshold: int = 50
                              ) -> K8sAuditAnomaly | None:
    per_user: collections.Counter = collections.Counter()
    per_user_audits: dict[str, list[str]] = collections.defaultdict(list)
    for e in events:
        if (e.get("responseStatus") or {}).get("code") != 403:
            continue
        u = _user(e)
        if not u:
            continue
        per_user[u] += 1
        if len(per_user_audits[u]) < 10:
            per_user_audits[u].append(e.get("auditID",""))
    worst = [(u, c) for u, c in per_user.items() if c >= threshold]
    if not worst:
        return None
    worst.sort(key=lambda r: -r[1])
    wu, wc = worst[0]
    return K8sAuditAnomaly(
        anomaly_id="FORBIDDEN_SPIKE",
        summary=(f"{len(worst)} identity/-ies hit ≥ {threshold} "
                 f"forbidden responses. Worst: {wu} ({wc} × 403). "
                 f"RBAC probing / discovery pattern."),
        confidence="medium",
        hypotheses=["H_BRUTE_FORCE", "H_CREDENTIAL_ACCESS"],
        attack=[("T1078.004", "Valid Accounts: Cloud Accounts")],
        facts={"forbid_counts": dict(per_user)},
        sample_audit_ids=per_user_audits[wu][:10],
    )


# --- Public entry point ------------------------------------------------------

_DETECTORS = (
    _detect_anonymous_non_probe,
    _detect_pod_exec,
    _detect_cluster_admin_binding,
    _detect_impersonation,
    _detect_bulk_secret_access,
    _detect_rbac_mutation_spike,
    _detect_sa_token_create,
    _detect_external_source_ip,
    _detect_forbidden_spike,
)


def run_all(path: Path) -> K8sAuditRun:
    events: list[dict] = list(_iter_events(path))
    total = len(events)
    time_min = time_max = None
    users: collections.Counter = collections.Counter()
    verbs: collections.Counter = collections.Counter()
    resources: collections.Counter = collections.Counter()
    for e in events:
        ts = e.get("requestReceivedTimestamp") or e.get("stageTimestamp")
        if ts:
            if time_min is None or ts < time_min:
                time_min = ts
            if time_max is None or ts > time_max:
                time_max = ts
        users[_user(e) or "-"] += 1
        verbs[e.get("verb","-")] += 1
        resources[_resource(e) or "-"] += 1
    anomalies: list[K8sAuditAnomaly] = []
    for det in _DETECTORS:
        hit = det(events)
        if hit is not None:
            anomalies.append(hit)
    return K8sAuditRun(
        log_path=path,
        total_events=total,
        time_min=time_min, time_max=time_max,
        anomalies=anomalies,
        user_counts=dict(users.most_common(20)),
        verb_counts=dict(verbs.most_common(20)),
        resource_counts=dict(resources.most_common(20)),
    )

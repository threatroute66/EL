"""Falco event-JSONL parser — runtime-behavioural detection on containers.

Parses the JSONL stream Falco (CNCF, Apache-2.0) emits when configured with
``json_output: true``. Each line is one rule-match event with priority,
output text, and structured fields. We don't try to wrap the Falco daemon
(it runs as a privileged-cluster sensor); we ingest the events the daemon
already produced.

This is a forensic-evidence parser, not an alert deduper. We surface the
high-priority rule hits (Critical / Error) and group by rule for a compact
case-level summary; ``H_CONTAINER_ESCAPE`` / ``H_K8S_PRIVILEGE_ESCALATION``
get tagged based on rule-family heuristics.

Project: https://falco.org
Event schema: https://falco.org/docs/alerts/output-formats/
"""
from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from el.schemas.finding import EvidenceItem


class FalcoEventsError(Exception):
    pass


# Rule-name substrings that Falco's bundled ruleset uses for container-
# escape behaviours. Keep CASE-INSENSITIVE for matching robustness.
_CONTAINER_ESCAPE_RULE_KEYWORDS = (
    "container escape",
    "container drift",
    "mount on suspicious filesystem",
    "write below /proc",
    "write below /sys",
    "load kernel module",
    "module loaded",
    "unprivileged delegation",
    "docker.sock",
    "containerd.sock",
    "host pid namespace",
    "host network namespace",
)

# Rule-name substrings for K8s-tier privilege-escalation behaviours.
_K8S_PRIVESC_RULE_KEYWORDS = (
    "create privileged pod",
    "create hostnetwork pod",
    "create hostpath",
    "attach to cluster-admin",
    "exec to pod",
    "service account",
    "k8s privileged",
    "k8s sensitive mount",
    "k8s rbac",
    "k8s clusterrolebinding",
)

# Falco priority levels; preserve the operational ordering.
_PRIORITY_RANK = {
    "EMERGENCY": 0, "ALERT": 1, "CRITICAL": 2, "ERROR": 3,
    "WARNING": 4, "NOTICE": 5, "INFORMATIONAL": 6, "INFO": 6,
    "DEBUG": 7,
}


@dataclass
class FalcoEvent:
    rule: str
    priority: str
    time: str
    output: str
    tags: list[str] = field(default_factory=list)
    container_id: str = ""
    container_name: str = ""
    k8s_namespace: str = ""
    k8s_pod: str = ""
    proc_cmdline: str = ""

    @classmethod
    def from_json(cls, obj: dict) -> "FalcoEvent | None":
        if not isinstance(obj, dict):
            return None
        rule = str(obj.get("rule") or "")
        if not rule:
            return None
        out_fields = obj.get("output_fields") or {}
        if not isinstance(out_fields, dict):
            out_fields = {}
        return cls(
            rule=rule,
            priority=str(obj.get("priority") or "").upper(),
            time=str(obj.get("time") or obj.get("evt.time") or "")[:64],
            output=str(obj.get("output") or "")[:500],
            tags=[str(t) for t in obj.get("tags") or []
                  if isinstance(t, (str, int))][:25],
            container_id=str(out_fields.get("container.id") or "")[:32],
            container_name=str(out_fields.get("container.name") or "")[:64],
            k8s_namespace=str(out_fields.get("k8s.ns.name") or "")[:64],
            k8s_pod=str(out_fields.get("k8s.pod.name") or "")[:64],
            proc_cmdline=str(out_fields.get("proc.cmdline") or "")[:300],
        )

    def is_container_escape(self) -> bool:
        rule_lower = self.rule.lower()
        return any(kw in rule_lower for kw in _CONTAINER_ESCAPE_RULE_KEYWORDS)

    def is_k8s_privesc(self) -> bool:
        rule_lower = self.rule.lower()
        return any(kw in rule_lower for kw in _K8S_PRIVESC_RULE_KEYWORDS)

    def severity_rank(self) -> int:
        return _PRIORITY_RANK.get(self.priority, 99)


@dataclass
class FalcoEventsResult:
    input_path: Path
    event_count: int
    events: list[FalcoEvent]
    rule_hits: dict[str, int] = field(default_factory=dict)
    priority_counts: dict[str, int] = field(default_factory=dict)
    container_escape_hits: int = 0
    k8s_privesc_hits: int = 0
    distinct_containers: int = 0
    distinct_k8s_pods: int = 0
    output_sha256: str = ""
    note: str = ""

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        # Top 10 rules by frequency for compact reporting.
        top_rules = sorted(self.rule_hits.items(),
                            key=lambda kv: -kv[1])[:10]
        return EvidenceItem(
            tool="falco_events",
            version="0.1.0",
            command=f"parse_jsonl({self.input_path.name})",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.input_path),
            extracted_facts={
                "event_count": self.event_count,
                "priority_counts": self.priority_counts,
                "top_rules": dict(top_rules),
                "container_escape_hits": self.container_escape_hits,
                "k8s_privesc_hits": self.k8s_privesc_hits,
                "distinct_containers": self.distinct_containers,
                "distinct_k8s_pods": self.distinct_k8s_pods,
                "note": self.note,
                **extra,
            },
        )

    def high_priority_events(self, max_count: int = 25) -> list[FalcoEvent]:
        """Return events at CRITICAL / ERROR priority or above, ordered."""
        ranked = [e for e in self.events if e.severity_rank() <= 3]
        return sorted(ranked, key=lambda e: e.severity_rank())[:max_count]


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    if not path.is_file():
        return "0" * 64
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _open_maybe_gz(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _iter_events(path: Path) -> Iterator[FalcoEvent]:
    """Yield FalcoEvent records from a JSONL file (or .jsonl.gz)."""
    if not path.is_file():
        return
    with _open_maybe_gz(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = FalcoEvent.from_json(obj)
            if ev:
                yield ev


def looks_like_falco_jsonl(path: Path) -> bool:
    """Heuristic: a JSONL file whose first non-empty line has ``rule`` and
    ``priority`` fields with ``output_fields`` is almost certainly Falco."""
    if not path.is_file():
        return False
    try:
        with _open_maybe_gz(path) as f:
            # Read a few lines; first one might be a comment.
            for _ in range(5):
                line = f.readline()
                if not line:
                    return False
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    return False
                if isinstance(obj, dict) and "rule" in obj and "priority" in obj:
                    return True
                return False
    except OSError:
        return False
    return False


def parse_jsonl(input_path: Path) -> FalcoEventsResult:
    """Parse a Falco event-JSONL file and aggregate.

    Args:
        input_path: ``falco_events.jsonl`` or ``.jsonl.gz``.
    """
    input_path = Path(input_path)
    if not input_path.is_file():
        raise FalcoEventsError(f"input not found: {input_path}")

    events: list[FalcoEvent] = []
    rule_hits: dict[str, int] = {}
    priority_counts: dict[str, int] = {}
    container_escape_hits = 0
    k8s_privesc_hits = 0
    container_ids: set[str] = set()
    k8s_pods: set[str] = set()

    for ev in _iter_events(input_path):
        events.append(ev)
        rule_hits[ev.rule] = rule_hits.get(ev.rule, 0) + 1
        prio = ev.priority or "UNKNOWN"
        priority_counts[prio] = priority_counts.get(prio, 0) + 1
        if ev.is_container_escape():
            container_escape_hits += 1
        if ev.is_k8s_privesc():
            k8s_privesc_hits += 1
        if ev.container_id:
            container_ids.add(ev.container_id)
        if ev.k8s_pod:
            k8s_pods.add(f"{ev.k8s_namespace}/{ev.k8s_pod}")

    return FalcoEventsResult(
        input_path=input_path,
        event_count=len(events),
        events=events,
        rule_hits=rule_hits,
        priority_counts=priority_counts,
        container_escape_hits=container_escape_hits,
        k8s_privesc_hits=k8s_privesc_hits,
        distinct_containers=len(container_ids),
        distinct_k8s_pods=len(k8s_pods),
        output_sha256=_sha256_path(input_path),
    )

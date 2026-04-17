"""Skill: AWS CloudTrail JSON parser.

Offline analysis only — no AWS API calls. CloudTrail can be delivered as
a single JSON file with a 'Records' array, or as line-delimited JSON,
or as multiple files in a directory. We accept all three.

Surfaces high-value events: ConsoleLogin, AssumeRole, CreateAccessKey,
PutBucketPolicy, PutObject (data exfil), iam:Create*, sts:GetCallerIdentity.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from el.schemas.finding import EvidenceItem


HIGH_VALUE_EVENTS = {
    "ConsoleLogin", "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
    "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey",
    "CreateUser", "DeleteUser", "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutRolePolicy", "CreateLoginProfile",
    "PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy",
    "PutObjectAcl", "PutObject", "GetObject",
    "CreateNetworkAclEntry", "AuthorizeSecurityGroupIngress",
    "GetCallerIdentity",  # recon
    "DeactivateMFADevice", "DeleteMFADevice",
}


@dataclass
class CloudTrailSummary:
    out_path: Path
    record_count: int = 0
    event_counts: Counter = field(default_factory=Counter)
    high_value_events: list[dict] = field(default_factory=list)
    failed_console_logins: int = 0
    distinct_principals: set[str] = field(default_factory=set)
    distinct_source_ips: set[str] = field(default_factory=set)
    distinct_regions: set[str] = field(default_factory=set)

    def as_evidence(self) -> EvidenceItem:
        sha = hashlib.sha256(self.out_path.read_bytes()).hexdigest()
        return EvidenceItem(
            tool="el.cloudtrail", version="0.1.0",
            command=f"el.cloudtrail.parse({self.out_path.parent})",
            output_sha256=sha, output_path=str(self.out_path),
            extracted_facts={
                "record_count": self.record_count,
                "distinct_principal_count": len(self.distinct_principals),
                "distinct_source_ip_count": len(self.distinct_source_ips),
                "distinct_region_count": len(self.distinct_regions),
                "high_value_event_count": len(self.high_value_events),
                "failed_console_logins": self.failed_console_logins,
                "event_name_top10": dict(self.event_counts.most_common(10)),
            },
        )


def _open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="ignore")
    return path.open("r", errors="ignore")


def _iter_records(path: Path) -> Iterator[dict]:
    with _open_text(path) as f:
        first = f.read(2048)
    if first.lstrip().startswith("{") and '"Records"' in first:
        with _open_text(path) as f:
            data = json.load(f)
        for r in data.get("Records", []):
            yield r
        return
    with _open_text(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def parse(input_path: Path, out_dir: Path) -> CloudTrailSummary:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "cloudtrail_summary.json"
    summary = CloudTrailSummary(out_path=summary_path)

    inputs: list[Path] = []
    if input_path.is_dir():
        inputs = [p for p in input_path.rglob("*") if p.is_file() and p.suffix in (".json", ".gz")]
    else:
        inputs = [input_path]

    for p in inputs:
        try:
            for rec in _iter_records(p):
                summary.record_count += 1
                ev = rec.get("eventName")
                if ev:
                    summary.event_counts[ev] += 1
                principal = (rec.get("userIdentity") or {}).get("arn") or \
                            (rec.get("userIdentity") or {}).get("userName")
                if principal:
                    summary.distinct_principals.add(principal)
                src = rec.get("sourceIPAddress")
                if src:
                    summary.distinct_source_ips.add(src)
                region = rec.get("awsRegion")
                if region:
                    summary.distinct_regions.add(region)
                if ev == "ConsoleLogin":
                    resp = (rec.get("responseElements") or {}).get("ConsoleLogin")
                    err = rec.get("errorMessage") or rec.get("errorCode")
                    if err or resp == "Failure":
                        summary.failed_console_logins += 1
                if ev in HIGH_VALUE_EVENTS:
                    summary.high_value_events.append({
                        "time": rec.get("eventTime"),
                        "name": ev,
                        "principal": principal,
                        "src": src,
                        "region": region,
                    })
        except Exception:
            continue

    payload = {
        "record_count": summary.record_count,
        "event_counts_top50": dict(summary.event_counts.most_common(50)),
        "high_value_events": summary.high_value_events[:200],
        "failed_console_logins": summary.failed_console_logins,
        "distinct_principals": sorted(summary.distinct_principals)[:200],
        "distinct_source_ips": sorted(summary.distinct_source_ips)[:200],
        "distinct_regions": sorted(summary.distinct_regions),
    }
    summary_path.write_text(json.dumps(payload, indent=2))
    return summary

"""LinuxForensicator — consume the exports dir DiskForensicator
emits for Linux disk images, run the triage-detector suite, promote
hits into Findings.

Chained from the coordinator after DiskForensicator when
`ctx.shared["linux_artifacts_dir"]` is set (parallel to how
WindowsArtifactAgent is chained off `artifacts_dir`).

Confidence tiering per family:
  reverse_shell / credential_access / ld_so_preload — always high
    (single hit is unambiguous)
  ssh_brute / ssh_spray — high when the detector fires (thresholds
    already filter noise)
  persistence_{ssh,cron} / defense_evasion — high
  download_cradle / base64_pipe / priv_esc — medium (can be
    legitimate admin activity in isolation)
  cron_suspicious_path — medium
  ssh_authorized_keys_anomaly — medium (pentester-comment signal is
    strong; sheer key count can be noisy on shared hosts)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import linux_triage as lt


_HIGH_FAMILIES = {
    "reverse_shell", "credential_access", "ld_so_preload",
    "ssh_brute", "ssh_spray", "persistence_ssh", "persistence_cron",
    "defense_evasion",
}


class LinuxForensicatorAgent(Agent):
    name = "linux_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        exports = ctx.shared.get("linux_artifacts_dir")
        if not exports:
            # Also try a direct path the coordinator may have created
            # without going through shared-context plumbing
            default = ctx.case_dir / "exports" / "linux-artifacts"
            if default.is_dir() and any(default.rglob("*")):
                exports = default
            else:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=("LinuxForensicator: no Linux artifacts "
                           "directory produced by upstream "
                           "DiskForensicator. This case either isn't a "
                           "Linux disk image or the extraction failed."),
                ))]
        exports = Path(exports)

        hits = lt.run_all(exports)
        if not hits:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"LinuxForensicator: walked extracted artifacts at "
                       f"{exports.name}/ — no malicious-pattern / "
                       f"brute-force / preload / authorized-key / "
                       f"cron-suspicious hits. Absence of evidence; not "
                       f"evidence of absence."),
            ))]

        # Shared evidence — hash the MANIFEST.txt the extractor wrote
        manifest = exports / "MANIFEST.txt"
        sha = "0" * 64
        if manifest.is_file():
            sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

        out: list[Finding] = []
        for h in hits:
            confidence = "high" if h.family in _HIGH_FAMILIES else "medium"
            facts = {
                "family": h.family,
                "matched_pattern": h.matched_pattern,
                "event_count": h.event_count,
                "top_users": h.top_users,
                "source_files": h.source_files[:5],
                "attack_techniques": [t for t, _ in h.attack],
                "sample_text_head": h.sample_text[:200],
            }
            ev = EvidenceItem(
                tool="el.linux_triage", version="0.1.0",
                command=f"run_all({exports.name})",
                output_sha256=sha, output_path=str(manifest),
                extracted_facts=facts,
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=confidence,
                claim=(f"Linux {h.family}: {h.event_count} event(s) "
                       f"matched pattern {h.matched_pattern!r}. "
                       f"ATT&CK: "
                       f"{', '.join(t for t, _ in h.attack) or '-'}. "
                       f"Sample: {h.sample_text[:150]!r}"
                       + (f" (users: {', '.join(h.top_users[:3])})"
                          if h.top_users else "")),
                evidence=[ev],
                hypotheses_supported=lt.hypotheses_for(h.family)
                                       or ["H_APT_ESPIONAGE"],
            )))

        # utmp/wtmp/btmp binary parsing — login session forensics
        out.extend(self._analyze_utmp_family(ctx, exports))
        # systemd-journal — sshd/sudo/unit-start extraction
        out.extend(self._analyze_systemd_journal(ctx, exports))
        return out

    def _analyze_utmp_family(self, ctx: AgentContext,
                              exports: Path) -> list[Finding]:
        """Parse /var/log/wtmp + /var/log/btmp + /var/run/utmp. Emits:
          - volume finding per file
          - high-confidence brute-force finding if btmp has >= 5
            failed attempts against one account from one source
          - medium-confidence remote-root-login finding per wtmp row
          - medium credential-stuffing finding if one user auths from
            many sources
        """
        from el.skills import utmp as utmp_skill
        import hashlib
        out: list[Finding] = []
        candidates = [
            ("btmp", exports / "var" / "log" / "btmp"),
            ("wtmp", exports / "var" / "log" / "wtmp"),
            ("utmp", exports / "var" / "run" / "utmp"),
            # Some extracts route these to /exports/linux-artifacts/var/log/
            ("btmp", exports / "log" / "btmp"),
            ("wtmp", exports / "log" / "wtmp"),
        ]
        seen_paths: set[str] = set()
        btmp_records: list = []
        wtmp_records: list = []
        for kind, path in candidates:
            if not path.is_file():
                continue
            if str(path) in seen_paths:
                continue
            seen_paths.add(str(path))
            recs = utmp_skill.parse_file(path)
            if not recs:
                continue
            if kind == "btmp":
                btmp_records.extend(recs)
            elif kind == "wtmp":
                wtmp_records.extend(recs)
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            ev = EvidenceItem(
                tool="el.utmp", version="0.1.0",
                command=f"parse_file({kind}:{path.name})",
                output_sha256=sha, output_path=str(path),
                extracted_facts={
                    "kind": kind,
                    "record_count": len(recs),
                    "earliest": min((r.ts_utc for r in recs
                                       if r.ts_utc), default=""),
                    "latest": max((r.ts_utc for r in recs
                                     if r.ts_utc), default=""),
                    "distinct_users": len({r.user for r in recs
                                             if r.user}),
                    "sample": [
                        {"type": r.type_name, "user": r.user,
                         "tty": r.tty, "host": r.host,
                         "ts": r.ts_utc}
                        for r in recs[:5]
                    ],
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"{kind} parsed ({path.name}): {len(recs)} "
                       f"record(s) across "
                       f"{len({r.user for r in recs if r.user})} "
                       f"distinct user(s)."),
                evidence=[ev],
                hypotheses_supported=["H_DISK_ARTIFACTS"],
            )))

        # Brute-force bursts from btmp
        if btmp_records:
            bursts = utmp_skill.failed_auth_bursts(btmp_records, threshold=5)
            for b in bursts:
                ev = EvidenceItem(
                    tool="el.utmp", version="0.1.0",
                    command="failed_auth_bursts(btmp)",
                    output_sha256="0" * 64,
                    output_path=str(exports),
                    extracted_facts={
                        "user": b.user, "source_host": b.source_host,
                        "count": b.count,
                        "first_ts_utc": b.first_ts_utc,
                        "last_ts_utc": b.last_ts_utc,
                        "sample_ttys": b.sample_ttys,
                    },
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="high",
                    claim=(f"btmp failed-auth burst: {b.count} failed "
                           f"login(s) for user {b.user!r} from "
                           f"{b.source_host!r} between {b.first_ts_utc} "
                           f"and {b.last_ts_utc} — brute-force or "
                           f"password-spray signature."),
                    evidence=[ev],
                    hypotheses_supported=["H_BRUTE_FORCE"],
                )))

        # Root-direct-remote-logins from wtmp
        if wtmp_records:
            roots = utmp_skill.root_direct_logins(wtmp_records)
            if roots:
                ev = EvidenceItem(
                    tool="el.utmp", version="0.1.0",
                    command="root_direct_logins(wtmp)",
                    output_sha256="0" * 64,
                    output_path=str(exports),
                    extracted_facts={
                        "count": len(roots),
                        "sample": [
                            {"ts": r.ts_utc, "tty": r.tty,
                             "host": r.host or r.addr, "pid": r.pid}
                            for r in roots[:5]
                        ],
                    },
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="medium",
                    claim=(f"wtmp: {len(roots)} direct remote root "
                           f"login(s) recorded. On hardened Linux hosts "
                           f"PermitRootLogin is typically `no`; remote "
                           f"root logins indicate either relaxed sshd "
                           f"config or compromise. Sample host: "
                           f"{(roots[0].host or roots[0].addr)!r} at "
                           f"{roots[0].ts_utc}."),
                    evidence=[ev],
                    hypotheses_supported=["H_LATERAL_MOVEMENT",
                                           "H_CREDENTIAL_ACCESS"],
                )))

            # Source-diversity signal (same user, many sources)
            div = utmp_skill.source_diversity(wtmp_records)
            for user, sources in div.items():
                if len(sources) < 10:
                    continue
                ev = EvidenceItem(
                    tool="el.utmp", version="0.1.0",
                    command="source_diversity(wtmp)",
                    output_sha256="0" * 64,
                    output_path=str(exports),
                    extracted_facts={
                        "user": user,
                        "source_count": len(sources),
                        "sample_sources": sorted(sources)[:10],
                    },
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="medium",
                    claim=(f"wtmp source-diversity: user {user!r} "
                           f"authenticated from {len(sources)} distinct "
                           f"source hosts/IPs — credential-stuffing or "
                           f"access-broker pattern."),
                    evidence=[ev],
                    hypotheses_supported=["H_BRUTE_FORCE"],
                )))
        return out

    def _analyze_systemd_journal(self, ctx: AgentContext,
                                   exports: Path) -> list[Finding]:
        """Walk /var/log/journal/ + run journalctl over it; emit
        sshd + sudo findings."""
        from el.skills import systemd_journal as jnl
        out: list[Finding] = []
        journal_candidates = [
            exports / "var" / "log" / "journal",
            exports / "log" / "journal",
        ]
        journal_dir = next(
            (p for p in journal_candidates if p.is_dir()), None)
        if not journal_dir:
            return out
        entries = jnl.parse_journal_dir(journal_dir)
        if not entries:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"systemd journal directory present at "
                       f"{journal_dir.name} but `journalctl` returned "
                       f"no records (timeout / permission / "
                       f"unreadable format)."),
            ))]

        ssh_events = jnl.extract_ssh_auth(entries)
        sudo_events = jnl.extract_sudo_invocations(entries)

        # Volume finding
        ev_summary = EvidenceItem(
            tool="el.systemd_journal", version="0.1.0",
            command=f"journalctl -o json on {journal_dir.name}",
            output_sha256="0" * 64, output_path=str(journal_dir),
            extracted_facts={
                "entry_count": len(entries),
                "ssh_event_count": len(ssh_events),
                "sudo_event_count": len(sudo_events),
                "distinct_units": len(
                    {e.unit for e in entries if e.unit}),
            },
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"systemd journal parsed: {len(entries)} entry(ies), "
                   f"{len(ssh_events)} ssh auth event(s), "
                   f"{len(sudo_events)} sudo/su invocation(s)."),
            evidence=[ev_summary],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        # SSH brute-force aggregation
        failed = [s for s in ssh_events if s.kind == "failed"]
        if len(failed) >= 5:
            by_source: dict[str, int] = {}
            for s in failed:
                if s.source_host:
                    by_source[s.source_host] = (
                        by_source.get(s.source_host, 0) + 1)
            top_sources = sorted(
                by_source.items(), key=lambda kv: -kv[1])[:5]
            ev = EvidenceItem(
                tool="el.systemd_journal", version="0.1.0",
                command="extract_ssh_auth(failed filter)",
                output_sha256="0" * 64, output_path=str(journal_dir),
                extracted_facts={
                    "failed_count": len(failed),
                    "top_source_hosts": top_sources,
                    "sample_events": [
                        {"user": s.user, "src": s.source_host,
                         "ts": s.ts_utc}
                        for s in failed[:10]
                    ],
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="high",
                claim=(f"systemd-journal sshd: {len(failed)} failed "
                       f"password event(s). Top source(s): "
                       f"{', '.join(f'{h}({c})' for h, c in top_sources)}."),
                evidence=[ev],
                hypotheses_supported=["H_BRUTE_FORCE"],
            )))

        # Sudo escalations
        if sudo_events:
            root_targets = [s for s in sudo_events
                             if s.as_user == "root"]
            ev = EvidenceItem(
                tool="el.systemd_journal", version="0.1.0",
                command="extract_sudo_invocations",
                output_sha256="0" * 64, output_path=str(journal_dir),
                extracted_facts={
                    "total_events": len(sudo_events),
                    "escalations_to_root": len(root_targets),
                    "distinct_invokers": len(
                        {s.user for s in sudo_events if s.user}),
                    "sample_commands": [
                        {"user": s.user, "as_user": s.as_user,
                         "cmd": s.command[:120], "ts": s.ts_utc}
                        for s in sudo_events[:8]
                    ],
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"systemd-journal sudo: {len(sudo_events)} "
                       f"sudo/su invocation(s), {len(root_targets)} "
                       f"escalation(s) to root across "
                       f"{len({s.user for s in sudo_events if s.user})} "
                       f"distinct invoker(s)."),
                evidence=[ev],
                hypotheses_supported=["H_LIVING_OFF_THE_LAND"],
            )))
        return out

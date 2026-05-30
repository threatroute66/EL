"""MacOSForensicator — consume the exports dir DiskForensicator emits
for APFS disk images, run the macos_triage detector suite, promote
hits into Findings.

Chained from the coordinator after DiskForensicator when
`ctx.shared["macos_artifacts_dir"]` is set (parallel to how
LinuxForensicatorAgent handles ext4 and WindowsArtifactAgent handles
NTFS).

Confidence tier:
  launch_persistence_suspicious → high (plist in /tmp is unambiguous)
  shell_history_*_credential_access → high
  shell_history_*_reverse_shell → high
  everything else → medium
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import macos_triage as mt


_HIGH_FAMILIES = {
    "launch_persistence_suspicious",
    "shell_history_reverse_shell",
    "shell_history_credential_access",
    "shell_history_defense_evasion",
    "shell_history_persistence_ssh",
    "shell_history_persistence_cron",
    # macOS-only — both extremely specific (launchctl-screensharing
    # enablement + ssh-port-forward of VNC). False-positive surface
    # is essentially zero; ship at high confidence.
    "shell_history_remote_access_screensharing",
    "shell_history_tunnel_vnc",
}


class MacOSForensicatorAgent(Agent):
    name = "macos_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        # Input modes (mirrors LinuxForensicatorAgent):
        # (1) Chained from DiskForensicator with `macos_artifacts_dir`
        #     set in shared context (existing wiring)
        # (2) Triage routed evidence_kind == "macos-fs-dir" → use
        #     `ctx.input_path` directly as the extracted FS root
        # (3) CyLR macOS zip — auto-extract once into <case>/raw/cylr/,
        #     then point the detectors at the resulting tree (private/var/,
        #     System/Library/, Users/, Library/ — a macOS FS root by
        #     construction). Idempotent on re-render.
        # (4) Default fallback to `<case_dir>/exports/macos-artifacts`
        kind = ctx.shared.get("evidence_kind") or ""
        exports = ctx.shared.get("macos_artifacts_dir")
        if not exports and kind == "macos-fs-dir":
            exports = ctx.input_path
        if not exports and kind == "cylr-collection-macos":
            import zipfile
            extracted_dir = ctx.case_dir / "raw" / "cylr"
            extracted_dir.mkdir(parents=True, exist_ok=True)
            already_extracted = any(
                extracted_dir.glob("CyLR_Collection_Log_*.log"))
            if not already_extracted:
                try:
                    with zipfile.ZipFile(ctx.input_path) as zf:
                        zf.extractall(extracted_dir)
                except (zipfile.BadZipFile, OSError) as e:
                    return [self.emit(ctx, Finding(
                        case_id=ctx.case_id, agent=self.name,
                        confidence="insufficient",
                        claim=(f"CyLR zip extraction failed: {e}. "
                               "Pre-extract the archive and re-investigate "
                               "the resulting directory."),
                    ))]
            exports = extracted_dir
        if not exports:
            default = ctx.case_dir / "exports" / "macos-artifacts"
            if default.is_dir() and any(default.rglob("*")):
                exports = default
            else:
                return [self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=("MacOSForensicator: no macOS artifacts "
                           "directory produced by upstream "
                           "DiskForensicator. This case either isn't "
                           "a macOS/APFS disk image or the extraction "
                           "failed."),
                ))]
        exports = Path(exports)

        out: list[Finding] = []

        hits = mt.run_all(exports)
        if not hits:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"MacOSForensicator: walked extracted artifacts "
                       f"at {exports.name}/ — no malicious-pattern / "
                       f"persistence-plist / quarantine-anomaly / "
                       f"download-plist-suspicious hits. Absence of "
                       f"evidence; not evidence of absence."),
            )))
        else:
            manifest = exports / "MANIFEST.txt"
            sha = "0" * 64
            if manifest.is_file():
                sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

            for h in hits:
                confidence = "high" if h.family in _HIGH_FAMILIES else "medium"
                facts = {
                    "family": h.family,
                    "matched_pattern": h.matched_pattern,
                    "event_count": h.event_count,
                    "source_files": h.source_files[:5],
                    "attack_techniques": [t for t, _ in h.attack],
                    "sample_text_head": h.sample_text[:200],
                }
                ev = EvidenceItem(
                    tool="el.macos_triage", version="0.1.0",
                    command=f"run_all({exports.name})",
                    output_sha256=sha, output_path=str(manifest),
                    extracted_facts=facts,
                )
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence=confidence,
                    claim=(f"macOS {h.family}: {h.event_count} "
                           f"event(s) matched pattern {h.matched_pattern!r}. "
                           f"ATT&CK: "
                           f"{', '.join(t for t, _ in h.attack) or '-'}. "
                           f"Sample: {h.sample_text[:150]!r}"),
                    evidence=[ev],
                    hypotheses_supported=mt.hypotheses_for(h.family)
                                           or ["H_APT_ESPIONAGE"],
                )))

        # Tier 4.3 — macOS Unified Logs (tracev3) deep-dive via Mandiant's
        # parser. Runs UNCONDITIONALLY — a benign but artifact-rich Mac (no
        # malicious-pattern hit above) still has a fully parseable Unified
        # Log store, and short-circuiting here used to leave it untouched.
        # The Mandiant Rust parser runs over a string-resolvable logarchive
        # assembled from the extracted filesystem; emits a high-signal-event
        # summary finding when something fires.
        out.extend(self._run_unified_logs(ctx, exports))
        out.extend(self._run_execpolicy(ctx, exports))
        out.extend(self._run_install_log(ctx, exports))
        out.extend(self._run_apple_mail(ctx, exports))
        out.extend(self._run_network_history(ctx, exports))
        return out

    def _run_network_history(self, ctx: AgentContext,
                             exports: Path) -> list[Finding]:
        """Parse DHCP leases + Wi-Fi known networks into a movement timeline.
        Emits a grounded summary (SSIDs + leased router MACs). No-op if
        neither artifact is present."""
        from el.skills import macos_network_history as nh
        try:
            run = nh.parse(exports,
                           output_dir=ctx.case_dir / "analysis" / self.name
                           / "network_history")
        except nh.MacOSNetworkHistoryError:
            return []
        if run.total == 0:
            return []

        ssids = ", ".join(n.ssid for n in run.networks) or "-"
        routers = ", ".join(sorted({l.router_mac for l in run.leases
                                    if l.router_mac})) or "-"
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=(f"macOS network history: {len(run.networks)} known "
                   f"Wi-Fi network(s) [{ssids}]; {len(run.leases)} DHCP "
                   f"lease(s), leased router MAC(s): {routers}."),
            evidence=[run.as_evidence()],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))]

    def _run_apple_mail(self, ctx: AgentContext,
                        exports: Path) -> list[Finding]:
        """Parse the Apple Mail .emlx store into a message inventory. Emits a
        grounded summary (count + top correspondents). No-op if absent."""
        from el.skills import apple_mail as am
        root = am.find_mail_root(exports)
        if root is None:
            return []
        analysis = ctx.case_dir / "analysis" / self.name / "apple_mail"
        try:
            run = am.parse(root, output_dir=analysis)
        except am.AppleMailError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"Apple Mail parse skipped: {e}"))]
        if run.total == 0:
            return []

        corr = ", ".join(f"{a} ({n})" for a, n in run.top_correspondents(5))
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=(f"Apple Mail: {run.total} message(s) parsed from "
                   f"{root.name}/. Top correspondents: {corr or '-'}."),
            evidence=[run.as_evidence()],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))]

    def _run_execpolicy(self, ctx: AgentContext,
                         exports: Path) -> list[Finding]:
        """Parse the Gatekeeper/notarization ExecPolicy scan cache. Emits a
        grounded inventory summary plus a per-executable lead for any binary
        recorded as unsigned-and-downloaded or signed-but-invalid (the
        dropper / tampered-binary patterns). No-op if the DB isn't present."""
        from el.skills import macos_execpolicy as ep
        db = ep.find_execpolicy(exports)
        if db is None:
            return []
        analysis = ctx.case_dir / "analysis" / self.name / "execpolicy"
        try:
            run = ep.parse(db, output_dir=analysis)
        except ep.MacOSExecPolicyError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"macOS ExecPolicy parse skipped: {e}"))]
        if run.total == 0:
            return []

        out: list[Finding] = []
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=(f"macOS ExecPolicy: {run.total} executable(s) scanned by "
                   f"Gatekeeper — {len(run.unsigned)} unsigned, "
                   f"{len(run.invalid)} invalid-signature, "
                   f"{len(run.quarantined)} quarantined (downloaded)."),
            evidence=[run.as_evidence()],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        # Narrow, low-false-positive leads: a plain unsigned local interpreter
        # is benign, so only surface signed-but-invalid (revoked/tampered) or
        # unsigned-AND-quarantined (an unsigned binary that came from the net).
        strong = [m for m in run.measurements
                  if (m.is_signed is True and m.is_valid is False)
                  or (m.is_signed is False and m.is_quarantined is True)]
        for m in strong:
            why = ("signed but signature invalid/revoked"
                   if m.is_signed else "unsigned and quarantined (downloaded)")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"macOS ExecPolicy flagged {m.file_identifier!r} "
                       f"({m.bundle_identifier or 'no bundle id'}): {why}. "
                       f"cdhash={m.cdhash or '-'}, "
                       f"team={m.team_identifier or '-'}, "
                       f"first-scanned {m.scanned_utc or '?'} UTC."),
                evidence=[run.as_evidence(facts={
                    "file_identifier": m.file_identifier,
                    "cdhash": m.cdhash,
                    "is_signed": m.is_signed,
                    "is_valid": m.is_valid,
                    "is_quarantined": m.is_quarantined,
                    "scanned_utc": m.scanned_utc,
                })],
                hypotheses_supported=["H_MAC_FILELESS_AMFI_BYPASS",
                                       "H_LIVING_OFF_THE_LAND"],
            )))
        return out

    def _run_install_log(self, ctx: AgentContext,
                          exports: Path) -> list[Finding]:
        """Parse install.log into a software-install timeline. Emits a grounded
        summary (installed apps, tz/host changes). No-op if absent."""
        from el.skills import macos_install_log as il
        logs = il.find_install_logs(exports)
        if not logs:
            return []
        analysis = ctx.case_dir / "analysis" / self.name / "install_log"
        try:
            run = il.parse(logs[0], output_dir=analysis)
        except il.MacOSInstallLogError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"macOS install.log parse skipped: {e}"))]
        if not run.installed_apps and not run.durations:
            return []

        recent = ", ".join(
            f"{a.name} ({a.version})" for a in run.installed_apps[-5:]) or "-"
        tz_note = ""
        if run.tz_changed:
            tz_note = (f" Device crossed timezones (offsets "
                       f"{', '.join(o for o, _ in run.tz_offsets)}).")
        return [self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="medium",
            claim=(f"macOS install.log: {len(run.installed_apps)} app "
                   f"install(s) recorded; most recent: {recent}.{tz_note}"),
            evidence=[run.as_evidence()],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        ))]

    def _run_unified_logs(self, ctx: AgentContext,
                            exports: Path) -> list[Finding]:
        """Drive macos_unifiedlogs against the extracted filesystem.

        Prefers a freshly-assembled logarchive (diagnostics + uuidtext, so
        message strings resolve); falls back to whatever
        :func:`find_unified_logs` locates (a pre-exported ``.logarchive`` or a
        bare ``diagnostics/`` tree). No-op silently if the parser isn't
        installed or no unified-log artifacts are present."""
        from el.skills import macos_unifiedlogs as mul
        out: list[Finding] = []
        analysis = ctx.case_dir / "analysis" / self.name / "unified_logs"

        # Assemble a string-resolvable logarchive when the raw store is
        # present (returns None when there's no uuidtext table to gain from,
        # in which case we parse whatever find_unified_logs turns up).
        target = None
        try:
            target = mul.build_logarchive(exports, analysis / "logarchive")
        except (mul.MacOSUnifiedLogsError, OSError):
            target = None
        if target is None:
            target = mul.find_unified_logs(exports)
        if target is None:
            return out
        try:
            run = mul.parse(target, analysis)
        except (mul.MacOSUnifiedLogsError, OSError, TypeError, ValueError) as e:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"macOS Unified Logs parse skipped: {e}",
            )))
            return out

        ev = run.as_evidence()
        if run.event_count == 0:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=(f"macOS Unified Logs: parser ran on {target.name} "
                       f"with rc={run.rc} and produced 0 events"
                       + (f" — note: {run.note}" if run.note else "")),
                evidence=[ev],
            )))
            return out

        # Headline summary.
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"macOS Unified Logs parsed: "
                   f"{run.event_count:,} event(s) across "
                   f"{run.distinct_processes} process(es) and "
                   f"{len(run.by_subsystem)} subsystem(s); "
                   f"{run.high_signal_count} high-signal event(s) "
                   "(TCC / AMFI / Gatekeeper / Sandbox / kextd)"),
            evidence=[ev],
        )))

        # If high-signal events are present, surface a TCC/AMFI/Gatekeeper
        # cluster finding so the analyst sees the anomaly without trawling
        # the full JSONL.
        if run.high_signal_count > 0:
            samples = list(run.iter_high_signal(max_count=5))
            sample_str = ""
            if samples:
                sample_event = samples[0]
                sample_str = (f" — sample: subsystem='{sample_event.subsystem}' "
                              f"process='{sample_event.process}' "
                              f"type='{sample_event.log_type}'")
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="medium",
                claim=(f"macOS Unified Logs flagged "
                       f"{run.high_signal_count} high-signal event(s) "
                       f"(security-subsystem hits or fault/error/alert "
                       f"log-types){sample_str}"),
                evidence=[ev],
                hypotheses_supported=["H_MAC_TCC_BYPASS",
                                       "H_MAC_FILELESS_AMFI_BYPASS"],
            )))
        return out

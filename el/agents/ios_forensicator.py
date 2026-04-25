"""IOSForensicator — primary investigator for iOS filesystem tree inputs.

iOS cases arrive as already-extracted filesystem trees (checkm8 /
GrayKey / Cellebrite / advanced-logical extraction), not as block
images. No mount needed — the agent walks the input dir, runs
`extract_ios_artifacts` to produce the sealed exports subtree, then
runs `ios_triage.run_all` for detection.

Routed from Triage when `ctx.shared["evidence_kind"] == "ios-fs-dir"`
(parallel to how `android-fs-dir` routes to AndroidForensicatorAgent
and `windows-artifacts-dir` routes to WindowsArtifactAgent).

Confidence tiers:
  jailbreak_indicator → medium (informational — jailbroken ≠ compromised,
    but flips the threat model; iOS sandbox is weakened or absent)
  sideloaded_app → high (on iOS the only non-App-Store path is
    enterprise provisioning / TestFlight / dev signing — each a
    deliberate threat-model shift)
  provisioning_profile → medium (stock consumer iOS has none;
    presence = enterprise MDM or dev/sideload tooling)
  messenger_presence → low (purely informational pivot)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import ios_artifacts as ia
from el.skills import ios_triage as it


_CONFIDENCE_BY_FAMILY = {
    "jailbreak_indicator":    "medium",
    "sideloaded_app":         "high",
    "provisioning_profile":   "medium",
    "messenger_presence":     "low",
}


class IOSForensicatorAgent(Agent):
    name = "ios_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        src = ctx.input_path
        if not src.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("IOSForensicator: input is not a directory. "
                       "iOS cases arrive as file-system trees "
                       "(checkm8 / GrayKey / Cellebrite output), "
                       "not as block images."),
            ))]

        exports = ctx.case_dir / "exports" / "ios-artifacts"
        try:
            counts = ia.extract_ios_artifacts(src, exports)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"iOS extraction errored: {e}",
            ))]

        out: list[Finding] = []
        if not counts:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"IOSForensicator: walked {src.name} but no iOS "
                       f"artifacts recognised (no System/Library/"
                       f"CoreServices/SystemVersion.plist, no /private/"
                       f"var/mobile/Library/ DBs, no /private/var/"
                       f"containers/Bundle/Application/ bundles). "
                       f"Likely not an iOS filesystem tree."),
            )))
            return out

        listing = "\n".join(sorted(
            str(p.relative_to(exports))
            for p in exports.rglob("*") if p.is_file()))
        listing_path = exports / "MANIFEST.txt"
        listing_path.parent.mkdir(parents=True, exist_ok=True)
        listing_path.write_text(listing)
        summary_ev = EvidenceItem(
            tool="el.ios_artifacts", version="0.1.0",
            command=f"extract_ios_artifacts({src.name})",
            output_sha256=hashlib.sha256(listing.encode()).hexdigest(),
            output_path=str(listing_path),
            extracted_facts=counts,
        )
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"iOS artifacts extracted from {src.name}: {summary}"),
            evidence=[summary_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        hits = it.run_all(exports)
        for h in hits:
            confidence = _CONFIDENCE_BY_FAMILY.get(h.family, "medium")
            ev = EvidenceItem(
                tool="el.ios_triage", version="0.1.0",
                command=f"run_all({exports.name}, family={h.family})",
                output_sha256=summary_ev.output_sha256,
                output_path=str(listing_path),
                extracted_facts={
                    "family": h.family,
                    "matched_pattern": h.matched_pattern,
                    "event_count": h.event_count,
                    "source_files": h.source_files[:5],
                    "attack_techniques": [t for t, _ in h.attack],
                    "sample_text_head": h.sample_text[:200],
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence=confidence,
                claim=(f"iOS {h.family}: {h.event_count} signal(s); "
                       f"{h.matched_pattern}. "
                       f"ATT&CK: "
                       f"{', '.join(t for t, _ in h.attack) or '-'}. "
                       f"Sample: {h.sample_text[:150]!r}"),
                evidence=[ev],
                hypotheses_supported=it.hypotheses_for(h.family)
                                       or ["H_DISK_ARTIFACTS"],
            )))

        # iLEAPP wrap — Brignoni's 80+-artifact parser. Skips silently
        # when iLEAPP isn't installed; emits one finding per surfaced
        # high-value artifact (calls, SMS, Safari history, locations,
        # app installs, Wi-Fi). Storage cost: ~tens of MB of TSV/HTML
        # under <case_dir>/exports/ileapp/.
        out.extend(self._run_ileapp(ctx, src))
        return out

    # Per-artifact display names + confidences. iLEAPP names its TSV
    # files in a stable scheme; we surface a curated subset.
    _ILEAPP_HIGH_VALUE = {
        # filename substring → (display label, confidence, hypotheses)
        "Call History":           ("call history",        "medium", []),
        "SMS messages":           ("SMS / iMessage",      "medium", []),
        "iMessage":               ("iMessage threads",    "medium", []),
        "Calendar":               ("calendar events",     "low",    []),
        "Contacts":               ("contacts",            "low",    []),
        "Safari Browsing History": ("Safari history",     "medium", []),
        "Safari History":         ("Safari history",      "medium", []),
        "Wifi Networks":          ("Wi-Fi network history", "medium",
                                    ["H_DISK_ARTIFACTS"]),
        "WiFi":                   ("Wi-Fi network history", "medium",
                                    ["H_DISK_ARTIFACTS"]),
        "Locations":              ("location history",    "medium", []),
        "Significant Locations":  ("significant locations",
                                   "medium", []),
        "Installed Apps":         ("installed apps",      "low",
                                    ["H_DISK_ARTIFACTS"]),
        "Application State":      ("app last-state",      "low",    []),
        "Knowledge":              ("KnowledgeC events",   "low",    []),
        "Apple Pay":              ("Apple Pay transactions",
                                   "medium", []),
        "AirDrop":                ("AirDrop transfers",   "medium", []),
        "Bluetooth":              ("Bluetooth pairings",  "low",    []),
    }

    def _run_ileapp(self, ctx: AgentContext, src: Path) -> list[Finding]:
        from el.skills import ileapp as ileapp_skill
        if not ileapp_skill.is_ileapp_available():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("iLEAPP not installed at /opt/iLEAPP "
                       "(or `EL_ILEAPP_DIR`). Skipping the 80+-artifact "
                       "Brignoni parser pass; the four built-in "
                       "detectors above still ran."),
            ))]

        out_dir = ctx.case_dir / "exports" / "ileapp"
        try:
            r = ileapp_skill.run(src, out_dir)
        except ileapp_skill.ILeappError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"iLEAPP failed: {e}",
            ))]

        out: list[Finding] = []
        # One summary finding for the whole run
        populated_count = sum(1 for t in r.tables if t.populated)
        ev = EvidenceItem(
            tool="iLEAPP", version=r.version or "unknown",
            command=f"ileapp.py -t fs -i {src.name} -o {out_dir.name}",
            output_sha256=hashlib.sha256(
                r.stdout_path.read_bytes() if r.stdout_path.exists()
                else b"").hexdigest(),
            output_path=str(r.report_dir),
            extracted_facts={
                "tables": len(r.tables),
                "populated_tables": populated_count,
                "rc": r.rc,
            },
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"iLEAPP v{r.version or '?'} parsed {len(r.tables)} "
                   f"artifact module(s); {populated_count} populated. "
                   f"Report: {r.report_dir.name}"),
            evidence=[ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        # Per-artifact findings for the curated high-value subset
        for table in r.tables:
            if not table.populated:
                continue
            label, conf, hyps = (None, "low", [])
            for needle, (lbl, c, h) in self._ILEAPP_HIGH_VALUE.items():
                if needle.lower() in table.name.lower():
                    label, conf, hyps = lbl, c, h
                    break
            if label is None:
                continue   # skip non-curated tables — would flood the ledger
            sample = ""
            if table.rows:
                # First row's column-1 value is usually the most-recent
                # / first event — useful for the claim.
                cols_to_show = min(3, len(table.headers))
                sample = " | ".join(
                    table.rows[0][i] for i in range(cols_to_show)
                    if i < len(table.rows[0])
                )[:200]
            tev = EvidenceItem(
                tool="iLEAPP", version=r.version or "unknown",
                command=f"_TSV/{table.name}",
                output_sha256=hashlib.sha256(
                    table.path.read_bytes()).hexdigest(),
                output_path=str(table.path),
                extracted_facts={
                    "artifact": label, "rows": table.total_rows,
                    "headers": table.headers[:8],
                    "truncated": table.truncated,
                },
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=conf,
                claim=(f"iLEAPP {label}: {table.total_rows} row(s) "
                       f"parsed from {table.name}"
                       + (f" (sample: {sample!r})" if sample else "")
                       + (" [truncated to 5000 rows for display]"
                          if table.truncated else "")),
                evidence=[tev],
                hypotheses_supported=hyps,
            )))
        return out

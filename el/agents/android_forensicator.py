"""AndroidForensicator — primary investigator for Android filesystem
tree inputs.

Android cases typically arrive as already-extracted file-system
trees (Belkasoft output / UFED Reader export / adb pull of /data
and /storage). No mounting needed — the agent walks the input dir,
runs `extract_android_artifacts` to produce the sealed exports
subtree, then runs `android_triage.run_all` for detection.

Routed from Triage when `ctx.shared["evidence_kind"] == "android-fs-dir"`
(parallel to how `windows-artifacts-dir` routes to
WindowsArtifactAgent).

Confidence tiers:
  rooted_device → medium (informational — rooted ≠ compromised, but
    flips the threat model)
  sideloaded_apk → high (the primary delivery vector for Android
    malware in the wild)
  data_local_tmp_executable → high (attacker shell staging)
  messenger_presence → low (purely informational)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import android_artifacts as aa
from el.skills import android_triage as at


_CONFIDENCE_BY_FAMILY = {
    "rooted_device":              "medium",
    "sideloaded_apk":             "high",
    "data_local_tmp_executable":  "high",
    "messenger_presence":         "low",
}


class AndroidForensicatorAgent(Agent):
    name = "android_forensicator"

    def run(self, ctx: AgentContext) -> list[Finding]:
        src = ctx.input_path
        # ALEAPP-only path: input is a .tar/.zip/.gz archive of an
        # Android extraction (Magnet Acquire / UFED export). The
        # archive-mode wrap drives ALEAPP directly without
        # filesystem extract — the wrap handles unpacking.
        if src.is_file() and src.suffix.lower() in (
                ".tar", ".zip", ".gz"):
            return self._run_aleapp(ctx, src)
        if not src.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("AndroidForensicator: input is not a directory "
                       "or supported archive (.tar / .zip / .gz). "
                       "Android cases arrive as file-system trees "
                       "(Belkasoft / UFED / adb-pull) or as Magnet/"
                       "UFED archive bundles."),
            ))]

        exports = ctx.case_dir / "exports" / "android-artifacts"
        try:
            counts = aa.extract_android_artifacts(src, exports)
        except Exception as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"Android extraction errored: {e}",
            ))]
        out: list[Finding] = []
        if not counts:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"AndroidForensicator: walked {src.name} but no "
                       f"Android artifacts recognised (no data/system/"
                       f"packages.xml, no data/data/ per-app dirs, no "
                       f"data/adb/, no data/local/tmp/). Likely not an "
                       f"Android filesystem tree."),
            )))
            return out

        listing = "\n".join(sorted(
            str(p.relative_to(exports))
            for p in exports.rglob("*") if p.is_file()))
        listing_path = exports / "MANIFEST.txt"
        listing_path.parent.mkdir(parents=True, exist_ok=True)
        listing_path.write_text(listing)
        summary_ev = EvidenceItem(
            tool="el.android_artifacts", version="0.1.0",
            command=f"extract_android_artifacts({src.name})",
            output_sha256=hashlib.sha256(listing.encode()).hexdigest(),
            output_path=str(listing_path),
            extracted_facts=counts,
        )
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"Android artifacts extracted from {src.name}: "
                   f"{summary}"),
            evidence=[summary_ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))

        hits = at.run_all(exports)
        for h in hits:
            confidence = _CONFIDENCE_BY_FAMILY.get(h.family, "medium")
            ev = EvidenceItem(
                tool="el.android_triage", version="0.1.0",
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
                claim=(f"Android {h.family}: {h.event_count} "
                       f"signal(s); {h.matched_pattern}. "
                       f"ATT&CK: "
                       f"{', '.join(t for t, _ in h.attack) or '-'}. "
                       f"Sample: {h.sample_text[:150]!r}"),
                evidence=[ev],
                hypotheses_supported=at.hypotheses_for(h.family)
                                       or ["H_DISK_ARTIFACTS"],
            )))
        # ALEAPP wrap — Brignoni's 150+-artifact Android parser.
        # Skips silently when ALEAPP isn't installed; emits one
        # Finding per surfaced high-value artefact (contacts2,
        # mmssms, Chrome history, app-data DBs, Wi-Fi config).
        out.extend(self._run_aleapp(ctx, src))
        return out

    # ALEAPP TSV name → (display label, confidence, hypotheses).
    # Curated to high-signal artefacts so the ledger doesn't flood
    # on the 150+ tables ALEAPP can produce. Names are substring-
    # matched case-insensitive against table.name.
    _ALEAPP_HIGH_VALUE = {
        "Contacts":               ("contacts",            "low",    []),
        "SMS":                    ("SMS / MMS",           "medium", []),
        "MMS":                    ("SMS / MMS",           "medium", []),
        "Call":                   ("call history",        "medium", []),
        "Chrome":                 ("Chrome history",      "medium", []),
        "Chrome History":         ("Chrome history",      "medium", []),
        "Browser":                ("browser history",     "medium", []),
        "WhatsApp":               ("WhatsApp messages",   "medium", []),
        "Telegram":               ("Telegram messages",   "medium", []),
        "Signal":                 ("Signal messages",     "medium", []),
        "Installed Apps":         ("installed apps",      "low",
                                    ["H_DISK_ARTIFACTS"]),
        "Package":                ("package inventory",   "low",
                                    ["H_DISK_ARTIFACTS"]),
        "WiFi":                   ("Wi-Fi configuration", "medium",
                                    ["H_DISK_ARTIFACTS"]),
        "Wifi":                   ("Wi-Fi configuration", "medium",
                                    ["H_DISK_ARTIFACTS"]),
        "Bluetooth":              ("Bluetooth pairings",  "low",    []),
        "Location":               ("location history",    "medium", []),
        "Locations":              ("location history",    "medium", []),
        "Notification":           ("notification history","low",    []),
        "Logcat":                 ("logcat snapshots",    "low",    []),
    }

    def _run_aleapp(self, ctx: AgentContext, src: Path
                    ) -> list[Finding]:
        from el.skills import aleapp as aleapp_skill
        if not aleapp_skill.is_aleapp_available():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("ALEAPP not installed at /opt/ALEAPP "
                       "(or `EL_ALEAPP_DIR`). Skipping the 150+-"
                       "artifact Brignoni parser pass; the four "
                       "built-in detectors above still ran."),
            ))]
        out_dir = ctx.case_dir / "exports" / "aleapp"
        try:
            r = aleapp_skill.run(src, out_dir)
        except aleapp_skill.ALeappError as e:
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=f"ALEAPP failed: {e}",
            ))]
        out: list[Finding] = []
        populated = sum(1 for t in r.tables if t.populated)
        ev = EvidenceItem(
            tool="ALEAPP", version=r.version or "unknown",
            command=(f"aleapp.py -t {aleapp_skill.detect_mode(src)} "
                      f"-i {src.name} -o {out_dir.name}"),
            output_sha256=hashlib.sha256(
                r.stdout_path.read_bytes() if r.stdout_path.exists()
                else b"").hexdigest(),
            output_path=str(r.report_dir),
            extracted_facts={
                "tables": len(r.tables),
                "populated_tables": populated,
                "rc": r.rc,
            },
        )
        out.append(self.emit(ctx, Finding(
            case_id=ctx.case_id, agent=self.name, confidence="high",
            claim=(f"ALEAPP v{r.version or '?'} parsed "
                   f"{len(r.tables)} artefact module(s); "
                   f"{populated} populated. "
                   f"Report: {r.report_dir.name}"),
            evidence=[ev],
            hypotheses_supported=["H_DISK_ARTIFACTS"],
        )))
        for table in r.tables:
            if not table.populated:
                continue
            label, conf, hyps = (None, "low", [])
            for needle, (lbl, c, h) in self._ALEAPP_HIGH_VALUE.items():
                if needle.lower() in table.name.lower():
                    label, conf, hyps = lbl, c, h
                    break
            if label is None:
                continue
            sample = ""
            if table.rows:
                cols_to_show = min(3, len(table.headers))
                sample = " | ".join(
                    table.rows[0][i] for i in range(cols_to_show)
                    if i < len(table.rows[0])
                )[:200]
            tev = EvidenceItem(
                tool="ALEAPP", version=r.version or "unknown",
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
                claim=(f"ALEAPP {label}: {table.total_rows} row(s) "
                       f"parsed from {table.name}"
                       + (f" (sample: {sample!r})" if sample else "")
                       + (" [truncated for display]"
                          if table.truncated else "")),
                evidence=[tev],
                hypotheses_supported=hyps,
            )))
        return out

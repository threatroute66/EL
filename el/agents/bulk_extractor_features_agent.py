"""BulkExtractorFeaturesAgent — surface bulk_extractor histograms
as Findings.

Triage routes here when `evidence_kind == "bulk-extractor-output"`.
The skill walks the output dir and identifies every populated feature
recorder + carved-record bucket; this agent turns each into a
hypothesis-tagged Finding the analyst can act on.

Confidence policy
-----------------
- ``high``      — non-empty `email`, `aes_keys`, `ccn`, `evtx_carved`,
                  `winpe_carved` (small set, very high signal)
- ``medium``    — `domain` / `url` / `ip` with ≥1 unique value;
                  `exif` with content; carved subdirs with files
- ``low``       — `telephone`, `httplogs`, `json` content (often noisy)
- ``insufficient`` — scanner ran and produced nothing (kept so the
                     ledger documents what was searched)
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from el.agents.base import Agent, AgentContext
from el.schemas.finding import EvidenceItem, Finding
from el.skills import bulk_extractor_features as bef


_HIGH_FEATURES = {"email", "aes_keys", "ccn", "ccn_track2"}
_HIGH_CARVED = {"evtx_carved", "winpe_carved", "ntfsmft_carved",
                "ntfslogfile_carved"}
_MEDIUM_FEATURES = {"domain", "url", "ip", "ether", "exif", "json"}
_LOW_FEATURES = {"telephone", "httplogs", "find", "gps", "elf",
                 "alerts"}

_HYPOTHESIS_BY_FEATURE = {
    # bulk_extractor pulls credentials and crypto material from raw
    # bytes — credit-card numbers and AES keys are credential-access
    # candidates regardless of source, exposed-keys / payment-data
    # scenarios.
    "ccn":        ["H_INSIDER_DATA_EXFIL"],
    "ccn_track2": ["H_INSIDER_DATA_EXFIL"],
    "aes_keys":   ["H_CREDENTIAL_ACCESS"],
    # Email / domain / URL / IP coverage feeds the C2 + recon story
    # without committing to one hypothesis.
    "email":      ["H_BEC_ACCOUNT_TAKEOVER", "H_INSIDER_EMAIL_EXFIL"],
    "domain":     ["H_C2_BEACONING", "H_APT_ESPIONAGE"],
    "url":        ["H_C2_BEACONING", "H_APT_ESPIONAGE"],
    "ip":         ["H_C2_BEACONING"],
    "exif":       [],   # contextual, no hypothesis lift
}


class BulkExtractorFeaturesAgent(Agent):
    name = "bulk_extractor_features"

    def run(self, ctx: AgentContext) -> list[Finding]:
        out: list[Finding] = []
        if not ctx.input_path.is_dir():
            return [self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=("BulkExtractorFeaturesAgent expects a directory "
                       "input (bulk_extractor output dir)"),
            ))]

        summary = bef.summarise(ctx.input_path)

        # Per-feature findings — populated and empty alike (empty as
        # "insufficient" so the ledger records what was searched).
        for feat in summary.features.values():
            ev = self._feature_evidence(feat)
            if not feat.has_content:
                out.append(self.emit(ctx, Finding(
                    case_id=ctx.case_id, agent=self.name,
                    confidence="insufficient",
                    claim=(f"bulk_extractor `{feat.name}` scanner ran "
                           f"and produced no output. Absence of "
                           f"evidence; not evidence of absence."),
                    evidence=[ev] if ev else [],
                )))
                continue

            if feat.name in _HIGH_FEATURES:
                conf = "high"
            elif feat.name in _MEDIUM_FEATURES:
                conf = "medium"
            elif feat.name in _LOW_FEATURES:
                conf = "low"
            else:
                conf = "low"

            top_str = ", ".join(
                f"{val} (×{cnt})" for cnt, val in feat.top[:5]
            )
            claim = (
                f"bulk_extractor `{feat.name}`: "
                f"{feat.record_count} occurrence(s) across "
                f"{feat.unique_values} unique value(s)."
                + (f" Top: {top_str}." if top_str else "")
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=conf,
                claim=claim, evidence=[ev] if ev else [],
                hypotheses_supported=_HYPOTHESIS_BY_FEATURE.get(feat.name, []),
            )))

        # Carved-record findings — high-signal because successful
        # carve = slack-space recovery, often missed on the live FS.
        for carve in summary.carved.values():
            ev = self._carved_evidence(carve)
            if not carve.has_content:
                continue   # don't flood the ledger with "no carve"
            conf = "high" if carve.name in _HIGH_CARVED else "medium"
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence=conf,
                claim=(f"bulk_extractor carved `{carve.name}` records: "
                       f"{carve.record_count} TSV row(s) + "
                       f"{carve.file_count} file(s) in companion dir. "
                       f"Carved records are slack-space reconstructions "
                       f"often missed on the live filesystem."),
                evidence=[ev] if ev else [],
                hypotheses_supported=["H_ANTI_FORENSICS"]
                                     if "evtx" in carve.name or "ntfs" in carve.name
                                     else [],
            )))

        if not out:
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name,
                confidence="insufficient",
                claim=(f"BulkExtractorFeaturesAgent: input dir "
                       f"`{ctx.input_path.name}` did not contain any "
                       f"bulk_extractor canonical files."),
            )))

        # Surface the report.xml manifest as a separate evidence
        # anchor — the analyst can re-derive everything from this
        # one file plus the source image hash.
        if summary.report_xml:
            try:
                sha = hashlib.sha256(
                    summary.report_xml.read_bytes()
                ).hexdigest()
            except OSError:
                sha = "0" * 64
            ev = EvidenceItem(
                tool="bulk_extractor", version="1.6+",
                command=f"bulk_extractor … (manifest: report.xml)",
                output_sha256=sha,
                output_path=str(summary.report_xml),
                extracted_facts={"report_xml": True},
            )
            out.append(self.emit(ctx, Finding(
                case_id=ctx.case_id, agent=self.name, confidence="low",
                claim=("bulk_extractor `report.xml` manifest captured "
                       "(disk MD5, scanner versions, command line, "
                       "timing). Anchor for reproducibility."),
                evidence=[ev],
            )))

        return out

    # --- helpers ---------------------------------------------------------

    def _feature_evidence(self, feat: bef.FeatureSummary) -> EvidenceItem | None:
        target = feat.histogram_path or feat.feature_path
        if target is None:
            return None
        try:
            sha = hashlib.sha256(target.read_bytes()).hexdigest()
        except OSError:
            sha = "0" * 64
        return EvidenceItem(
            tool="bulk_extractor", version="1.6+",
            command=f"bulk_extractor → {target.name}",
            output_sha256=sha,
            output_path=str(target),
            extracted_facts={
                "feature": feat.name,
                "records": feat.record_count,
                "unique_values": feat.unique_values,
                "top_5": [v for _, v in feat.top[:5]],
            },
        )

    def _carved_evidence(self, carve: bef.CarvedSummary) -> EvidenceItem | None:
        target = carve.txt_path or carve.subdir_path
        if target is None:
            return None
        # For the subdir, hash the txt manifest if present (small);
        # the carved files themselves can be huge.
        anchor = carve.txt_path if carve.txt_path else carve.subdir_path
        try:
            if anchor and anchor.is_file():
                sha = hashlib.sha256(anchor.read_bytes()).hexdigest()
            else:
                sha = "0" * 64
        except OSError:
            sha = "0" * 64
        return EvidenceItem(
            tool="bulk_extractor", version="1.6+",
            command=f"bulk_extractor → {target.name}",
            output_sha256=sha,
            output_path=str(target),
            extracted_facts={
                "carve": carve.name,
                "records": carve.record_count,
                "files": carve.file_count,
            },
        )

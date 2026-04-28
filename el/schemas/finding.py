from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from ulid import ULID

# Cap on EvidenceItem.human_summary so it stays scannable in the
# executive (non-expert) report tier; longer prose belongs in the
# analyst track (claim + extracted_facts).
HUMAN_SUMMARY_MAX_CHARS = 200

Confidence = Literal["high", "medium", "low", "insufficient"]
RedReviewStatus = Literal["pending", "passed", "challenged", "unresolved"]
# NATO Admiralty-code source reliability (A-F) + info credibility (1-6).
# "X" is "explicitly unset" — the default for evidence not yet migrated.
SourceReliability = Literal["A", "B", "C", "D", "E", "F", "X"]
InfoCredibility = Literal["1", "2", "3", "4", "5", "6", "X"]


def _ulid() -> str:
    return str(ULID())


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceItem(BaseModel):
    tool: str
    version: str
    command: str
    output_sha256: str
    output_path: str
    extracted_facts: dict = Field(default_factory=dict)
    captured_utc: datetime = Field(default_factory=_now_utc)
    # Admiralty-code provenance pair. Defaults to "X X" (explicitly
    # unset) so untouched call sites still validate; el.intel.admiralty
    # carries the canonical tool-tier mapping for migrating callers.
    source_reliability: SourceReliability = "X"
    info_credibility: InfoCredibility = "X"
    # Plain-English restatement of what this evidence shows, for the
    # non-expert (executive) report tier. None = renderer falls back
    # to a glossary-translated version of the parent Finding.claim.
    # Capped to keep exec-tier output scannable.
    human_summary: str | None = None

    @property
    def admiralty(self) -> str:
        """Two-character Admiralty rating like ``A1`` for compact
        rendering in reports."""
        return f"{self.source_reliability}{self.info_credibility}"

    @field_validator("human_summary")
    @classmethod
    def _summary_length(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if len(v) > HUMAN_SUMMARY_MAX_CHARS:
            raise ValueError(
                f"human_summary must be ≤ {HUMAN_SUMMARY_MAX_CHARS} chars "
                f"(got {len(v)}); long prose belongs in the analyst tier."
            )
        return v


class RedReview(BaseModel):
    status: RedReviewStatus = "pending"
    challenger_notes: str = ""
    disconfirming_checklist: list[str] = Field(default_factory=list)
    resolved_items: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    finding_id: str = Field(default_factory=_ulid)
    case_id: str
    agent: str
    claim: str
    confidence: Confidence
    evidence: list[EvidenceItem] = Field(default_factory=list)
    hypotheses_supported: list[str] = Field(default_factory=list)
    hypotheses_refuted: list[str] = Field(default_factory=list)
    ach_score_delta: dict[str, int] = Field(default_factory=dict)
    red_review: RedReview = Field(default_factory=RedReview)
    created_utc: datetime = Field(default_factory=_now_utc)
    # Device tag for multi-host bundle cases. None = single-host case
    # (the default; existing behaviour). When a bundle's synthesis
    # pass copies a device's findings into the bundle ledger, it
    # stamps each one with the device label so the executive report
    # can group findings by device. Optional + backwards-compatible.
    device: str | None = None

    @field_validator("agent", "claim", "case_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must be non-empty")
        return v

    @model_validator(mode="after")
    def _evidence_required_unless_insufficient(self) -> "Finding":
        if self.confidence != "insufficient" and not self.evidence:
            raise ValueError(
                "evidence[] is required for any confidence other than 'insufficient'. "
                "If you cannot ground the claim, set confidence='insufficient'."
            )
        return self

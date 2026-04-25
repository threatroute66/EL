from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from ulid import ULID

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

    @property
    def admiralty(self) -> str:
        """Two-character Admiralty rating like ``A1`` for compact
        rendering in reports."""
        return f"{self.source_reliability}{self.info_credibility}"


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

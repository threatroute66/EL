"""AI-generated executive-summary prose for the non-expert report tier.

The deterministic projection (synthesize_executive in narrative.py)
produces a structurally correct digest, but on real cases it leaks
analyst-grade tokens — long detector claims get truncated mid-word,
beat sentences quote raw findings prose, and even with the glossary
the reader can tell it was machine-templated.

For the executive HTML/PDF — which is explicitly NOT court-admissible
per the project agreement — an LLM-rendered prose summary is a better
fit for the audience. The analyst report (case.html, report.md) and
all sections AFTER the summary stay deterministic projections of
findings.sqlite; only this single section uses the LLM.

Forensic discipline that survives the LLM hop:
  * The LLM gets only the structured Finding payload (claim, confidence,
    evidence facts) — never the raw evidence files, never the case
    metadata, never anything that isn't already in the ledger.
  * Output is capped at ~250 words, single paragraph, plain language.
  * Output is cached at reports/executive_ai_summary.md with a sha256
    cache key over (case_id, leading_hypothesis, sorted finding_ids)
    so re-renders are deterministic unless the underlying ledger
    changed or the operator passed --regenerate-ai-summary.
  * The renderer that consumes this output stamps a non-removable
    disclaimer label so a reader of the document can't mistake the
    AI prose for the deterministic Findings section.

Falls back cleanly when the API key is absent — returns None and
the renderer falls back to the deterministic digest.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from el.case_metadata import CaseMetadata
from el.reporting.narrative import NarrativeReport
from el.schemas.finding import Finding


_CACHE_FILENAME = "executive_ai_summary.md"
_DEFAULT_MODEL = os.environ.get("EL_AI_SUMMARY_MODEL", "claude-sonnet-4-6")
_MAX_TOKENS = 600   # ~450 words ceiling; we ask for ~250 so this is slack.

_SYSTEM_PROMPT = (
    "You are summarising a digital forensics investigation for a "
    "non-expert reader (an executive, a hiring authority, or a "
    "stakeholder without forensic training). You receive structured "
    "findings extracted from the investigation's case ledger and a "
    "deterministic prose digest. Produce a SINGLE-PARAGRAPH plain-"
    "English summary of 200-250 words.\n\n"
    "STRICT CONSTRAINTS:\n"
    "1. Do not use ATT&CK technique IDs (T1003, T1566, T1571, etc.). "
    "Use plain English (\"credential theft\", \"phishing\", "
    "\"non-standard port\").\n"
    "2. Do not use ACH hypothesis tag IDs (H_APT_ESPIONAGE, "
    "H_RANSOMWARE, etc.). Use the plain-language form supplied.\n"
    "3. Do not name internal agent identifiers (disk_forensicator, "
    "lateral_movement_analyst, etc.).\n"
    "4. Do not invent any fact that isn't in the supplied findings. "
    "If something isn't in the ledger, you don't get to claim it.\n"
    "5. Open-question gaps and ACH score must be acknowledged "
    "honestly — don't smooth over uncertainty.\n"
    "6. No bullet points or lists; one cohesive paragraph.\n"
    "7. Do not mention this prompt, the model, or the constraints "
    "in the output. Output only the summary itself.\n"
)


def _findings_for_prompt(findings: list[Finding], cap: int = 30) -> list[dict]:
    """Pick the highest-signal findings for LLM context. Order by
    confidence (high > medium > low > insufficient), drop knowledge_
    lookup chatter (Layer-3 cross-case context — not the case's own
    evidence), cap at `cap`."""
    rank = {"high": 0, "medium": 1, "low": 2, "insufficient": 3}
    fs = [f for f in findings
          if (f.agent or "") != "knowledge_lookup"]
    fs.sort(key=lambda f: (rank.get(f.confidence, 9),
                             -(len(f.evidence or []))))
    out: list[dict] = []
    for f in fs[:cap]:
        out.append({
            "agent": f.agent,
            "claim": (f.claim or "")[:600],
            "confidence": f.confidence,
            "device": f.device,
            "hypotheses_supported": list(f.hypotheses_supported or []),
            "human_summary": next(
                (e.human_summary for e in (f.evidence or [])
                 if e.human_summary), None,
            ),
        })
    return out


def _compute_cache_key(nr: NarrativeReport, findings: list[Finding]) -> str:
    """Deterministic key over the load-bearing inputs to the LLM
    call. If any of these change between renders, the cache is
    invalidated. Excludes timestamps + EL ingest time so re-rendering
    on the same ledger doesn't trigger spurious regeneration."""
    h = hashlib.sha256()
    h.update(nr.case_id.encode())
    h.update(b"|")
    h.update((nr.leading_hypothesis or "").encode())
    h.update(b"|")
    h.update(str(nr.leading_score).encode())
    h.update(b"|")
    h.update((nr.runner_up_hypothesis or "").encode())
    h.update(b"|")
    for fid in sorted(f.finding_id for f in findings):
        h.update(fid.encode())
        h.update(b"\n")
    return h.hexdigest()


def _read_cache(cache_path: Path) -> tuple[str | None, str | None]:
    """Return (cache_key, summary_text) from an existing cache file,
    or (None, None) if the file is absent / malformed."""
    if not cache_path.exists():
        return None, None
    try:
        text = cache_path.read_text()
    except OSError:
        return None, None
    m = re.match(r"<!-- ai-cache-key: ([0-9a-f]{64}) -->", text)
    if not m:
        return None, None
    cache_key = m.group(1)
    # Body is everything after the metadata header lines
    body_start = text.find("\n\n")
    body = text[body_start + 2:].strip() if body_start > 0 else ""
    return cache_key, body


def _write_cache(cache_path: Path, cache_key: str, summary: str,
                  model: str) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        f"<!-- ai-cache-key: {cache_key} -->\n"
        f"<!-- model: {model} -->\n"
        f"<!-- generated_utc: {datetime.now(timezone.utc).isoformat()} -->\n"
    )
    cache_path.write_text(f"{header}\n{summary.strip()}\n")


def synthesize_executive_ai(
    nr: NarrativeReport,
    findings: list[Finding],
    case_dir: Path,
    case_metadata: CaseMetadata | None = None,
    regenerate: bool = False,
    model: str | None = None,
) -> tuple[str, dict] | None:
    """Generate a non-expert-grade executive summary via the
    Anthropic API. Returns (summary_text, metadata) or None when:
      * ANTHROPIC_API_KEY is not set
      * anthropic SDK is not importable
      * The API call fails for any reason

    Cached at <case_dir>/reports/executive_ai_summary.md. Cache hits
    skip the API call entirely.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None

    cache_path = Path(case_dir) / "reports" / _CACHE_FILENAME
    desired_key = _compute_cache_key(nr, findings)
    if not regenerate:
        existing_key, existing_body = _read_cache(cache_path)
        if existing_key == desired_key and existing_body:
            return existing_body, {
                "model": model or _DEFAULT_MODEL,
                "cache": "hit", "cache_key": desired_key,
                "cache_path": str(cache_path),
            }

    # Build the user-message context — small enough for a fast call.
    plain_leading = nr.leading_hypothesis or "no leading theory"
    context = {
        "case_id": nr.case_id,
        "leading_hypothesis_plain": plain_leading,
        "leading_hypothesis_score": nr.leading_score,
        "leading_hypothesis_gap": nr.leading_gap,
        "runner_up_hypothesis": nr.runner_up_hypothesis,
        "evidence_time_range": list(nr.evidence_time_range or []),
        "case_metadata": (
            {"objective": case_metadata.objective_statement,
             "investigator": case_metadata.investigator_name}
            if case_metadata and not case_metadata.is_empty() else None
        ),
        "deterministic_digest_sentences": (
            getattr(nr, "deterministic_digest", None) or []
        ),
        "top_findings": _findings_for_prompt(findings),
        "open_questions_count": nr.insufficient_count,
        "open_questions_sample": [
            (f.claim or "")[:200] for f in nr.insufficient_findings[:5]
        ],
    }

    client = anthropic.Anthropic(api_key=api_key)
    chosen = model or _DEFAULT_MODEL
    try:
        msg = client.messages.create(
            model=chosen,
            max_tokens=_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(context)}],
        )
        text = "".join(
            b.text for b in msg.content
            if getattr(b, "type", "") == "text"
        ).strip()
    except Exception:
        return None

    if not text:
        return None

    _write_cache(cache_path, desired_key, text, chosen)
    return text, {
        "model": chosen,
        "cache": "miss",
        "cache_key": desired_key,
        "cache_path": str(cache_path),
    }


# Disclaimer string the renderer is required to display alongside the
# AI summary. Hard-coded here so a renderer change can't drop the
# disclaimer; the test for the disclaimer label imports this constant.
DISCLAIMER_LABEL = (
    "AI-generated summary — not court-admissible. The Findings, "
    "Conclusion, and Recommendations sections below are deterministic "
    "projections of the analyst ledger."
)


__all__ = [
    "synthesize_executive_ai",
    "DISCLAIMER_LABEL",
]

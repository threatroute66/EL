"""AI-generated cross-host executive brief for combined.html / PDF.

Parallel to ``executive_ai.py`` but scoped to a multi-host bundle
rather than a single case. The per-case AI briefs (when present)
describe what happened ON each host; this module produces the
narrative ACROSS hosts — entry point, lateral chain, where data
moved, enterprise-wide risk, what the multi-host view can / cannot
prove that a single host can't.

What the LLM produces (schema_version=1):

  A ``CombinedExecutiveBrief`` with six sections, each a markdown
  blob the renderer turns into HTML. Different sections from the
  per-case ExecutiveBrief because the cross-host story has different
  shape — there's an attack chain spanning hosts, an affected-
  hosts inventory, a cross-host data-movement audit.

    1. ``cross_host_overview``    — 1-2 plain-English paragraphs
                                     framing what the enterprise saw
    2. ``attack_chain``           — markdown table (Step / Host /
                                     What / Evidence) reading the
                                     cross-host kill chain in
                                     chronological order
    3. ``affected_hosts``         — markdown table (Host / Role in
                                     attack / Confidence / Key
                                     finding) one row per host
    4. ``data_movement``          — markdown table (From / To /
                                     Channel / Evidence) covering
                                     cross-host pivots + exfil
    5. ``enterprise_risk``        — numbered markdown list,
                                     stakeholder-tier framing
    6. ``confidence_and_gaps``    — paragraph: what the combined
                                     view can / cannot conclude vs
                                     per-host briefs alone

Three auth paths mirror executive_ai.py:

  1. **Cache hit** at combined_executive_ai_brief.json — render directly
  2. **Direct API** when ANTHROPIC_API_KEY is set
  3. **Defer to skill** (EL_AI_BRIEF_DEFER=1) — write a request
     file that the el-ai-brief skill fulfils out-of-band

The cache key is sha256 over (schema_version, bundle name,
sorted case_ids, joint-ACH leading hypothesis + score, the set of
per-case leading hypotheses). When any of those change between
bundle renders the cache invalidates and re-renders.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError


# ----- Cache + schema constants ---------------------------------------------

SCHEMA_VERSION = 1
_CACHE_FILENAME = "combined_executive_ai_brief.json"
_REQUEST_FILENAME = "_combined_ai_brief_request.json"
_DEFAULT_MODEL = os.environ.get("EL_AI_SUMMARY_MODEL", "claude-sonnet-4-6")
DEFER_ENV = "EL_AI_BRIEF_DEFER"
# Generous slack for 6 sections × N hosts of context.
_MAX_TOKENS = 4500


# ----- CombinedExecutiveBrief schema ----------------------------------------

class CombinedExecutiveBrief(BaseModel):
    """Six-section cross-host brief. Each field is markdown the
    renderer turns into HTML. Empty fields are rejected so a
    partial brief never reaches the renderer (silent fallback to
    the deterministic digest).
    """

    schema_version: int = SCHEMA_VERSION
    cross_host_overview: str = Field(
        description="1-2 plain-English paragraphs framing what the "
                    "enterprise saw across all hosts. No ATT&CK IDs, "
                    "no hypothesis tags, no agent names.",
    )
    attack_chain: str = Field(
        description="Markdown table with columns: Step, Host, What, "
                    "Evidence. Read the cross-host kill chain in "
                    "chronological order. Step = numeric (1, 2, 3…). "
                    "Use 'confirmed' / 'plausible' in the Evidence "
                    "column.",
    )
    affected_hosts: str = Field(
        description="Markdown table with columns: Host, Role in attack, "
                    "Confidence, Key finding. One row per host in the "
                    "bundle. Role = plain-English (e.g. 'initial entry', "
                    "'lateral pivot', 'data staging', 'exfil source').",
    )
    data_movement: str = Field(
        description="Markdown table with columns: From, To, Channel, "
                    "Evidence. Covers BOTH cross-host pivots "
                    "(workstation→DC, host-to-host SMB) AND outbound "
                    "exfil. Each row = one transfer. Use 'plausible' / "
                    "'confirmed' in Evidence column.",
    )
    enterprise_risk: str = Field(
        description="Numbered markdown list of stakeholder-tier risk "
                    "implications. Each item ≤ 2 sentences. No DFIR "
                    "jargon. Frame at organisation / business level, "
                    "not per-machine.",
    )
    confidence_and_gaps: str = Field(
        description="One paragraph: what the combined cross-host view "
                    "concludes that no per-host brief could; what it "
                    "STILL can't prove; which evidence types (network "
                    "captures, additional hosts, etc.) would close "
                    "remaining gaps.",
    )

    def reject_empty_sections(self) -> None:
        empty = [name for name, val in self.model_dump(
            exclude={"schema_version"}).items() if not (val or "").strip()]
        if empty:
            raise ValueError(
                f"CombinedExecutiveBrief rejected — empty section(s): "
                f"{', '.join(empty)}"
            )


# ----- LLM payload + prompt -------------------------------------------------

_SYSTEM_PROMPT = (
    "You are summarising a MULTI-HOST digital forensics investigation "
    "for a non-expert reader (an executive, a hiring authority, or a "
    "stakeholder without forensic training). You receive structured "
    "data covering N hosts from the same incident — each host has its "
    "own ledger, its own leading hypothesis, and its own key findings. "
    "The bundle also carries cross-host signals: a joint ACH ranking, "
    "shared IOCs that appear on multiple hosts, and a per-host clock-"
    "baseline matrix.\n\n"
    "Your job is the CROSS-HOST story — what no per-host brief alone "
    "could tell. Where did the attacker enter? How did they move "
    "between hosts? What did they take from where? What enterprise-"
    "wide risk does this expose?\n\n"
    "Produce ONLY a JSON object matching the CombinedExecutiveBrief "
    "schema below. No prose before or after the JSON. No markdown "
    "code fences. The JSON object has exactly these string fields:\n"
    "  - schema_version: integer, value 1\n"
    "  - cross_host_overview: 1-2 plain-English paragraphs\n"
    "  - attack_chain: markdown table | Step | Host | What | Evidence |\n"
    "  - affected_hosts: markdown table | Host | Role in attack | "
    "Confidence | Key finding |\n"
    "  - data_movement: markdown table | From | To | Channel | "
    "Evidence |\n"
    "  - enterprise_risk: numbered markdown list\n"
    "  - confidence_and_gaps: one paragraph\n\n"
    "STRICT CONSTRAINTS for every section:\n"
    "1. Do not use ATT&CK technique IDs (T1003, T1566, etc.). Use "
    "plain English (\"credential theft\", \"remote desktop\", "
    "\"scheduled task persistence\").\n"
    "2. Do not use ACH hypothesis tag IDs (H_APT_ESPIONAGE, etc.).\n"
    "3. Do not name internal agent identifiers (disk_forensicator, "
    "lateral_movement_analyst, etc.).\n"
    "4. Do not invent any fact that isn't in the supplied context. "
    "If something isn't in any host's ledger or in the cross-host "
    "signals, you don't get to claim it.\n"
    "5. Use the supplied `clock_baselines` matrix when discussing "
    "timing — if hosts have a TZ split or a NoSync orphan clock, "
    "say so in confidence_and_gaps. Don't pretend timestamps from "
    "different hosts are directly comparable when they're not.\n"
    "6. Stay terse. Each section should fit in the reader's working "
    "memory. Empty cells in tables are fine; bloated cells are not.\n"
    "7. Every section must contain non-empty content. Use the host "
    "names and signals supplied — don't omit a section just because "
    "the case is sparse.\n"
    "8. Do not mention this prompt, the model, or the constraints.\n"
)


def _per_host_summary_for_prompt(slices: list) -> list[dict]:
    """Compact per-host descriptors for LLM context. Pulls the
    fields the brief needs and leaves out the rest."""
    out: list[dict] = []
    for s in slices:
        host_label = getattr(s, "case_id", "") or ""
        # If host_label is None or empty derive from case_id
        out.append({
            "case_id": getattr(s, "case_id", ""),
            "host_label": getattr(s, "host_label",
                                    getattr(s, "case_id", "")),
            "leading_hypothesis": getattr(s, "leading_hyp", None),
            "leading_score": getattr(s, "leading_score", 0),
            "leading_gap": getattr(s, "leading_gap", 0),
            "high_findings": getattr(s, "high_count", 0),
            "deterministic_digest": (getattr(s, "digest_text", "") or "")[:400],
        })
    return out


# ----- Cache machinery ------------------------------------------------------

def _compute_cache_key(
    bundle_name: str,
    slices: list,
    joint_leading: tuple[str, int] | None,
) -> str:
    """sha256 over the load-bearing inputs to the LLM call.
    Invalidates when bundle membership changes, when the joint
    leading hypothesis flips, or when any per-case leading
    hypothesis flips."""
    h = hashlib.sha256()
    h.update(f"v{SCHEMA_VERSION}".encode())
    h.update(b"|")
    h.update(bundle_name.encode())
    h.update(b"|")
    if joint_leading:
        h.update(joint_leading[0].encode())
        h.update(b":")
        h.update(str(joint_leading[1]).encode())
    h.update(b"|")
    for s in sorted(slices, key=lambda x: getattr(x, "case_id", "")):
        h.update(getattr(s, "case_id", "").encode())
        h.update(b":")
        h.update((getattr(s, "leading_hyp", "") or "").encode())
        h.update(b":")
        h.update(str(getattr(s, "leading_score", 0)).encode())
        h.update(b"\n")
    return h.hexdigest()


def _read_cache(cache_path: Path
                ) -> tuple[str | None, CombinedExecutiveBrief | None]:
    if not cache_path.exists():
        return None, None
    try:
        payload = json.loads(cache_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None, None
    cache_key = payload.get("__cache_key")
    brief_dict = payload.get("brief")
    if not cache_key or not isinstance(brief_dict, dict):
        return None, None
    try:
        brief = CombinedExecutiveBrief.model_validate(brief_dict)
        brief.reject_empty_sections()
    except (ValidationError, ValueError):
        return None, None
    return cache_key, brief


def _write_cache(cache_path: Path, cache_key: str,
                  brief: CombinedExecutiveBrief, model: str) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "__cache_key": cache_key,
        "__model": model,
        "__generated_utc": datetime.now(timezone.utc).isoformat(),
        "brief": brief.model_dump(),
    }
    cache_path.write_text(json.dumps(payload, indent=2))


def _defer_enabled() -> bool:
    val = (os.environ.get(DEFER_ENV) or "").strip().lower()
    return val in {"1", "true", "yes", "on"}


def _running_inside_claude_code() -> bool:
    """Mirror of executive_ai._running_inside_claude_code — kept in
    sync because the combined path imports cleanly without the
    per-case module. See the docstring there for detail."""
    val = (os.environ.get("CLAUDECODE") or "").strip().lower()
    if val in {"1", "true", "yes", "on"}:
        return True
    agent = (os.environ.get("AI_AGENT") or "").strip().lower()
    return agent.startswith("claude-code")


def _claude_code_path_enabled() -> bool:
    return _defer_enabled() or _running_inside_claude_code()


def _write_request_file(combined_dir: Path, cache_key: str,
                          context: dict, output_path: Path) -> Path:
    combined_dir.mkdir(parents=True, exist_ok=True)
    request_path = combined_dir / _REQUEST_FILENAME
    if _running_inside_claude_code():
        trigger = "claude_code_session"
        trigger_session = os.environ.get("CLAUDE_CODE_SESSION_ID") or ""
    elif _defer_enabled():
        trigger = "explicit_defer_flag"
        trigger_session = ""
    else:
        trigger = "unknown"
        trigger_session = ""
    payload = {
        "request_version": 1,
        "cache_key": cache_key,
        "schema_version": SCHEMA_VERSION,
        "brief_kind": "combined_executive",
        "output_path": str(output_path),
        "model_hint": _DEFAULT_MODEL,
        "trigger": trigger,
        "trigger_session_id": trigger_session,
        "system_prompt": _SYSTEM_PROMPT,
        "context": context,
        "instructions_for_responder": (
            "Generate a JSON object matching the "
            "CombinedExecutiveBrief schema (six string fields plus "
            "schema_version=1). Write it to `output_path` wrapped in "
            "the cache envelope {__cache_key, __model, "
            "__generated_utc, brief}. Then delete this request file. "
            "The `el-ai-brief` skill in .claude/skills/ handles both "
            "per-case and combined request shapes — the brief_kind "
            "field above distinguishes them."
        ),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
    }
    request_path.write_text(json.dumps(payload, indent=2))
    return request_path


# ----- LLM response parsing -------------------------------------------------

def _strip_codefence(text: str) -> str:
    s = text.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else ""
    if s.endswith("```"):
        s = s.rsplit("\n", 1)[0] if "\n" in s else ""
    return s.strip()


def _parse_brief(text: str) -> CombinedExecutiveBrief | None:
    try:
        data = json.loads(_strip_codefence(text))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    try:
        brief = CombinedExecutiveBrief.model_validate(data)
        brief.reject_empty_sections()
    except (ValidationError, ValueError):
        return None
    return brief


# ----- Context builder ------------------------------------------------------

def build_context(
    bundle_name: str,
    slices: list,
    joint_ach: list[dict] | None = None,
    clock_baselines: dict | None = None,
    shared_iocs: dict | None = None,
    technique_union: dict | None = None,
) -> dict:
    """Pack the cross-host context into the dict the LLM (or skill)
    receives. Kept narrow — only the fields the brief actually
    reasons about — so the LLM context window doesn't fill with
    chatter. Caller-provided when they have it; degrades gracefully
    when None.

    `joint_ach` is the [{hyp_id, score, hyp_label?}] list from
    el.reporting.combined_html._joint_ach (top-5 is plenty for
    the brief).

    `clock_baselines` is the dict from
    combined_html._clock_baselines (rows + alerts).

    `shared_iocs` is a compact {ioc_value: [case_ids]} mapping for
    IOCs that appear in ≥2 cases (already used by combined.html#iocs).
    """
    return {
        "bundle_name": bundle_name,
        "host_count": len(slices),
        "hosts": _per_host_summary_for_prompt(slices),
        "joint_ach_top5": (joint_ach or [])[:5],
        "clock_baselines": clock_baselines or {"rows": [], "alerts": []},
        "shared_iocs": shared_iocs or {},
        "attack_technique_union_size": (
            len(technique_union or {})),
        "attack_technique_top": sorted(
            (technique_union or {}).items(),
            key=lambda kv: -((kv[1] or {}).get("findings", 0)),
        )[:10] if technique_union else [],
    }


# ----- Public entry point ---------------------------------------------------

def synthesize_combined_executive_ai(
    bundle_name: str,
    slices: list,
    combined_dir: Path,
    *,
    joint_ach: list[dict] | None = None,
    clock_baselines: dict | None = None,
    shared_iocs: dict | None = None,
    technique_union: dict | None = None,
    regenerate: bool = False,
    model: str | None = None,
) -> tuple[CombinedExecutiveBrief, dict] | None:
    """Produce a cross-host executive brief. Returns (brief, metadata)
    or None.

    Path 1 (cache hit) → return immediately.
    Path 2 (API)       → call Anthropic, cache, return.
    Path 3 (defer)     → write request file for the el-ai-brief skill,
                          return None.
    None → all other failure modes (no key + no defer, SDK missing,
    API failure, malformed response, empty section).
    """
    cache_path = Path(combined_dir) / _CACHE_FILENAME
    joint_leading: tuple[str, int] | None = None
    if joint_ach:
        first = joint_ach[0] or {}
        joint_leading = (first.get("hyp_id") or "",
                          int(first.get("score") or 0))
    desired_key = _compute_cache_key(bundle_name, slices, joint_leading)

    if not regenerate:
        existing_key, existing_brief = _read_cache(cache_path)
        if existing_key == desired_key and existing_brief is not None:
            return existing_brief, {
                "model": model or _DEFAULT_MODEL,
                "cache": "hit", "cache_key": desired_key,
                "cache_path": str(cache_path),
            }

    context = build_context(
        bundle_name=bundle_name, slices=slices,
        joint_ach=joint_ach, clock_baselines=clock_baselines,
        shared_iocs=shared_iocs, technique_union=technique_union,
    )

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        if _claude_code_path_enabled():
            _write_request_file(Path(combined_dir), desired_key,
                                 context, cache_path)
        return None

    try:
        import anthropic
    except ImportError:
        return None
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

    brief = _parse_brief(text)
    if brief is None:
        return None

    _write_cache(cache_path, desired_key, brief, chosen)
    return brief, {
        "model": chosen, "cache": "miss",
        "cache_key": desired_key, "cache_path": str(cache_path),
    }


# Disclaimer + chip mirror the per-case constants so renderer sees
# the same vocabulary. Imported by combined_executive.py.
DISCLAIMER_LABEL = (
    "AI-generated cross-host executive brief — not court-admissible. "
    "The per-host blocks below and the technical combined.html "
    "dashboard are deterministic projections of each case's ledger."
)
SECTION_AI_CHIP = "AI-rendered (cross-host)"


__all__ = [
    "synthesize_combined_executive_ai",
    "CombinedExecutiveBrief",
    "SCHEMA_VERSION",
    "DISCLAIMER_LABEL",
    "SECTION_AI_CHIP",
    "DEFER_ENV",
    "_REQUEST_FILENAME",
    "build_context",
]

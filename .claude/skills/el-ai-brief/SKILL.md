---
name: el-ai-brief
description: |
  Fulfil a deferred EL executive-brief request that the `el` CLI
  emitted while running without `ANTHROPIC_API_KEY` set. Use this
  whenever a case directory under `/opt/EL/cases/` contains a
  `reports/_ai_brief_request.json` file, OR when the user invokes
  `/el-ai-brief` directly (with no arg = process every case that
  has a pending request; with an arg = process only that case-id).
  This skill is the path-2 alternative to setting an API key — EL's
  defer mode writes the request, Claude Code (this skill) writes
  the response, then re-renders the executive HTML+PDF so the
  six-section brief lands in the final report.
---

# el-ai-brief — fulfil a deferred EL executive brief

EL's `executive_ai.py` runs in one of three modes:

1. **Cache hit** (no work for this skill).
2. **Direct API** (`ANTHROPIC_API_KEY` set — this skill not needed).
3. **Deferred** (`EL_AI_BRIEF_DEFER=1` set, no API key — EL writes a
   request file and this skill fulfils it). **You are mode 3.**

## When to fire

Fire when **any** of the following is true:

- The user explicitly invokes `/el-ai-brief` (with or without a case-id arg).
- A new `_ai_brief_request.json` file appears under any
  `/opt/EL/cases/<id>/reports/` directory (e.g. after an `el investigate`).
- A new `_combined_ai_brief_request.json` file appears under any
  `/opt/EL/cases/_combined/<bundle>/` directory (after an
  `el combined-report`). Same shape as per-case requests but carries
  `brief_kind: "combined_executive"` and a different output path.

If the user hasn't asked for it and there are no pending requests on
disk, do nothing — this skill is a worker, not a watchdog.

## Procedure

1. **Discover pending requests**.
   ```bash
   find /opt/EL/cases -maxdepth 4 \
        \( -name "_ai_brief_request.json" \
        -o -name "_combined_ai_brief_request.json" \) -type f
   ```
   If the user passed a case-id, scope to that case's per-case
   request OR (when the id matches a `_combined/<bundle>/` dir) the
   combined request under that bundle. If nothing matches, tell the
   user "no pending requests" and stop.

2. **For each request file**, read it. The schema is:
   ```json
   {
     "request_version": 1,
     "cache_key": "<sha256 — must round-trip into the response>",
     "schema_version": 2,
     "output_path": "<absolute path to executive_ai_brief.json>",
     "model_hint": "claude-sonnet-4-6",
     "system_prompt": "<the same prompt the SDK path would have used>",
     "context": { ...case context (findings, hypothesis, etc.)... },
     "instructions_for_responder": "...",
     "generated_utc": "..."
   }
   ```

3. **Generate the brief**. Apply the request's `system_prompt`
   verbatim to its `context` payload — the prompt itself spells out
   the exact schema fields the response must contain. There are two
   request shapes:

   **Per-case** (`reports/_ai_brief_request.json`, schema_version=2)
   produces an `ExecutiveBrief` with these fields:
   - `schema_version` (integer, value **2**)
   - `what_happened` — 1-2 plain-English paragraphs
   - `what_was_taken` — markdown bullet list
   - `where_it_went` — markdown table *Channel | Destination | Evidence*
   - `when_timeline` — markdown table *Date (UTC) | Window | What*
   - `risk_implications` — numbered markdown list
   - `confidence_and_limits` — one paragraph

   **Combined / cross-host** (`_combined_ai_brief_request.json`,
   `brief_kind: "combined_executive"`, schema_version=1) produces a
   `CombinedExecutiveBrief` with these fields:
   - `schema_version` (integer, value **1**)
   - `cross_host_overview` — 1-2 plain-English paragraphs
   - `attack_chain` — markdown table *Step | Host | What | Evidence*
   - `affected_hosts` — markdown table *Host | Role | Confidence | Key finding*
   - `data_movement` — markdown table *From | To | Channel | Evidence*
   - `enterprise_risk` — numbered markdown list
   - `confidence_and_gaps` — one paragraph

   **Constraints — non-negotiable for both shapes:**
   - No ATT&CK technique IDs (T1003, T1566, …). Use plain English.
   - No ACH hypothesis tag IDs (`H_APT_ESPIONAGE`, …).
   - No internal agent identifiers (`disk_forensicator`, …).
   - No fact that isn't in the supplied context.
   - Every section must be non-empty (the EL renderer rejects empty
     sections and falls back to the deterministic digest).
   - Acknowledge uncertainty / open questions honestly in
     `confidence_and_limits` (per-case) or `confidence_and_gaps`
     (combined).
   - For combined: use the `clock_baselines` matrix when discussing
     timing — if hosts have a TZ split or NoSync orphan clock, name
     it in `confidence_and_gaps`.

4. **Write the response** to `output_path` (NOT the request path),
   wrapped in the cache envelope:
   ```json
   {
     "__cache_key": "<the cache_key from the request, copied exactly>",
     "__model": "<this model's id, e.g. claude-opus-4-7>",
     "__generated_utc": "<ISO-8601 UTC now>",
     "brief": { ...the six-section JSON above... }
   }
   ```
   The cache_key MUST match the request's cache_key byte-for-byte —
   otherwise EL will treat the response as stale on the next render
   and not pick it up.

5. **Delete the request file** once the response is on disk.
   `rm <request_path>`. This is the signal that the request is
   fulfilled; leaving it in place will cause the skill to re-process
   on the next fire.

6. **Re-render the report** so the new brief surfaces in the HTML
   and PDF the user will actually read:

   **Per-case** request:
   ```bash
   /opt/EL/.venv/bin/el report /opt/EL/cases/<case-id> --html
   ```
   (PDF regenerates as a side effect of the HTML pipeline.)

   **Combined** request: re-run `el combined-report` against the
   same bundle membership (the cache hit on the next pass picks up
   your response).
   ```bash
   /opt/EL/.venv/bin/el combined-report \
     /opt/EL/cases/<case-A> /opt/EL/cases/<case-B> ... \
     --name <bundle-name>
   ```
   The bundle name is the directory name under
   `/opt/EL/cases/_combined/`. Member case dirs can be inferred from
   the response `output_path` parent — every host that contributed
   to the bundle.

7. **Tell the user** which case(s) or bundle you fulfilled and the
   new URL on the case server:
   - Per-case: `http://localhost:8089/<case-id>/reports/executive.html`
   - Combined: `http://localhost:8089/_combined/<bundle>/combined_executive.html`

   Stay terse — one line per case / bundle.

## Failure modes

- **Schema validation fails on the EL side** (any section empty,
  missing field, malformed JSON cache envelope): EL silently falls
  back to the deterministic digest on render. If the user reports
  "I don't see the AI brief in my report", re-fire this skill with
  `--force` (re-generate the response) and verify the response
  file's `__cache_key` matches the request's `cache_key`.
- **Request file references a case dir that no longer exists** (e.g.
  case archived/deleted): delete the orphan request file with a note
  to the user, then continue.
- **Multiple request files** for the same case (shouldn't happen,
  but possible if a previous fulfilment was interrupted): use the
  one with the most recent `generated_utc`.

## What you must NOT do

- Don't fabricate findings or destinations not present in the
  supplied `context.top_findings`.
- Don't strip the cache envelope on the response file — EL's
  `_read_cache` requires `__cache_key` + `brief` keys.
- Don't write to the request file path (the response goes to
  `output_path`, not back into the request).
- Don't run `el investigate` or `el report --regenerate-ai-summary`
  unless the user explicitly asks — both are heavier operations
  than this skill needs.
- Don't skip the schema validation just because your prose reads
  well — the EL renderer's validator is the source of truth for
  what makes the brief land in the report.

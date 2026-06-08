# EL — Agent Execution Logs

_Find Evil 2026 submission deliverable. Per the rubric:_

> _"Include Agent Execution Logs — Structured logs showing the full agent
> communication and tool execution sequence. For multi-agent submissions:
> agent-to-agent message logs with timestamps … tool execution logs with
> timestamps and token usage … **Judges must be able to trace any finding
> back to the specific tool execution that produced it.**"_

EL is a multi-agent system, so this document covers both halves: the
**agent-to-agent communication trace** and the **per-tool execution log**,
and shows the finding → tool round-trip judges must be able to walk.

A committed, ready-to-inspect sample from a full run on **public M57-Jean
evidence** lives at
[`sample-reports/execution-logs/m57-jean/`](../sample-reports/execution-logs/m57-jean/)
— you don't have to run a case to see the logs. (Per-case logs are written
under `cases/<id>/` which is gitignored, so that directory is the canonical
committed copy.)

---

## The three log artifacts every run produces

| File | Format | Purpose |
|---|---|---|
| `reports/execution_log.jsonl` | JSON Lines, one event per line | The machine-readable spine — every state transition, agent start/stop, agent handoff, tool execution, finding emission, and LLM call, each stamped `ts_utc` |
| `analysis/forensic_audit.log` | Human-readable text, one line per event | The same events in a chain-of-custody log an analyst (or court) can read top-to-bottom |
| `reports/traceability_matrix.md` | Markdown table | One row per EvidenceItem: `finding_id → agent → tool → command → output sha256 → output path`. The reverse-lookup index |

All timestamps are UTC ISO-8601. Every event carries `case_id` and (where
agent-scoped) `agent`, plus the run `pid`.

---

## Event schema (`execution_log.jsonl`)

Observed event types from the M57-Jean reference run (497 events):

| `event` | Count* | Carries | Answers |
|---|---|---|---|
| `intake_complete` | 1 | `input_path`, `input_sha256`, `input_size_bytes` | provenance of the evidence itself |
| `state_transition` | 7 | `from_`, `to` | the coordinator FSM moving through INTAKE→…→DONE |
| `agent_start` / `agent_done` | 16 / 16 | `agent`, `state`, `findings_emitted` | which agent ran when, and how much it produced |
| `agent_handoff` | 2 | `published` (e.g. `evidence_kind=EWF (E01)`) | **agent-to-agent message** — what one agent published to shared state for the next |
| `tool_execution` | 223 | `tool`, `tool_version`, `command`, `output_sha256`, `output_path`, `finding_id`, `confidence` | **the tool log** — every CLI invocation bound to the finding it produced |
| `finding_emitted` | 229 | `finding_id`, `confidence`, `claim`, `hypotheses_supported/refuted`, `red_review_status`, `evidence_count` | what each agent concluded |
| `llm_call` | — | `component`, `model`, `transport`, `input_tokens`, `output_tokens` | **token usage** for the two advisory LLM steps |
| `red_review_deferred` / `red_review_llm_applied` | 1 | `findings`, `trigger` / `verdicts`, `changed` | the adversarial-review handoff + merge |
| `knowledge_iocs_recorded` | 1 | — | Layer-3 cross-case IOC write |
| `case_sealed` / `case_complete` | 1 | — | seal manifest + terminal state |

\* counts from the M57-Jean sample; they scale with case size.

---

## Multi-agent communication trace

EL's agents don't message each other directly over a bus — they
communicate through **shared case state mediated by the coordinator**, and
every such exchange is logged. The sequence for any run reads as:

```
state_transition (intake → triage)
  agent_start  triage
    tool_execution  el.triage  → finding_emitted (evidence_kind decided)
  agent_handoff  triage  published="evidence_kind=EWF (E01)"   ← the message
  agent_done   triage  findings_emitted=1
state_transition (triage → hypothesis_gen → parallel_investigate)
  agent_start  disk_forensicator         ← routed BY the published evidence_kind
    tool_execution × N  → finding_emitted × N
  agent_done   disk_forensicator
  agent_start  windows_artifact          ← chained agent, consumes prior outputs
    ...
state_transition (… → adversarial_review)
  red_review_deferred  findings=229  trigger=claude_code_session   ← handoff to challenger
  red_review_llm_applied  verdicts=…  changed=…                    ← merge back
state_transition (… → report → done)
  case_sealed ; case_complete
```

The `agent_handoff` event is the literal agent-to-agent message: `triage`
publishes `evidence_kind=EWF (E01)`, and the coordinator's `KIND_TO_AGENT`
routing turns that into the `agent_start disk_forensicator` you see next.
Chained agents (e.g. `windows_artifact` after `disk_forensicator`) consume
the prior agent's `output_path`s — the linkage is visible because both the
producing `tool_execution` and the consuming agent's commands reference the
same path.

To replay just the communication spine from a sample log:

```bash
jq -r 'select(.event|test("state_transition|agent_start|agent_done|agent_handoff|red_review")) |
       "\(.ts_utc)  \(.event)  \(.agent // .extra.from_+"→"+.extra.to // "")  \(.extra.published // "")"' \
   sample-reports/execution-logs/m57-jean/execution_log.jsonl
```

---

## Tracing a finding back to its tool execution (the round-trip)

This is the rubric's hard requirement. Two equivalent paths:

### Path 1 — via the JSONL log

A `tool_execution` event and the `finding_emitted` it produced share a
`finding_id`. Example, verbatim from the M57-Jean sample:

```json
{ "event": "tool_execution", "agent": "email_forensicator",
  "tool": "libpff/pffexport", "tool_version": "pffexport 20180714",
  "command": "/usr/bin/pffexport -q -t …/Administrator--outlook …/Administrator--outlook.pst",
  "output_sha256": "81f6a1445db1aa8a5a3c273b4ccaf821ceb3c1f3cf2a35f71eba110a9db3c8aa",
  "output_path": "…/exports/windows-artifacts/mail/Administrator--outlook.pst",
  "finding_id": "01KT9VTPAQB527688YEFTWZMXX", "confidence": "high" }

{ "event": "finding_emitted", "agent": "email_forensicator",
  "finding_id": "01KT9VTPAQB527688YEFTWZMXX", "confidence": "high",
  "extra": { "claim": "PST parsed (Administrator--outlook.pst): …",
             "red_review_status": "passed", "evidence_count": 1 } }
```

```bash
# Pull the full tool+finding pair for any finding_id:
FID=01KT9VTPAQB527688YEFTWZMXX
jq "select(.finding_id==\"$FID\")" sample-reports/execution-logs/m57-jean/execution_log.jsonl
```

### Path 2 — via the traceability matrix + sha256 recompute

`reports/traceability_matrix.md` is the same linkage as a Markdown table.
The integrity check: recompute the sha256 on the cited `output_path` and
confirm it matches the logged `output_sha256`.

```bash
# On a live case (not the committed sample, whose outputs live under gitignored cases/):
sha256sum <output_path from the matrix row>
# Must equal the output sha256 column. If it doesn't, EL produced a
# hallucinated claim — it hasn't in 36+ real cases, but the test is yours.
```

The two paths agree by construction: the matrix is rendered from the same
`EvidenceItem`s that the `tool_execution` events log.

---

## Token usage

The only LLM calls in a run are the two **advisory** steps (the red-review
challenger and the executive brief). Each emits an `llm_call` event with
`component`, `model`, `transport`, and token counts:

```json
{ "event": "llm_call", "extra": { "component": "executive_ai",
  "model": "claude-sonnet-4-6", "transport": "claude_cli_headless",
  "input_tokens": "…", "output_tokens": "…" } }
```

```bash
# Total output tokens spent on advisory LLM steps in a run:
jq -r 'select(.event=="llm_call") | .extra.output_tokens' \
   reports/execution_log.jsonl | paste -sd+ | bc
```

The forensic extractors are deterministic CLI tools and consume **zero
tokens** — the `tool_execution` count (223 on M57-Jean) is the real work,
and none of it is model-driven. This is the structural reason a finding can
never be a hallucination: the claim is bound to a tool's output file, not
to model output.

---

## Reading the human-readable audit log

For a top-to-bottom narrative (no `jq`), `analysis/forensic_audit.log` is
the same events as aligned text:

```
2026-06-04T17:45:20+00:00 [INFO] case=m57-jean event=agent_start pid=… agent=email_forensicator state=parallel_investigate
2026-06-04T17:45:20+00:00 [INFO] case=m57-jean event=tool_execution … tool=libpff/pffexport finding_id=01KT9VTPAQB527688YEFTWZMXX
…
```

It opens with `intake_complete` (input sha256 + size) and closes with
`case_sealed` / `case_complete`, so the whole chain of custody for the run
is one readable file.

---

## Where to look — quick reference

| You want | Open |
|---|---|
| The full machine-readable trace | `sample-reports/execution-logs/m57-jean/execution_log.jsonl` |
| Finding → tool → sha256 index | `sample-reports/execution-logs/m57-jean/traceability_matrix.md` |
| Human-readable chain of custody | `sample-reports/execution-logs/m57-jean/forensic_audit.log` |
| The same on your own run | `cases/<id>/reports/` + `cases/<id>/analysis/forensic_audit.log` |
| The sha256 round-trip walkthrough | [`JUDGES.md`](JUDGES.md#verifying-any-single-finding--the-sha256-round-trip) |

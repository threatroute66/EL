# Sample Agent Execution Logs

Committed, ready-to-inspect execution logs from a full EL run — so judges
can read the structured agent-communication + tool-execution trace without
running a case (per-case logs are written under `cases/<id>/`, which is
gitignored).

Schema, the multi-agent communication trace, the finding→tool round-trip,
and token-usage location are documented in
[`docs/agent_execution_logs.md`](../../docs/agent_execution_logs.md).

## `m57-jean/` — run on public M57-Jean evidence

The [M57-Jean](https://digitalcorpora.org/corpora/scenarios/m57-patents/)
disk image (public, Digital Corpora) investigated end-to-end. 497 logged
events across 16 agents.

| File | What it is |
|---|---|
| `execution_log.jsonl` | Machine-readable spine — every state transition, agent start/stop, agent handoff, tool execution (with `output_sha256` + `finding_id`), finding emission, and LLM call, each stamped `ts_utc` (UTC) |
| `traceability_matrix.md` | `finding_id → agent → tool → command → output sha256 → output path` — the reverse-lookup index |
| `forensic_audit.log` | The same events as a top-to-bottom human-readable chain-of-custody log |

Quick starts:

```bash
# The agent-to-agent communication spine
jq -r 'select(.event|test("state_transition|agent_start|agent_done|agent_handoff|red_review")) |
       "\(.ts_utc)  \(.event)  \(.agent // .extra.from_+"→"+.extra.to // "")  \(.extra.published // "")"' \
   m57-jean/execution_log.jsonl

# Every tool a given agent ran
jq -r 'select(.event=="tool_execution" and .agent=="email_forensicator") |
       "\(.ts_utc)  \(.tool_version)  \(.command)"' m57-jean/execution_log.jsonl

# Trace one finding back to the tool execution that produced it
jq 'select(.finding_id=="01KT9VTPAQB527688YEFTWZMXX")' m57-jean/execution_log.jsonl
```

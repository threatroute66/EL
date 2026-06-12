# M57-Jean — committed agent execution logs

A full EL run on the public [M57-Jean](https://digitalcorpora.org/corpora/scenarios/m57-patents/)
disk image (Digital Corpora), committed so the logs can be inspected
**without running a case** and **without opening the raw `.jsonl`**.

> **Why this page exists.** GitHub's `robots.txt` blocks automated crawlers
> from the directory-listing API and from `raw.githubusercontent.com`, so a
> bot-driven reviewer may be unable to open `execution_log.jsonl` directly.
> This README renders on the folder page, so the file inventory and the
> spot-check evidence below are readable from the rendered Markdown even when
> the raw file is not crawlable. The files themselves are present and
> non-empty — verify with the line counts + sha256 in the table.

## File inventory (verify present + non-empty)

| File | Lines | Bytes | SHA-256 |
|---|---:|---:|---|
| [`execution_log.jsonl`](execution_log.jsonl) | 497 | 238,884 | `9f6d3e3ee81192c62c75028598420cf5e0f197f69001254e8b9248fb11878885` |
| [`traceability_matrix.md`](traceability_matrix.md) | 228 | 46,165 | `6a71cf858a65251a5de1365dabe7661fdcc53e07db84159983492cb3136924a0` |
| [`forensic_audit.log`](forensic_audit.log) | 50 | 6,648 | `d43bf7a406c964ae84655906c564459e64be9767d757c67861c7d23061c1b89a` |

`execution_log.jsonl` is 497 events across 16 agents: 7 `state_transition`,
16 `agent_start` / 16 `agent_done`, 2 `agent_handoff` (the multi-agent
message spine), 223 `tool_execution`, 229 `finding_emitted`, plus
`intake_complete`, `knowledge_iocs_recorded`, and `red_review_deferred`.
Every event carries a `ts_utc` (UTC) timestamp. Schema + the token-usage
(`llm_call`) location are documented in
[`docs/agent_execution_logs.md`](../../../docs/agent_execution_logs.md).

## Spot-check: one finding → the tool execution that produced it

The M57 narrative's exfil-vector claim (Jean's Outlook mailbox) traces to
finding **`01KT9VTPAQB527688YEFTWZMXX`**. Both events below are quoted
**verbatim** from `execution_log.jsonl` (two lines of the file). They share
the same `finding_id`, `ts_utc`, and `agent`, and the `output_sha256`
(`81f6a1445db1…`) is the hash of the parsed evidence — the reverse-lookup
anchor:

```json
{"ts_utc":"2026-06-04T17:45:20+00:00","event":"tool_execution","case_id":"m57-jean","agent":"email_forensicator","tool":"libpff/pffexport","tool_version":"pffexport 20180714","command":"/usr/bin/pffexport -q -t /opt/EL/cases/m57-jean/analysis/email_forensicator/Administrator--outlook /opt/EL/cases/m57-jean/exports/windows-artifacts/mail/Administrator--outlook.pst","output_sha256":"81f6a1445db1aa8a5a3c273b4ccaf821ceb3c1f3cf2a35f71eba110a9db3c8aa","output_path":"/opt/EL/cases/m57-jean/exports/windows-artifacts/mail/Administrator--outlook.pst","finding_id":"01KT9VTPAQB527688YEFTWZMXX","confidence":"high"}
{"ts_utc":"2026-06-04T17:45:20+00:00","event":"finding_emitted","case_id":"m57-jean","agent":"email_forensicator","finding_id":"01KT9VTPAQB527688YEFTWZMXX","confidence":"high","extra":{"claim":"PST parsed (Administrator--outlook.pst): 1 message(s) across 10 folder(s) (Calendar, Contacts, Deleted Items, Drafts, Inbox\u2026). Inferred local domain(s): unknown","hypotheses_supported":["H_MAILBOX_PARSED"],"hypotheses_refuted":[],"red_review_status":"passed","evidence_count":1}}
```

The same row is the first column of [`traceability_matrix.md`](traceability_matrix.md)
(`finding_id → agent → tool → command → output sha256 → output path`).

## Reproduce the lookup locally

```bash
# Confirm the three files are present + non-empty, with these exact hashes
wc -l execution_log.jsonl traceability_matrix.md forensic_audit.log
sha256sum execution_log.jsonl traceability_matrix.md forensic_audit.log

# Trace the spot-checked finding back to its tool execution
jq 'select(.finding_id=="01KT9VTPAQB527688YEFTWZMXX")' execution_log.jsonl

# The agent-to-agent handoff spine
jq -r 'select(.event|test("state_transition|agent_handoff|agent_start|agent_done")) |
       "\(.ts_utc)  \(.event)  \(.agent // "")"' execution_log.jsonl
```

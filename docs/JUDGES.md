# Judges' Quickstart — EL

> One page from fresh SIFT to a verifiable EL run. Three paths: a **5-minute test-suite walk-through** (Path A) that proves the architectural contracts with no evidence download; a **30-minute end-to-end investigation** against a public DFIR scenario where EL reached the canonical answer two public human writeups missed, run as a **standalone CLI** (Path B); and the **same investigation driven conversationally from inside a Claude Code session** with no `ANTHROPIC_API_KEY` (Path C).

## Prerequisites

| Resource | Need |
|---|---|
| OS | SANS SIFT Workstation (Ubuntu 22.04 base) — [download](https://www.sans.org/tools/sift-workstation/) |
| Protocol SIFT | [github.com/teamdfir/protocol-sift](https://github.com/teamdfir/protocol-sift) installed under `~/.claude/` |
| RAM | 16 GB recommended (vol3 on DC-class images can hit 8 GB anon-RSS) |
| Disk | 100 GB free (M57-Jean evidence + EL working set + sealed archive) |
| Time | 5 min (test-suite only) · 30 min (M57-Jean end-to-end) · 60 min (with `--timeline`) |

## Path A — 5-minute contract verification (no evidence download)

The fastest way to verify EL's accuracy and constraint architecture without downloading anything. Demonstrates the *Constraint Implementation*, *IR Accuracy*, and *Audit Trail Quality* judging criteria.

> Note: a Docker-based cold-run smoke test exists at `Dockerfile.smoke`
> (~3 min build, ~5 min run) and verifies install.sh actually works on
> a fresh non-SIFT Ubuntu 22.04 — see [`docs/cold-run.md`](cold-run.md)
> for the result on `main` and the two friction points the test
> surfaced (Python 3.11+ preflight, `bulk-extractor` archive removal).

```bash
# 1. Clone + bootstrap (idempotent; safe to re-run)
git clone https://github.com/threatroute66/EL.git /opt/EL
cd /opt/EL
./install.sh

# 2. Health check — every tool EL needs, schema validates, Kùzu importable
.venv/bin/el doctor

# 3. Full test suite (3,178 passed, 89 skipped, ~10 minutes wall-clock)
make test

# 4. Just the explicit bypass-attempt suite (~0.2 s)
.venv/bin/pytest -q tests/test_security_boundaries.py

# 5. Just the false-positive regression locks (90+ assertions)
.venv/bin/pytest -q tests/test_ioc_*.py \
                    tests/test_*_guard*.py \
                    tests/test_*_fp_*.py \
                    tests/test_h_ransomware_*.py

# 6. Schema contract — no claim without evidence (except 'insufficient')
.venv/bin/pytest -q tests/test_finding_contract.py
```

**What this proves**

| Check | Criterion it answers |
|---|---|
| 36 tests in `test_security_boundaries.py` named after the bypass attempt and asserting refusal | *Constraint Implementation* — guardrails are architectural and explicitly tested for bypass |
| `test_finding_contract.py` — Pydantic refuses to construct any non-`insufficient` Finding with empty evidence | *IR Accuracy* — schema-enforced anti-hallucination |
| 90+ FP regression tests, each tied to a real case that originally produced the false positive | *IR Accuracy* — "honesty valued over perfection" posture made operational |
| `test_coordinator_blocks.py` — refusal to SYNTHESIZE while any Finding is `red_review.status == "unresolved"` | *Autonomous Execution Quality* — adversarial review is non-skippable |

## Path B — 30-minute end-to-end on a public DFIR scenario (standalone CLI)

The case: **M57-Jean** ([digitalcorpora.org](https://digitalcorpora.org/corpora/scenarios/m57-patents/)) — Pat Moore at the M57 startup investigates how a confidential spreadsheet leaked. The canonical answer per the scenario design: **Jean was socially engineered by a spoofed "Alison/President" email and replied with `m57biz.xls` attached** (not insider theft, not external compromise — pretexting-driven BEC exfil). Two public human writeups missed it; EL reached it with finding-level attribution.

```bash
# 1. Download the 2-part E01 (~3.2 GB compressed, ~10 GB raw NTFS inside)
cd /cases
wget https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2008-m57-patents/drives-redacted/nps-2008-jean.E01
wget https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2008-m57-patents/drives-redacted/nps-2008-jean.E02

# 2. Run the full pipeline (~15-25 min without --timeline; ~60 min with)
/opt/EL/.venv/bin/el investigate /cases/nps-2008-jean.E01 \
    --case-id m57-jean-judge \
    --investigator "Judge"

# 3. Open the executive report
xdg-open /opt/EL/cases/m57-jean-judge/reports/executive.html
# OR via the bundled HTTP server (Snap-confined browsers can't read /opt/ from file://)
/opt/EL/.venv/bin/el serve --port 8089 &
xdg-open http://localhost:8089/m57-jean-judge/reports/executive.html
```

**Expected verdict (locks against my own results — your run should reproduce these)**

- **Leading hypothesis:** `H_BEC_ACCOUNT_TAKEOVER`, currently score 51, gap `+38` over runner-up `H_INSIDER_EMAIL_EXFIL` 13 on `main`. *(See the [M57-Jean row in the accuracy report](accuracy_report.md#m57-jean-nps--digitalcorpora--bec--pretexting-exfil) for the comparison vs two public human writeups.)* **What to lock against is the *ranking + the canonical answer* (BEC/pretext leads, by a wide gap), not the exact score:** the ACH score drifts with the `~/.el/knowledge.sqlite` corpus state — rarity-bucketing demotes IOCs as more cases accrue (earlier runs scored 57). A fresh run should reproduce the leader and a large gap, ±a few points on the absolute number.
- **Two inbound phishing findings** by `email_forensicator` — display-name (`Alison`) vs SMTP-address mismatch, plus two reply-chain precursor findings tying the inbound pretext emails to outbound "RE:" replies.
- **Attachment named inline:** `1_m57biz.xls (291840 B)` in the narrative.
- **Anti-forensics signal:** 15 zero-size + 15 zero-timestamp Windows system binaries + 15 MACB-timestomp-skew findings (mass-wiped `auditusr.exe`, `pdh.dll`, `ciadmin.dll`, …).
- **Activity envelope:** `2001-08-23 → 2008-07-20` (timestomp anomaly → last exfil email).
- **Recovery corroboration:** 3 of the wiped binaries recovered from unallocated space (`tsk_recover`).

Compare against the [two public human writeups EL beat on this scenario](accuracy_report.md#m57-jean-nps--digitalcorpora--bec--pretexting-exfil).

## Path C — run the same investigation *inside* Claude Code (no API key)

Path B above drives EL as a standalone CLI. EL is equally designed to be
driven **conversationally from inside a Claude Code session** — the way it
was built and the way the author runs it day-to-day. The difference that
matters for judges: the two LLM-augmented steps (the adversarial
**red-review challenger** and the six-section **executive brief**) are
fulfilled by *your own Claude Code session*, so **no `ANTHROPIC_API_KEY` is
required** — the same model auth you already use for Claude Code does the
work. EL detects `CLAUDECODE=1`, writes a self-describing request file for
each step, and two bundled skills (`/el-red-review`, `/el-ai-brief`)
transport the model output back to disk and re-render the report.

```bash
# 1. Same install + evidence download as Path B (skip if already done).
#    Then open Claude Code IN the EL project dir so the project CLAUDE.md
#    operating context + the bundled skills both load automatically:
cd /opt/EL && claude
```

Then, inside the session, either ask in natural language —

> "Investigate /cases/nps-2008-jean.E01 with EL, case-id `m57-jean-judge`,
> then fulfil the red-review and executive-brief requests and open the
> report."

— or run the deterministic sequence (the leading `!` runs a shell command
in-session so its output lands in the transcript):

```
!/opt/EL/.venv/bin/el investigate /cases/nps-2008-jean.E01 --case-id m57-jean-judge --investigator "Judge"
/el-red-review m57-jean-judge
/el-ai-brief m57-jean-judge
!/opt/EL/.venv/bin/el serve --port 8089 &
```

Open `http://localhost:8089/m57-jean-judge/reports/executive.html`. The
**expected verdict is identical to Path B** — the forensic extractors are
deterministic CLI tools; running them from inside Claude Code changes only
*who fulfils the two advisory LLM steps* (your session vs an API key), never
the Findings ledger or the ACH ranking.

### A note on auto-detach (large evidence)

M57-Jean's two-part E01 is ~3.2 GB on disk — **below** the 4 GB
auto-detach threshold (`EL_AUTODETACH_GB`, default 4) — so `el investigate`
runs **attached**: it blocks until done, and the `/el-red-review` +
`/el-ai-brief` skills fulfil the deferred steps in-session as shown above.

Evidence **at or above 4 GB on disk** (e.g. a 36 GB physical-disk E01 or a
multi-device bundle) auto-promotes to a detached `systemd --user` transient
unit so a GUI/login-session restart or `systemd-oomd` can't kill a
multi-hour run. A **detached** run has no live assistant attached, so it
**self-fulfils** the red-review and executive-brief steps headlessly via
`claude -p` (still your Claude Code auth, still no API key) — you do *not*
invoke the two slash-commands; they're already done by the time the unit
exits. In that case `el investigate` returns immediately with a unit name;
follow progress with `journalctl --user -u <unit> -f` or tail the per-case
`analysis/forensic_audit.log`. Pass `--foreground` to force an attached run,
or set `EL_AUTODETACH_GB=0` to disable the threshold entirely.

## Verifying any single finding — the sha256 round-trip

This is the heart of the *Audit Trail Quality* criterion. Any factual claim in the ledger is bound to a tool's output file whose sha256 is recorded on the `EvidenceItem`. You can recompute the hash and verify the claim's provenance:

```bash
CASE=/opt/EL/cases/m57-jean-judge

# 1. Pick any high-confidence finding from the ledger
sqlite3 $CASE/findings.sqlite "
SELECT finding_id, agent, substr(claim,1,80)
FROM findings WHERE confidence='high' LIMIT 5"

# 2. Use the finding_id to walk back to the tool execution
FID=01KPWZNEC5FR8KWZETDM2BFG8B   # substitute one of yours
jq "select(.finding_id==\"$FID\")" $CASE/reports/execution_log.jsonl

# 3. The output also lives in the structured EvidenceItem
sqlite3 $CASE/findings.sqlite "
SELECT json_extract(payload_json,'\$.evidence[0].output_sha256'),
       json_extract(payload_json,'\$.evidence[0].output_path'),
       json_extract(payload_json,'\$.evidence[0].command')
FROM findings WHERE finding_id='$FID'"

# 4. Recompute the sha256 on the cited output_path — must match
sha256sum <output_path from step 3>

# 5. The traceability_matrix.md collects every (finding_id, command,
#    output_path, sha256) row in one Markdown table for offline review
less $CASE/reports/traceability_matrix.md
```

If the sha256 of step 4 doesn't match step 3, EL has produced a hallucinated claim. (It hasn't yet in 36+ real cases — but the test is yours to run.)

## What to look for — judging criteria reference

| Criterion | Where to look |
|---|---|
| **Autonomous Execution Quality** — does the agent reason about next steps, handle failures, self-correct in real time? | [README § Self-correction](../README.md#self-correction) names seven within-run primitives with the case that surfaced each. [accuracy_report.md § Self-correction sequences](accuracy_report.md#self-correction-sequences-during-real-case-work) walks four end-to-end loops where insufficient-finding → code fix → test-locked. The M57 run above demonstrates the mmls→fls fallback and `EvidenceTimeKey` extension paths in action. |
| **IR Accuracy** — findings correct, hallucinations flagged, confirmed vs inferred distinguished | Per-finding `confidence` field (`high`/`medium`/`low`/`insufficient`); `insufficient` is a first-class output meaning EL couldn't extract, NOT that nothing happened. M57-Jean leading hypothesis is the canonical scenario answer where [two public human writeups missed](accuracy_report.md#m57-jean-nps--digitalcorpora--bec--pretexting-exfil). 90+ FP regression tests in `tests/test_ioc_*.py` + `test_*_fp_*.py`. |
| **Breadth and Depth** — how much case data, depth on fewer beats shallow on many | [README § Architecture](../README.md#architecture) lists 34 specialist agents covering Windows + Linux + macOS + iOS + Android disk + memory, plus network (pcap/Zeek/Suricata), cloud (AWS/Azure/M365/GCP), email (PST/OST/MBOX), browser (Hindsight), and multi-host bundles (`investigate-bundle` → per-host + cross-host combined dashboard). [accuracy_report.md § Validated real-case results](accuracy_report.md#validated-real-case-results) lists every corpus EL has been exercised on end-to-end (M57-Jean, GMU LoneWolf, nromanoff/Lone Wolf, SRL-2018 36-case sweep, BelkaCTF mobile + macOS + Linux, ~2000 malware-traffic pcaps). |
| **Constraint Implementation** — architectural vs prompt-based, tested for bypass | `tests/test_security_boundaries.py` — 36 named bypass-attempt tests across 7 architectural boundaries (Pydantic schema, state-machine transitions, ACH exclusion, read-only-evidence chmod-strip, summary length cap, default red_review status, Confidence Literal type). Each test is named after the bypass attempt; if any starts passing the wrong direction the boundary regressed. LLM is advisory-only — [README § The contract](../README.md#the-contract) + [accuracy_report.md § Hallucination posture](accuracy_report.md#hallucination-posture--why-el-cannot-invent-a-claim). |
| **Audit Trail Quality** — can a finding be traced back to the specific tool execution? | The sha256 round-trip above. Every Finding has `evidence[].output_sha256` + `evidence[].output_path` + `evidence[].command`. The case's `reports/traceability_matrix.md` is a single Markdown table of every (finding_id → command → output → sha256) row. `reports/execution_log.jsonl` carries timestamps + agent attribution per tool invocation. A committed sample of all three log artifacts from a public-evidence run is at [`sample-reports/execution-logs/m57-jean/`](../sample-reports/execution-logs/); the schema + finding→tool round-trip + token usage are documented in [`agent_execution_logs.md`](agent_execution_logs.md). Sealed archive at `cases/_archives/<case>-<TS>.tar.gz` has a merkle root over the whole case dir; `el seal-verify <case>` re-hashes to confirm no drift. |
| **Usability and Documentation** — can another practitioner deploy and build on this? | `install.sh` is idempotent, runs on a fresh SIFT, ships under 30 minutes including dependency installation. `el doctor` reports every tool's presence + version + path so missing optional tools are visible. Per-case `CLAUDE.md` briefing is auto-generated at intake. [README § Install](../README.md#install) has the host-requirements table; [README § Usage](../README.md#usage) has every CLI invocation. The [capability-gap-analysis.md](capability-gap-analysis.md) is a working roadmap, not a marketing doc — items are explicitly tracked as shipped / partial / not-yet. |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `el doctor` says vol3 missing | `pip install -e .` didn't run cleanly in the venv | `cd /opt/EL && .venv/bin/pip install -e .[dev]` |
| `el investigate` raises "ewfmount not found" | Optional libewf-tools not on PATH | `sudo apt-get install ewf-tools libewf-dev` (already pre-installed on SIFT) |
| Memory image fails vol3 plugins with `Unable to locate symbols` | OS-specific ISF (debug-symbol pack) not in the local cache | Pre-download from `downloads.volatilityfoundation.org/volatility3/symbols/windows/` into `volatility3/symbols/windows/`, or run with internet access for auto-fetch. EL surfaces the exact URL in the `insufficient` finding's claim text. |
| `case.html` shows a blank page when opened from `file://` | Chromium snap can't read `/opt/` paths from `file://` URIs | Run `el serve --port 8089` and open `http://localhost:8089/<case-id>/reports/case.html` |
| `el investigate` halts at SYNTHESIZE with "unresolved findings" | Red Reviewer challenged a finding and no LLM was available to resolve | This is **working as designed** — adversarial review is non-skippable. Inspect `findings.sqlite` for rows where `red_review.status='unresolved'`, then either set `ANTHROPIC_API_KEY` and re-render or manually resolve via the ledger CLI. |

## Repository layout (1-screen orientation)

```
/opt/EL/
├── el/
│   ├── agents/             34 specialist agents — one per evidence kind
│   ├── skills/             Subprocess wrappers around vetted CLI tools
│   ├── orchestrator/       Coordinator state machine
│   ├── intel/              Hypotheses (33), ACH engine, MITRE map
│   ├── schemas/            Pydantic Finding contract (the enforcement)
│   ├── reporting/          report.md + case.html + executive HTML/PDF + STIX
│   └── cli.py              `el` typer entrypoint
├── tests/                  3,178 passing — run via `make test` (~10 min)
│   ├── test_security_boundaries.py     Find Evil bypass-test artifact
│   ├── test_finding_contract.py        Pydantic schema enforcement
│   └── test_ioc_*.py / test_*_fp_*.py  90+ false-positive regression locks
├── docs/
│   ├── JUDGES.md                       (you are here)
│   ├── accuracy_report.md              Per-corpus validation + honest misses
│   ├── evidence_datasets.md            What EL was tested against + sources + findings
│   ├── agent_execution_logs.md         Log schema + finding→tool round-trip + token usage
│   ├── capability-gap-analysis.md      Working roadmap (shipped vs open)
│   ├── state-machine.md                FSM diagram + transition table
│   └── protocol-sift.md                Inheritance contract from upstream
├── cases/                              Per-case workspaces (gitignored)
├── install.sh                          Idempotent bootstrap from fresh SIFT
├── Makefile                            `make doctor` / `make test`
├── README.md                           Architecture + Install + Usage
└── LICENSE                             Apache 2.0
```

## One-line summary for the rubric

> EL is a multi-agent DFIR orchestrator that runs vetted CLI tools, binds every factual claim to a tool's output file via sha256, refuses to score hypotheses while any Finding is under unresolved adversarial review, and emits `insufficient` as a first-class output whenever extraction fails — so the worst-case failure mode is a silent gap the analyst can see, never a confident false claim.

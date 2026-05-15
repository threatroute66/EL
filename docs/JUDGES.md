# Judges' Quickstart — EL

> One page from fresh SIFT to a verifiable EL run. Two paths: a **5-minute test-suite walk-through** that proves the architectural contracts (no evidence download required) and a **30-minute end-to-end investigation** against a public DFIR scenario where EL reached the canonical answer that two public human writeups missed.

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

# 3. Full test suite (2,258 tests, ~7 minutes wall-clock)
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

## Path B — 30-minute end-to-end on a public DFIR scenario

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

- **Leading hypothesis:** `H_BEC_ACCOUNT_TAKEOVER` score 57, gap `+42` over runner-up `H_ANTI_FORENSICS` 15. *(See the [M57-Jean row in the accuracy report](accuracy_report.md#m57-jean-nps--digitalcorpora--bec--pretexting-exfil) for the comparison vs two public human writeups. A later run captured in `capability-gap-analysis.md` records `gap +44 over H_INSIDER_EMAIL_EXFIL 13` after additional detection improvements — both numbers are post-fix; your run on current `main` should match one of them depending on the corpus state of `~/.el/knowledge.sqlite` at the time.)*
- **Two inbound phishing findings** by `email_forensicator` — display-name (`Alison`) vs SMTP-address mismatch, plus two reply-chain precursor findings tying the inbound pretext emails to outbound "RE:" replies.
- **Attachment named inline:** `1_m57biz.xls (291840 B)` in the narrative.
- **Anti-forensics signal:** 15 zero-size + 15 zero-timestamp Windows system binaries + 15 MACB-timestomp-skew findings (mass-wiped `auditusr.exe`, `pdh.dll`, `ciadmin.dll`, …).
- **Activity envelope:** `2001-08-23 → 2008-07-20` (timestomp anomaly → last exfil email).
- **Recovery corroboration:** 3 of the wiped binaries recovered from unallocated space (`tsk_recover`).

Compare against the [two public human writeups EL beat on this scenario](accuracy_report.md#m57-jean-nps--digitalcorpora--bec--pretexting-exfil).

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
| **Breadth and Depth** — how much case data, depth on fewer beats shallow on many | [README § Architecture](../README.md#architecture) lists 29 specialist agents covering Windows + Linux + macOS + iOS + Android disk + memory, plus network (pcap/Zeek/Suricata), cloud (AWS/Azure/M365/GCP), email (PST/OST/MBOX), browser (Hindsight). [accuracy_report.md § Validated real-case results](accuracy_report.md#validated-real-case-results) lists every corpus EL has been exercised on end-to-end (M57-Jean, GMU LoneWolf, nromanoff/Lone Wolf, SRL-2018 36-case sweep, BelkaCTF mobile + macOS + Linux, ~2000 malware-traffic pcaps). |
| **Constraint Implementation** — architectural vs prompt-based, tested for bypass | `tests/test_security_boundaries.py` — 36 named bypass-attempt tests across 7 architectural boundaries (Pydantic schema, state-machine transitions, ACH exclusion, read-only-evidence chmod-strip, summary length cap, default red_review status, Confidence Literal type). Each test is named after the bypass attempt; if any starts passing the wrong direction the boundary regressed. LLM is advisory-only — [README § The contract](../README.md#the-contract) + [accuracy_report.md § Hallucination posture](accuracy_report.md#hallucination-posture--why-el-cannot-invent-a-claim). |
| **Audit Trail Quality** — can a finding be traced back to the specific tool execution? | The sha256 round-trip above. Every Finding has `evidence[].output_sha256` + `evidence[].output_path` + `evidence[].command`. The case's `reports/traceability_matrix.md` is a single Markdown table of every (finding_id → command → output → sha256) row. `reports/execution_log.jsonl` carries timestamps + agent attribution per tool invocation. Sealed archive at `cases/_archives/<case>-<TS>.tar.gz` has a merkle root over the whole case dir; `el seal-verify <case>` re-hashes to confirm no drift. |
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
│   ├── agents/             29 specialist agents — one per evidence kind
│   ├── skills/             Subprocess wrappers around vetted CLI tools
│   ├── orchestrator/       Coordinator state machine
│   ├── intel/              Hypotheses (25+), ACH engine, MITRE map
│   ├── schemas/            Pydantic Finding contract (the enforcement)
│   ├── reporting/          report.md + case.html + executive HTML/PDF + STIX
│   └── cli.py              `el` typer entrypoint
├── tests/                  2,258 tests — run via `make test` (~7 min)
│   ├── test_security_boundaries.py     Find Evil bypass-test artifact
│   ├── test_finding_contract.py        Pydantic schema enforcement
│   └── test_ioc_*.py / test_*_fp_*.py  90+ false-positive regression locks
├── docs/
│   ├── JUDGES.md                       (you are here)
│   ├── accuracy_report.md              Per-corpus validation + honest misses
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

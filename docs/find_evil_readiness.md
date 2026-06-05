# EL — Find Evil 2026 Submission Readiness

Self-assessment against [docs/quality_criteria.txt](./quality_criteria.txt).
Written as an honest audit, not a marketing pitch. Grades: ✅ meets, ⚠ partial
(gap explicit), ❌ not yet.

---

## One-paragraph summary

EL is a 34-agent DFIR orchestrator running on the SANS SIFT Workstation,
built during the 2026-04-15 → 2026-06-15 hackathon window as a Python
multi-agent framework. It takes evidence (memory image, pcap, EVTX,
CloudTrail/Entra/M365 logs, E01 disk image with NTFS/ext4/APFS, or an
already-extracted filesystem tree for Windows / Linux / macOS / Android /
iOS), routes it through a coordinator state machine to specialist agents,
and produces a sealed case directory with a structured Findings ledger,
an Executive Narrative, an ACH hypothesis ranking, a self-contained HTML
case view, a STIX 2.1 bundle, and — satisfying the Find Evil audit-trail
requirement directly — an `execution_log.jsonl` + `traceability_matrix.md`
linking every claim to the specific subprocess that produced it. Every
claim is Pydantic-enforced to carry tool + version + command +
`output_sha256` + `output_path`, and `confidence="insufficient"` is a
first-class output ("I don't know" beats a guess). 3,255 tests
(3,169 pass · 86 skip, ~11 min). Validated end-to-end on 12 distinct
evidence types including M57-Jean,
LoneWolf, BelkaCTF mobile / macOS / Android, SRL-2018 (paired
memory + disk + baseline), and ~2000 malware-traffic pcaps.

---

## Stage 1 — Project Requirements

### 1.1 Agentic framework as the primary execution engine ✅

- **Framework used**: custom multi-agent Python orchestrator in
  `el/orchestrator/coordinator.py` driving 34 specialist Agent classes
  (`el/agents/*.py`), each implementing the `Agent ABC → run(ctx) → list[Finding]`
  contract (`el/agents/base.py`). The coordinator is a deterministic state
  machine with legal transitions in `el/orchestrator/states.py`.
- **Claude Code integration**: EL ships the `el` CLI and a per-case
  `CLAUDE.md` briefing written by `el.case_template`; inside a Claude Code
  session the analyst drives EL via the CLI and can ask Claude to reason
  over the sealed outputs. An `.mcp.json` scaffold is in the repo root for
  future MCP-server integration.
- **Criterion language**: *"comparable agentic architectures are permitted"*
  — the 34-agent coordinator, Pydantic-schema contract between agents, and
  red-reviewer blocking transition satisfy the "agentic framework"
  definition.

### 1.2 Self-correction ✅

Three architectural mechanisms, all tested and fired on real cases:

- **Red Reviewer** (`el/agents/red_reviewer.py`) runs unconditionally
  after every agent pass. It is a *rule-based adversarial challenger*
  augmented by an LLM challenger when `ANTHROPIC_API_KEY` is set. It
  flags findings that lack corroboration, lean on a single source,
  fall for Office-spawn-shell false positives, etc.
- **State-machine refusal**: the `SYNTHESIZE` state refuses to advance
  while any Finding has `red_review.status == "unresolved"`. Enforced
  in `coordinator.py`; regression-tested in
  `tests/test_coordinator_blocks.py`.
- **`confidence="insufficient"` as a first-class output**: Pydantic
  schema (`el/schemas/finding.py:58`) accepts high/medium/low only
  when `evidence[]` is non-empty; otherwise the agent is required to
  emit `confidence="insufficient"` with a claim naming what it could
  not extract. This is how EL's credential/lateral-movement/sigma
  agents reported on the M57 Jean XP case — they parsed the legacy
  `.evt` but found no threshold-crossing patterns, so they emitted
  `insufficient` rather than inventing activity.

### 1.3 Accuracy validation ✅

- **Every claim ships with its source**: `EvidenceItem` required fields
  are `tool`, `version`, `command`, `output_sha256`, `output_path`
  (`el/schemas/finding.py`). Schema validation rejects any `high|
  medium|low`-confidence Finding with empty `evidence[]` — attempts
  to construct one raise `pydantic.ValidationError` before the row
  is committed to the SQLite ledger.
- **Traceability artefact**: `reports/traceability_matrix.md` is a
  flat table `finding_id · agent · conf · tool · command · output
  sha256 · output path` — one row per EvidenceItem. Satisfies the
  literal submission requirement *"Judges must be able to trace any
  finding back to the specific tool execution that produced it."*
- **Per-file seal**: `seal.py` writes a sha256 manifest of the entire
  case directory at coordinator-DONE and verifies with `el
  seal-verify`. Any tamper of an evidence file after sealing produces
  a hash drift report.

### 1.4 Analytical reasoning (structured narrative, not a raw log) ✅

- `el/reporting/narrative.py` emits a six-beat Executive Narrative
  (What / Leading theory / Trigger / Chain / Impact / Current state
  + open questions) in both Markdown (`reports/narrative.md`) and as
  the top `#narrative` section of `reports/case.html`.
- Every factual sentence ends with an inline `[<finding_id>]`
  citation that is clickable in the HTML to open the finding's
  evidence drawer.
- Multi-hypothesis branch: when the ACH gap between leader and
  runner-up is `< 3`, the narrative renders **both** stories in
  parallel so a sycophantic single-theory report is structurally
  impossible when the evidence is ambiguous.
- Beyond prose: ACH ranking, ATT&CK coverage heatmap grouped by
  tactic, Diamond Model projection, Kùzu entity graph, Discovery
  Timeline + Attack-Event Timeline (artifact times) are all
  first-class structured views.

### 1.5 Functionality: installable + running on platform ✅

- One-step bootstrap: `./install.sh` (idempotent). Installs apt
  packages, creates venv, runs `el doctor` which probes every
  external tool (vol3, Sleuth Kit, EZ Tools via dotnet, plaso,
  bulk_extractor, yara, evtexport, msiecfexport, cryptsetup, …).
- **3,255 pytest tests** (3,169 pass · 86 skip) in ~11 min. Includes real-LUKS
  end-to-end round-trip, real pefile carve analysis on LoneWolf,
  and content-schema regression tests.
- Host requirements documented in README (RAM / vCPU / disk / SIFT
  base).

### 1.6 Platform: SIFT Workstation / Linux ✅

- Tool list in `~/.claude/CLAUDE.md` (global) is the canonical SIFT
  inventory; EL's skill wrappers target exactly those paths
  (`/opt/zimmermantools/*.dll`, `/usr/bin/fls`, etc.).
- `el doctor` prints a per-tool availability table.

### 1.7 Novel contribution within the hackathon window ✅

- Repository history: all commits fall between 2026-04-15 and today.
- The novel contributions are documented per-commit; key original
  work includes the Red Reviewer architecture, the Pydantic
  `insufficient`-is-first-class contract, the Kùzu Locard-graph
  substrate, the cross-case rarity-bucketed knowledge store, the
  six-beat Executive Narrative synthesizer, the Roussev & Quates
  three-tier similarity workflow (ssdeep + stego-carrier detector +
  memory-timeline baseline diff), and the finding → tool-execution
  traceability matrix.
- Pre-existing open-source libraries used (oletools, regipy, pefile,
  volatility3, scapy, stix2, kuzu, ppdeep, imagehash) are wrapped
  thinly and cited with their licenses.

### 1.8 Third-party licensing ✅

- Every pip dep in `pyproject.toml` is permissive:
  `oletools` (BSD-2), `regipy` (MIT), `pefile` (MIT), `volatility3`
  (Volatility Software License v1.0, MIT-compatible terms), `scapy`
  (GPL-2 — **note flag below**), `stix2` (BSD-3), `kuzu` (MIT),
  `ppdeep` (LGPL-3), `imagehash` (BSD-2). EL's own source is
  Apache-2.0.
- ✅ **scapy GPL-2 flag is now explicit in README** (commit `6bf5b68`)
  under a "Third-party dependency license notices" section. Table
  enumerates every pip dependency with license; the scapy row is
  called out with the fallback path (remove `scapy` from
  `pyproject.toml` → `NetworkAnalyst` runs Zeek-only, still
  BSD-3-Clause). No runtime dependency on scapy exists outside
  `el/skills/scapy_pcap.py` — verifiable by grep.

---

## Stage 1 — Submission Requirements

### 2.1 Public repo with MIT or Apache 2.0 ✅

- `https://github.com/threatroute66/EL` — public, Apache 2.0
  (`LICENSE` at repo root).
- GitHub "About" sidebar shows the Apache-2.0 badge.

### 2.2 README with setup instructions ✅

- `README.md` contains: architecture overview, agent + skill
  inventory, host requirements table, `./install.sh` instructions,
  usage examples for every CLI verb, case-workspace schema,
  cross-case knowledge layer description, the Finding contract, a
  validated-on-real-evidence table with 12 rows, and a license
  statement.
- Banner image `docs/EL.png` embedded at top.

### 2.3 Local reproducibility ✅

- Any case can be re-produced from scratch: `./install.sh` →
  `el investigate <evidence>` → `el report <case_dir> --html` →
  `el serve` → open `http://127.0.0.1:8089/<case_id>/reports/case.html`
  in a browser. Every report is a **deterministic projection** of
  the sealed Findings + ACH; running `el report` twice produces
  byte-identical artefacts.
- Individual agent test: `.venv/bin/pytest tests/`.

### 2.4 Text description of features ✅

Lives in `README.md` — "What it does", "Architecture", "The
contract", "Analyst web view", "Cross-case institutional knowledge"
sections cover every feature. Also this document.

### 2.5 Demo video ❌ **NOT YET MADE — postponed per submission plan**

- Needs: <5-min screencast with audio, terminal execution against
  real evidence, at least one self-correction sequence.
- Suggested script: (1) `el doctor` to show tool availability,
  (2) `el investigate /cases/m57-jean.E01` — highlight the
  inbound-phishing detector firing on a real inbox, (3) `el report
  --html --watch` with a browser open showing the live-update web
  view, (4) Red Reviewer challenging a single-source Finding and
  blocking SYNTHESIZE until it's resolved as the **self-correction
  moment**, (5) `traceability_matrix.md` to show the judge-required
  audit trail.

### 2.6 Architecture diagram ✅ **Mermaid diagram in README (commit `6bf5b68`)**

Full pipeline rendered as a Mermaid `flowchart TB`: 12 evidence-input
types → Intake (hash + manifest + read-only enforcement) → Triage →
Coordinator state machine → 34 specialist agents (subgraph) →
shared per-case substrate (findings.sqlite + graph.kuzu +
~/.el/knowledge.sqlite) → Correlator → ACH Engine → Red Reviewer
(with the loop-back to Coordinator when a Finding remains
unresolved) → Reporter → judge-facing outputs (report.md +
narrative.md + case.html + stix-bundle.json + findings.json + the
three execution-log artefacts + seal.json). Renders inline on
GitHub; degrades to readable Mermaid markup elsewhere.

### 2.7 Evidence dataset documentation ✅

- README "Validated on real evidence" table: 12 case rows with
  sample source, type, size, and what EL found — including the
  M57-Jean canonical-answer delta vs. two public GitHub writeups.
- `docs/capability-gap-analysis.md` has a "Validated / Untested
  formats" tracker: every disk format / memory format / log
  format with status (✅ / partial / ❌) and a suggested corpus
  source for the untested ones.
- `docs/SRL-2018-shakedown.md` documents the SRL-2018 Stark
  Research Labs corpus sweep results.

### 2.8 Accuracy report ✅ **CONSOLIDATED at `docs/accuracy_report.md` (commit `d25a95b`)**

Judge-facing document covering:
- Three-layer accuracy architecture (schema + Red Reviewer +
  rarity bucketing)
- Validated real-case results including M57-Jean scoreboard vs.
  two public writeups, LoneWolf paired disk+memory, SRL-2018
  corpus top scores, mobile + macOS baselines
- **8 known false-positive classes** with root cause, fix, and
  the regression-test file locking each in (IOC noise in 6
  categories + disk-anomaly FPs + hypothesis-scorer filename
  leaks + empty-pslist hidden-process + ACH tool-failure scoring
  + family-fingerprint context scoping + IOC feedback-loop guard
  + Zeek/tshark tool-output header noise). **90+ targeted
  assertions across 13 test files.**
- Known honest misses (format-by-format severity table)
- Hallucination posture — why EL cannot invent a claim
- Judge reproduction steps with concrete `pytest` + `jq` +
  `sha256sum` commands

### 2.9 Agent execution logs ✅

- `reports/execution_log.jsonl` — one JSON object per line, sorted by
  `ts_utc`. Event types: `state_transition` · `agent_start` · `agent_done`
  · `tool_execution` (one per EvidenceItem) · `finding_emitted` (one
  per Finding, shares `finding_id` with its tool_executions) · plus
  intake/seal/knowledge events.
- `reports/execution_log.md` — human-readable roll-up grouped by
  state-machine phase + agent.
- `reports/traceability_matrix.md` — flat judge-friendly table.
- **Built for this exact requirement** — see commit `ca8e2d4`.
- Validated on LoneWolf disk case: 259 events / 117 findings / 105
  tool_executions, every tool_execution `finding_id` resolves to a
  `finding_emitted` row (contract asserted in tests).

---

## Stage 2 — Judging Criteria (equally weighted)

### 3.1 Autonomous Execution Quality ✅

- **State machine reasoning**: coordinator picks the primary investigator
  from triage's `evidence_kind`, chains follow-on agents when upstream
  produces usable output (e.g. `WindowsArtifactAgent` is chained after
  `DiskForensicator` extracts artifacts).
- **Failure handling**: every skill wrapper is subprocess-timeout-hard
  and catches known tool errors, emitting `confidence="insufficient"`
  rather than propagating. `windows_artifact._evtx` auto-falls-back
  to legacy `.evt` via `evtexport` when EvtxECmd has nothing to parse.
  `mount_linux_ro` raises a targeted "LUKS container" error pointing
  at `mount_luks_ro` when it detects the magic.
- **Real-time self-correction**: Red Reviewer challenges every
  finding the moment it's emitted (event-driven via the `self.emit`
  helper on the Agent base class), blocks SYNTHESIZE, and the
  coordinator refuses to transition until challenges are resolved
  or downgraded.

### 3.2 IR Accuracy ✅

- **Confirmed vs inferred**: the four-level `confidence` enum
  (`high | medium | low | insufficient`) is the primary channel.
  `high` = direct tool-output match. `medium` = structural
  inference (e.g. "PE has packed entropy — plausibly a dropper").
  `low` = cross-case context (Layer-3 overlap findings from the
  knowledge DB don't lift any hypothesis). `insufficient` = documented
  non-finding.
- **Hallucination flags**: Red Reviewer challenges single-source
  findings; knowledge_lookup results are hard-capped at `confidence=
  "low"` so a cross-case IP match NEVER auto-lifts a hypothesis.
- **ACH score-delta per Finding**: every Finding carries
  `ach_score_delta: dict[H_*, int]` so the contribution of each
  finding to each hypothesis is visible in the ACH consistency
  matrix.
- **Real-case validation**: M57-Jean — EL reached the canonical BEC
  answer that two public GitHub writeups both got wrong (Basilmellow
  invented USB-insider details on a Win7 path when the image is XP;
  jynxora landed on external-compromise+AIM6 but missed the email
  vector). EL correctly classified as BEC with `H_BEC_ACCOUNT_TAKEOVER`
  leading by a wide gap (currently score 51, gap +38 over
  `H_INSIDER_EMAIL_EXFIL` 13 on `main`; the absolute score drifts a few
  points with the knowledge-store corpus, the ranking is stable), and
  surfaced the actual exfil email with attachment name/size inline.

### 3.3 Breadth and Depth of Analysis ✅

**Breadth — 12 validated evidence types**:
Windows memory (workstation + DC), NTFS E01 disk, paired memory+disk+
baseline, malware-traffic pcaps (~2000-pcap corpus sweep), MDD-format
XP memory, Linux ext4, macOS APFS, Android filesystem tree, iOS 14
filesystem tree, AWS CloudTrail, Azure Entra sign-in / M365 UAL, NPS
M57-Jean multi-part E01, GMU LoneWolf paired 13 GB disk + 18 GB
memory.

**Depth — per-evidence-type detector counts**:
- Windows disk: 12 EZ-tool parsers (MFTECmd, RECmd-Kroll-batch,
  AmcacheParser, AppCompatCacheParser, PECmd, EvtxECmd, SrumECmd,
  SBECmd, JLECmd, LECmd, RBCmd, BAM/DAM)
- Memory: 18 vol3 plugins including modules/modscan diff, ldrmodules
  three-list diff, malfind + credential-access carve-out, PE-header
  anomaly detection, Memory Baseliner diff
- Network: scapy pcap parsing + Zeek replay + Kerberos wire triage +
  DGA entropy + DNS tunneling + SMB admin-share writes
- Cloud: AWS CloudTrail + VPC Flow + Azure Entra sign-in + M365 UAL
  + Azure Activity + GCP Cloud Audit
- Malware analysis: YARA + capa + FLOSS + pefile deep-dive (imphash +
  Rich Header + section entropy + sensitive-import groups) + 19-family
  fingerprint library
- Mobile: iOS (jailbreak + sideload + provisioning + messenger) +
  Android (Magisk + sideload APK + /data/local/tmp staging +
  messenger) with their own filesystem-tree extractors
- Linux: utmp/wtmp/btmp binary parser + systemd-journal +
  `ld.so.preload` + auth-log burst + shell-history malicious
  patterns + cron + SSH authorized_keys anomaly

**Multi-host depth — `el investigate-bundle`**: an enterprise scenario
spanning N hosts runs as one bundle — each device through the full
per-host pipeline, then a synthesis pass merges every finding and
recomputes ACH on the union so cross-host evidence sums into the same
hypothesis. It auto-renders a cross-host dashboard
(`cases/_combined/<bundle>/combined.html`: joint ACH heatmap, unified
swim-lane timeline, merged Locard graph, cross-host IOC overlap, per-host
drill-down). Validated on the 3-host **2019 Narcos** corpus (per-host +
combined graphs populate; joint leader `H_APT_ESPIONAGE` over 17 k
findings) and the SRL-2018 multi-host sweep. Bundles auto-detach to a
`systemd --user` unit so a multi-hour run survives logout.

### 3.4 Constraint Implementation ✅ (ARCHITECTURAL, NOT PROMPT-BASED)

This is the criterion judges pay closest attention to. EL's guardrails
are enforced at the **Python / OS / schema layer** — there is no
possibility of prompt-based bypass because the LLM is never in the
decision path for evidence extraction.

- **Finding schema validation (Pydantic)** (`el/schemas/finding.py`):
  any Finding constructed with `confidence ∈ {high, medium, low}`
  AND empty `evidence[]` raises `ValidationError` at construction time.
  No way to emit a grounded claim without citing a tool.
- **State-machine transition validation**: `can_transition()` in
  `states.py` is a whitelist; illegal transitions raise. Can't
  skip SYNTHESIZE-blocks-on-unresolved-red-review.
- **Read-only evidence** (`el/evidence/intake.py:_evidence_is_protected`):
  intake strips write bits on any input under `/cases/`, `/mnt/`,
  `/media/`, `/evidence/`.
- **Tool invocation**: subprocess `capture_output=True, timeout=N`
  on every external call; no shell=True; paths interpolated as
  list-form arguments, not f-strings.
- **LLM boundary**: the LLM (when enabled) is **only** called by the
  Red Reviewer with structured Finding payload and a structured
  response schema; the LLM cannot invoke tools, cannot write to the
  case dir, and cannot modify a Finding — it can only return a
  challenge verdict that the rule-based challenger merges with its own.
- **`el serve` HTTP server**: binds 127.0.0.1 only by default; the
  systemd user unit ships with `NoNewPrivileges=true`,
  `ProtectSystem=strict`, `ReadOnlyPaths=/opt/EL/cases`.
- **Tested for bypass**: 3,255 tests include schema-violation
  attempts (`tests/test_finding_contract.py`), state-machine refusal
  (`tests/test_coordinator_blocks.py`), ACH-no-score-from-insufficient
  (`tests/test_ach_excludes_insufficient.py`), ssdeep+phash cross-
  case lookup respects case boundaries, etc.

### 3.5 Audit Trail Quality ✅

- Finding `finding_id` is a ULID — monotonic + sortable + unique.
- `traceability_matrix.md` gives the exact walk from claim to
  subprocess. Every row carries the `output_path` — the judge can
  `cat` that file + recompute the sha256 + verify it matches.
- `execution_log.jsonl` is fully parseable; a single `jq` pipeline
  can extract every tool execution for any claim:
  ```
  jq 'select(.event=="tool_execution" and .finding_id=="<FID>")' \
      reports/execution_log.jsonl
  ```
- `analysis/forensic_audit.log` is append-only + grep-friendly
  (`key=value`).
- `seal.json` at case DONE + `el seal-verify` = tamper-evident
  bundle.

### 3.6 Usability and Documentation ✅

- README: ~30 KB of structured install + usage + architecture
  documentation.
- `el doctor` diagnostics.
- `el serve` + systemd unit for a persistent case viewer.
- `el knowledge` + `el seal-verify` + `el ledger` + `el hunt` —
  every operational verb is a CLI command with `--help`.
- Web view: self-contained `case.html`, no CDN, no framework,
  works from `file://`, clickable ATT&CK counts drill into
  supporting findings, Discovery + Attack-Event timelines side by
  side.
- docstrings + type hints on every skill / agent entry point.

---

## Gap list — updated status

| # | Gap | Status | Reference |
|---|---|---|---|
| 1 | **Demo video** | ❌ Not recorded — postponed | Requires a prepared sequence incl. self-correction scene |
| 2 | Consolidated Accuracy Report | ✅ **Closed** | `docs/accuracy_report.md`, commit `d25a95b` |
| 3 | Architecture diagram upgrade | ✅ **Closed** | Mermaid block in `README.md` "Architecture", commit `6bf5b68` |
| 4 | Scapy (GPL-2) dependency flag | ✅ **Closed** | README "Third-party dependency license notices" section, commit `6bf5b68` |
| 5 | MCP-server integration | ❌ Not shipped — postponed | `.mcp.json` scaffold exists; no `el/mcp/server.py` yet |
| 6 | Live `demo_case` evidence | ❌ Not shipped — postponed | Script to seed `/cases/demo/` awaits |

---

## Recommended submission checklist (updated)

Complete:
1. ✅ Consolidated Accuracy Report (gap #2) — commit `d25a95b`
2. ✅ Architecture diagram upgrade (gap #3) — commit `6bf5b68`
3. ✅ Scapy GPL-2 license flag (gap #4) — commit `6bf5b68`

Remaining (postponed for separate sessions):
4. Ship a runnable demo case (gap #6)
5. Record the demo video (gap #1) — last, after repo is frozen
6. Optional: MCP server (gap #5)

Submission-day validation: `./install.sh --doctor` on a fresh SIFT
VM, then run the demo case and confirm `reports/traceability_matrix.md`
+ `reports/narrative.md` + `reports/case.html` all populate. Capture
the full output into a pastebin link as a backup to the video.

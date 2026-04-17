# CLAUDE.md

Project-level guidance for Claude Code when working on the EL codebase itself.
For user-facing docs see [README.md](./README.md). For per-case briefings see
the auto-generated `cases/<case_id>/CLAUDE.md` produced by the coordinator.

This project is the **EL — Edmond Locard DFIR orchestrator** referenced in
the global `~/.claude/CLAUDE.md` (Protocol SIFT) — a multi-agent forensic
orchestrator built on the SANS SIFT Workstation. The global file already
declares tool paths, evidence rules, and the read-only-on-evidence
constraint; this file adds the project-specific contracts.

---

## Operator preferences (load-bearing)

- **No sycophancy, no false positives.** Every finding ships with the tool,
  version, command, output sha256. The Pydantic schema rejects high/medium/low
  confidence with empty `evidence[]`. `confidence="insufficient"` is a
  first-class output — better than a guess.
- **No questions during a task.** Run workflows fully autonomously; deliver
  final findings. If blocked, pick the most reasonable path and note it.
  Architectural discussion and convergence on direction are exempt — that's
  not "asking during a task."
- **Tool output IS evidence.** Agents are Python orchestration around
  vetted CLI tools. Do NOT ask Claude to "read" event logs or parse
  process trees — deterministic parsers exist. LLMs reason about
  prioritisation, falsification, and narrative; they don't extract.
- **UTC everywhere.** SHA-256 manifests for inputs, evidence outputs, and
  provisioning snapshots.

---

## Codebase layout

```
el/
├── agents/                # one Agent class per file; each has a name + run(ctx)
│   ├── base.py            # Agent ABC + AgentContext (case_id, case_dir, input_path, manifest, shared)
│   ├── triage.py          # routing — sets ctx.shared['evidence_kind']
│   ├── memory_forensicator.py
│   ├── disk_forensicator.py
│   ├── windows_artifact.py
│   ├── network_analyst.py
│   ├── log_analyst.py
│   ├── cloud_forensicator.py
│   ├── endpoint_analyst.py
│   ├── timeline_synthesist.py
│   ├── correlator.py
│   ├── threat_hunter.py
│   └── red_reviewer.py
├── skills/                # subprocess wrappers; each returns a dataclass with as_evidence()
│   ├── vol3.py
│   ├── sleuthkit.py
│   ├── ezt.py             # EZ Tools via dotnet
│   ├── plaso.py
│   ├── scapy_pcap.py
│   ├── cloudtrail.py
│   ├── velociraptor.py
│   ├── ioc_extract.py     # regex extractor + noise filters
│   ├── yara_hunt.py
│   ├── memory_baseliner.py
│   └── (challengers/rules.py — adversarial review baseline)
├── intel/
│   ├── hypotheses.py      # 10 case-level hypotheses with deterministic scorers
│   ├── ach.py             # Heuer-style scoring + ranking
│   └── attack_map.py      # rule_id / hypothesis / claim-pattern → MITRE T-IDs
├── orchestrator/
│   ├── coordinator.py     # the state machine — owns dispatch + post-passes
│   └── states.py          # State enum + legal transitions (immutable)
├── evidence/
│   ├── intake.py          # hashing + manifest + per-case workspace creation
│   ├── ledger.py          # SQLite findings ledger (insert / list)
│   └── graph.py           # Kùzu graph init + open
├── reporting/
│   ├── render.py          # Markdown report rendering (deterministic projection)
│   └── stix.py            # STIX 2.1 bundle emission
├── schemas/
│   └── finding.py         # Pydantic Finding + EvidenceItem + RedReview (the contract)
├── audit.py               # forensic_audit.log writer
├── case_template.py       # per-case CLAUDE.md generator
├── tooling.py             # tool registry / probes for `el doctor`
├── provisioning.py        # `el provision-snapshot` snapshot capture
└── cli.py                 # typer entrypoints: doctor / intake / investigate / report / hunt / ledger / provision-snapshot

tests/                     # pytest; run with `make test`
provisioning/              # apt-packages.txt + optional-tools.txt + snapshots/
install.sh                 # idempotent bootstrap from a fresh SIFT
Makefile                   # install / doctor / test / snapshot / clean
```

---

## Common workflows

```bash
# After any code change
make test                  # runs pytest -q (under 10s for the full suite)

# Verify EL is healthy on this host
make doctor                # = .venv/bin/el doctor

# Run end-to-end against a case
.venv/bin/el investigate /cases/<input> --case-id <name>

# Re-render a report after editing the ledger or improving a filter
.venv/bin/el report /opt/EL/cases/<name>

# Standalone YARA sweep on an existing case
.venv/bin/el hunt /opt/EL/cases/<name>

# Snapshot host state for chain of custody
.venv/bin/el provision-snapshot --label <reason>
```

---

## The Finding contract (don't break this)

```python
class Finding(BaseModel):
    finding_id: str               # ULID, auto
    case_id: str                  # non-empty
    agent: str                    # non-empty
    claim: str                    # non-empty
    confidence: Literal["high", "medium", "low", "insufficient"]
    evidence: list[EvidenceItem]  # REQUIRED unless confidence == "insufficient"
    hypotheses_supported: list[str]
    hypotheses_refuted: list[str]
    ach_score_delta: dict[str, int]
    red_review: RedReview         # status: pending|passed|challenged|unresolved
    created_utc: datetime
```

Validation rule (model_validator at line ~58 in `el/schemas/finding.py`):
**any confidence other than `insufficient` requires a non-empty `evidence[]`**.

If you find yourself wanting to bypass this, the answer is almost always:
emit a second finding at `confidence="insufficient"` explaining what
would be needed to make a grounded claim.

---

## State machine contract

```
INTAKE → TRIAGE → HYPOTHESIS_GEN → PARALLEL_INVESTIGATE → CORRELATE
       → ADVERSARIAL_REVIEW → SYNTHESIZE → REPORT → DONE
                                    ↓
                                 BLOCKED  (any unresolved finding)
```

Defined in `el/orchestrator/states.py`. The coordinator refuses illegal
transitions (raises). Don't add states without updating the `TRANSITIONS`
table in the same file.

`SYNTHESIZE` only fires when **no Finding has `red_review.status == "unresolved"`.**
With the rule-based challenger active, this is rarely the failure mode —
the LLM challenger absence is the more common source of `unresolved`.

---

## Adding things

**New agent** — copy any agent in `el/agents/` as a template. Inherit
`Agent`, set `name`, implement `run(ctx) -> list[Finding]`. Use
`self.emit(ctx, Finding(...))` to write to the ledger. Wire into
`KIND_TO_AGENT` in `el/orchestrator/coordinator.py` keyed on the
`evidence_kind` Triage sets.

**New skill** — `el/skills/<name>.py`. Subprocess wrapper. Return a
dataclass with an `as_evidence(facts: dict | None = None) -> EvidenceItem`
method. Output goes to `<case_dir>/analysis/<agent>/...`. Capture stderr
to a sibling `.stderr` file. Use `_which(<bin>)` and raise a
`<Skill>Error` on missing tooling.

**New hypothesis** — `el/intel/hypotheses.py`. Add a `Hypothesis` to
the `HYPOTHESES` list with a deterministic `score(finding) -> int`.
Update `_h_benign` if the new hypothesis should refute the null.
Add an entry to `HYPOTHESIS_MAP` in `el/intel/attack_map.py` if it
maps to MITRE techniques. Lock the new behavior in with a test in
`tests/test_ach.py`.

**New tool probe** — `el/tooling.py`. Add a `probe_*()` function
returning `ToolStatus`. Append to the `survey()` list. The probe
should ALSO check `Path(sys.executable).parent / <tool>` because
venv-installed binaries aren't on `$PATH` when EL is invoked
without venv activation (this bit us on vol3 — see `_vol_executable`).

**Operator gotchas from Protocol SIFT SKILL files** — when adding a
skill wrapper for a tool covered by `~/.claude/skills/<area>/SKILL.md`,
read the SKILL first and bake its operator-tier defaults into the
wrapper's defaults. Examples currently live in:
- `el/skills/plaso.py` — `--parsers win10 --hashers md5,sha256 --timezone UTC` defaults
- `el/skills/sleuthkit.py` — `mactime -z UTC` default
- `el/skills/ezt.py` — `EvtxECmd --maps`, `RECmd --bn Kroll_Batch.reb`, `MFTECmd --at`

---

## Don't

- **Don't add agents that re-implement what a CLI tool already does.** If
  Plaso parses it, wrap Plaso. If EvtxECmd parses it, wrap EvtxECmd.
- **Don't write to evidence directories.** Read-only on `/cases/`,
  `/mnt/`, `/media/`. All output goes under `cases/<case_id>/{analysis,exports,reports,raw}/`.
- **Don't make the Red Reviewer optional.** It's the primary
  anti-sycophancy mechanism. The rule-based challenger ALWAYS runs;
  the LLM augments. Don't skip-on-error — emit `unresolved`.
- **Don't write sycophantic prose into reports.** The reporter is a
  deterministic projection of structured Findings. No "this strongly
  suggests..."  unless the Finding's `claim` field said so.
- **Don't use `git add -A` blindly** in code-change commits — the
  coordinator writes to `cases/`, `analysis/forensic_audit.log`, and
  `provisioning/snapshots/` during runs; those are gitignored but
  always inspect `git status -s` before staging.

---

## Forensic discipline (inherited from global CLAUDE.md)

- All outputs to UTC timestamps.
- All evidence inputs are read-only; intake auto-strips write bits when
  the input lives under `/cases/`, `/mnt/`, `/media/`, or `/evidence/`.
- Every finding's evidence carries a sha256 of the raw output it
  references. The reproducibility section of `report.md` lists every
  command — anyone can re-run and verify hashes match.

---

## Tests

```bash
make test                  # 65+ tests, under 10s
.venv/bin/pytest -q tests/test_finding_contract.py   # the most important file — locks the no-false-positive contract
.venv/bin/pytest -q tests/test_coordinator_blocks.py # the state-machine refusal-to-synthesize contract
.venv/bin/pytest -q tests/test_ioc_real_data_noise.py # regression tests captured from a real Windows memory image
```

Test fixtures use the `isolated` pattern (`monkeypatch.setattr(intake_mod,
"CASE_ROOT", tmp_path / "cases")`) — keeps real cases in `/opt/EL/cases/`
untouched.

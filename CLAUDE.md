# CLAUDE.md

Project-level guidance for Claude Code when working on the EL codebase itself.
For user-facing docs see [README.md](./README.md). For per-case briefings see
the auto-generated `cases/<case_id>/CLAUDE.md` produced by the coordinator.

This project is **EL — A tribute to Edmond Locard**, a multi-agent DFIR
orchestrator referenced in the global `~/.claude/CLAUDE.md` (Protocol SIFT)
and built on the SANS SIFT Workstation. The global file already declares
tool paths, evidence rules, and the read-only-on-evidence constraint; this
file adds the project-specific contracts.

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
│   ├── memory_forensicator.py     # vol3 plugins + hidden-process diff + PE-header + credential-access carve-out + process anomalies
│   ├── disk_forensicator.py       # ewfmount + mmls + per-partition fls + mactime + disk anomaly + NTFS mount + artifact extraction
│   ├── windows_artifact.py        # auto-chained after disk extracts: MFTECmd, RECmd, AmcacheParser, EvtxECmd, etc.
│   ├── network_analyst.py
│   ├── log_analyst.py
│   ├── cloud_forensicator.py
│   ├── endpoint_analyst.py        # Velociraptor JSONL collections
│   ├── timeline_synthesist.py     # Plaso (opt-in via --timeline)
│   ├── correlator.py              # Kùzu cross-agent graph queries
│   ├── threat_hunter.py           # YARA sweep with auto-generated rules from extracted IOCs
│   ├── malware_triage.py          # strings + 14-family fingerprint match across .dmp + analysis text
│   └── red_reviewer.py            # rule challenger (always) + LLM challenger (if API key)
├── skills/                # subprocess wrappers; each returns a dataclass with as_evidence()
│   ├── vol3.py            # incl. --dump integration; venv-bin discovery via sys.executable
│   ├── sleuthkit.py       # mmls/fls/mactime + ewfmount -X allow_other + mount_ntfs + extract_windows_artifacts
│   ├── ezt.py             # EZ Tools via dotnet — 11 wrappers
│   ├── plaso.py           # log2timeline + psort + pinfo with SKILL defaults
│   ├── scapy_pcap.py      # flows + DNS + HTTP Host/URI/UA + TLS SNI
│   ├── cloudtrail.py      # AWS CloudTrail JSON / JSONL
│   ├── velociraptor.py
│   ├── ioc_extract.py     # regex extractor + noise filters (timestamps, version strings, X.509 OIDs, secp256k1)
│   ├── yara_hunt.py
│   ├── dump_analysis.py   # ASCII + UTF-16LE strings extraction + structural fingerprints
│   ├── memory_baseliner.py        # supports both image (-b) and JSON baselines; vol3-2.27 patched
│   ├── disk_anomaly.py    # 9 SKILL/MITRE-grounded path patterns
│   └── (challengers/rules.py — adversarial review baseline)
├── intel/
│   ├── hypotheses.py      # 15 case-level hypotheses with deterministic scorers
│   ├── ach.py             # Heuer-style scoring + ranking; insufficient findings excluded
│   ├── attack_map.py      # 14 ATT&CK technique mappings (T-IDs)
│   └── malware_families.py        # 14 family fingerprint patterns + hypothesis tags + ATT&CK
├── orchestrator/
│   ├── coordinator.py     # the state machine — dispatch + IOC re-extract + cross-case lookup + seal at DONE
│   └── states.py          # State enum + legal transitions (immutable)
├── evidence/
│   ├── intake.py          # hashing + manifest + per-case workspace creation; accepts files OR directories
│   ├── ledger.py          # SQLite findings ledger (insert / list)
│   └── graph.py           # Kùzu graph init + open (per-case)
├── reporting/
│   ├── render.py          # Markdown report rendering (deterministic projection)
│   └── stix.py            # STIX 2.1 bundle emission
├── schemas/
│   └── finding.py         # Pydantic Finding + EvidenceItem + RedReview (the contract)
├── audit.py               # forensic_audit.log writer
├── case_template.py       # per-case CLAUDE.md generator
├── tooling.py             # tool registry / probes for `el doctor`
├── provisioning.py        # `el provision-snapshot` snapshot capture
├── seal.py                # Layer 2 — per-case sha256 manifest + tar.gz archive at DONE
├── knowledge.py           # Layer 3 — ~/.el/knowledge.sqlite cross-case IOC store
└── cli.py                 # typer entrypoints: doctor / intake / investigate / report / hunt / ledger /
                           #                    provision-snapshot / seal-verify / knowledge

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
.venv/bin/el investigate <input> --baseline <baseline.img>   # paired memory diff
.venv/bin/el investigate <input> --timeline                  # also Plaso super-timeline (slow)

# Re-render a report after editing the ledger or improving a filter
.venv/bin/el report /opt/EL/cases/<name>

# Standalone YARA sweep on an existing case
.venv/bin/el hunt /opt/EL/cases/<name>

# Verify a sealed case has not drifted
.venv/bin/el seal-verify /opt/EL/cases/<name>

# Cross-case IOC lookup (Layer 3 institutional knowledge)
.venv/bin/el knowledge stats
.venv/bin/el knowledge lookup <ipv4|domain|hash>

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

## Three knowledge layers (where improvement persists)

EL improves on two complementary tracks. Both are real, both compose:

| Layer | What it captures | Where it lives | Updated |
|---|---|---|---|
| **1. Code** | Detection patterns, hypothesis scorers, family fingerprints, bug fixes | git repo (`el/`, `tests/`) | When a human commits |
| **2. Per-case state** | This investigation's evidence, reasoning, conclusion | `cases/<id>/` + sealed `cases/_archives/<id>-<TS>.tar.gz` | At coordinator-DONE (sha256 manifest + tar.gz; `el seal-verify` re-checks) |
| **3. Institutional knowledge** | Every IOC every case has ever seen | `~/.el/knowledge.sqlite` | Continuously — every `el investigate` writes; every new case reads (cross-case overlap → low-confidence Findings) |

**Key contract for Layer 3**: cross-case overlap is **suggestive**, not
load-bearing. Findings from `knowledge_lookup` carry `confidence='low'`
and ACH does NOT lift any hypothesis from them. Forensic conclusions in
case B must stand on case B's own findings; case A is context only. This
keeps the per-case forensic chain clean while still letting the analyst
see when an IOC is recurring across investigations.

When extending: ANY change that lets one case's evidence directly score
another case's hypothesis is a Layer-3 violation. Don't.

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

**Step 0 (always): does SIFT already ship the tool?** Before writing a
new skill, check
[`docs/sans_sift_tools.md`](./docs/sans_sift_tools.md) — the
exhaustive, category-organized reference for what's installed on the
SANS SIFT Workstation. EL's design philosophy is *tool output IS
evidence* (load-bearing rule from "Operator preferences" above): we
wrap court-vetted CLI tools, we don't reimplement them. If a SIFT
default tool already does the job, the new skill is a subprocess
wrapper around it — not a Python re-implementation.

Concrete examples of this rule paying off:
- We wrapped `evtxexport` / `EvtxECmd` rather than writing an EVTX
  parser; `mactime` rather than rolling our own timeline join;
  `ewfmount` rather than parsing E01 internals; `qemu-img` for
  VHDX/VMDK conversion rather than implementing the formats.
- The few cases where we *did* write a parser (utmp/wtmp/btmp,
  IIS W3C, Windows Timeline ActivitiesCache.db) were because no
  SIFT default covers them — `utmpdump` exists but only prints
  human-readable form, not structured fields a detector can score.

When the SIFT-bundled tool only partially covers what's needed
(e.g. `utmpdump` for utmp), document the gap in the new skill's
docstring and link back to the SIFT entry that motivated the choice.
When the SIFT entry is `[commonly added]` rather than `[default]`,
note it in `el/tooling.py probe_*()` so `el doctor` flags missing
optional tools rather than failing at run-time.

**New agent** — copy any agent in `el/agents/` as a template. Inherit
`Agent`, set `name`, implement `run(ctx) -> list[Finding]`. Use
`self.emit(ctx, Finding(...))` to write to the ledger. Wire into
`KIND_TO_AGENT` in `el/orchestrator/coordinator.py` keyed on the
`evidence_kind` Triage sets.

**New skill** — `el/skills/<name>.py`. Subprocess wrapper around the
SIFT-bundled CLI identified in Step 0. Return a dataclass with an
`as_evidence(facts: dict | None = None) -> EvidenceItem` method.
Output goes to `<case_dir>/analysis/<agent>/...`. Capture stderr
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
- `el/skills/plaso.py` — `--parsers win_gen --hashers md5,sha256 --timezone UTC` defaults (Plaso 2024+ removed `win10` preset; `win_gen` covers XP / 7 / 8 / 10 / 11)
- `el/skills/sleuthkit.py` — `mactime -z UTC` default
- `el/skills/ezt.py` — `EvtxECmd --maps`, `RECmd --bn Kroll_Batch.reb`, `MFTECmd --at`

---

## Don't

- **Don't add agents or skills that re-implement what a CLI tool
  already does.** If Plaso parses it, wrap Plaso. If EvtxECmd parses
  it, wrap EvtxECmd. **Check `docs/sans_sift_tools.md` first** — that
  reference lists every default + commonly-added tool on the SANS
  SIFT Workstation, organised by category. If the bundled tool meets
  the need, the new skill is a subprocess wrapper around it.
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
make test                  # 109+ tests, under 10s
.venv/bin/pytest -q tests/test_finding_contract.py        # the no-false-positive contract (Pydantic schema)
.venv/bin/pytest -q tests/test_coordinator_blocks.py      # state-machine refusal-to-synthesize contract
.venv/bin/pytest -q tests/test_ach_excludes_insufficient.py  # tool-failure messages must not score
.venv/bin/pytest -q tests/test_seal_and_knowledge.py      # Layer 2 + Layer 3 contracts
.venv/bin/pytest -q tests/test_credential_access.py       # JIT carve-out for lsass / winlogon / csrss
.venv/bin/pytest -q tests/test_disk_anomaly.py            # 9 SKILL/MITRE-grounded path patterns
.venv/bin/pytest -q tests/test_ioc_*                      # 5 files of IOC false-positive regressions
```

Test fixtures use the `isolated` pattern (`monkeypatch.setattr(intake_mod,
"CASE_ROOT", tmp_path / "cases")` + `monkeypatch.setenv("EL_KNOWLEDGE_DB",
...)`) — keeps real cases in `/opt/EL/cases/` and the global knowledge
store untouched.


# Protocol SIFT → EL: how the foundation shapes this project

EL is the implementation of **Protocol SIFT** — the AI-agent orchestration
layer that sits on top of the SANS SIFT Workstation. The classical SIFT
Workstation is the tool stack: 200+ DFIR utilities, court-vetted, all in
PATH. Protocol SIFT is the *contract* that says how an AI agent is
allowed to use them. EL is the multi-agent orchestrator that runs to
that contract.

This document explains where Protocol SIFT lives, what EL inherits
verbatim, what EL extends, and the workflow for adding new capability
without breaking the inheritance chain.

---

## 1. Where Protocol SIFT lives

Three files on the host, all under `~/.claude/`:

| Path | Role |
|---|---|
| `~/.claude/CLAUDE.md` | **Charter.** Operator preferences, forensic constraints, installed tool paths, tool routing, shell aliases. Loaded into every Claude Code conversation as the global instruction file. |
| `~/.claude/skills/<area>/SKILL.md` | **Per-domain operator-tier playbooks.** One per tool family — `plaso-timeline/`, `sleuthkit/`, `memory-analysis/`, `windows-artifacts/`, `yara-hunting/`. Each is a curated flag set, recipe list, and "gotcha" checklist for a working DFIR analyst. |
| Cast / SaltStack `teamdfir/sift-saltstack` | Provisions the underlying tools. The charter and SKILL files reference, but don't install, the binaries. |

EL extends this, project-locally:

| Path | Role |
|---|---|
| `/opt/EL/CLAUDE.md` | **Project contract.** Loaded alongside the global charter in any Claude Code session opened against this repo. Adds the project-specific contracts (the Pydantic Finding shape, state-machine, three knowledge layers) on top of the SIFT charter. |
| `/opt/EL/docs/sans_sift_tools.md` | Exhaustive category-organised reference to every default + commonly-added SIFT tool. Step-0 lookup before any skill wrapper gets written. |
| `/opt/EL/cases/<case_id>/CLAUDE.md` | **Per-case briefing.** Auto-generated at coordinator-DONE. Loads when an analyst opens that case directory in Claude Code; carries the manifest, leading-hypothesis summary, agent counts, re-run commands. |

The three layers compose: global charter (what's a forensic tool, what
are the rules) → project contract (what's the EL data shape) → per-case
briefing (what's *this* investigation about). A Claude Code session
opened in a case directory gets all three loaded automatically.

---

## 2. What EL inherits verbatim from Protocol SIFT

### Forensic charter

The global `~/.claude/CLAUDE.md` declares:

> **Evidence integrity** — Never modify files in `/cases/`, `/mnt/`,
> `/media/`, or any `evidence/` directory.
>
> **Output routing** — Write all scripts, CSVs, JSON, and reports to
> `./analysis/`, `./exports/`, or `./reports/`. Never write to `/` or
> evidence directories.
>
> **Timestamps** — Always output in UTC.
>
> **Verification** — Verify tool success after every run. On failure:
> read stderr → hypothesize → correct → retry.
>
> **No hallucinations** — Never guess, assume, or fabricate forensic
> artifacts, file contents, or system states.
>
> **Deterministic execution** — Use court-vetted CLI tools to generate
> facts; ground all conclusions in raw tool output.

Every one of those lines is structurally enforced in EL:

- **Read-only on evidence**: `el/evidence/intake.py` strips write bits when
  the input lives under `/cases/`, `/mnt/`, `/media/`, or `/evidence/`.
- **Output routing**: every agent writes under
  `cases/<case_id>/{analysis,exports,reports,raw}/` — the directory
  layout is created at intake.
- **UTC**: every timestamp serialised by an agent is UTC; the narrative
  module has a `_parse_any_dt` helper that folds naive datetimes to UTC
  precisely because the charter is "UTC everywhere."
- **Verification**: every `Skill` wrapper captures stderr to a sibling
  `.stderr` file and surfaces non-zero return codes as
  `confidence="insufficient"` rather than swallowing them.
- **No hallucinations**: the Pydantic `Finding` schema rejects
  `confidence ∈ {high, medium, low}` with empty `evidence[]`.
  `confidence="insufficient"` is a first-class output — better than a
  guess. There is *no* code path where an LLM string becomes a claim.
- **Deterministic execution**: agents are Python orchestration around
  vetted CLI tools. The LLM never extracts facts; it reasons about
  prioritisation and falsification.

### Tool paths

The charter declares the canonical invocations:

| Tool | Charter says | EL skill wraps as |
|---|---|---|
| Volatility 3 | `vol3` (stable symlink → `/opt/EL/.venv/bin/vol`, v2.27.0; run `el doctor` for the resolved path) — NOT a standalone `/opt/volatility3-*/vol.py`, which does not exist on a venv install | `el/skills/vol3.py` discovers via `_vol_executable` (PATH `vol`, then the venv `vol` beside the active interpreter); `install.sh` drops the `vol3` symlink |
| Sleuth Kit | `fls`, `icat`, `mactime`, `tsk_recover` (PATH) | `el/skills/sleuthkit.py` |
| EWF tools | `ewfmount`, `ewfinfo`, `ewfverify` (PATH) | `el/skills/sleuthkit.py:ewfmount` (with `-X allow_other`) |
| Plaso | `log2timeline.py`, `psort.py`, `pinfo.py` (GIFT PPA) | `el/skills/plaso.py` |
| YARA | `/usr/local/bin/yara` (v4.1.0) | `el/skills/yara_hunt.py` |
| EZ Tools | `dotnet /opt/zimmermantools/<Tool>.dll` | `el/skills/ezt.py` (11 wrappers) |
| bulk_extractor | `bulk_extractor` (PATH, defaults to 4 threads) | `el/skills/bulk_extractor.py` |

### SKILL operator-tier defaults

Each `~/.claude/skills/<area>/SKILL.md` documents the working analyst's
flag set. EL bakes those into the wrappers as defaults so a fresh agent
run produces the same output a SIFT operator would type by hand:

- `el/skills/plaso.py` — `--parsers win_gen --hashers md5,sha256
  --timezone UTC` (the SKILL's "always pass `--timezone UTC`" rule, plus
  `win_gen` which replaced `win10` in Plaso 2024+).
- `el/skills/sleuthkit.py` — `mactime -z UTC` per the `sleuthkit/`
  SKILL's "always force UTC" rule.
- `el/skills/ezt.py` — `EvtxECmd --maps`, `RECmd --bn Kroll_Batch.reb`,
  `MFTECmd --at` per the `windows-artifacts/` SKILL.
- `el/skills/yara_hunt.py` — recursive scan with `-r`, no slack-space
  toggle (which YARA 4.x SKILL flags as too-noisy).

When SIFT updates and a SKILL changes (e.g. Plaso renames `win10` →
`win_gen` in 2024+), the wrappers track. The local `/opt/EL/CLAUDE.md`
documents the current bake-in next to each wrapper.

### Step-0 lookup

The single most important rule the project CLAUDE.md adds:

> **Step 0 (always): does SIFT already ship the tool?** Before writing a
> new skill, check `docs/sans_sift_tools.md`. EL's design philosophy is
> *tool output IS evidence*: we wrap court-vetted CLI tools, we don't
> reimplement them. If a SIFT default tool already does the job, the
> new skill is a subprocess wrapper around it — not a Python
> re-implementation.

Concrete examples this rule has paid off:

- We wrapped `evtxexport` / `EvtxECmd` rather than writing an EVTX
  parser; `mactime` rather than rolling our own timeline join; `ewfmount`
  rather than parsing E01 internals; `qemu-img` for VHDX/VMDK conversion
  rather than implementing the formats.
- The few cases where we did write a parser (utmp/wtmp/btmp, IIS W3C,
  Windows Timeline ActivitiesCache.db) were because no SIFT default
  covers the *structured* output form a detector needs.

---

## 3. What EL extends beyond Protocol SIFT

The charter is a contract for a single analyst working interactively at
the SIFT terminal. EL is what the contract becomes when you build a
multi-agent orchestrator on top:

| EL adds | Why |
|---|---|
| **Pydantic `Finding` schema** (`el/schemas/finding.py`) | Enforces the charter's "no hallucinations" rule mechanically. A Finding with `confidence ∈ {high, medium, low}` and empty `evidence[]` raises `ValidationError` at construction. |
| **State-machine coordinator** (`el/orchestrator/coordinator.py`) | Turns the charter's serial workflow into a parallelisable state graph — `INTAKE → TRIAGE → HYPOTHESIS_GEN → PARALLEL_INVESTIGATE → CORRELATE → ADVERSARIAL_REVIEW → SYNTHESIZE → REPORT → DONE`. Refuses illegal transitions; refuses `SYNTHESIZE` while any Finding has `red_review.status == "unresolved"`. |
| **ACH ranking** (`el/intel/hypotheses.py` + `el/intel/ach.py`) | Heuer's *Analysis of Competing Hypotheses* over 15 case-level hypotheses. Deterministic scorer per hypothesis; never declares the leader "true" — surfaces ranking + diagnostic findings + open disconfirmers. |
| **Red Reviewer** (`el/agents/red_reviewer.py`) | Adversarial review on every Finding. Rule-based challenger always runs (no API key required); LLM challenger augments when `ANTHROPIC_API_KEY` is set. Unresolved challenges block the state machine from `SYNTHESIZE`. |
| **Three knowledge layers** | Layer 1: code (detectors, scorers — git-tracked). Layer 2: per-case state (sealed `tar.gz` + sha256 manifest at coordinator-DONE). Layer 3: institutional knowledge (`~/.el/knowledge.sqlite`, every IOC every case has ever seen, with rarity bucketing). The strict contract: **cross-case overlap is suggestive, not load-bearing** — Layer-3 findings carry `confidence="low"` and ACH does *not* lift any hypothesis from them. |
| **Reporting projections** | Markdown narrative + per-case HTML dashboard + multi-case HTML stitch + STIX 2.1 bundle + per-case Kùzu graph + ATT&CK heatmap + Diamond Model + KAC. All deterministic projections of the Finding ledger; no LLM at synthesis time. |
| **Auto-generated per-case `CLAUDE.md`** (`el/case_template.py`) | Lets a Claude Code session opened in a case directory pick up the case manifest + leading hypothesis + agent counts + re-run commands without the analyst loading them by hand. The per-case file inherits the global charter and the project contract. |

None of these *replace* the SIFT charter — they enforce it at machine
speed across a multi-host case.

---

## 4. The workflow for extending EL while honoring SIFT

When a new evidence kind, parser, or detector lands in scope:

1. **Step 0 — check `docs/sans_sift_tools.md`.** Is the tool already a
   SIFT default? Is it a `[commonly added]` tool? Or is there no SIFT
   coverage at all?
2. **If a SIFT tool covers it** — read `~/.claude/skills/<area>/SKILL.md`
   for the operator-tier flag set, then write the wrapper at
   `el/skills/<name>.py`. Bake the SKILL defaults into the wrapper
   defaults. Add a probe in `el/tooling.py` so `el doctor` flags it
   missing rather than failing at run-time.
3. **If a `[commonly added]` tool covers it** — same as above, but the
   probe in `el/tooling.py` should distinguish "missing optional tool" from
   "missing required tool" so `el doctor` reports it as advisory.
4. **If no SIFT coverage** — document the gap in the new skill's
   docstring, link the SIFT entry that motivated the choice, and roll a
   minimal Python parser. Examples currently in-tree: `el/skills/utmp.py`
   (utmpdump prints human-readable form, not structured fields a
   detector can score), `el/skills/iis_w3c.py`, `el/skills/win_timeline.py`
   (Windows Timeline ActivitiesCache.db).
5. **Wire into an agent** — add or extend an agent in `el/agents/`,
   keyed via `KIND_TO_AGENT` in `el/orchestrator/coordinator.py` on the
   `evidence_kind` Triage sets.
6. **Hypothesis lift, if applicable** — add a scorer to
   `el/intel/hypotheses.py`. Add an entry in `el/intel/attack_map.py` if
   the new signal maps to a MITRE technique. Lock the behavior in with
   a test in `tests/test_ach.py`.

The inheritance chain stays clean: every new EL capability is grounded
in either a SIFT-bundled tool or an explicit, documented gap.

---

## 5. The "tool output IS evidence" rule, end to end

The single most load-bearing rule in this stack is the charter's "tool
output IS evidence." Walking it through one finding:

1. Operator runs `el investigate /cases/m57-jean/nps-2008-jean.E01`.
2. The coordinator dispatches `DiskForensicatorAgent` (an EL contract).
3. The agent calls `el/skills/sleuthkit.py:ewfmount` (a wrapper around
   the SIFT-bundled `ewfmount`, defaults baked from
   `~/.claude/skills/sleuthkit/SKILL.md`).
4. `ewfmount` writes to `cases/m57-jean/.../analysis/disk_forensicator/...`
   (the charter's output-routing rule, enforced by intake's directory
   creation).
5. The agent constructs a `Finding` (Pydantic, schema-enforced) carrying
   the exact `command`, `output_sha256`, and `output_path` of the
   ewfmount run.
6. `red_reviewer` challenges the finding (always-on; LLM augments).
7. `ach.score_findings` ranks hypotheses from the finding ledger
   (deterministic; never lifted by LLM-generated content).
8. `narrative.synthesize` projects the ledger to Markdown; `render_html`
   projects it to a single-file dashboard; `stix.emit_bundle` projects
   it to a MISP-importable bundle.
9. At `DONE`, `seal.py` sha256-hashes the case directory and writes
   `_archives/<case>-<TS>.tar.gz`. `el seal-verify` re-hashes any time
   later to detect drift.

A judge reading the report can recompute every `output_sha256` from the
sealed archive and confirm the finding hasn't been tampered with. That's
the SIFT charter — *deterministic execution* + *evidence integrity* —
enforced one schema constraint and one sha256 at a time.

---

## 6. Reference

- `~/.claude/CLAUDE.md` — global charter (Protocol SIFT)
- `~/.claude/skills/{plaso-timeline,sleuthkit,memory-analysis,windows-artifacts,yara-hunting}/SKILL.md`
  — per-domain operator playbooks
- `/opt/EL/CLAUDE.md` — project contract; the load-bearing additions on
  top of the global charter
- `docs/sans_sift_tools.md` — exhaustive SIFT tool inventory; Step-0
  lookup for any new wrapper
- `docs/accuracy_report.md` — how the inheritance chain is enforced at
  the schema, state-machine, and test layers
- `docs/find_evil_readiness.md` — the Find Evil 2026 submission shape;
  references this same chain
- [Cast / sift-saltstack](https://github.com/teamdfir/sift-saltstack)
  — the SIFT provisioning tree EL's `el doctor` probes

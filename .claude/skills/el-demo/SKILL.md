---
name: el-demo
description: |
  Drive EL through a GENUINE runtime self-correction on real evidence and
  narrate it, for the Find Evil demo / "Interaction with EL" walkthrough.
  Use when the user invokes `/el-demo` (optionally with a path to a memory
  image as the argument). EL ingests a Digital Corpora "2019 Narcos" memory
  image, Volatility 3 builds no kernel layer (the System DTB sits above the
  truncated 4 GB capture), EL detects this via a raw-byte ntoskrnl banner
  scan, names the Windows build, and RE-ROUTES the image to the carve
  pipeline instead of dead-ending — recording the correction as a
  first-class artifact. This skill runs that end-to-end and reports the
  before/after. Nothing is staged: the correction is driven by the image's
  physical structure and fires on every run.
allowed-tools:
  - Bash(bash /opt/EL/scripts/record_self_correction_demo.sh*)
  - Bash(EL_SC_FAST=1 EL_CASE=el-demo bash /opt/EL/scripts/record_self_correction_demo.sh*)
  - Bash(/opt/EL/.venv/bin/el self-corrections*)
  - Bash(/opt/EL/.venv/bin/el report*)
  - Bash(grep *)
  - Bash(tail *)
---

# el-demo — run EL's genuine self-correction live, in a Claude Code session

This is the agentic-loop demo: a human asks Claude, Claude runs the
court-vetted CLI tools, **EL self-corrects at runtime**, Claude reports
back. The self-correction is real — it is wired into EL's code at the point
where triage detects that Volatility 3 could not build a kernel layer and
re-routes to carving (`memory_truncated_acquisition_fallback`). See
[el/self_correction.py](../../../el/self_correction.py) and
[docs/accuracy_report.md](../../../docs/accuracy_report.md) (§ "Runtime
self-corrections are recorded").

## When to fire

- The user invokes `/el-demo` (with no arg = use the default Narcos memory
  image; with an arg = treat it as a path to a memory image to run instead).

Do nothing autonomously — this is a user-triggered demo, not a watchdog.

## What it does

`scripts/record_self_correction_demo.sh` (fast mode) launches the
investigation fully detached, watches the forensic audit log, and prints the
self-correction the instant it lands (~13 s), then exits — the carve + report
finish in the background. You run that script and narrate the result.

## Procedure

1. **Confirm the default image is readable** (or use the user's argument).
   Default: `/media/sansforensics/images1/2019 Narcos/Narcos-1/Memory Dump/Narcos-Mem-1.001`
   If the user passed a path in `$ARGUMENTS`, use that instead.

2. **Run the demo (fast mode, dedicated `el-demo` case so it never clobbers
   other cases):**
   ```bash
   EL_SC_FAST=1 EL_CASE=el-demo bash /opt/EL/scripts/record_self_correction_demo.sh "$ARGUMENTS"
   ```
   (With no argument, `"$ARGUMENTS"` is empty and the script uses its default
   Narcos image.) The command returns in ~15–20 s with the
   `⟳ SELF-CORRECTION RECORDED` block captured in its output.

   If you prefer to drive it yourself rather than via the script: launch
   `/opt/EL/.venv/bin/el investigate "<image>" --case-id el-demo --foreground`
   in the background, then poll
   `/opt/EL/cases/el-demo/analysis/forensic_audit.log` for a line containing
   `event=self_correction` (use a bounded `until` loop), and surface it.

3. **Show the structured record** at the terminal:
   ```bash
   /opt/EL/.venv/bin/el self-corrections /opt/EL/cases/el-demo
   ```

4. **Narrate the before/after** in plain language — the four fields that make
   it a real self-correction, in order:
   - **trigger** — Volatility 3 automagic built no kernel layer for the image.
   - **initial** — EL was about to route to the structured memory pipeline
     (pslist / pstree / malfind).
   - **detection** — a raw-byte ntoskrnl banner scan confirmed it IS Windows
     memory and named the build (e.g. **10.0.17763 / 1809**), but found no
     usable DTB in the captured range — a truncated / non-atomic acquisition.
   - **correction → outcome** — EL reclassified the evidence as carve-only and
     re-routed to the carve pipeline, so bulk_extractor + IOC carve still
     recover the strings / credentials / process names the structured plugins
     could not.

5. **Point the user at the surfaced evidence:**
   - Web view: `http://localhost:8089/el-demo/reports/case.html` → the
     **Runtime Self-Corrections** panel (lands when the background carve +
     report finish).
   - JSONL: `/opt/EL/cases/el-demo/analysis/self_corrections.jsonl`
   - Exec log: `/opt/EL/cases/el-demo/reports/execution_log.jsonl`
     (`event=self_correction`)

   Keep it tight — a few lines. The point already made itself.

## Notes

- The investigation continues in the background after the script returns
  (fast mode). The self-correction is the demo; the full carve + report just
  finish on their own. To wait for the whole run instead, set `EL_SC_FAST=0`.
- `el-demo` is a throwaway case — the script `rm -rf`s and recreates it each
  run, and kills any prior in-flight `el-demo` investigation first. Evidence
  under `/media/...` is read-only and never touched.
- This is a sibling to `el-ai-brief` / `el-red-review`: all three are the
  Claude-Code-in-the-loop face of EL's deferral/automation surface.

## What you must NOT do

- Don't describe a self-correction the run didn't actually produce. If the
  `event=self_correction` line never appears (e.g. a non-Windows image, or
  vol3 unexpectedly succeeds), say so and show the audit log — never narrate
  a correction that isn't in `self_corrections.jsonl`.
- Don't run against a real evidence case-id — always use the `el-demo` case
  so nothing of value is overwritten.

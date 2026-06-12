#!/usr/bin/env bash
#
# record_self_correction_demo.sh — drive EL through a GENUINE runtime
# self-correction on real evidence and surface it live, for the Find Evil
# demo screencast.
#
# What it shows (all real, nothing scripted):
#   1. EL ingests a Digital Corpora "2019 Narcos" memory image.
#   2. Volatility 3 automagic builds NO kernel layer (the image's System DTB
#      sits above the truncated 4 GB capture range — a real acquisition limit).
#   3. EL detects this, raw-byte-scans for the ntoskrnl banner, confirms it IS
#      Windows memory + names the build, and RE-ROUTES the image to the carve
#      pipeline instead of dead-ending.
#   4. That correction is recorded as a first-class event in
#      analysis/self_corrections.jsonl and the execution log — we print it live.
#
# Record it with:   asciinema rec -c scripts/record_self_correction_demo.sh
# Override the image with:   scripts/record_self_correction_demo.sh /path/to/mem.001
#
set -uo pipefail

EL_ROOT="${EL_ROOT:-/opt/EL}"
EL="${EL_BIN:-$EL_ROOT/.venv/bin/el}"
IMG="${1:-/media/sansforensics/images1/2019 Narcos/Narcos-1/Memory Dump/Narcos-Mem-1.001}"
CASE="${EL_CASE:-sc-demo}"
CASE_DIR="$EL_ROOT/cases/$CASE"
AUDIT="$CASE_DIR/analysis/forensic_audit.log"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
cyan() { printf '\033[36m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }

bold "EL · runtime self-correction demo"
dim  "evidence : $IMG"
dim  "case     : $CASE"
echo

if [[ ! -r "$IMG" ]]; then
  echo "ERROR: cannot read evidence image: $IMG" >&2
  echo "Pass a readable memory image as the first argument." >&2
  exit 1
fi

# Fresh case dir so the demo is reproducible run-to-run (evidence is read-only;
# we only remove EL's own prior output for this demo case).
rm -rf "$CASE_DIR"

cyan ">> el investigate (the memory image vol3 cannot build a kernel layer for)"
# --foreground keeps it attached so the screencast shows the live run.
"$EL" investigate "$IMG" --case-id "$CASE" --foreground &
EL_PID=$!

# Watch the audit log for the self-correction event and print it the instant
# EL records it (it fires at TRIAGE, early in the run).
cyan ">> watching the forensic audit log for the self-correction ..."
shown=0
for _ in $(seq 1 240); do
  if [[ -f "$AUDIT" ]] && grep -q "event=self_correction" "$AUDIT" 2>/dev/null; then
    shown=1
    echo
    bold "================ ⟳  SELF-CORRECTION RECORDED  ⟳ ================"
    grep "event=self_correction" "$AUDIT" | tail -1
    echo
    bold "Structured record (analysis/self_corrections.jsonl):"
    "$EL" self-corrections "$CASE_DIR"
    bold "==============================================================="
    echo
    break
  fi
  kill -0 "$EL_PID" 2>/dev/null || break
  sleep 1
done

[[ "$shown" -eq 0 ]] && dim "(no self-correction event observed yet — see the audit log)"

cyan ">> letting the carve pipeline finish (recovers what the structured plugins could not) ..."
wait "$EL_PID"

echo
bold "Final self-correction ledger for this case:"
"$EL" self-corrections "$CASE_DIR"

echo
dim  "Web view  : http://localhost:8089/$CASE/reports/case.html  (Self-corrections panel)"
dim  "JSONL     : $CASE_DIR/analysis/self_corrections.jsonl"
dim  "Exec log  : $CASE_DIR/reports/execution_log.jsonl  (event=self_correction)"

#!/usr/bin/env python3
"""Standalone Opus 4.8 red-review runner for a completed case.

Reads findings from the EL ledger, batches them, calls
`claude -p --model claude-opus-4-8` for each batch, writes
_red_review_verdicts.json, clears the applied marker, and
re-renders the report.

Usage:
    python3 /opt/EL/scripts/opus_red_review.py <case_id>
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, '/opt/EL')
os.environ.setdefault('EL_RED_MODEL', 'claude-opus-4-8')

from el.evidence.ledger import list_findings
from el.agents.red_reviewer import (
    SYSTEM, _review_payload, _review_cache_key, _parse_review_array,
)

CASE_ID   = sys.argv[1] if len(sys.argv) > 1 else 'vanko-r2'
CASE_DIR  = Path('/opt/EL/cases') / CASE_ID
REPORTS   = CASE_DIR / 'reports'
MODEL     = 'claude-opus-4-8'
CHUNK     = 10
TIMEOUT   = 420   # generous: Opus 4.8 is faster than 4-7 but still variable

_AUP = ("usage policy", "aup", "acceptable use", "violates our")


def _headless_batch(chunk_findings, batch_num: int, total: int) -> dict | None:
    prompt = (
        SYSTEM
        + "\n\n--- FINDINGS TO CHALLENGE (JSON) ---\n"
        + json.dumps(_review_payload(chunk_findings))
        + "\n\nRespond with ONLY the JSON array of verdicts — no prose, no code fence."
    )
    t0 = time.time()
    try:
        proc = subprocess.run(
            ['claude', '-p', '--model', MODEL, '--output-format', 'json'],
            input=prompt, capture_output=True, text=True, timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        print(f"  [{batch_num}/{total}] TIMEOUT after {TIMEOUT}s", flush=True)
        return None

    elapsed = time.time() - t0

    if proc.returncode != 0:
        stderr_l = (proc.stderr or '').lower()
        label = 'AUP' if any(m in stderr_l for m in _AUP) else f'rc={proc.returncode}'
        print(f"  [{batch_num}/{total}] FAILED ({label}, {elapsed:.0f}s)", flush=True)
        return None

    text = proc.stdout
    try:
        env = json.loads(proc.stdout)
        if isinstance(env, dict):
            if env.get('is_error'):
                result_l = (env.get('result') or '').lower()
                label = 'AUP' if any(m in result_l for m in _AUP) else 'error-envelope'
                print(f"  [{batch_num}/{total}] FAILED ({label}, {elapsed:.0f}s)", flush=True)
                return None
            text = env.get('result', proc.stdout)
    except json.JSONDecodeError:
        pass

    verdicts = _parse_review_array(text) if text else None
    if verdicts:
        statuses = {}
        for r in verdicts.values():
            statuses[r.status] = statuses.get(r.status, 0) + 1
        print(f"  [{batch_num}/{total}] OK  {len(verdicts)} verdicts {statuses}  ({elapsed:.0f}s)", flush=True)
        return verdicts
    else:
        print(f"  [{batch_num}/{total}] parse-failed ({elapsed:.0f}s)", flush=True)
        return None


def main():
    print(f"=== Opus 4.8 Red Review — {CASE_ID} ===", flush=True)
    findings = list_findings(CASE_DIR, case_id=CASE_ID)
    reviewable = [f for f in findings if f.confidence != 'insufficient']
    print(f"Findings: {len(findings)} total, {len(reviewable)} reviewable", flush=True)

    cache_key = _review_cache_key(CASE_ID, reviewable)
    print(f"Cache key: {cache_key[:16]}...", flush=True)

    chunks = [reviewable[i:i + CHUNK] for i in range(0, len(reviewable), CHUNK)]
    print(f"Batches: {len(chunks)} × {CHUNK}  (model={MODEL}  timeout={TIMEOUT}s)\n", flush=True)

    all_verdicts: dict = {}
    failed = aup_blocked = 0

    for i, chunk in enumerate(chunks, 1):
        result = _headless_batch(chunk, i, len(chunks))
        if result is None:
            failed += 1
        else:
            all_verdicts.update(result)

    print(f"\nDone: {len(all_verdicts)} verdicts collected, {failed} batches failed", flush=True)
    if not all_verdicts:
        print("ERROR: no verdicts — aborting, existing verdicts untouched.", flush=True)
        sys.exit(1)

    # Write verdicts file
    out_path = REPORTS / '_red_review_verdicts.json'
    out = {
        "__cache_key": cache_key,
        "__model": MODEL,
        "__generated_utc": datetime.now(timezone.utc).isoformat(),
        "verdicts": [
            {
                "finding_id": fid,
                "status": v.status,
                "challenger_notes": v.notes,
                "disconfirming_checklist": v.checklist,
            }
            for fid, v in all_verdicts.items()
        ],
    }
    out_path.write_text(json.dumps(out, indent=2))
    print(f"Verdicts written → {out_path}", flush=True)

    # Clear applied marker so el report re-merges
    applied = REPORTS / '_red_review_applied.json'
    if applied.exists():
        applied.unlink()
        print(f"Applied marker cleared.", flush=True)

    # Re-render
    print("Re-rendering report…", flush=True)
    result = subprocess.run(
        ['/opt/EL/.venv/bin/el', 'report', str(CASE_DIR), '--html'],
        capture_output=False, text=True,
    )
    print(f"el report exit={result.returncode}", flush=True)
    print("=== Complete ===", flush=True)


if __name__ == '__main__':
    main()

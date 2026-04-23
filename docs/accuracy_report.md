# EL — Accuracy Self-Assessment Report

_Honest self-assessment of EL's detection accuracy across every
real-evidence case it has been exercised against, including
known false-positive classes we've already fixed as regression
tests and the formats EL cannot currently parse. Written to
satisfy the Find Evil 2026 submission requirement:_

> _"Include an Accuracy Report — Self-assessment of findings
> accuracy. False positives, missed artifacts, hallucinated
> claims identified during testing. **Honesty valued over
> perfection.**"_

---

## Approach

EL's accuracy posture has three architectural layers, not a
single QA step:

1. **Schema-enforced tool-grounding.** A Finding with
   `confidence ∈ {high, medium, low}` and empty `evidence[]`
   raises `pydantic.ValidationError` at construction time. The
   only escape is `confidence="insufficient"` — that is a
   first-class output, not a rejection. `tests/test_finding_
   contract.py` is the regression lock.
2. **Rule-based adversarial review** on every emitted Finding
   (`RedReviewer` runs unconditionally; LLM challenger augments
   when `ANTHROPIC_API_KEY` is set). Unresolved challenges block
   the state machine from reaching `SYNTHESIZE`.
3. **Cross-case rarity bucketing** (`~/.el/knowledge.sqlite`).
   Observations seen in 30+ prior cases are classified
   `ubiquitous` and DO NOT lift any hypothesis; `rare` (≤2
   prior cases) gets surfaced as `confidence="low"` context.
   Cross-case overlap is explicitly context, never evidence.

Every known false-positive class we've discovered during real-
case work has become a named regression test. The FP test
inventory (grep across `tests/test_ioc_*.py`,
`test_*_guard*.py`, `test_*_fp_*.py`, `test_h_ransomware_*.py`)
currently holds **90+ targeted anti-FP assertions** across
13 test files.

---

## Validated real-case results

Each row lists what EL found + the specific finding_id trail
judges can walk via `reports/traceability_matrix.md`.

### M57-Jean (NPS / digitalcorpora) — BEC / pretexting exfil

**Canonical answer per scenario**: Jean was social-engineered
by a spoofed email from the company president ("Alison") and
replied with `m57biz.xls` attached. Not insider theft, not
external compromise — pretexting-driven exfil.

| Measure | EL | [Basilmellow writeup](https://github.com/Basilmellow/Autopsy-M57-Linux-Forensics) | [jynxora writeup](https://github.com/jynxora/M57-Jean-Case-Analysis) |
|---|---|---|---|
| Leading hypothesis | ✅ BEC / pretext exfil | ❌ Invented "USB insider" (on a Win7 path — image is XP) | ❌ "Browser exploit + AIM6 bundleware", missed email vector |
| ACH gap over runner-up | +44 (score 57 vs 13) | — | — |
| Exfil email identified | ✅ Two subjects ("Thanks!" + "Please send me the information now") | ❌ Invented `confidential_client_list.xls` | ❌ Named the file but missed the outbound |
| Attachment name + size | ✅ `1_m57biz.xls (291840 B)` named inline in narrative | ❌ | ❌ |
| Display-name vs SMTP mismatch | ✅ 4 findings (2 inbound phishing + 2 reply-chain precursors) | — | — |
| IE5 tracker-sync URLs | ✅ 24 `__utm` session-sync patterns flagged from 4778 parsed records | — | ✅ partial |
| Anti-forensics wiped binaries | ✅ 15 zero-size + 15 zero-timestamp system binaries | — | ✅ partial |

EL is the only analysis of the three that reached the canonical
conclusion, and it did so with per-finding evidence citations
that a judge can verify by recomputing `output_sha256` on each
`output_path`.

### GMU LoneWolf (paired disk + memory)

| Signal | Result |
|---|---|
| Disk leading hypothesis | H_APT_ESPIONAGE score 21 (gap +9 over H_LATERAL_MOVEMENT 12) |
| Memory leading hypothesis | H_C2_BEACONING score 11 (gap +8 over H_APT_ESPIONAGE 3) |
| Cobalt Strike attribution | ✅ Family fingerprint in `domain.txt` + `url.txt` (Malleable-C2 `__utm.gif` pattern) |
| Live C2 beacons | ✅ 4 Azure-hosted IPs at :443 in Netscan (52 + 17 + 7 + 7 repeated CLOSED connections) |
| Lateral-movement chain | ✅ Multi-technique kill-chain 2018-03-27 → 2018-04-06: service install + WMI event-consumer + PS-remoting |
| Anti-forensics | ✅ 15 zero-size + 15 zero-timestamp Windows system binaries |
| PE deep-dive | ✅ 149/150 carved PEs analyzed, 1 with `credential_dump` import signature (OpenProcess + ReadProcessMemory) |
| Cross-case knowledge overlap | ✅ 19 Layer-3 hits linking memory IOCs to 14 prior Qakbot/Valak/Ursnif/Icedid/Ta551 pcap campaigns |

### FOR508 Stark Research Labs (SRL-2018) — 36-case corpus

Documented in `docs/SRL-2018-shakedown.md`. Top-scoring cases:
- `srl-admin-memory` — H_APT_ESPIONAGE score 38 (full attack chain via Memory Baseliner diff: PsExec → spinlock.exe Meterpreter → Mnemosynei386.sys driver → dllhost/svchost disguise)
- `srl-rd-04-memory` — 35
- `srl-dmz-ftp-disk` — 31
- `srl-dc-disk-r3` — 30
- `srl-rd-01-disk` — 29
- 33 SRL cases scored ≥19 on at least one hypothesis

### BelkaCTF mobile + macOS

- **BelkaCTF Android**: Magisk root + `com.topjohnwu.magisk` sideloaded via packageinstaller + WhatsApp presence (3 detector hits)
- **BelkaCTF iPhone SE (iOS 14.3)**: 18 encrypted-messenger / privacy-tool apps flagged (Signal, Telegram, Wickr Enterprise, ProtonMail, Tutanota, Onion Browser, KeepSafe, Burner, ...) + clean extraction of 63 app Info.plists + 105 bundle metadata + SMS/AddressBook/CallHistory/KnowledgeC/Health databases
- **BelkaCTF macOS Big Sur**: clean baseline (8 etc_core + 3 SSH + 2 system launch plists + 1 KnowledgeC + 1 Quarantine + 3 Safari). No hits — correctly emitted zero malicious-activity findings rather than inventing them.
- **BelkaCTF Kidnapper (Linux ext4)**: `LinuxForensicator` extracted 12 /etc + 22 cron + 204 systemd services. Clean baseline, no detector hits.

### Malware-traffic pcap corpus sweep

~2000 malware-traffic-analysis pcaps from 2013-2025 processed
through the pipeline. Populated `~/.el/knowledge.sqlite` with
Layer-3 IOC counts driving the rarity-bucketing that suppresses
common MS infrastructure IPs (e.g. `13.107.6.254` seen in
22 prior cases = `ubiquitous`, no hypothesis lift) while
surfacing true-positive IOCs when they re-appear in a new
case (the LoneWolf memory → Qakbot/Valak match above is
directly driven by this store).

---

## Known false-positive classes — already fixed as regression tests

Every class below fired at least once on a real case, was caught,
and is now locked in as a test that blocks the pattern from
regressing.

### IOC extraction noise (6 distinct categories)

`tests/test_ioc_*.py` (10 files, ~50 assertions)

| Class | Root cause | Fix + test |
|---|---|---|
| **Timestamps masquerading as hashes** | `12:34:56` patterns fooling MD5 regex | hex-chunk + colon-delimiter guard; `test_ioc_extract.py` |
| **Version strings as domains** | `2.27.0-rc1` matching domain regex | dotted-integer-only filter; `test_ioc_real_data_noise.py` |
| **X.509 OID labels** | `2.5.29.15`, `1.3.6.1.4.1.311` matching IPv4 patterns | OID-prefix allowlist; `test_ioc_crypto_noise.py` |
| **Crypto curve constants (secp256k1 / secp256r1)** | 256-bit hex constants matching sha256 regex | named-constant allowlist; `test_ioc_crypto_noise.py` |
| **File-extension TLDs** | `.onion`, `.local`, `.test` mimicking real TLDs in filenames | context-aware suppression — only flag when URL-shaped; `test_ioc_filename_filter.py` |
| **Windows internals** | `machine.scc`, `system32.log` matching domain regex | Win-internals allowlist; `test_ioc_disk_noise.py` |

### Disk anomaly false positives

`tests/test_disk_anomaly_fp_regressions.py` — **25 assertions**.
Covers:
- `svchost.exe` + `lsass.exe` in `WinSxS`, `i386/amd64` install
  caches, `ServicePackFiles`, `dllcache` (legitimate Windows
  component stores — NOT masquerade)
- Installer-temp hex directories under `Temp/<hex>/` (MSI /
  InstallShield / VMware unpack paths)
- Chrome / Teams / Dashlane / OneDrive legitimately-in-AppData
  installers
- Stock Microsoft scheduled task names in `Windows/Tasks/` (e.g.
  `GoogleUpdateTaskMachineCore` — OEM task, not suspicious)

### Hypothesis-scorer filename leaks

`tests/test_h_ransomware_filename_leak.py` — **7 assertions**.

Historical bug: `_h_ransomware` matched the bare substring
`"encrypt"`, which picked up `"encrypted-messenger"` in benign
iOS findings and pushed H_RANSOMWARE to the top of the ACH
ranking on M57-Jean (score 3). Fix: tightened to specific
ransom-note phrases (`"files encrypted"`,
`"files have been encrypted"`, `"encrypt your files"`,
`"encrypting files"`). Test locks this in. The filename-leak
guard was generalised across every keyword hypothesis scorer
in a follow-up commit (`3fa18a6`).

### Memory-forensics hidden-process false flag

`tests/test_hidden_process_diff_guard.py` — **2 assertions**.

Historical bug: when `pslist` returned 0 rows (symbol-mismatch
on domain-controller memory images), the naïve psscan-pslist
diff reported every single psscan entry as a "hidden process".
Fix: empty-pslist short-circuit — when pslist is empty, emit
`confidence="insufficient"` stating the symbol mismatch rather
than concatenating 200 false hidden-process findings. Test
constructs a synthetic empty-pslist scenario and asserts the
insufficient output.

### ACH scoring of tool-failure messages

`tests/test_ach_excludes_insufficient.py`.

Historical bug: tool-failure `insufficient` findings ("vol3
symbol mismatch: Cannot determine memory OS family") were being
scored in the ACH matrix, shifting hypothesis rankings based on
what EL couldn't extract rather than what it saw. Fix: ACH
engine explicitly excludes `confidence="insufficient"` from all
scoring. Test covers every hypothesis scorer.

### Family-fingerprint context scoping

`tests/test_malware_family_context.py` + `test_c2_score_discrimination.py`.

Historical bug: the Trickbot `/table.bmp` pattern fired on M57-
Jean because it appeared in benign IE5 cache records as a
filename — not a C2 URI. Fix: context-scoped pattern matching
(`memory` vs `network` vs `disk` vs `log` evidence contexts);
URL-shaped patterns only fire in network context. Tests lock
the scope constraints.

### IOC feedback loop guard

`tests/test_ioc_feedback_loop_guard.py` — **13 assertions**.

Historical concern: YARA rules are auto-generated from extracted
IOCs; EL scans the whole case dir with those rules. Without a
guard, a rule would match its own source IOC in `iocs.json` and
the cycle would inflate "IOC match" counts indefinitely. Fix:
rule-generation excludes paths inside `analysis/` + `exports/`
+ `reports/` so YARA can only match on evidence, not on EL's
own output. Test synthesizes an infinite-loop scenario and
asserts bounded output.

### Zeek / tshark tool-output IOC noise

`tests/test_ioc_zeek_tshark_noise.py` — **7 assertions**.

Tool tables contain their own field names + CSV headers
(`src_ip`, `dst_ip`, `field_name`) that look IPv4-ish to the
naïve regex. Fix: skip IOC extraction from the first few
columns of CSV/TSV files + from known tool-output header
patterns.

---

## Known honest misses

The capability-gap-analysis tracker documents formats EL
cannot currently parse. Summarising here for the accuracy
audit:

| Miss | What EL does instead | Priority |
|---|---|---|
| Encrypted containers (FileVault legacy, BitLocker untested, APFS-encrypted) | Raises targeted error pointing at unlock primitive (LUKS works end-to-end; others need operator-supplied key path) | Medium — operator-blockable |
| ReFS / btrfs / xfs / zfs filesystems | `disk_forensicator` emits `insufficient` — Sleuth Kit doesn't support ReFS, extractor assumes ext* | Low — rare in IR corpora |
| AFF4 + `.ad1` commercial containers | Not supported | Low — EnCase/FTK-only |
| LiME / AVML (Linux memory) | Not supported — vol3 symbol + profile path untested | Medium |
| Hyper-V / VMware VM memory snapshots | Vol3 flat-`.vmem` works; `.vmss`/`.vmsn` snapshot-side untested | Low |
| Suricata EVE / IIS W3C / ESXi / Kubernetes audit logs | Not parsed; `CloudForensicator` silent-dispatches and emits `insufficient` when shape isn't recognised | Medium |
| Office XLM macros / PDF object streams | VBA via olevba shipped; XLM via `pcodedmp` + PDF via `pdfparser` not yet wired into `malware_triage` | Medium |
| Teams / Slack LevelDB + IndexedDB | Not parsed — needs LevelDB Python dep | Low |
| NetFlow / IPFIX agent integration | Skill is shipped (nfdump wrapper + detectors); agent-side routing waits for a real nfcapd corpus | Medium |

In the submission review: "honest" means these are **surfaced as
insufficient findings**, never guessed. An evidence kind EL
doesn't understand produces `triage: Input has no recognised
magic header — treating as opaque memory candidate` followed by
an explicit downstream `insufficient`, not a silent pipeline
exit.

---

## Hallucination posture — why EL cannot invent a claim

EL uses an LLM **only** in two narrow places, both architecturally
sandboxed from the evidence path:

1. **Red Reviewer LLM challenger** (optional, gated on
   `ANTHROPIC_API_KEY`). The LLM receives a structured
   `Finding` payload and returns a structured response shape
   (`{"status": "challenged|passed", "notes": str,
   "disconfirming_checklist": [str]}`). It cannot invoke a
   tool, cannot write to the case directory, and cannot mutate
   a Finding — the rule-based challenger merges its verdict
   with its own, with severity-bias toward "challenged".
2. **Per-case `CLAUDE.md` briefing**. A deterministic template
   (`el.case_template`) renders evidence metadata + the
   ledger's leading-hypothesis summary; the human analyst
   can then ask Claude Code to reason over the sealed state.
   Claude is not driving EL's extractors.

**Every factual claim in the Finding ledger is produced by a
deterministic Python function call against a CLI tool's output
file whose sha256 is recorded on the `EvidenceItem`.** There is
no code path where an LLM's string output becomes a claim.
The Red Reviewer's LLM is advisory-only.

---

## Running the accuracy check yourself

Judges can independently verify the contract:

```bash
# 1. Every Finding must have evidence[] or confidence=insufficient
.venv/bin/pytest -q tests/test_finding_contract.py

# 2. Insufficient findings must not score any hypothesis
.venv/bin/pytest -q tests/test_ach_excludes_insufficient.py

# 3. State machine refuses SYNTHESIZE on unresolved Findings
.venv/bin/pytest -q tests/test_coordinator_blocks.py

# 4. All 90+ anti-false-positive regression tests
.venv/bin/pytest -q tests/test_ioc_*.py tests/test_*_guard*.py \
                  tests/test_*_fp_*.py tests/test_h_ransomware_*.py

# 5. Full suite (1053 tests) — runs in ~60s
make test

# 6. Walk a specific finding back to its tool execution
jq 'select(.finding_id=="01KPWZNEC5FR8KWZETDM2BFG8B")' \
   cases/<case_id>/reports/execution_log.jsonl
sha256sum <the output_path from the row>
# Should match the output_sha256 in the tool_execution event
```

---

## Summary grade

**Strengths**
- Schema-enforced evidence: no claim can exist without its tool-trace, verifiable via Pydantic model construction attempts.
- Red Reviewer is non-optional and blocks state-machine progress; "insufficient" is first-class.
- Cross-case knowledge is context-only: rarity bucketing prevents ubiquitous-IP noise from lifting hypotheses.
- 90+ FP regression tests grounded in real-case bugs we've hit.
- Real-case validation: beat two public human writeups on M57-Jean to reach the canonical BEC answer.

**Known gaps (being honest)**
- Several evidence formats untested or unsupported (see table above). EL emits `insufficient` on those rather than guessing.
- Office-document coverage is VBA + RTF only; XLM + PDF deferred.
- NetFlow agent-side routing pending a real nfcapd corpus.
- LLM Red Reviewer's "challenged" verdicts are suggestive, not deterministic — the rule-based challenger is the hard gate.

**Bottom line** — EL is designed so that the worst-case failure
mode is a silent "insufficient" finding, never a confident false
claim. The accuracy contract is enforced at the Pydantic / state
machine / tests layer, not at the LLM prompt. Judges can verify
every row of the `traceability_matrix.md` by recomputing an
sha256 — no trust of EL required.

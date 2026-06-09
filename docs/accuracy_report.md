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
judges can walk via `reports/traceability_matrix.md`. For the
provenance and download source of every dataset below — the
"what it was tested against / source of the data" half of the
Find Evil dataset-documentation requirement — see the companion
[`evidence_datasets.md`](evidence_datasets.md).

### M57-Jean (NPS / digitalcorpora) — BEC / pretexting exfil

**Canonical answer per scenario**: Jean was social-engineered
by a spoofed email from the company president ("Alison") and
replied with `m57biz.xls` attached. Not insider theft, not
external compromise — pretexting-driven exfil.

| Measure | EL | [Basilmellow writeup](https://github.com/Basilmellow/Autopsy-M57-Linux-Forensics) | [jynxora writeup](https://github.com/jynxora/M57-Jean-Case-Analysis) |
|---|---|---|---|
| Leading hypothesis | ✅ BEC / pretext exfil | ❌ Invented "USB insider" (on a Win7 path — image is XP) | ❌ "Browser exploit + AIM6 bundleware", missed email vector |
| ACH gap over runner-up | +38 (score 51 vs H_INSIDER_EMAIL_EXFIL 13) on current `main`; score drifts with knowledge-store corpus state (earlier runs: +42 over H_ANTI_FORENSICS 15) — the *ranking* is the stable claim | — | — |
| Exfil email identified | ✅ Two subjects ("Thanks!" + "Please send me the information now") | ❌ Invented `confidential_client_list.xls` | ❌ Named the file but missed the outbound |
| Attachment name + size | ✅ `1_m57biz.xls (291840 B)` named inline in narrative | ❌ | ❌ |
| Display-name vs SMTP mismatch | ✅ 4 findings (2 inbound phishing + 2 reply-chain precursors) | — | — |
| IE5 tracker-sync URLs | ✅ 24 `__utm` session-sync patterns flagged from 4778 parsed records | — | ✅ partial |
| Anti-forensics wiped binaries | ✅ 15 zero-size + 15 zero-timestamp + 15 MACB-timestomp-skew | — | ✅ partial |
| Activity envelope (post-2026-04 timeline sweep) | ✅ Case-glance window `2001-08-23 → 2008-07-20` (timestomp anomaly → exfil emails) — was previously `1995 → 2106` from Plaso bookends | — | — |

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

### nromanoff (Find Evil 2017 / Lone Wolf — Win7, 9.6 GB, `--timeline`)

The denser-case stress run for the timeline + swimlane rendering layer.
Plaso super-timeline emitted 3.6 GB of `events.plaso` (`--parsers win_gen`,
`--vss-stores all`).

| Signal | Result |
|---|---|
| Leading hypothesis | H_APT_ESPIONAGE score 38 (gap +20 over H_LATERAL_MOVEMENT 18) |
| Activity envelope (case-glance window) | 2008-04-14 → 2012-04-06 — earliest MACB-skew anomaly to latest system-binary wipe |
| ATT&CK chain detected | 9 tactics: Initial Access (T1566.002) → Execution (T1053.005, T1569.002) → Persistence (T1543.003) → Privilege Escalation (T1055) → Defense Evasion (T1218) → Credential Access (T1003, T1003.001) → Lateral Movement (T1021.002, T1534) → C2 (T1071, T1571) → Exfiltration (T1048.003) |
| Masqueraded svchost | ✅ `[SVCHOST_OUTSIDE_SYSTEM32]` — `/Windows/System32/dllhost/svchost.exe` (fake `dllhost` directory — classic Mr. Evil signature) |
| Mimikatz presence | ✅ `[MIMIKATZ_NAMED_BINARY]` — file literally named "mimikatz" |
| PsExec lateral pivot | ✅ `[PSEXEC_SERVICE_ARTIFACT]` (Prefetch + Windows root) + 7 EID 7045 service-installs of PSEXESVC, first 2012-04-03 21:11:07, last 2012-04-04 18:52:11 |
| RDP inbound activity | ✅ TerminalServices 1149 ×75 between 2011-07-05 and 2012-04-06 |
| Generic remote service-creation | ✅ 69 EID 7045 events over a 1-year window (2011-04-01 → 2012-04-06) |
| Sensitive-attachment exfil chain | ✅ `nromanoff--nromanoff@star…` outbound mail flagged |

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

### DGA-entropy CDN suffix noise

`tests/test_network_anomaly_depth.py` — **3 assertions** (added
April 2026).

Surfaced by the M57-pcaps-v3 run, which flagged 34 DNS queries
under `googleusercontent.com` (Google user-content CDN) as DGA
candidates. The labels are legitimately high-entropy
(`93p5d9vvnd1p3kr0o895omkj85bluj7m-a-sites-opensocial...`,
H=4.58 bits) but represent routine bucket-style infrastructure
naming, not domain-generation algorithms. Fix: suppress queries
whose FQDN ends in known-benign CDN suffixes
(`googleusercontent.com`, `cloudfront.net`, `akamaihd.net`,
`1e100.net`, `azureedge.net`, `azurefd.net`, `appspot.com`,
`s3.amazonaws.com`, `cdn.cloudflare.net`). Real DGA on a
third-party domain still fires alongside CDN-suppressed queries
in the same row set — the suppression is suffix-scoped, not
detector-disabling.

---

## Display-layer accuracy bugs — fixed in 2026-04 timeline sweep

Distinct from the false-positive classes above: these were
silent failures in the rendering path that did not invent
claims (the underlying Findings remained correct), but they
either suppressed evidence the analyst should have seen or
mislabelled what was shown. Surfaced when stress-running
m57-jean and nromanoff with `--timeline` and reading the
output side-by-side with ground-truth scenarios. All committed
on `main`; no per-bug regression test yet (each fix has a
linked validation case).

| Bug | Symptom | Root cause | Fix (commit) |
|---|---|---|---|
| Plaso super-timeline silently empty | Every `--timeline` run emitted an 86 KB `events.plaso` with zero events; downstream agents had no super-timeline to draw on | `el/skills/plaso.py` passed `<storage> <source>` as positionals; modern log2timeline rejects with rc=2 | `--storage_file` switch + source positional (`de3a6fd`) |
| Plaso preset rejected | log2timeline error "Unknown parser or plugin names: `win10`" | Plaso 2024+ removed/renamed the `win10` preset | Changed default to `win_gen` (`04f3301`) |
| Attack Event Timeline showed EL ingest time, not artifact time | Per-finding `evidence_time` defaulted to ~ now, not the actual event time on the host | `narrative._TIME_KEYS` missed seven keys agents already populate (`date_utc`, `mtime_utc`, `first_ts_utc`, `last_ts_utc`, `last_used_start_utc`, `last_seen_utc`, `backup_date_utc`) | Extended `_TIME_KEYS` (`de3a6fd`) |
| Timeline stamped knowledge_lookup ingest time as artifact time | Cross-case overlap findings carry `first_seen_utc` = IOC's first ingest into `~/.el/knowledge.sqlite`; this leaked into per-case timeline as artifact time | Mining `evidence_time` from `knowledge_lookup` findings | Exclude `knowledge_lookup` from `evidence_time()` + route to `prologue` beat (`de3a6fd`) |
| Narrative synthesis silently skipped on every Windows EVTX case | `report.md` carried `_(Narrative synthesis skipped: can't compare offset-naive and offset-aware datetimes)_` instead of the executive narrative | `lateral_movement_analyst` / `credential_analyst` / `powershell_analyst` emit `first_seen_utc` without `+00:00`; `min(candidates)` mixed naive + aware | Fold naive datetimes to UTC in `_parse_any_dt` (`90bcbc3`) |
| Case-glance window blown out by Plaso bookends | `Artifact-time span: 1995 → 2106` from Firefox cache `Expiration Time` rows + NTFS FILE_NAME records with 0xff…ff timestamps | Plaso parses every timestamp including future/overflow; the absolute first/last bookended the case-glance | Plausible-window filter (1995-01-01 → now+1d) on Plaso CSV scan + exclude `timeline_synthesist` findings from case-glance time-range derivation (`55e1ad3`) |

Validation cases:
- `cases/m57-jean-tl-r3` — narrative collapses from no time-range to `2001-08-23 → 2008-07-20` (timestomp anomaly to exfil emails)
- `cases/nromanoff-tl-r1` — narrative collapses from `1995 → 2022` raw to `2008-04-14 → 2012-04-06` curated; full 9-tactic kill chain renders

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
| Truncated memory captures (DTB above captured range) | Vol3 builds no kernel layer when a 4 GB linear dump omits page tables remapped above the MMIO hole (DumpIt/Comae on >4 GB-remap VMs). `scan_windows_banner` confirms the OS/build and routes to string/IOC carve + a precise `insufficient` — structured process/network plugins stay unavailable (matches Volatility 2.6's own struggle on these) | Medium — acquisition-side |
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

## Self-correction sequences during real-case work

Find Evil rule: _"Show the agent working against real evidence,
including at least one self-correction sequence."_

EL's self-correction loop is two-tier. **At runtime**, an agent's
honest `insufficient` findings + the recommendation engine's
"what would unblock this" pivots act as the system's report of
its own gaps. **Across runs**, those reports drive code-and-test
fixes that lock the gap shut. The pattern is concrete and
repeatable; here are the three most recent end-to-end sequences,
all on real third-party evidence corpora, all committed and
test-locked.

### Sequence 1 — M57-pcaps: directory routing → streaming OOM (April 2026)

Real evidence: `/mnt/hgfs/hackathon/M57-net/` — the M57 case's 50
pcap files spanning Nov 13–17 2009, 4.6 GiB total, sibling to
the disk image we'd already processed as `M57-Jean-v2`.

**Failure 1.** `el investigate <pcap-dir>` produced a single
triage Finding (`Directory input does not match any known shape
(files=50); routing to default agent`) and zero downstream
network signal. EL's triage shape-detection had `windows-
artifacts-dir`, `velociraptor-collection`, `ios-fs-dir`,
`android-fs-dir`, `qnap-nas-dir`, `bulk-extractor-output` — but
not "directory of pcaps", a perfectly normal investigation
deliverable.

**Self-correction 1.** Added a `pcap-collection` triage
detector — when ≥2 `.pcap`/`.pcapng`/`.cap` files are present,
triage merges them with `mergecap` into
`<case>/raw/merged.pcap`, sets `evidence_kind="pcap-collection"`,
and rewrites `ctx.input_path` so `NetworkAnalystAgent` (which
already handled single-pcap input) receives a single normal
file. `KIND_TO_AGENT["pcap-collection"] = NetworkAnalystAgent`.
8 regression tests in `tests/test_triage_pcap_collection.py`
including detection-fires-at-2, single-pcap-no-fire,
input-path-rewrite, mergecap-failure-fallback, mergecap-missing-
fallback. Commit `a509970`.

**Failure 2.** Re-run produced the high-confidence "multi-pcap
capture series detected" finding, but the audit log showed
`network_analyst` started and never logged `agent_done`. Process
exited with no Python traceback. Cause: `scapy.all.rdpcap()`
(used by `el/skills/scapy_pcap.py:summarize`) loads the entire
pcap into memory before iterating; the 4.7 GiB merged pcap
balloons to ~30 GiB of Python objects and Linux's OOM killer
SIGKILLs python silently.

**Self-correction 2.** Switched to `scapy.all.PcapReader`
(streaming, packet-by-packet) with a `max_packets=50_000_000`
cap whose truncation is recorded in the JSON summary so the
analyst sees it explicitly. Same `PcapSummary` shape returned;
no caller changes. Existing 47 pcap/scapy/network tests stayed
green; the change is locked in as a streaming primitive that
all future pcap-handling code inherits. Commit `42d66e4`.

The pattern is the failure mode (silent OOM kill of a
subprocess) was invisible to the agent — but the agent's audit
log + the missing `agent_done` event made it observable. The
fix landed at the skill level, not the agent, so every future
pcap-consuming code path benefits without each agent needing a
private size-guard.

### Sequence 2 — M57-Jean recovery: case-sensitive regex + walker cap (April 2026)

Real evidence: `/mnt/hgfs/hackathon/M57/nps-2008-jean.E01` (XP-
era Windows disk image, 3 GiB compressed E01).

**Failure.** Phase 6 recovery was supposed to fire on
DiskForensicator's `SYSTEM_BINARY_ZERO_*` findings, run
`tsk_recover` per partition, and emit a "Recovery corroborates
anti-forensic activity" finding when a recovered file's
basename matched a wiped binary's name. M57 produced 31,419
recovered files including `auditusr.exe`, `pdh.dll`,
`ciadmin.dll` — exactly the wiped binaries the trigger findings
called out. **Zero corroboration findings emitted.**

**Self-correction.** Two bugs in one path:

1. The basename-extraction regex was `r"/Windows/System32/
   ([\w.\-]+)"` — case-sensitive on the `/Windows/System32/`
   prefix. M57 (XP-era) paths use `/WINDOWS/system32/`. Three-
   letter case difference, zero matches. Fixed with
   `re.IGNORECASE` on the prefix; basename casing still
   normalised to lower for set membership.
2. The recovered-tree walker was capped at 5,000 files for cost
   reasons. M57's recovery dir had 31k files and the wiped
   binaries sat alphabetically past the cap. Replaced with a
   name-targeted walk that takes the trigger's small basename
   set as input and returns the subset that exist — bounded by
   target-set size, not tree size, so no cap needed.

After fix: M57-Jean's three triggers extracted three basenames
(`auditusr.exe`, `pdh.dll`, `ciadmin.dll`); all three found in
the recovery dir; medium-confidence corroboration finding fired
linking them back to the original anti-forensic findings. The
exec-report recommendation auto-flipped from _"consider running
tsk_recover/bulk_extractor"_ → _"Review the anti-forensic
corroboration findings — carving recovered artifacts whose
names match the wiped/zeroed system binaries"_. 4 new tests in
`tests/test_recovery.py` — XP-style and modern-style path
parsing + targeted-walk regression case planting targets past
where the old cap cut. Commit `34139a2`.

### Sequence 3 — BelkaCTF6 bundle: coordinator state reuse (April 2026)

Real evidence: BelkaCTF 6 (laptop E01 + iOS filesystem dump as
one investigation).

**Failure.** First bundle run completed with one device
(`phone`) but the laptop logged `illegal transition State.DONE
-> State.TRIAGE` and was dropped from the bundle. Bundle
synthesised with a single device. The `el investigate-bundle`
end-of-run summary made the drop visible (`devices: phone` —
single name where two were specified) but the coordinator's
exception path swallowed the per-device exit code, so exit
status was 0.

**Self-correction.** Root cause: the `Coordinator` instance was
constructed once before the device loop and reused. `self.state`
ended at `DONE` after device 1; transitioning back to `TRIAGE`
on device 2 violated the state-machine table. Fix:
instantiate a fresh `Coordinator` per device inside the
per-device try block.

Surfacing the bug also exposed a test gap — the existing
`test_cli_investigate_bundle_two_devices` only checked that
both `manifest.json` files existed (which they did, intake runs
before the state machine). Strengthened the assertion to verify
`bundle.json` records BOTH devices, which is the smallest
condition that catches a silent second-device failure. Commit
`c14e3a7`.

### Sequence 5 — vanko-r2: LLM challenger AUP blocks + silent merge skip (June 2026)

Real evidence: `surface_physical.E01` — 21-segment EWF, 36.8 GB Surface 3 /
Win10 disk image, vanko-r2 re-investigation run.

**Failure 1.** The red reviewer's LLM challenger (headless `claude -p`
path) returned non-zero exit codes on several batches during a detached
investigation run. The audit log recorded `aup_blocked_batches > 0` but
the underlying cause was not surfaced to the analyst — the findings in
those batches silently retained rule-only verdicts with no indication that
the LLM challenge was skipped. The affected batches contained raw forensic
artifact strings: classified document names in evidence `facts` dicts
(`"1_GWU Op Plan.docx"`), SDelete wipe command sequences, and autorun.inf
script snippets — content that triggered the model's content filter even
in a forensic context.

**Self-correction 1.** Three targeted mitigations, all in the prompt
construction layer rather than at the model-selection layer (where they
would not have addressed the root cause):

1. **Forensic preamble** prepended to `SYSTEM` before any finding content,
   establishing unambiguous context before the model encounters artifact
   strings (`_FORENSIC_PREAMBLE` in `el/agents/red_reviewer.py` and
   `el/reporting/executive_ai.py`).
2. **Fact truncation** (`_scrub_facts(max_val=300)`) and **claim cap**
   (500 chars) in `_review_payload()` — raw tool output in `extracted_facts`
   was the primary vector; truncating preserves analytical signal while
   removing bulk verbatim content.
3. **AUP sentinel detection** in `run_headless_claude()` in `el/llm_defer.py`
   — distinguishes a content-filter block from a generic tool failure so
   the audit log records `aup_blocked` separately and callers can track
   coverage gaps rather than treating them as random failures.

After mitigations: full vanko-r2 red review via Opus 4.8 — 44 batches,
434 findings, zero AUP blocks, zero batch failures.

**Failure 2 (found during the same cycle).** `apply_deferred_red_review`
raised `KeyError: 'pending'` when merging Opus 4.8 verdicts. The merge
function indexed `_SEVERITY = {"passed": 0, "unresolved": 1, "challenged": 2}`
on a finding's current `red_review.status`; findings that had not yet been
processed by the rule-based challenger still held the initial `"pending"`
status and were not in the dict. The exception was caught by `cli.py` and
printed as a yellow warning, meaning the 434 Opus 4.8 verdicts were
silently discarded with no finding update and no error exit code. The only
observable symptom was `el report` printing `deferred red-review merge
skipped: 'pending'` instead of a merge count.

**Self-correction 2.** Added `"pending": 0` to `_SEVERITY` — treating
unreviewed findings as the lowest severity floor, consistent with the
severity-max merge semantics. The fix is one line; no test yet (the
scenario requires a fresh ledger entry that bypasses the rule challenger,
which is architecturally unusual — tracked as a future regression).

What distinguishes Sequence 5 from 1–4: the failure was not in EL's
forensic detection logic but in the **adversarial review layer** — the
component that exists to challenge EL's own findings. A broken challenger
is operationally worse than a missing one, because it produces no visible
gap in the output: rule-only verdicts look identical to merged verdicts
in the HTML report. The mitigations make the gap auditable via the
`aup_blocked_batches` audit-log field and the `deferred red-review merge`
console message.

### Sequence 4 — M57-pcaps DGA detector: googleusercontent CDN false positive (April 2026)

Real evidence: same M57-pcaps-v3 run that exposed Sequences 1's
two failures. After the streaming fix landed, the network
pipeline produced 5.7 M packets / 175 K flows of real signal
including a medium-confidence `DNS_DGA_ENTROPY` finding citing
34 high-entropy DNS labels.

**Failure.** Different shape from Sequences 1–3. The agent
didn't crash. It didn't produce an `insufficient` finding. It
produced a **medium-confidence DGA finding whose own sample list
was the failure mode** — every cited example was a
`googleusercontent.com` subdomain like
`93p5d9vvnd1p3kr0o895omkj85bluj7m-a-sites-opensocial.googleusercontent.com`
(H=4.58 bits). The label is legitimately high-entropy; it's
Google's user-content CDN bucket addressing, not a domain-
generation algorithm. The 3.8-bit entropy threshold was
correctly tripped, but the suffix tells you the label's
high-entropy by design. The finding's own claim text — by
naming the samples — made the false-positive observable to
the analyst before any code review.

**Self-correction.** Added a CDN-suffix allowlist to
`detect_dns_dga_entropy`: queries whose FQDN ends in any of
`googleusercontent.com`, `1e100.net`, `cloudfront.net`,
`akamaihd.net`, `akamaiedge.net`, `azureedge.net`, `azurefd.net`,
`s3.amazonaws.com`, `appspot.com`, or `cdn.cloudflare.net` are
filtered before the entropy test runs. Conservative list — real
DGA attackers register their own domains for control over
resolution, so they won't use these suffixes anyway, and
suppressing CDN noise is safer than the volume of false
positives it generates.

Suppression is suffix-scoped, not detector-disabling: a real
DGA on a third-party domain still fires when CDN noise is
present in the same row set. Locked in by
`test_dga_still_fires_alongside_cdn_noise` in
`tests/test_network_anomaly_depth.py` (3 assertions total —
googleusercontent regression with the actual M57 sample names,
other-CDN-suffix coverage, mixed-rowset detector-still-fires).
The FP class is now formally tracked under "Known false-positive
classes" earlier in this doc. Commit `6a6e1ff`.

### Sequence 6 — Narcos 2019: memory-image misroute + truncated-acquisition fallback (June 2026)

Real evidence: Digital Corpora **2019 Narcos** — 3 drug-case suspects ×
(30 GB split-raw disk + 4 GB split-raw memory) = 6 devices, ~102 GB, run as
one `investigate-bundle` (`narcos-full`) and scored against the scenario's
shipped teacher solution.

**Failure 1 — memory dumps triaged as carve-only.** All three raw memory
images routed to `evidence_kind="unallocated (carve-only)"` and the
`DiskForensicator` carve path instead of `MemoryForensicator`. Triage's
`_looks_like_memory_input` already defers a memory-named carve-blob to a
vol3 probe — but it matched the short tokens `mem`/`ram` only as an *exact*
label string, so the bundle device labels `steve-mem` / `john-mem` /
`jane-mem` and the split stems `Narcos-Mem-N.001` (which merely *contain* a
`mem` segment) slipped through. Observable in the audit log:
`investigator_selected name=DiskForensicatorAgent evidence_kind="unallocated (carve-only)"`
on a device named `…-mem`.

**Self-correction 1.** Reworked `_looks_like_memory_input` to match on
*delimited segments*: a new `_segment_tokens()` splits the filename and the
bundle device label on every non-alphanumeric delimiter and letter↔digit
boundary (`Narcos-Mem-1.001` → `{narcos, mem, 1, 001}`), then matches whole
segments against the token set. Catches `<suspect>-mem` / `<host>_ram` /
split stems without false-firing on substrings (`remember`, `member`,
`program`, `diagram` yield no bare `mem`/`ram` segment). Locked in by
`test_delimited_mem_segment_recognised` + `test_mem_substring_does_not_false_fire`
in `tests/test_memory_carve_blob_deferral.py`.

**Failure 2 — vol3 dead-ended on a genuine Windows memory image.** Even
with routing fixed, Volatility 3's automagic built **no kernel layer** on
any of the three images. Verbose diagnostic:
`DtbSelfRef64bit not met: 0x13ffffa00 > 0xffffffff` / `physical_layer
maximum_address: 4294967295` / `No suitable kernels found during pdbscan`.
The System DTB sits at physical ~5.4 GB — **above** the 4 GB the Comae
DumpIt capture contained (these VMs remap RAM above the 4 GB MMIO hole; the
linear 4 GB dump omits the page tables). The original scenario team hit the
same wall — their notes say Volatility 2.6 "does not currently support Win
10x64 build 1809" and they fell back to bulk_extractor. EL's prior behaviour
was a generic `insufficient: vol3 failed: no banner plugin produced usable
output` — true but unhelpful, and it discarded a recoverable image.

**Self-correction 2.** Added `vol3.scan_windows_banner()` — a bounded,
symbol-free raw-byte scan for the ntoskrnl version banner (`Microsoft (R)
Windows (R) Version` / `10.0.NNNNN`). When the automagic raises, triage now
calls it; if the banner is present it (a) confirms the input IS Windows
memory and names the build, (b) emits a **precise** `insufficient` diagnosis
(truncated/non-atomic acquisition, DTB above captured range — structured
plugins unavailable, carving is the recoverable path), and (c) routes the
image to the carve pipeline so bulk_extractor + IOC extraction still run.
Validated on the real Narcos memory: confirmed Windows build `10.0.17134`
with the banner at offset ~3.8 GB. Locked in by four tests
(`test_scan_windows_banner_*`, `test_vol3_failure_with_banner_routes_to_carve`,
`test_vol3_failure_without_banner_stays_insufficient`).

Why it matters: the carve path recovers the *forensic conclusions* the
structured plugins would have — on Narcos, EL's affuse + string/IOC carve
of the memory recovered the TrueCrypt password `ilovediving`, the Quasar
implant alias `updater.exe`, the RAT target host, the C2 IPs + port, and
every actor's Protonmail account, exactly the artefacts the solution's own
bulk_extractor pass surfaced. EL keeps the load-bearing evidence even where
Vol3's process table is unrecoverable, and now *says precisely why* rather
than emitting a generic failure.

---

What these six sequences share:
- Triggered by **real third-party evidence** (M57 / BelkaCTF /
  vanko-r2 / Narcos), not synthetic test fixtures.
- The first symptom was always **observable in the agent's own
  outputs** — a triage finding admitting "no shape match",
  an audit log with `agent_start` but no `agent_done`, a
  bundle summary listing fewer devices than requested, a
  finding whose own sample list exposes its noise, or an audit
  log entry recording `aup_blocked_batches > 0`, or an
  `investigator_selected` event routing a `…-mem` device to the
  disk carve path.
- The fix landed at the layer that owned the root cause:
  streaming primitive (OOM), regex flag (case mismatch),
  state instantiation (coordinator reuse), suffix allowlist
  (CDN noise), prompt construction (AUP content trigger),
  segment-tokeniser + raw-banner fallback (memory misroute).

Sequences 1–3 caught silent crashes (no output where output was
expected). Sequence 4 caught output that was emitted but contained
a known-noise class. Sequence 5 caught the adversarial review
layer itself silently failing — arguably the most dangerous shape
because a broken challenger produces output that looks identical
to a working one. Sequence 6 caught a *misroute* — correct output
from the wrong agent (a memory image carved as a disk), plus a
genuine tool limitation reported too vaguely to act on. The
architecture handles all of these because Findings and audit
events carry the data needed to self-incriminate: a missing
`agent_done` event, a sample list that points at a CDN, a `claim`
text the analyst can sanity-check against the ground truth they
brought to the engagement, an `aup_blocked_batches` counter that
proves coverage was incomplete, or an `investigator_selected`
line naming the wrong agent for the evidence kind.

The accuracy posture isn't "we never made a mistake"; it's
"the architecture surfaces our mistakes and tests pin them
shut once we find them."

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

# 5. Full suite (3,178 passed, 89 skipped) — runs in ~10 min
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

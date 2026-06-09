# EL — Evidence Dataset Documentation

_Find Evil 2026 submission deliverable. Per the rubric:_

> _"Include Evidence Dataset Documentation — **What the agent was tested
> against, source of the data, and what the agent found.**"_

This document enumerates every evidence corpus EL has been exercised
against end-to-end, its provenance, and the result EL produced. Findings
are quoted from the per-case Findings ledger (`cases/<id>/findings.sqlite`)
or the validated rows in [`accuracy_report.md`](accuracy_report.md), not
re-narrated from memory. Where a dataset is publicly downloadable, the
source link lets a judge reproduce the run; where it is a course or
challenge corpus under redistribution restrictions, the source is named
and the run is reproducible only by a license-holder.

**Provenance discipline.** Every input is hashed at intake — `el intake`
records the input sha256 (or, for E01s, the acquirer's stored
acquisition hash via `ewfinfo`) into `cases/<id>/manifest.json`, and every
finding binds to a tool-output sha256. So "what EL found" on any row below
is itself reproducible and tamper-evident; see the sha256 round-trip in
[`JUDGES.md`](JUDGES.md#verifying-any-single-finding--the-sha256-round-trip).

---

## A. Publicly reproducible datasets

These are the rows a judge can independently obtain and re-run. EL's
canonical-answer claims are locked against them.

### A1. M57-Jean — BEC / pretexting exfil (NTFS disk)

| | |
|---|---|
| **Tested against** | `nps-2008-jean.E01` (+`.E02`) — Windows XP NTFS workstation image, ~3.2 GB compressed / ~10 GB raw, 2-part E01 |
| **Source** | Digital Corpora — M57-Patents scenario · https://digitalcorpora.org/corpora/scenarios/m57-patents/ · direct: `https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2008-m57-patents/drives-redacted/nps-2008-jean.E01` (`.E02`) · public, CC-licensed |
| **Ground truth** | Jean was socially engineered by a spoofed "Alison/President" email and replied with `m57biz.xls` attached — pretexting-driven BEC exfil |
| **What EL found** | Leading hypothesis **`H_BEC_ACCOUNT_TAKEOVER`** by a wide ACH gap. Two inbound phishing findings (display-name vs SMTP mismatch) + two reply-chain precursors; attachment named inline `1_m57biz.xls (291840 B)`; anti-forensics signal (15 zero-size + 15 zero-timestamp + 15 MACB-skew system binaries); 3 wiped binaries recovered from unallocated space. **EL reached the canonical answer that two public human writeups missed** — see [accuracy_report.md § M57-Jean](accuracy_report.md#m57-jean-nps--digitalcorpora--bec--pretexting-exfil) for the head-to-head. |

### A2. Lone Wolf 2018 — APT espionage + Cobalt Strike (paired disk + memory)

| | |
|---|---|
| **Tested against** | "Lone Wolf" Windows disk image + paired memory capture (run as `nromanoff` Win7 9.6 GB disk and as the GMU LoneWolf paired disk+memory) |
| **Source** | Digital Corpora — 2018 Lone Wolf scenario (Thomas Moore) · https://digitalcorpora.org/corpora/scenarios/ · public |
| **What EL found** | Disk leader **`H_APT_ESPIONAGE`** (nromanoff score 38, gap +20); memory leader **`H_C2_BEACONING`** (score 11, gap +8). Cobalt Strike family fingerprint (Malleable-C2 `__utm.gif`) in `domain.txt`/`url.txt`; 4 Azure-hosted C2 IPs at :443 in netscan; multi-technique lateral-movement chain (service install + WMI consumer + PS-remoting); full 9-tactic ATT&CK chain on nromanoff. See [accuracy_report.md § GMU LoneWolf](accuracy_report.md#gmu-lonewolf-paired-disk--memory) and § nromanoff. |

### A3. BelkaCTF — mobile + macOS + Linux

| | |
|---|---|
| **Tested against** | Android FFS (Magisk-rooted), iPhone SE iOS 14.3 FFS, macOS Big Sur, "Kidnapper" Linux ext4 |
| **Source** | Belkasoft CTF challenge sets · https://belkasoft.com/ctf · publicly published challenges |
| **What EL found** | Android: Magisk root + `com.topjohnwu.magisk` sideload + WhatsApp (3 detector hits). iPhone SE: 18 encrypted-messenger/privacy apps flagged + clean extraction of 63 app Info.plists / SMS / KnowledgeC / Health DBs. macOS Big Sur: **clean baseline, zero malicious-activity findings** (correctly emitted nothing rather than inventing). Kidnapper Linux: clean baseline, no detector hits. The two clean baselines are deliberate — they demonstrate EL's no-false-positive posture. See [accuracy_report.md § BelkaCTF](accuracy_report.md#belkactf-mobile--macos). |

### A4. malware-traffic-analysis.net pcap corpus — Layer-3 knowledge seeding

| | |
|---|---|
| **Tested against** | ~2,000 malware-traffic pcaps, 2013–2025 |
| **Source** | malware-traffic-analysis.net (Brad Duncan) · https://www.malware-traffic-analysis.net/ · publicly published |
| **What EL found** | Populated `~/.el/knowledge.sqlite` with Layer-3 IOC counts that drive rarity-bucketing — common MS infrastructure (`13.107.6.254`, 22 prior cases = `ubiquitous`, no hypothesis lift) is suppressed while true-positive IOCs re-surface in new cases (the Lone Wolf memory → Qakbot/Valak/Ursnif/Icedid/Ta551 cross-case match is driven directly by this store). Demonstrates the Layer-3 contract: cross-case overlap is context, never load-bearing evidence. |

---

## B. Course / challenge corpora (license- or challenge-restricted)

Reproducible by a license-holder; provenance named, redistribution not
ours to grant.

### B1. SANS FOR508 Stark Research Labs (SRL-2018) — 21-host enterprise APT

| | |
|---|---|
| **Tested against** | 7 E01 disk images (11–18 GB each, ~105 GB) + 22 memory images (~60 GB uncompressed) from a 21-host simulated enterprise compromise; acquired 2018-09-05→07 |
| **Source** | SANS FOR508 course dataset — "Stark Research Labs / Compromised Enterprise Network" · course-restricted |
| **What EL found** | Per-case ACH put **`H_APT_ESPIONAGE`** as leader on 12 of 21 hosts; no false-positive false-leader cases after the session's detector/scoring fixes. Cross-host correlation surfaced the shared attacker infrastructure (C2 `172.16.4.10:8080`, WinRM pivot `172.16.5.21:5985`, multi-protocol staging `172.16.4.6`). Full multi-host bundle run (ingress → pivot → impact) reconstructed in [`sample-reports/SRL-2018-shakedown.md`](../sample-reports/SRL-2018-shakedown.md). |

### B2. Narcos 2019 — 6-device drug-trafficking scenario (disk + memory) · **public**

| | |
|---|---|
| **Tested against** | 3 suspects × (30 GB split-raw disk + 4 GB split-raw memory) = 6 devices, ~102 GB. Steve Kowhai (Narcos-1, Win10 1809), John Fredricksen (Narcos-2, 1803), Jane Estaban (Narcos-3, 1709) |
| **Source** | Digital Corpora — 2019 Narcos scenario · https://digitalcorpora.org/corpora/scenarios/2019-narcos/ · **public** (a teacher solution + per-actor artefact spreadsheets ship with the scenario, used here as the scoring baseline) |
| **What EL found** | 6-device `investigate-bundle`; per-device ACH leader **Targeted intrusion / espionage** (score 22–29). Independently reproduced the solution's findings on the artefact-recovery dimensions: full per-suspect software stack via amcache∧shimcache execution corroboration (Image Steganography 1.5.2, TrueCrypt 7.1a, Quasar RAT, CCleaner, Baidu AV, Discord, OpenOffice — with exact paths); Australian time-zone attribution for the two interdicted suspects; Protonmail accounts for all three; and — from memory string/IOC carve — the TrueCrypt password `ilovediving`, the Quasar implant alias `updater.exe`, target host `JOHNFLAPTOP`, and the C2 channel `202.2.12.12 ↔ 202.2.12.13:4782`. Full side-by-side in `cases/narcos-full/reports/EL_vs_solution_comparison.md`. **Surfaced a real limitation** (Vol3 could not build a kernel layer on the truncated 4 GB Comae captures — the same wall the original team's Volatility 2.6 hit) that drove the June 2026 memory-handling fixes — see [accuracy_report.md § Sequence 6](accuracy_report.md#sequence-6--narcos-2019-memory-image-misroute--truncated-acquisition-fallback). |

### B3. Rocba — disk + memory challenge

| | |
|---|---|
| **Tested against** | `rocba-cdrive.e01` (Windows C: drive) + `Rocba-Memory.raw` (physical memory) |
| **Source** | "Standard Forensic Case" challenge set, local lab corpus |
| **What EL found** | Paired disk+memory bundle; leading hypothesis **Targeted intrusion / espionage** (`H_APT_ESPIONAGE`, score 31, gap +19) with NTFS anti-forensic tampering signal. |

### B4. Vanko Surface 3 — Win10 insider device destruction (primary case)

| | |
|---|---|
| **Tested against** | `surface_physical.E01` — Microsoft Surface 3 / Windows 10 physical disk, 36.8 GB, 21-segment E01 (acquired 2016-11-04) |
| **Source** | "Standard Forensic Case 2" — Windows 10 Surface 3 acquisition, local lab corpus |
| **What EL found** | Leading hypothesis **Insider device / evidence destruction** (`H_INSIDER_DEVICE_DESTRUCTION`, score 41, gap +5). Surfaced anti-forensic wipe of EVTX channels, executed-binary corpus (VeraCrypt, Tor Browser, SDelete-shape), iCloud account attribution (`anthony.vanko@icloud.com`), and a ReadNotify email-tracking chain. This case drove the June 2026 AUP-mitigation + deferred-red-review hardening documented as [accuracy_report.md § Sequence 5](accuracy_report.md#sequence-5--vanko-r2-llm-challenger-aup-blocks--silent-merge-skip). The full Opus 4.8 adversarial red-review (434 findings) is on file in `cases/vanko-r2/reports/`. |

---

## C. Coverage summary

Across A+B, EL has been exercised end-to-end on **12 distinct evidence
types**: Windows NTFS disk (XP/7/10), Windows physical memory, multi-host
enterprise bundles, iOS full-filesystem, Android full-filesystem, macOS
filesystem, Linux ext4, and network pcap — plus the cloud / log-corpus
agents covered by synthetic fixtures in `tests/`. The hypothesis space
exercised spans BEC, APT espionage, C2 beaconing, lateral movement, and
insider device destruction as confirmed ACH leaders on real evidence.

What every row shares: **the finding is bound to a tool execution by
sha256, and the leading hypothesis is the ACH engine's deterministic
projection of the ledger — not an LLM's narrative.** A judge can recompute
any hash to verify provenance, on any dataset in section A without a
license.

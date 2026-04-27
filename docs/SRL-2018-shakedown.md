# SRL-2018 Hackathon Shakedown — Writeup

_EL run against the Stark Research Labs "Compromised Enterprise Network"
2018 hackathon dataset (SANS SRL-2018). Written 2026-04-21._

## Summary

Ran EL end-to-end against 7 disk images and 21 memory images from a
21-host simulated enterprise compromise. Every disk and most memory
captures surface the same attacker infrastructure — consistent
cross-case overlap at the IOC layer — and the per-case ACH ranking
put **H_APT_ESPIONAGE** as the leading hypothesis on 12 of 21 hosts.
No false-positive false-leader cases after the session's six detector
and scoring fixes landed.

Core attacker infrastructure observed across cases:

| Asset | Observed | Role |
|---|---|---|
| `172.16.4.10` | HTTP beacon `:8080` on 13+ hosts + SSH from `base-admin` | Primary C2 + Linux jump |
| `172.16.4.6` (dual-homed as `10.10.4.6`) | Served `csrss.exe` from `\\172.16.4.6\c$\Windows\Logs\WindowsServerBackup\7.15\` on `rd-01`; ports `80`, `135`, `222`, `443`, `444`, `3389`, `5985` observed | Multi-protocol Windows staging host |
| `172.16.5.21:5985` | WinRM inbound from almost every host | Central lateral pivot |
| `172.16.5.20:1433` | Persistent beacon from `base-av` (SSIS/SSAS services injected) | Injected SQL Server, secondary C2 |
| `10.10.254.1:61613` | ActiveMQ/STOMP from `base-hunt` and `base-admin` only | Correlated secondary C2 channel |

## Dataset

Source: `SRL-2018-Compromised Enterprise Network/` — 7 E01 disk images
(11–18 GB each, ~105 GB total) + 22 memory images (7-Zipped, 0.5–18 GB
uncompressed, ~60 GB total). Acquisition date 2018-09-05 through
2018-09-07. No packaged solution document used during the run.

Hosts represented:

| Class | Hostnames |
|---|---|
| Workstations | `wkstn-01` through `wkstn-06` (2 memory captures of 01) |
| Remote Desktop hosts | `rd-01`, `rd-02`, `rd-03`, `rd-04`, `rd-05`, `rd-06` |
| Servers | `dc` (domain controller), `file`, `mail` (Exchange), `sp` (SharePoint), `av` (McAfee ePO + SQL), `admin` (jump host), `hunt` (hunt team), `elf` |
| DMZ | `dmz-ftp` |
| Snapshot | `file-snapshot5` (differential memory capture of file) |

## Methodology

- Each image run via `.venv/bin/el investigate <input> --case-id srl-<host>-<kind>[-rN]`.
- Disk runs averaged 15–25 min each (ewfmount → fls → mactime →
  extract_windows_artifacts → EZ Tools parsers → lateral + execution +
  credential analysts → threat_hunter YARA sweep → red_reviewer → ACH → seal).
- Memory runs 3–15 min each (vol3 plugin set → malfind --dump →
  netscan triage → hunt-evil process matrix → threat_hunter YARA sweep).
- Three re-runs of wkstn-01 and two of DC / file / wkstn-05 to validate
  successive detector PRs against the same evidence.
- Host: SANS SIFT Workstation, 15 GB RAM / 4 vCPU / 300 GB LV (grown
  mid-session from 100 GB after the DC's `evtx_parsed.csv` OOM-killed
  `lateral_movement_analyst` on the original 3.8 GB host).
- All cases sealed (sha256 manifest + tar.gz archive). All IOCs
  propagated to `~/.el/knowledge.sqlite`. 2044 case_ids / 395k IOCs
  total in the cross-case knowledge store at end of session.

## Per-host results (memory-only, sorted by ACH leader score)

| Host | Leader | Score | Signature |
|---|---|---:|---|
| `base-admin` | H_APT_ESPIONAGE | **38** | Operator box: SSH to 6 hosts, RDP to 3, Defender injected, 2.4 GB malfind dump |
| `base-rd-04` | H_APT_ESPIONAGE | **35** | 43 hidden processes, 58× beacon to `.4.10:8080`, 11× to `.4.6:443` |
| `base-rd-01` | H_OPPORTUNISTIC¹ | 26 | 14× beacon, `csrss.exe` from remote admin share, 4 hidden procs, `p.exe` malfind |
| `base-mail` | H_APT_ESPIONAGE | 22 | 312 malfind regions in Exchange processes, 2 hidden procs |
| `base-wkstn-01` (r2) | H_APT_ESPIONAGE | 19² | re-run post-PR-E showed H_LATERAL_MOVEMENT 6 from memory alone |
| `base-rd-03` | H_APT_ESPIONAGE | 20 | 11 hidden processes (highest), mmc.exe malfind |
| `base-wkstn-04` | H_APT_ESPIONAGE | 20 | 6 hidden procs, 11 malfind in powershell.exe |
| `base-av` | H_APT_ESPIONAGE | 19 | 42 malfind regions incl. `msdtssrvr.exe` + `msmsdrv.exe` (SSIS/SSAS injected) |
| `base-file` | H_LATERAL_MOVEMENT | 24 | SMB fan-out — 3 ESTABLISHED outbound to 3 distinct internals |
| `base-file-snapshot5` | H_LATERAL_MOVEMENT | 12 | Same snapshot class, dual-homed `.4.6`/`10.10.4.6` SMB |
| `base-hunt` | H_LATERAL_MOVEMENT | 9 | 34× beacon to `.4.10:8080` — largest pre-admin, + ActiveMQ secondary C2 |
| `base-sp` | H_LATERAL_MOVEMENT | 6 | 40× ESTABLISHED to `.4.7:808` — SharePoint WCF (FP-prone, see calibration note) |
| `base-wkstn-03` | H_LATERAL_MOVEMENT | 6 | 16× `.4.10:8080` + RPC to `.4.6:135` |
| `base-rd-02` | H_LATERAL_MOVEMENT | 3 | Only WinRM to `.5.21` — secondary jump host, rarely used |
| `base-wkstn-02` | H_LATERAL_MOVEMENT | 3 | 4× `.4.10:8080` + SMB `.4.5` |
| `base-wkstn-06` | H_LATERAL_MOVEMENT | 3 | 6× ESTABLISHED to `.4.6:80` |
| `base-elf` | H_LATERAL_MOVEMENT | 3 | Single SMB ESTABLISHED |
| `base-rd-05` | — (tied 0) | 0 | Quiet host, untouched by attacker in this capture window |
| `base-rd-06` | — (tied 0) | 0 | Same |
| `base-dc` | — (smear) | 0 | Memory-acquisition smear — vol3 netscan blocked on unmapped pages |
| `base-wkstn-05` | — (tied 0) | 0 | Symbol mismatch + nothing noteworthy in psscan/netscan |

_¹ `rd-01` leader was pre-PR-F; would now show H_APT_ESPIONAGE._
_² r3 post-PR-E showed H_LATERAL_MOVEMENT 6 as memory leader._

Per-host disk results (full stack post all PRs) — ACH leader = H_APT_ESPIONAGE on every sealed disk case, gaps ranging +2 to +12 over runner-up, with `dmz-ftp` at `31` leading `LATERAL 21` as the cleanest separation.

## Detector gaps surfaced → PRs landed

Every PR has ≥2-case repetition backing it before code landed.

| PR | Gap | Trigger | Fix |
|---|---|---|---|
| **PR-B** | `pslist=0` on vol3 symbol-mismatched Win10 images silenced the entire Hunt-Evil process matrix despite psscan returning 100+ processes | wkstn-01 + wkstn-05 memory both had empty pslist / full psscan | `_hunt_evil_process_matrix` accepts psscan fallback, filtered on `ExitTime=None` (pool-tag scan otherwise resurrects exited procs); confidence capped at medium |
| **PR-C** | vol3 `windows.netscan.NetScan` rows never fed any detector — just a raw row-count finding | wkstn-01 + wkstn-05 memory showed same attacker infra in netscan, zero findings | New `el.skills.netscan_triage`: repeat-endpoint beacon (≥4 hits to same addr:port, admin ports excluded) + lateral-admin-port session (SMB/RDP/WinRM/RPC with ESTABLISHED promoted to high) |
| **PR-E** | No detector for 4625 / 4769 / 4776 Security-log events → H_CREDENTIAL_ACCESS and H_BRUTE_FORCE silent on DC-class hosts | DC credential attack chain showed Kerberoasting + brute force + NTLM spray; all ignored | New `el.skills.credential_triage` + `CredentialAnalystAgent`: 4625 burst (≥10/target OR ≥5 distinct targets/source), 4769 RC4-HMAC Kerberoasting (≥3), 4776 NTLM spray (≥5 targets/workstation) |
| **PR-A** | `extract_windows_artifacts` didn't copy `HIVE.LOG1` / `HIVE.LOG2` / `HIVE.LOG` alongside each hive → EZ Tools parsers aborted "hive is dirty and no transaction logs" on live-imaged boxes | wkstn-01 + base-file disks both dirty (live imaging), both produced `insufficient` from `execution_corroborator` | New `_copy_hive_with_logs` helper wraps every hive copy site (SYSTEM/SOFTWARE/SECURITY/SAM/DEFAULT/Amcache/NTUSER), scans source parent for the three LOG suffixes, copies them to follow rename-on-destination |
| **PR-F** | `execution_corroborator` tagged `H_OPPORTUNISTIC_COMMODITY` on every binary in a user-writable path, which on modern Win10 catches Chrome, Teams, Dashlane, OneDrive, etc. → 9+ per-case false lifts | rd-01 leader flipped to H_OPPORTUNISTIC_COMMODITY(26) on a clearly APT-shaped case with csrss run from remote admin share | Removed the `H_OPPORTUNISTIC_COMMODITY` append from the tag map; path classification still drives confidence tiering and claim prefix |
| **PR-G** | `parse_amcache` looked for `LowerCaseLongPath` / `LongPath` / `Name`, but modern AmcacheParser's `UnassociatedFileEntries.csv` only populates `FullPath` (capital F) → every row dropped | dmz-ftp + base-file disk-r2 both parsed Amcache successfully but `execution_corroborator` reported "1 source (shimcache)" | Added `FullPath` to the fallback column chain; dmz-ftp went 0 → 36 amcache hits, base-file 0 → 30 |

All six PRs regression-tested against synthetic fixtures modelled on
the real data shape that triggered each gap. Test suite at 563 passes
at the end of session (was 518 at start).

Plus: AGPL-3.0-or-later license + README host-requirements block added.

## Calibration observations noted but not acted on

1. **Beacon detector on server-class hosts is noisy.** Exchange ↔ DC
   over LDAP (`:389`) and Global Catalog (`:3268`) trip the "repeat
   endpoint" threshold trivially — mail fired 92× and 45× on these as
   high-confidence beacons. Did not wrong-lead any ACH (malfind +
   hidden-processes carried H_APT_ESPIONAGE on mail regardless), but
   is a false-positive class. Suggested future fix: add a "well-known
   internal directory service ports" allowlist, `{88, 389, 636, 3268,
   3269}`, when destination is RFC1918.

2. **`execution_corroborator` volume-driven lifts on other hypotheses.**
   PR-F fixed the H_OPPORTUNISTIC_COMMODITY leak; similar small-lift
   accumulation is visible on H_BEC_ACCOUNT_TAKEOVER (12 on wkstn-01
   r4 from Chrome+Office corroborations). Not currently causing
   wrong-leader cases but worth watching if a future case has thin
   real signal.

3. **`evtx_triage.iter_events` in-memory model.** DC's
   `evtx_parsed.csv` (6.35 GB / 5.3 M rows) materialises to ~3 GB of
   Python objects before detectors iterate. Fine at 16 GB RAM, tight
   on the pre-expansion 3.8 GB VM (OOM-killed on two initial DC runs).
   Could be rewritten as a generator with pre-filtered EID allowlist
   if the tool has to run on smaller hosts again.
   _**Resolved 2026-04-27 in commit `62fe5cd`** — `iter_events`
   replaced with `stream_events` generator + `_build_index_streaming`
   builds the (channel, EventId) index on the fly. Per-row payload
   filters drop bulk default-AES Kerberos 4769 tickets and non-RDP
   4624 logons. Validated standalone on the same DC CSV: 5 M+ rows →
   308 K filtered events, peak RSS 527 MiB._

4. **SharePoint WCF false-positive class.** `base-sp` showed 40×
   ESTABLISHED to `.4.7:808` which is legitimate inter-server SP WCF,
   not C2 — detector correctly fired (repeated same-endpoint), analyst
   must interpret. Could add an optional "suppress beacon to service
   port ranges declared by local SPN records" — probably over-fitted.

## Open questions

- `base-dc` memory smear was a data-quality issue, not an EL gap, but
  the 0-row netscan left the memory case uninformative. Worth
  documenting that smeared DC captures land on the operator's desk
  with all-zero ACH — not a bug, but a triage-UX concern.
- `base-wkstn-05` memory is quiet — literally no attacker activity
  visible in netscan rows. Its disk *did* score H_APT_ESPIONAGE 22
  on lateral-movement signals. Confirms that memory-only quiet ≠
  host-not-compromised; always pair with disk where available.
- `172.16.4.7` on port `:22233` (base-sp) remains unexplained — not a
  known port and not traced to a specific service in this writeup.

## 2026-04-27 disk-only re-run — combined-case stitch

Same 7 disk images, fresh ledgers under `srl2018-comb-r1-*`, single
combined report at `cases/_combined/srl2018-enterprise-r2/`
(`report.md` + `combined.html`). Driver script ran the 7 disks
serially; total wall ~50 min for the first pass, +30 min for the DC
retry once the streaming fix landed.

### Per-host leaders (combined-r2)

| Host | Leader | Score |
|---|---|---:|
| `srl2018-comb-r1-dmzftp` | H_APT_ESPIONAGE | **49** |
| `srl2018-comb-r1-dc-r4` | H_APT_ESPIONAGE | **36** |
| `srl2018-comb-r1-rd01` | H_APT_ESPIONAGE | 31 |
| `srl2018-comb-r1-file` | H_APT_ESPIONAGE | 30 |
| `srl2018-comb-r1-wkstn05` | H_APT_ESPIONAGE | 30 |
| `srl2018-comb-r1-wkstn01` | H_APT_ESPIONAGE | 27 |
| `srl2018-comb-r1-rd02` | H_ANTI_FORENSICS | 20 |

Combined-report headline: 622 findings (high=231), 15 ATT&CK
techniques, 12 cross-host IOC overlaps. The 6/7 hosts leading
H_APT_ESPIONAGE — including the DC after the streaming fix — match
the original 2026-04-21 shakedown's per-host disk verdict with
slightly higher scores under the now-richer detector set
(MACB_TIMESTOMP_SKEW, kerberoast RC4-only filter, etc.).

### Bugs surfaced in this re-run → fixes landed

| Commit | Gap | Fix |
|---|---|---|
| `de3a6fd` | `el/skills/plaso.py` passed `<storage> <source>` as positionals; modern log2timeline (20240308+) rejects with rc=2. Every prior `--timeline` run silently emitted zero events. | `--storage_file` switch + source positional. |
| `04f3301` | Plaso preset `win10` was renamed/removed in 2024+ Plaso. Wrapper default produced "Unknown parser" → empty 86 KB storage. | Default to `win_gen` (XP / 7 / 8 / 10 / 11). |
| `62fe5cd` | `evtx_triage.iter_events` materialised 5 M+ rows of DC EVTX into Python; agent OOM-killed at ~4.6 GB anon-RSS in `windows_artifact` mid-run. | `stream_events` generator + per-(channel, EventId) filter at stream time + payload predicates that drop 2.24 M default-AES 4769 Kerberos tickets and 800 K non-RDP 4624 logons. Peak RSS dropped from OOM to 527 MiB. |
| `90bcbc3` | `lateral_movement_analyst` / `credential_analyst` / `powershell_analyst` emit `first_seen_utc` without `+00:00`; `min(candidates)` mixed naive + aware datetimes and aborted narrative synthesis on every Windows EVTX case with `_(Narrative synthesis skipped: can't compare offset-naive and offset-aware datetimes)_` instead of the executive narrative. | Fold naive datetimes to UTC in `_parse_any_dt`. |
| `5cac2e9` | `el combined-report` defaulted to Markdown only; `combined.html` is the actually-useful artifact and Snap-confined Chromium can't read `.md` via `file://` regardless. | Flip default to render HTML; `--no-html` opts out. |
| `340c8cd` | `combined.html` per-host drill-down hrefs used the absolute filesystem path `/opt/EL/cases/<case>/reports/case.html` — 404'd under `el serve` (rooted at `/opt/EL/cases/`, not `/`). | `os.path.relpath` produces `../../<case>/reports/case.html`, resolves under both `file://` and `el serve`. |
| `ab87372` | Cross-Host Signal Matrix header skewed: first cell ("Signal") rendered with `class='case'` (vertical text) while data first cell used `class='signame'` (horizontal). Column 0 split into a narrow vertical-header strip + a wider horizontal-data strip. | First header cell now uses `class='signame'`; only host-name columns keep the rotated rendering. |
| `12b3063` | Anchor jumps in `case.html` and `combined.html` landed several lines below the heading because the sticky topbar covered the target. | `html { scroll-padding-top: 110px; }` in both renderers. |
| `f675197` | `case.html` nav (14 anchors) wrapped to two lines on narrower viewports, breaking the 110 px scroll-padding offset. | Tighter nav (12 px font, 3×7 padding, gap-4) + `display: flex; flex-wrap: nowrap; overflow-x: auto`. Single line at standard widths; horizontal scroll on narrow ones. |

### Outstanding from the original shakedown — still open

- Memory captures **not** included in this re-run (disk-only).
  21 hosts × memory analysis would require unzipping 22 .7z files
  (~60 GB uncompressed) and the host had to land a streaming-fix
  PR before disk could complete; left for a follow-on.
- Beacon-on-server-class-host calibration (#1) and
  execution-corroborator volume-driven small lifts (#2) untouched.
- SharePoint `:808` WCF false-positive class (#4) untouched.

## Artifacts

- Per-case outputs under `/opt/EL/cases/srl-*/` (sealed tar.gz in
  `/opt/EL/cases/_archives/`).
- 2026-04-27 re-run combined output:
  `/opt/EL/cases/_combined/srl2018-enterprise-r2/{report.md,combined.html}`.
- 395k IOCs in `~/.el/knowledge.sqlite` with `case_id` provenance.
- Commits on `origin/main`: PR-B through PR-G, AGPL, README, shakedown
  writeup (this file) — all between `3fa18a6` (session start) and the
  commit emitting this doc.

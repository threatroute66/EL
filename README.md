# EL — A tribute to Edmond Locard

<p align="center">
  <img src="docs/EL.png" alt="EL — Edmond Locard DFIR orchestrator" width="640">
</p>

A multi-agent DFIR orchestrator for the SANS SIFT Workstation, built for
the [SANS Find Evil 2026](https://findevil.devpost.com/) competition and
designed as a reusable forensic investigation framework.

> **"Every contact leaves a trace."** — Edmond Locard, 1910
>
> EL takes Locard's exchange principle as its data model. Every artifact is
> a trace; every trace has a contact (entity) on each end. The per-case
> Kùzu graph is the materialised contact substrate over which specialist
> agents reason.

---

## What it does

Hand EL a piece of evidence — memory image, pcap, EVTX file, CloudTrail
JSON, Azure sign-in / M365 UAL export, extracted-artifacts directory,
Velociraptor collection bundle, E01 disk image (NTFS / ext4 / APFS), or
extracted filesystem tree (Windows / Linux / macOS / Android / iOS) —
and it produces:

- **A structured Findings ledger** — every claim ships with the tool, version,
  command, output sha256, supporting/refuting hypotheses, and an
  adversarial-review verdict. No claim without evidence.
- **A ranked hypothesis table** — Heuer's *Analysis of Competing
  Hypotheses* over 15 case-level hypotheses (ransomware, APT espionage,
  insider exfil, BEC, supply chain, brute force, cloud persistence, C2
  beaconing, opportunistic commodity, process injection, credential
  access, lateral movement, persistence variants, plus a null
  benign-no-incident).
- **A Markdown report** with executive summary, hypothesis ranking, most
  diagnostic findings, MITRE ATT&CK techniques implicated, IOC catalog,
  and a per-finding disconfirming-evidence checklist.
- **A self-contained HTML case view** (`el report --html`) — single-file
  dark-theme dashboard with ACH ranking, filterable findings grid,
  detail drawer, SVG attack-chain graph pulled from the Kùzu substrate,
  ATT&CK coverage heatmap grouped by tactic, and Diamond Model
  projection. Zero CDN, works from `file://`; `--watch` mode re-renders
  live as agents emit findings.
- **A STIX 2.1 bundle** + **machine-readable findings.json** + **per-case
  Kùzu graph** + **forensic_audit.log** + **per-case CLAUDE.md** for
  follow-on interactive analysis.

The contract is hard: EL refuses to advance to synthesis while any finding
remains `red_review.status == "unresolved"`, and `confidence="insufficient"`
is a first-class output. **An honest "I don't know" beats a confident
guess.**

---

## Architecture

```
                ┌────────────────┐
   Evidence ─▶  │   Coordinator  │  state machine
                └────────┬───────┘  intake → triage → hypothesis_gen →
                         │          parallel_investigate → correlate →
                         ▼          adversarial_review → synthesize →
              ┌──────────────────┐  report → done   (or → blocked)
              │     Triage       │
              │  (route by kind) │
              └─────────┬────────┘
                        │
        ┌───────────────┴────────────────┐
        ▼                                ▼
   Specialist agents              ThreatHunter (YARA sweep
   (one per evidence kind)        from extracted IOCs)
        │
        ▼
    Kùzu graph + SQLite findings ledger
        │
        ▼
   ┌──────────────────┐
   │   Correlator     │  cross-agent shared-entity queries
   └─────────┬────────┘
             ▼
   ┌──────────────────┐
   │  ACH Engine      │  10 hypotheses × all findings → ranking
   └─────────┬────────┘
             ▼
   ┌──────────────────┐
   │  Red Reviewer    │  rule-based challenger (always)
   │                  │  + LLM challenger (if ANTHROPIC_API_KEY)
   └─────────┬────────┘
             ▼
       Reporter → MD report + STIX 2.1 + findings.json
```

### Agents

| Agent | Owns |
|---|---|
| `Triage` | First-touch: hash, file-magic, evidence-kind classification, vol3 banner OS detection, directory-shape recognition (Windows-artifacts / Velociraptor / Android / iOS / macOS — mobile shapes detected by cheap `is_dir()` probes before the expensive filesystem walk) |
| `MemoryForensicator` | Volatility 3 plugins (`pslist`, `psscan`, `pstree`, `cmdline`, `malfind --dump`, `netstat`, `netscan`, `dlllist`, `svcscan`, `modules`, `modscan`, `ldrmodules`, `handles`, `getsids`, `ssdt`, `driverirp`, `filescan`, `mftscan`); psscan-pslist hidden-process diff; modules-vs-modscan unlinked-driver diff; ldrmodules three-list reflective-injection diff; PE-header / process-anomaly detection; credential-access carve-out (lsass / winlogon / csrss); optional Memory Baseliner image-vs-image diff |
| `DiskForensicator` | Sleuth Kit (`mmls`, `fls`, `mactime`); EWF integrity verification + `ewfmount` + per-partition (and no-partition fallback) walk; NTFS mount + artifact extraction; ext4 mount; APFS mount via `fsapfsmount`; disk anomaly scoring (PsExec service binary, PyInstaller `_MEI` temp dirs, svchost/lsass outside System32, exe-in-Temp, non-MS scheduled tasks, mimikatz-named binaries, vssadmin shadow-copy deletion traces) |
| `WindowsArtifactAgent` | Extracted-artifacts directory pipeline — auto-chained after DiskForensicator extracts: MFTECmd, RECmd-Kroll-batch, AmcacheParser, AppCompatCacheParser, PECmd, EvtxECmd, SrumECmd, SBECmd, JLECmd, LECmd, RBCmd, BAM/DAM registry subtree decoding, ActivitiesCache.db (Windows Timeline) parsing |
| `LinuxForensicator` | Extracted Linux filesystem tree (ext4 mount or pre-extracted) — pulls `/etc`, `/var/log`, `/var/spool/cron`, per-user histories + SSH. 5 detectors: shell-history malicious (reverse shell / download cradle / base64 pipe / persistence / defense evasion / priv esc / credential access), `/etc/ld.so.preload`, auth-log failure burst, `authorized_keys` anomaly, cron suspicious |
| `MacOSForensicator` | Extracted macOS filesystem (APFS mount or pre-extracted). Pulls `/private/etc`, `/Library/Launch{Agents,Daemons,StartupItems}`, per-user Safari/KnowledgeC/Quarantine/LoginItems/LaunchAgents, `/private/var/log`. 4 detectors: LaunchAgent/Daemon suspicious-path persistence, shell-history malicious (shared Linux pattern library), Safari `QuarantineEventsV2` raw-IP / suspicious-TLD download source, Safari `Downloads.plist` anomalies |
| `AndroidForensicator` | Pre-extracted Android filesystem tree (Belkasoft / UFED / adb-pull). Pulls `/data/system/*.xml+db`, `/data/adb/`, `/data/local/tmp/`, ANR traces, tombstones, per-app messenger DBs. 4 detectors: rooted device (Magisk markers), sideloaded APKs (packages.xml installer heuristic with OEM exemptions), `/data/local/tmp` executable staging, messenger presence |
| `IOSForensicator` | Pre-extracted iOS filesystem tree (checkm8 / GrayKey / Cellebrite). Pulls SystemVersion.plist, `/private/var/mobile/Library/` user-data DBs (SMS, AddressBook, CallHistory, knowledgeC, interactionC, Safari, Mail, Notes, Health), per-app iTunesMetadata + BundleMetadata + Info.plist, provisioning profiles. 4 detectors: jailbreak indicators, sideloaded apps (no iTunesMetadata + non-Apple bundle id), provisioning-profile presence, messenger / privacy-tool presence (Signal / Telegram / Wickr / Session / Threema / Onion Browser / KeepSafe / Burner / ProtonMail / Tutanota / …) |
| `NetworkAnalyst` | pcap parsing via scapy: flows, DNS, HTTP Hosts + URIs + User-Agents, TLS SNI, suspicious-port flagging, Zeek replay with DGA entropy + DNS tunneling + SMB admin-share write detection, wire-layer Kerberos triage |
| `LogAnalyst` | EvtxECmd → high-value Event ID extraction (4624, 4625, 4672, 4688, 4697, 4698, 4720, 4732, 4769, 4776, 1102, 7045); SIGMA rule evaluator |
| `CloudForensicator` | AWS CloudTrail JSON + AWS VPC Flow Logs + Azure Entra sign-in logs + M365 Unified Audit Log + Azure Activity + GCP Cloud Audit. Sniffs input shape and dispatches; detectors for brute / spray, legacy-auth bypass, impossible travel, OAuth consent, inbox-rule external forwarding |
| `EndpointAnalyst` | Velociraptor collection bundles (Pslist / Netstat / Autoruns / Prefetch / TaskScheduler artifacts) |
| `BrowserForensicator` | Chrome / Edge / Firefox history, cookies, login-data, downloads from extracted user profiles |
| `CredentialAnalyst` | Kerberos anomalies from EVTX — RC4-HMAC TGS-REQ (Kerberoasting), AS-REQ failure burst, krbtgt-service TGS-REQ (golden-ticket smell) |
| `PowerShellAnalyst` | EID 4104 ScriptBlock decoding (base64 + gzip) + malicious pattern match, EID 4103 module logging, PSReadline history, transcription logs |
| `SigmaAnalyst` | Native SIGMA rule evaluator over parsed EVTX — EventID-indexed pre-filter, 90%-coverage modifier set, tag-to-hypothesis mapping |
| `EmailForensicator` | `.pst` / `.ost` / `.msg` / `.eml` parsing via `libpff` + `libolecf` wrappers |
| `ExecutionCorroborator` | Cross-artifact execution confirmation — Prefetch × Amcache × Registry × EvidenceOfExecution overlap |
| `LateralMovementAnalyst` | Cross-host pivot detection from EVTX 4624/4625/4648/4672/4769 + Security-Auditing event chaining |
| `TimelineSynthesist` | Plaso `log2timeline.py --parsers win10 --hashers md5,sha256 --timezone UTC` + `psort.py` + `pinfo.py` (opt-in via `--timeline`) |
| `Correlator` | Kùzu graph queries — top destination IPs, cross-host shared processes, entity counts, netscan-triage cluster lifting |
| `ThreatHunter` | Auto-generates a per-case YARA file from extracted IOCs; sweeps the input + analysis dir; uses `el hunt <case>` CLI for standalone re-sweeps |
| `MalwareTriage` | Per-region `.dmp` strings extraction + 19-family fingerprint library (mimikatz / cobalt strike / metasploit / empire / darkcomet / njrat / remcos / agent tesla / hancitor / trickbot / qakbot / icedid / sliver / ip_lookup_chain / angler / nuclear / fiesta EKs / asprox / dyre). Also scans non-memory analysis text (pcap summaries, EVTX CSVs, fls bodyfiles) for the same fingerprints; `capa` + `FLOSS` integration with ATT&CK technique attribution on dumped PEs / shellcode |
| `RedReviewer` | Rule-Based Challenger always runs (Office-spawn-shell, JIT carve-out for credential targets, LOLBin, network-context, low-confidence corroboration, single-evidence); LLM challenger augments when `ANTHROPIC_API_KEY` is set |

Plus the **ACH engine** (Heuer-style scoring; not a Claude agent — pure Python) which
emits a ranked-hypothesis Finding and writes a per-case `ach_matrix.json`.

### Skills

Tool wrappers, shared by agents, hardened against the operator-tier gotchas
documented in
[Protocol SIFT](https://github.com/teamdfir/protocol-sift)'s
five `SKILL.md` files (memory-analysis, sleuthkit, plaso-timeline,
windows-artifacts, yara-hunting).

| Skill | Wraps |
|---|---|
| `vol3` | Volatility 3 plugins; `--offline` opt-in to skip symbol-download hangs; `--dump` integration; 18 plugins wired |
| `sleuthkit` | `mmls`, `fls`, `mactime` (`-z UTC` default), `ewfinfo`, `ewfverify`, `ewfmount -X allow_other`, `img_stat`, `fsstat`, `tsk_recover`, `mount_ntfs` / `mount_linux_ro` / `mount_apfs_ro`, `extract_windows_artifacts` |
| `ezt` | EZ Tools via `dotnet`: EvtxECmd (`--maps` default), MFTECmd (`--at` default), RECmd (`--bn Kroll_Batch.reb` default), AmcacheParser, AppCompatCacheParser, PECmd, SBECmd, JLECmd, LECmd, SrumECmd, RBCmd |
| `plaso` | `log2timeline.py` with SKILL defaults (`--parsers win10 --hashers md5,sha256 --timezone UTC`), `psort.py`, `pinfo.py` |
| `scapy_pcap` | pcap parsing in pure Python — flows, DNS, HTTP Host/URI/User-Agent, TLS SNI |
| `cloudtrail` / `azure_signin` / `m365_audit` / `gcp_audit` / `aws_vpc_flow` | JSON / JSONL parsers; shape-sniff dispatch from `cloud_forensicator` |
| `velociraptor` | Velociraptor JSONL collection parser; Pslist / Netstat / Autoruns / Prefetch / TaskScheduler |
| `kerberos_triage` | Zeek `kerberos.log` detectors — RC4-HMAC Kerberoasting, AS-REQ brute/spray, krbtgt golden-ticket smell |
| `sigma_engine` | Native SIGMA rule evaluator — modifier set + condition grammar covering ~90% of community Windows rules |
| `ioc_extract` | Regex extractor (IPv4, IPv6, domain, URL, MD5/SHA1/SHA256, email, registry key, Windows path); defang-aware; noise-filtered (timestamps, version strings, X.509 OID labels, secp256k1/secp256r1 curve constants, file-extension TLDs, Windows internals); ubiquitous-IOC suppression from `~/.el/knowledge.sqlite` |
| `yara_hunt` | `yara` wrapper + per-case rule generator from extracted IOCs |
| `dump_analysis` | Pure-Python ASCII + UTF-16LE strings extraction from memory dumps; structural fingerprints (MZ header, PE signature, NOP sleds) |
| `memory_baseliner` | Memory Baseliner `-proc/-drv/-svc` comparisons; supports both image-vs-image (`-b <baseline.img>`) and JSON baseline workflows; auto-patched for vol3 ≥ 2.5 API |
| `capa` / `floss` | `capa` rule-pack resolver + shellcode-mode dispatch + FLOSS decoded-string extraction — ATT&CK technique attribution on PE / shellcode dumps |
| `bam_dam` / `win_timeline` | BAM/DAM registry subtree decoding via `regipy` + ActivitiesCache.db (Windows Timeline) via `sqlite3 ro=immutable` |
| `linux_artifacts` / `linux_triage` | Extract + detect on Linux filesystem trees — 5 detectors keyed on the Linux pattern library (reverse shell / download cradle / base64 pipe / persistence / defense evasion / priv esc / credential access) |
| `macos_artifacts` / `macos_triage` | Extract + detect on macOS filesystem trees — 4 detectors on LaunchAgents, Quarantine events, Safari downloads, shell history (delegates to Linux library) |
| `android_artifacts` / `android_triage` | Extract + detect on Android filesystem trees — 4 detectors (rooted device, sideloaded APK, `/data/local/tmp` staging, messenger presence) |
| `ios_artifacts` / `ios_triage` | Extract + detect on iOS filesystem trees — 4 detectors (jailbreak indicators, sideloaded app, provisioning profile, messenger / privacy-tool presence) |
| `disk_anomaly` | 9 SKILL/MITRE-grounded path patterns matched against fls bodyfiles |
| `rule_challenger` | Deterministic adversarial-review rules baseline; JIT carve-out for credential-access targets (lsass / winlogon / csrss) |
| `seal` | Per-case sha256 manifest + `merkle_root` + `tar.gz` archive emission at coordinator-DONE |
| `knowledge` | `~/.el/knowledge.sqlite` cross-case IOC + family-attribution store; rarity bucketing (rare / uncommon / common / ubiquitous) |
| `stix_import` | STIX 2.1 inbound bundle ingestion into `~/.el/knowledge.sqlite` with provenance tag |

---

## Install

### Host requirements

| Resource | Minimum | Recommended | Driver |
|---|---|---|---|
| RAM | 8 GB | **16 GB** | DC-class `evtx_parsed.csv` is 6+ GB / 5 M+ rows; `iter_events` materialises it into a Python list. Runs with <8 GB RAM will OOM on domain-controller / long-running-server images. 16 GB also lets disk + memory investigations run in parallel and leaves headroom for vol3 on 8 GB memory captures |
| vCPU | 2 | **4** | EvtxECmd, AmcacheParser, RECmd and bulk_extractor are multi-threaded; vol3 runs plugins sequentially but the agent launches several per case |
| Disk | 100 GB | **300–500 GB** | Each DC / RD case produces 6–10 GB of exports before sealing; sealed archives compound. 100 GB forces cleanup cycles during a corpus run |
| Base OS | — | SANS SIFT Workstation (Ubuntu 22.04) | Sleuth Kit, Plaso, EZ Tools runtime, dotnet, bulk_extractor already present |

### Install steps

```bash
git clone https://github.com/threatroute66/EL.git /opt/EL
cd /opt/EL
./install.sh
```

`install.sh` is idempotent. It:

1. Snapshots host state (`dpkg -l`, `/opt`, vol3 presence) into `provisioning/snapshots/` for chain of custody.
2. Installs apt packages from `provisioning/apt-packages.txt` (currently `yara` + `gh`).
3. Creates a Python venv (prefers `virtualenv`, falls back to `python -m venv`).
4. `pip install -e .[dev]` (volatility3, scapy, stix2, kuzu, anthropic, pydantic, etc.).
5. Snapshots post-install state and writes a diff.
6. Runs `el doctor`.

Re-verify anytime with `./install.sh --doctor` or `make doctor`.

Optional tools we detect but don't install: Memory Baseliner, zeek,
suricata, tshark, PECmd. See `provisioning/optional-tools.txt`.

---

## Usage

```bash
# Survey the host: which tools are present, schema sane, Kùzu importable
el doctor

# Investigate evidence end-to-end
el investigate /cases/memory.img --case-id wkstn-01
el investigate /cases/capture.pcap
el investigate /cases/cloudtrail.json --case-id apt-29-cloud
el investigate /cases/extracted-artifacts/ --case-id host-42-disk
el investigate /cases/velociraptor-bundle/ --case-id endpoint-collection

# Optional flags
el investigate <input> --baseline /path/to/baseline.json   # Memory Baseliner comparison
el investigate <input> --timeline                           # also run Plaso super-timeline (slow)

# Re-render report from an existing case ledger (no re-investigation)
el report /opt/EL/cases/wkstn-01

# Also render a self-contained HTML case view (reports/case.html)
el report /opt/EL/cases/wkstn-01 --html

# Live-update mode: re-render on every findings.sqlite change. Open
# case.html?watch=3 in a browser for auto-reload every 3 s.
el report /opt/EL/cases/wkstn-01 --html --watch

# Browse all case reports via a local HTTP server — needed when the
# default browser is a snap (Chromium on Ubuntu) that can't read
# /opt/ from file://. Loopback-only by default.
el serve                                   # http://127.0.0.1:8089/
el serve --port 9000                       # custom port
el serve --root /opt/EL/cases/srl-admin-memory  # single case

# Install the viewer as a systemd --user service: auto-starts at
# next login and survives reboots (once user-linger is enabled).
# Ships the unit at ~/.config/systemd/user/el-serve.service with
# hardening (NoNewPrivileges, ReadOnlyPaths=<root>, ProtectSystem=strict).
el serve --install-service                 # idempotent
./install.sh --with-serve                  # one-step: install + enable at bootstrap
loginctl enable-linger $USER               # survive reboots even when not logged in
el serve --uninstall-service               # reverse

# Standalone YARA sweep over an existing case (auto-generates rules from iocs.json)
el hunt /opt/EL/cases/wkstn-01
el hunt /opt/EL/cases/wkstn-01 --rules /opt/signature-base/yara/

# Memory timeline across multiple RAM-snapshot cases (Roussev & Quates
# 2012 M57 Case-2 methodology): diff each snapshot's module inventory
# against a baseline + against the previous snapshot to reveal what
# executables / DLLs / drivers entered or left memory between snapshots.
el timeline-memory /opt/EL/cases/host-day1 /opt/EL/cases/host-day3 \
    --baseline /opt/EL/cases/host-baseline-disk
el timeline-memory /opt/EL/cases/srl-*-memory    # earliest becomes baseline

# Browse the findings ledger
el ledger /opt/EL/cases/wkstn-01

# Capture a host-state snapshot for chain of custody (any time)
el provision-snapshot --label pre-incident

# Verify a sealed case has not drifted since coordinator-DONE
el seal-verify /opt/EL/cases/wkstn-01

# Query the cross-case knowledge store (~/.el/knowledge.sqlite)
el knowledge stats
el knowledge lookup 8.8.8.8
el knowledge lookup evil.example.com
```

Each case workspace lives at `cases/<case_id>/`:

```
cases/<case_id>/
├── manifest.json              # input hashes + intake UTC + magic + case_dir
├── findings.sqlite            # structured Findings ledger
├── graph.kuzu/                # per-case Kùzu graph (entities + edges)
├── iocs.json                  # extracted IOC catalog
├── ach_matrix.json            # hypothesis × finding score matrix
├── transitions.json           # coordinator state-machine trace
├── CLAUDE.md                  # case-scoped Claude Code briefing
├── analysis/
│   ├── forensic_audit.log    # append-only event log
│   ├── triage/                # tool outputs grouped by agent
│   ├── memory_forensicator/
│   ├── threat_hunter/
│   └── …
├── exports/                   # extracted artifacts
├── reports/
│   ├── report.md              # human-readable report
│   ├── findings.json          # machine-readable Findings dump
│   └── stix-bundle.json       # STIX 2.1 (MISP-importable)
├── seal.json                  # per-file sha256 manifest + merkle root + sealed_utc + el_git_rev
└── raw/                       # working space
```

A `cases/_archives/<case_id>-<TS>.tar.gz` archive of the entire case dir
(seal.json embedded) is also written at coordinator-DONE for off-host
retention. `el seal-verify <case_dir>` re-hashes everything and reports
any drift.

---

## Cross-case institutional knowledge

In addition to the per-case workspace, EL maintains a global
`~/.el/knowledge.sqlite` store recording every IOC every case has ever
extracted, with full provenance: `(value, ioc_type, case_id, observed_utc,
agent, sealed)`. After IOC extraction in each new case, EL queries the
store for prior observations from OTHER cases and emits suggestive
`Cross-case overlap` Findings:

> "Cross-case overlap: ipv4 `203.0.113.7` previously observed in case(s)
> `wkstn-03`. Suggestive only — confidence stays 'low' because cross-case
> overlap is context, not evidence for this case's hypotheses."

These findings carry `confidence='low'` on purpose — they show the
analyst when an indicator is being seen across investigations without
auto-lifting any hypothesis. Forensic conclusions in case B must stand
on case B's own findings; case A is context, not evidence. The store is
updated atomically as part of every `el investigate` run; sealed cases
flip `sealed=1` so the knowledge layer can distinguish provisional
observations from hash-verified ones.

---

## The contract

Every finding ships with mandatory provenance:

```json
{
  "finding_id": "01KPDWYY9AV2HZ7ZXZ55CHDG3B",
  "case_id": "wkstn-01",
  "agent": "memory_forensicator",
  "claim": "Hidden processes detected — 2 PID(s) in psscan but absent from pslist",
  "confidence": "high",
  "evidence": [{
    "tool": "volatility3", "version": "2.27.0",
    "command": "vol -q -r json -f /cases/wkstn-01.img windows.psscan.PsScan",
    "output_sha256": "…", "output_path": "…/windows_psscan_PsScan.json",
    "extracted_facts": {"row_count": 169, "rc": 0, "hidden_pids": [214668, 215928]}
  }],
  "hypotheses_supported": ["H_PROCESS_INJECTION", "H_ROOTKIT"],
  "ach_score_delta": {"H_APT_ESPIONAGE": 3, "H_BENIGN_NO_INCIDENT": -3},
  "red_review": {
    "status": "challenged",
    "challenger_notes": "[NO_EVIDENCE_NO_CLAIM] A single tool's output is not corroboration…",
    "disconfirming_checklist": ["Re-run the same plugin with a different symbol set or tool version", …]
  }
}
```

Three hard rules (Pydantic-enforced):

1. **No finding without `evidence[]`.** The schema rejects high/medium/low
   confidence with empty evidence. The only escape is `confidence="insufficient"`.
2. **`insufficient` is a first-class output.** Better than a guess.
3. **Reproducibility manifest** ships with every report — every Finding's
   evidence carries the exact command. `el report <case>` re-renders deterministically.

---

## Validated on real evidence

EL has been exercised end-to-end on the following real evidence types,
with each case surfacing bugs that became permanent regression tests:

| Sample | Type | Size | Result |
|---|---|---:|---|
| SANS Hackathon-2026 wkstn | Win memory | 3 GB | H_APT_ESPIONAGE +3, 2 hidden processes detected |
| SANS Hackathon-2026 dc | Win Server memory | 5 GB | Vol3 symbol mismatch surfaced as actionable; honest "insufficient" output (with our fix to score insufficient findings as neutral) |
| 2020 Jimmy Wilson FTK image | E01 disk (NTFS) | 296 MB / 890 MB raw | Full chain: ewfmount → mmls → fls → mactime → mount + extract → WindowsArtifactAgent ran 4 EZ Tool parsers |
| Charlie 2009 (XP-era) memory | MDD memory dump | 2 GB | H_APT_ESPIONAGE +19 (gap +9), credential-access carve-out flagged 10 RWX regions across lsass/winlogon/csrss; 28 dumped regions for offline RE |
| FOR508 Stark Research Labs nrom | Paired memory + 9.7 GB E01 + baseline image | ~15 GB | Memory: H_APT_ESPIONAGE +25 with full attack chain via Memory Baseliner diff (PsExec → spinlock.exe Meterpreter, Mnemosynei386.sys driver, dllhost\svchost disguise). Disk: H_APT_ESPIONAGE +20 with 7 disk anomalies independently corroborating the memory finding |
| Malware-Traffic-Analysis pcaps | Hancitor / Trickbot / Qakbot / Cobalt Strike | 5–40 MB each | Family fingerprint library attributes Hancitor (`/8/forum.php` URI) and Trickbot (gtag check-in pattern) directly from network traffic |
| Malware-Traffic-Analysis corpus sweep | ~2000 pcaps (2013–2025) | ~50 GB total | Long-tail rarity bucketing validated in production; cross-case IOC knowledge store populated with 2000+ pcap case_ids |
| BelkaCTF Kidnapper | Linux E01 (ext4) | 890 MB | `LinuxForensicator` + `ext4` mount; 12 /etc + 22 cron + 204 systemd services extracted; clean baseline (no malicious history patterns) |
| BelkaCTF macOS Big Sur | macOS APFS filesystem tree | ~40 GB | `MacOSForensicator` + `fsapfsmount` APFS mount; 8 /etc_core + 3 SSH + 2 system launch plists + 1 KnowledgeC + 1 Quarantine + 3 Safari — clean baseline, no hits |
| BelkaCTF Android | Extracted filesystem tree | ~30 GB | `AndroidForensicator` detected Magisk root + com.topjohnwu.magisk sideloaded via packageinstaller + WhatsApp presence — 3 detector hits |
| BelkaCTF iPhone SE (iOS 14.3) | Extracted filesystem tree | ~200 GB | `IOSForensicator` pulled 63 app Info.plists + 105 bundle metadata + SMS/AddressBook/CallHistory/KnowledgeC/Health DBs; 18 encrypted-messenger / privacy-tool apps detected (Signal, Telegram, Wickr Enterprise, ProtonMail, Tutanota, Onion Browser, KeepSafe, Burner, …) — end-to-end in 1m39s after the intake Merkle-hash perf fixes |
| [NPS M57-Jean](https://digitalcorpora.org/corpora/scenarios/m57-jean/) | NTFS E01 multi-part (Windows XP) | 3 GB | **EL arrived at the canonical answer neither [Basilmellow](https://github.com/Basilmellow/Autopsy-M57-Linux-Forensics) nor [jynxora](https://github.com/jynxora/M57-Jean-Case-Analysis) reached**: BEC / pretexting exfil (H_BEC_ACCOUNT_TAKEOVER score **57, gap +44** post-gap-closure, up from 30 initial). Full story reconstructed: (1) attacker sent inbound email spoofing `alison@m57.biz` from `tuckgorge@gmail.com` (2 subjects: "Thanks!" + "Please send me the information now"), (2) Jean replied with `1_m57biz.xls (291840B)` attached, (3) bonus anti-forensic cleanup (15 zero-size + 15 zero-timestamp Windows system binaries — `auditusr.exe`, `pdh.dll`, `ciadmin.dll`), (4) 4778 IE5 cache records parsed including 24 `__utm` tracker-sync session-hijack artefacts. The per-finding `[finding_id]` citations + competing-hypothesis narrative render in `case.html` end-to-end |

Across these cases, EL surfaced 40+ bugs that are now locked in as
regression tests — vol3 PATH inside venv subprocess, EVF vs EWF magic
typo, FUSE-inside-FUSE mount target, IOC false-positives across 6
distinct categories (timestamps, version strings, X.509 OID labels,
crypto curve constants, file-extension TLDs, Windows internals),
empty-pslist hidden-process false flag, ACH scoring tool-failure
messages, Memory Baseliner vol3-API drift, no no-partition extraction,
no disk-side hypothesis scoring, triage `rglob` over iOS HGFS mounts,
intake Merkle-hash dominated by per-file content reads on mobile trees,
`_h_ransomware` substring match on "encrypted-messenger" (fixed with
ransom-note phrase tightening), APFS dispatch gated on `fls` success
(iOS returns 0 rows on APFS — fix: run extraction regardless).

---

## Analyst web view

`el report --html` produces a single self-contained `reports/case.html`
that opens directly in any modern browser (`file://` — no CDN, no
framework, no build step, works inside a sealed `tar.gz` archive).
Rolled out in four tiers per
[docs/web-view-design.md](./docs/web-view-design.md):

1. **Static render** — executive summary, ACH ranking as horizontal
   bars, **chronological timeline** of findings, **Most Diagnostic
   Findings** (Heuer — highest ACH score-delta spread), **ACH
   consistency matrix** (finding × hypothesis grid), findings grid
   filterable by agent + confidence, per-finding detail drawer with
   evidence sha256s, extracted-facts, ACH Δ, and the disconfirming
   checklist from the Red Reviewer, IOC table, ATT&CK table.
   Deep-linkable by finding_id:
   `case.html#01KPMZC32QYA976TVHC026F5K0`.
2. **Attack-chain graph** — SVG force-directed layout of the per-case
   Kùzu substrate (Host / User / Process / File / IPAddress / Domain
   / Hash / NetworkFlow / Event nodes, 13 edge types). Pan + zoom +
   click-to-drawer; degree-capped at 500 nodes so huge graphs
   (scan-and-probe pcaps sit at 48k+) don't blow up the browser.
3. **ATT&CK coverage heatmap** — technique counts grouped by MITRE
   tactic, heat-coloured by finding count. 104 EL-emitted technique
   IDs mapped to primary tactics. Plus **Diamond Model** projection
   (Adversary / Capability / Infrastructure / Victim) for the
   ACH-leading hypothesis.
4. **Live-update mode** — `el report --html --watch` re-renders on
   every `findings.sqlite` change. Open `case.html?watch=3` in a
   browser for a 3-second auto-reload tick with a "LIVE" badge in the
   header. Matches the design doc's "static-served, no websockets"
   constraint so nothing new has to run beyond the local shell.

---

## Why this design

- **No sycophancy, no false positives** — Red Reviewer is non-optional. The
  rule-based challenger always runs (deterministic baseline). The LLM
  challenger augments when an `ANTHROPIC_API_KEY` is set; their results
  merge with severity-bias toward "challenged".
- **Tool output IS evidence** — Agents are Python orchestration around
  vetted CLI tools. We do NOT use an LLM to "read" event logs or parse
  process trees; deterministic parsers exist. LLMs reason about
  prioritisation and falsification, not extraction.
- **Hypothesis-driven, not playbook-driven** — ACH puts ≥3 competing
  hypotheses on the table for every case, including the null
  (`H_BENIGN_NO_INCIDENT`). A finding's diagnostic value is the variance
  of its scores across hypotheses (Heuer's standard).
- **Locard as data model** — the per-case Kùzu graph stores `Host`,
  `User`, `Process`, `File`, `RegistryKey`, `IPAddress`, `Domain`, `Hash`,
  `NetworkFlow`, `Event` nodes with edges like `EXECUTED`, `WROTE`,
  `CONNECTED_TO`, `CHILD_OF`, `RESOLVED_TO`, `AUTHENTICATED_AS`.
- **Chain of custody first** — read-only on `/cases/`, `/mnt/`, `/media/`;
  all derived data goes to `analysis/`, `exports/`, `reports/`; UTC
  everywhere; SHA-256 manifests for inputs, evidence outputs, and
  provisioning snapshots.

---

## Status

- **942 tests; `make test` runs them in ~50 seconds.**
- 24 specialist agents · 51 skill primitives · 15 case-level hypotheses
  with deterministic scorers · 104 ATT&CK technique → tactic mappings ·
  19 malware family fingerprints · 9 disk anomaly patterns
- Validated end-to-end on 11 evidence types: Windows memory (workstation
  + DC) · NTFS E01 disk · paired memory+disk+baseline · malware-traffic
  pcaps (~2000-pcap corpus sweep) · MDD-format XP memory · Linux ext4 ·
  macOS APFS · Android filesystem tree · iOS 14 filesystem tree · AWS
  CloudTrail JSON · Azure Entra sign-in / M365 UAL exports.
- Self-contained HTML case view (`el report --html`) covers all four
  design-doc tiers (static render, attack-chain graph, ATT&CK
  heatmap + Diamond Model, `--watch` live-update).
- All cases sealed (sha256 manifest + tar.gz archive + `seal-verify`
  CLI); all IOCs recorded into `~/.el/knowledge.sqlite` for cross-case
  retention (2000+ pcap cases + memory + disk cases in the current
  knowledge DB).

## Author

Created by **Murat Cakir**, [GSE #185](https://www.giac.org/certified-professional/Murat-Cakir/154250) — [LinkedIn](https://tr.linkedin.com/in/cakirm).

## License

EL is licensed under the **Apache License, Version 2.0**. See
[LICENSE](./LICENSE) for the full text.

Apache 2.0 is a permissive license: you may use, modify, and
redistribute EL in any product (commercial or non-commercial) provided
you preserve the copyright + license notices and mark any changes you
make. Apache 2.0 also grants an express patent license from every
contributor to every user — important for a DFIR tool that touches
techniques some vendors hold patents on.

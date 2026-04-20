# EL — A tribute to Edmond Locard

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

Hand EL a piece of evidence (memory image, pcap, EVTX file, CloudTrail
JSON, extracted-artifacts directory, or Velociraptor collection bundle)
and it produces:

- **A structured Findings ledger** — every claim ships with the tool, version,
  command, output sha256, supporting/refuting hypotheses, and an
  adversarial-review verdict. No claim without evidence.
- **A ranked hypothesis table** — Heuer's *Analysis of Competing
  Hypotheses* over 10 case-level hypotheses (ransomware, APT espionage,
  insider exfil, BEC, supply chain, brute force, cloud persistence, C2
  beaconing, opportunistic commodity, plus a null benign-no-incident).
- **A Markdown report** with executive summary, hypothesis ranking, most
  diagnostic findings, MITRE ATT&CK techniques implicated, IOC catalog,
  and a per-finding disconfirming-evidence checklist.
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
| `Triage` | First-touch: hash, file-magic, evidence-kind classification, vol3 banner OS detection, directory-shape recognition |
| `MemoryForensicator` | Volatility 3 plugins (`pslist`, `psscan`, `pstree`, `cmdline`, `malfind --dump`, `netstat`, `netscan`, `dlllist`, `svcscan`); psscan-pslist hidden-process diff; PE-header / process-anomaly detection; credential-access carve-out (lsass / winlogon / csrss); optional Memory Baseliner image-vs-image diff |
| `DiskForensicator` | Sleuth Kit (`mmls`, `fls`, `mactime`); EWF integrity verification + `ewfmount` + per-partition (and no-partition fallback) walk; NTFS mount + artifact extraction; **disk anomaly scoring** (PsExec service binary, PyInstaller `_MEI` temp dirs, svchost/lsass outside System32, exe-in-Temp, non-MS scheduled tasks, mimikatz-named binaries, vssadmin shadow-copy deletion traces) |
| `WindowsArtifactAgent` | Extracted-artifacts directory pipeline — auto-chained after DiskForensicator extracts: MFTECmd, RECmd-Kroll-batch, AmcacheParser, AppCompatCacheParser, PECmd, EvtxECmd, SrumECmd, SBECmd, JLECmd, LECmd, RBCmd |
| `NetworkAnalyst` | pcap parsing via scapy: flows, DNS, HTTP Hosts + URIs + User-Agents, TLS SNI, suspicious-port flagging |
| `LogAnalyst` | EvtxECmd → high-value Event ID extraction (4624, 4625, 4672, 4688, 4697, 4698, 4720, 4732, 4769, 4776, 1102, 7045) |
| `CloudForensicator` | AWS CloudTrail JSON (offline) — high-value events: ConsoleLogin, AssumeRole, CreateAccessKey, PutBucketPolicy, etc. |
| `EndpointAnalyst` | Velociraptor collection bundles (Pslist / Netstat / Autoruns artifacts) |
| `TimelineSynthesist` | Plaso `log2timeline.py --parsers win10 --hashers md5,sha256 --timezone UTC` + `psort.py` + `pinfo.py` (opt-in via `--timeline`) |
| `Correlator` | Kùzu graph queries — top destination IPs, cross-host shared processes, entity counts |
| `ThreatHunter` | Auto-generates a per-case YARA file from extracted IOCs; sweeps the input + analysis dir; uses `el hunt <case>` CLI for standalone re-sweeps |
| `MalwareTriage` | Per-region `.dmp` strings extraction + 14-family fingerprint library (mimikatz / cobalt strike / metasploit / empire / darkcomet / njrat / remcos / agent tesla / hancitor / trickbot / qakbot / icedid / sliver / ip_lookup_chain). Also scans non-memory analysis text (pcap summaries, EVTX CSVs, fls bodyfiles) for the same fingerprints |
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
| `vol3` | Volatility 3 plugins; `--offline` opt-in to skip symbol-download hangs; `--dump` integration |
| `sleuthkit` | `mmls`, `fls`, `mactime` (`-z UTC` default), `ewfinfo`, `ewfverify`, `ewfmount -X allow_other`, `img_stat`, `fsstat`, `tsk_recover`, `mount_ntfs` (ro+norecovery), `extract_windows_artifacts` |
| `ezt` | EZ Tools via `dotnet`: EvtxECmd (`--maps` default), MFTECmd (`--at` default), RECmd (`--bn Kroll_Batch.reb` default), AmcacheParser, AppCompatCacheParser, PECmd, SBECmd, JLECmd, LECmd, SrumECmd, RBCmd |
| `plaso` | `log2timeline.py` with SKILL defaults (`--parsers win10 --hashers md5,sha256 --timezone UTC`), `psort.py`, `pinfo.py` |
| `scapy_pcap` | pcap parsing in pure Python — flows, DNS, HTTP Host/URI/User-Agent, TLS SNI |
| `cloudtrail` | AWS CloudTrail JSON / JSONL parser; gzipped + multi-file directories supported |
| `velociraptor` | Velociraptor JSONL collection parser; Pslist / Netstat / Autoruns / Prefetch / TaskScheduler |
| `ioc_extract` | Regex extractor (IPv4, IPv6, domain, URL, MD5/SHA1/SHA256, email, registry key, Windows path); defang-aware; noise-filtered (timestamps, version strings, X.509 OID labels, secp256k1/secp256r1 curve constants, file-extension TLDs, Windows internals) |
| `yara_hunt` | `yara` wrapper + per-case rule generator from extracted IOCs |
| `dump_analysis` | Pure-Python ASCII + UTF-16LE strings extraction from memory dumps; structural fingerprints (MZ header, PE signature, NOP sleds) |
| `memory_baseliner` | Memory Baseliner `-proc/-drv/-svc` comparisons; supports both image-vs-image (`-b <baseline.img>`) and JSON baseline workflows; auto-patched for vol3 ≥ 2.5 API |
| `disk_anomaly` | 9 SKILL/MITRE-grounded path patterns matched against fls bodyfiles |
| `rule_challenger` | Deterministic adversarial-review rules baseline; JIT carve-out for credential-access targets (lsass / winlogon / csrss) |
| `seal` | Per-case sha256 manifest + `merkle_root` + `tar.gz` archive emission at coordinator-DONE |
| `knowledge` | `~/.el/knowledge.sqlite` cross-case IOC + family-attribution store |

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

# Standalone YARA sweep over an existing case (auto-generates rules from iocs.json)
el hunt /opt/EL/cases/wkstn-01
el hunt /opt/EL/cases/wkstn-01 --rules /opt/signature-base/yara/

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

Across these cases, EL surfaced 30+ bugs that are now locked in as
regression tests — vol3 PATH inside venv subprocess, EVF vs EWF magic
typo, FUSE-inside-FUSE mount target, IOC false-positives across 6
distinct categories (timestamps, version strings, X.509 OID labels,
crypto curve constants, file-extension TLDs, Windows internals),
empty-pslist hidden-process false flag, ACH scoring tool-failure
messages, Memory Baseliner vol3-API drift, no no-partition extraction,
no disk-side hypothesis scoring.

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

- **109 tests; `make test` runs them in ~10 seconds.**
- 13 specialist agents · 14 skill primitives · 15 case-level hypotheses
  with deterministic scorers · 14 ATT&CK technique mappings · 14 malware
  family fingerprints · 9 disk anomaly patterns
- Validated end-to-end on real evidence across all six evidence types
  (Windows memory, Windows DC memory, NTFS E01 disk, paired
  memory+disk+baseline, malware-traffic pcaps, MDD-format XP memory)
- All cases sealed (sha256 manifest + tar.gz archive + `seal-verify`
  CLI); all IOCs recorded into `~/.el/knowledge.sqlite` for cross-case
  retention.

## License

EL is licensed under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later). See [LICENSE](./LICENSE) for the full text.

The AGPL extends the GPL's share-alike obligation to *network* use: anyone
who modifies EL and runs the modified version as a service (including
internal tooling exposed over a network) must make the corresponding
source available to users of that service. Pure internal use without
modification is fine; so is unmodified redistribution. If you want to
embed EL in a closed commercial product or SaaS and cannot comply with
the AGPL's source-disclosure terms, contact the maintainer to discuss
a commercial license.

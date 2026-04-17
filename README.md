# EL — Edmond Locard

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
| `MemoryForensicator` | Volatility 3 plugins (`pslist`, `psscan`, `pstree`, `cmdline`, `malfind`, `netstat`, `netscan`, `dlllist`, `svcscan`); psscan-pslist hidden-process diff; optional Memory Baseliner comparison |
| `DiskForensicator` | Sleuth Kit (`mmls`, `fls`, `mactime`); EWF integrity verification; sector-size detection |
| `WindowsArtifactAgent` | Extracted-artifacts directory pipeline (MFTECmd, RECmd-Kroll-batch, AmcacheParser, AppCompatCacheParser, PECmd, EvtxECmd, SrumECmd, SBECmd, JLECmd, LECmd, RBCmd) |
| `NetworkAnalyst` | pcap parsing via scapy; flows, DNS, HTTP Hosts, TLS SNI, suspicious-port flagging |
| `LogAnalyst` | EvtxECmd → high-value Event ID extraction (4624, 4625, 4672, 4688, 4697, 4698, 4720, 4732, 4769, 4776, 1102, 7045) |
| `CloudForensicator` | AWS CloudTrail JSON (offline) — high-value events: ConsoleLogin, AssumeRole, CreateAccessKey, PutBucketPolicy, etc. |
| `EndpointAnalyst` | Velociraptor collection bundles (Pslist / Netstat / Autoruns artifacts) |
| `TimelineSynthesist` | Plaso `log2timeline.py --parsers win10 --hashers md5,sha256 --timezone UTC` + `psort.py` + `pinfo.py` (opt-in via `--timeline`) |
| `Correlator` | Kùzu graph queries — top destination IPs, cross-host shared processes, entity counts |
| `ThreatHunter` | Auto-generates a per-case YARA file from extracted IOCs; sweeps the input + analysis dir |
| `RedReviewer` | Rule-Based Challenger always runs; LLM challenger augments when `ANTHROPIC_API_KEY` is set |

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
| `vol3` | Volatility 3 plugins; `--offline` opt-in to skip symbol-download hangs |
| `sleuthkit` | `mmls`, `fls`, `mactime` (`-z UTC` default), `ewfinfo`, `ewfverify`, `img_stat`, `fsstat`, `tsk_recover` |
| `ezt` | EZ Tools via `dotnet`: EvtxECmd (`--maps` default), MFTECmd (`--at` default), RECmd (`--bn Kroll_Batch.reb` default), AmcacheParser, AppCompatCacheParser, PECmd, SBECmd, JLECmd, LECmd, SrumECmd, RBCmd |
| `plaso` | `log2timeline.py` with SKILL defaults (`--parsers win10 --hashers md5,sha256 --timezone UTC`), `psort.py`, `pinfo.py` |
| `scapy_pcap` | pcap parsing in pure Python (no system tools needed) |
| `cloudtrail` | AWS CloudTrail JSON / JSONL parser; gzipped + multi-file directories supported |
| `velociraptor` | Velociraptor JSONL collection parser; Pslist / Netstat / Autoruns / Prefetch / TaskScheduler |
| `ioc_extract` | Regex extractor (IPv4, IPv6, domain, URL, MD5/SHA1/SHA256, email, registry key, Windows path); defang-aware; noise-filtered |
| `yara_hunt` | `yara` wrapper + per-case rule generator from extracted IOCs |
| `memory_baseliner` | Memory Baseliner `-proc/-drv/-svc` comparisons against a known-good baseline JSON |
| `rule_challenger` | Deterministic adversarial-review rules baseline (Office-spawn-shell, malfind JIT, LOLBin, network-context, low-confidence corroboration, single-evidence) |

---

## Install

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

EL assumes a **SANS SIFT Workstation** base (Sleuth Kit, Plaso, EZ Tools,
dotnet, bulk_extractor already present). Optional tools we detect but
don't install: Memory Baseliner, zeek, suricata, tshark, PECmd. See
`provisioning/optional-tools.txt`.

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
└── raw/                       # working space
```

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

The first end-to-end validation ran against a 3 GB Windows workstation
memory image from the SANS Hackathon-2026 corpus:

- 17 findings emitted across 10 agents in 2m38s
- All 9 vol3 plugins parsed cleanly (pslist=163, psscan=169, pstree=1, cmdline=163, netstat=74, netscan=139, dlllist=3254, svcscan=1309, malfind=0)
- Hidden-process diff surfaced 2 PIDs (214668, 215928) — strong rootkit / unlinking indicator
- Threat Hunter YARA sweep: 9 hits on the memory image + 33 hits in the analysis dir (cross-tool corroboration)
- Adversarial review (rule-only mode): passed=1, challenged=15, unresolved=0
- Leading hypothesis: **H_APT_ESPIONAGE** at +3 (gap=+2)
- 2 MITRE ATT&CK techniques implicated: T1055 (Process Injection), T1071 (Application Layer Protocol)

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

- 65 tests; `make test` runs them in under 10 seconds.
- Validated on real Windows memory image; pcap, CloudTrail JSON, and
  Velociraptor JSONL collections via end-to-end test fixtures.
- Disk-image and EVTX paths are wired but not yet stress-tested on real
  evidence — they emit `insufficient` findings on incompatible inputs
  rather than crashing.

## License

Not yet declared. If you intend to fork or contribute, open an issue first.

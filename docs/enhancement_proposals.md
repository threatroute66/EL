# EL Enhancement Proposals — Modern DFIR Tooling Integration

**Date**: 2026-05-03
**Status**: PROPOSAL — research and prioritisation; no implementation yet
**Source**: Cross-reference of modern (2025-2026) OSS DFIR landscape against EL's current 27 agents / 87 skills / 23 hypotheses

---

## Methodology

1. Surveyed the active OSS DFIR landscape across 15 domains
2. Inventoried EL's current agents, skills, and hypothesis coverage
3. Cross-referenced gaps against `docs/sans_sift_tools.md` (SIFT defaults)
4. Filtered for: actively maintained (commits in 2024-2025), aligns with EL's "wrap don't reimplement" rule, fits existing Finding schema and ACH workflow
5. Prioritised by: real-world DFIR impact × ease of integration × non-overlap with existing skills

**Design constraints applied** (from `CLAUDE.md`):
- Subprocess wrapper over CLI/file-output, never re-implementation
- Output goes to `<case_dir>/analysis/<agent>/...` with stderr capture
- Every finding ships tool + version + command + sha256
- `confidence="insufficient"` is first-class (don't fake high-confidence)
- Layer-3 knowledge (cross-case overlap) stays *suggestive*, never load-bearing

---

## Tier 1 — High-impact, fits today's gaps cleanly

These address concrete weaknesses in EL's current coverage. Each is a single new skill + small agent enhancement; no architectural change required.

### 1.1 MemProcFS — memory as a filesystem
**Project**: github.com/ufrisk/MemProcFS  
**Gap addressed**: Vol3's plugin model is rigid; triage requires running 18 plugins and joining outputs. MemProcFS exposes the memory image as a virtual FS so `ls`, `grep`, `yara`, and `find` work natively.

**Why it fits EL**:
- Pure subprocess + FUSE mount — fits the "wrap CLI" rule
- Complements (does not replace) `vol3` skill: vol3 owns deep plugin analysis; MemProcFS owns triage breadth
- Built-in plugins (`Hunt-Mimikatz`, `Hunt-PEInjection`, `Hunt-PHANTOM-DLL`) provide independent corroboration of vol3 findings — direct value to Red Reviewer
- Linux build is stable as of 2024

**Integration shape**:
- Skill `el/skills/memprocfs.py` — mount image, list `forensic/`, `pyproc/`, `find/` virtual paths
- `MemoryForensicatorAgent` enhancement: after vol3 plugins run, mount with MemProcFS and walk `forensic/yara/` and `forensic/findevil/` outputs as independent corroboration
- Findings carry both `tool=volatility3` AND `tool=memprocfs` evidence — the Red Reviewer's "single tool corroboration" challenger gets satisfied automatically

**SIFT status**: Not on SIFT default; `install.sh` would download from GitHub releases (single static binary on Linux).

**Risk**: Low. Mounts are read-only via FUSE; failure is isolated to one agent.

---

### 1.2 MVT (Mobile Verification Toolkit) — Pegasus / mercenary spyware
**Project**: mvt.re (Amnesty Tech)  
**Gap addressed**: EL has iLEAPP/ALEAPP for general mobile artifacts but no mercenary-spyware detector. MVT is the standard for Pegasus, Predator, Reign, Triangulation IOC matching against iOS/Android collections.

**Why it fits EL**:
- Pure CLI + STIX2 IOC files (matches `stix_import` skill pattern already in EL)
- Outputs JSON; trivially parsed into Findings
- Maps directly to existing `H_MOBILE_SPYWARE_PERSISTENCE` hypothesis — currently has no scorer that uses real spyware-IOC evidence
- Amnesty Tech publishes IOCs as STIX2 bundles — flows into EL's Layer-3 knowledge store

**Integration shape**:
- Skill `el/skills/mvt.py` — wraps `mvt-ios` / `mvt-android` against extracted backups
- `IOSForensicatorAgent` and `AndroidForensicatorAgent` chain MVT after artifact extraction
- New `MalwareFamily` entries for known spyware (Pegasus, Predator) with MVT IOC source

**SIFT status**: Not present; pip-installable (`pip install mvt`).

**Risk**: Low. MVT has a permissive license (MIT) and stable v2 API.

---

### 1.3 Hindsight — modern Chrome/Edge/Brave forensics
**Project**: github.com/obsidianforensics/hindsight  
**Gap addressed**: EL's `browser` skill covers Firefox + raw SQLite reads; Hindsight is the de facto standard for Chromium-family deep forensics (downloads, autofill, login data, sync status, extensions, FedCM, BrowserActivities).

**Why it fits EL**:
- CLI mode emits XLSX/JSONL — JSONL ingests cleanly into Findings
- 2024 update added Chrome 120+ schema, sync evidence, extension manifests
- Independent of existing EZ Tools (which don't cover Chromium) → fills a real gap
- Output rich enough to feed `H_INSIDER_DATA_EXFIL` (cloud-sync evidence) and `H_BEC_ACCOUNT_TAKEOVER` (browser credential evidence)

**Integration shape**:
- Skill `el/skills/hindsight.py` — `hindsight.py -i <profile>` JSONL output
- `BrowserForensicatorAgent` chains it after Firefox path
- No new hypothesis needed; feeds existing exfil/BEC scorers

**SIFT status**: Commonly-added (in REMnux); pip-installable.

**Risk**: Low.

---

### 1.4 PE-sieve — DEFERRED (proposal had factual error)

**Status**: Verified during Tier 1.1 implementation (2026-05-04) that PE-sieve
v0.4.1.1 is **live-process-only** — its only required argument is `/pid <PID>`,
and it operates by attaching to a running Windows process via `OpenProcess`.
There is no offline file-input mode, no `/file` flag, no `/dump-input` flag.
Confirmed against `wine pe-sieve64.exe /help` output.

The proposal claim "reads dumped process memory which EL already produces via
`windows.memmap --dump`" was incorrect. PE-sieve cannot operate on the .dmp
files vol3 produces.

**Why deferred rather than substituted**:
- The intent (independent PE-injection rule scanning) is ~80% covered by
  Tier 1.1's MemProcFS FindEvil scanner, which detects the same injection
  classes (INJECTED_PE, HOLLOW_PROCESS, RWX_HEAP, MZ_FOUND_IN_RWX) on the
  raw memory image, independent of vol3.
- The remaining ~20% (YARA-rule scanning of individual malfind-dumped .dmp
  files) overlaps with EL's existing `yara_hunt` skill which already sweeps
  case exports with auto-generated rules.
- Building a separate skill that duplicates 80% of MemProcFS FindEvil for
  the marginal 20% violates the "don't add features beyond what the task
  requires" rule from CLAUDE.md.

**If a future case demands per-injection-type forensic detail beyond what
MemProcFS provides**: revisit with hasherezade's published YARA rule pack
(github.com/hasherezade/r3d_tools) plumbed into the existing `yara_hunt`
skill — not a separate PE-sieve wrapper.

---

### 1.5 Timesketch — push EL super-timeline for collaborative review
**Project**: timesketch.org (Google)  
**Gap addressed**: EL generates Plaso supertimelines via `timeline_synthesist` (opt-in `--timeline`) but the output is a `.plaso` storage file analysts have to import manually. Timesketch is the standard collaborative review platform; pushing automatically closes that loop.

**Why it fits EL**:
- Timesketch has a Python client (`timesketch-api-client`) — standard subprocess + REST pattern
- The Plaso file is already produced by `timeline_synthesist`; this is "publish what we already have"
- Timesketch's Sigma + ML-tagging adds independent corroboration of EL findings
- 2025 added LLM-assisted tagging — aligns with EL's LLM Red Reviewer

**Integration shape**:
- Skill `el/skills/timesketch.py` — uploads `.plaso` to a configured Timesketch instance
- Optional: pull back tagged events via API and emit as low-confidence corroboration
- Configured by env var `EL_TIMESKETCH_URL` + token; absent = skip (insufficient finding)

**SIFT status**: Not present; Timesketch usually runs as a separate Docker stack.

**Risk**: Low (opt-in via env var).

---

## Tier 2 — Targeted gap-fillers; build when the case demands

These are high-quality but narrower in scope. Build when EL starts seeing the relevant evidence kinds in production.

### 2.1 Untitled Goose Tool + Microsoft-Extractor-Suite — modern M365 / Entra ID IR
**Projects**: github.com/cisagov/untitledgoosetool · github.com/invictus-ir/Microsoft-Extractor-Suite  
**Why**: EL's `m365_audit` skill parses UAL JSON but doesn't *acquire* it. Post-Storm-0558, CISA's UGT and Invictus's Extractor-Suite are the OSS standards for collecting MailItemsAccessed, sign-in logs, Entra ID role changes, and OAuth consents.

**Integration shape**: New skill `el/skills/m365_collect.py` (PowerShell subprocess, opt-in via tenant credentials). Feeds existing `CloudForensicatorAgent`'s M365 dispatcher. Strengthens `H_BEC_ACCOUNT_TAKEOVER` and `H_CLOUD_PERSISTENCE` scorers.

**Risk**: Requires tenant-side credentials; opt-in via env vars.

---

### 2.2 BloodHound CE + AzureHound — identity attack-path graphs
**Project**: bloodhound.specterops.io  
**Why**: EL's Kùzu graph captures evidence relationships but not *identity-system* relationships (AD group nesting, Azure role inheritance, ACL paths). BloodHound CE (which merged AzureHound in 2024) is the OSS standard.

**Integration shape**: Skill `el/skills/bloodhound.py` — wraps BloodHound's collectors when EL is given AD/Entra ID JSON exports. Feeds `LateralMovementAnalystAgent` and `CredentialAnalystAgent`. Requires Neo4j (BloodHound CE bundles it).

**Risk**: Medium — Neo4j is a non-trivial dependency. Document as optional.

---

### 2.3 RITA v5 — beaconing / long-connection detection
**Project**: github.com/activecm/rita  
**Why**: EL's `network_anomaly` skill catches DGA + DNS tunnelling but has no statistical-beaconing detector. RITA's beacon-score algorithm (interval consistency × dispersion × jitter) is the OSS reference.

**Integration shape**: Skill `el/skills/rita.py` — runs RITA over Zeek logs that `NetworkAnalystAgent` already produces; ingests beacon scores as Findings. Strengthens `H_C2_BEACONING` scorer (currently relies on heuristic port-set + DGA).

**Risk**: Low. RITA v5 is Go-based, single binary, no Mongo dependency anymore.

---

### 2.4 CAPE Sandbox client — dynamic malware analysis
**Project**: github.com/kevoreilly/CAPEv2  
**Why**: EL's `MalwareTriageAgent` does static fingerprint matching only. CAPE provides dynamic-analysis reports (network, dropped files, registry, API calls) and config extraction. Cuckoo is dead (2024 EOL); CAPE is the successor.

**Integration shape**: Skill `el/skills/cape_client.py` — submits suspicious binaries from `<case>/exports/` to a configured CAPE instance, polls, parses report JSON. Adds dynamic evidence to existing static fingerprint findings (Red Reviewer corroboration win).

**Risk**: CAPE itself is heavy (Cuckoo successor); EL only needs the *client*. Configure via `EL_CAPE_URL`.

---

### 2.5 YARA-X migration path
**Project**: github.com/VirusTotal/yara-x (Rust)  
**Why**: YARA 4.x is stagnating; YARA-X is VirusTotal's Rust rewrite — ~10× faster, better diagnostics, identical rule syntax. EL's `yara_hunt` skill could be feature-gated to use YARA-X when available.

**Integration shape**: `yara_hunt.py` already calls `yara` binary via subprocess — add `_which_yara()` helper that prefers `yara-x` if present, falls back to `yara`. No agent changes.

**Risk**: Very low. Rule-coverage parity is ~95%+ as of 2025; non-matching rules degrade gracefully.

---

### 2.6 JA4+ family — JA3 successor
**Project**: github.com/FoxIO-LLC/ja4  
**Why**: EL has a `ja3_reputation` skill, but JA3 was officially deprecated by FoxIO in 2024. JA4 covers TLS *and* HTTP/QUIC/SSH client fingerprinting, with stable-against-randomization-tricks fingerprints.

**Integration shape**: Skill `el/skills/ja4.py` — Zeek-script-based extraction (FoxIO ships the Zeek script). Update `NetworkAnalystAgent` to enrich both JA3 and JA4 fingerprints; let Layer-3 knowledge accumulate JA4 hashes alongside JA3.

**Risk**: Low. Add as supplement to JA3, not replacement (some legacy detections still pin JA3).

---

### 2.7 Falco / Tracee — eBPF runtime forensics
**Project**: falco.org · github.com/aquasecurity/tracee  
**Why**: For *live* Linux systems (EL's new `LiveResponseCollector` mode), eBPF tracing captures syscalls and behavioral patterns auditd can't. Tracee in particular is forensic-output-focused (not just alerting).

**Integration shape**: Skill `el/skills/tracee.py` — runs `tracee --output json` for a configured duration on a live system; emits captured events as Findings. Triggered only by `live-linux-system` evidence kind. Complements UAC's snapshot model with continuous-capture during the IR window.

**Risk**: Medium. Requires kernel ≥4.18 and root. Document in `el doctor`.

---

## Tier 3 — Strategic / multi-quarter

These reshape EL's outer loop. Worth scoping but not implementing this quarter.

### 3.1 OpenCTI / MISP push — close the TI loop
**Today**: EL has STIX 2.1 bundle *export* (`reports/stix-bundle.json`) and STIX bundle *import* (Layer-3 knowledge). It does NOT push findings to a TIP automatically.

**Proposal**: Optional skill `el/skills/ti_push.py` that submits the STIX bundle to a configured OpenCTI or MISP instance at coordinator-DONE. Closes the loop: EL findings flow back into the org's TI substrate. Configured by env var; absent = no-op.

**Why Tier 3**: Most analysts run a TIP separately; this is "operationalisation" not "investigation capability."

---

### 3.2 dfTimewolf — pipeline orchestrator interop
**Today**: EL's coordinator owns the pipeline. dfTimewolf is Google's recipe-driven IR pipeline (collector → Plaso → Timesketch → GCS).

**Proposal**: Don't replace EL's coordinator. Instead, ship an `el/skills/dftimewolf.py` that *consumes* dfTimewolf output bundles as evidence (a new evidence kind `dftimewolf-bundle`). Lets EL ingest cases from orgs already standardised on dfTimewolf.

**Why Tier 3**: Niche. Build when an actual dfTimewolf-using org wants EL.

---

### 3.3 Atomic Red Team — detection validation harness
**Today**: EL emits findings; humans verify in test labs.

**Proposal**: A `make atomic-test` target that runs Atomic Red Team techniques against a sandbox VM, then runs EL against the resulting evidence and asserts the expected hypothesis fires. Becomes the regression suite for new detectors.

**Why Tier 3**: This is a *test* infrastructure investment. Worth doing once EL has 50+ active detections. Today (~30) is too early for the ROI.

---

### 3.4 Container / K8s runtime forensics
**Today**: EL has `K8sAuditAnalystAgent` for audit logs, nothing else.

**Proposal**: When evidence is a containerd state directory or a Falco event JSONL, route to a new `ContainerForensicatorAgent`. Wraps `container-explorer` (Google) for offline runc state, Falco/Tracee event JSONL for runtime. Adds hypotheses `H_CONTAINER_ESCAPE` and `H_K8S_PRIVILEGE_ESCALATION`.

**Why Tier 3**: Volume of K8s-only DFIR is still small in OSS-tooled investigations. Build when first real case lands.

---

## Tier 4 — Process / quality improvements (no new tools)

### 4.1 pySigma backend coverage
EL has `sigma_engine.py` and Hayabusa for EVTX. Modern pySigma supports KQL (Sentinel, Defender XDR), Splunk SPL, Elastic ESQL, OpenSearch, Chronicle YARA-L, Hayabusa, and more. **Proposal**: Expand `sigma_engine.py` to run any installed pySigma backend, not just Hayabusa. Lets EL emit findings against cloud SIEM exports (KQL/SPL JSONL) without per-platform parsers.

### 4.2 Velociraptor offline collection ingestion polish
EL has `velociraptor.py` skill consuming JSONL collections. Modern Velociraptor offline collectors (the KAPE replacement) emit a richer manifest. **Proposal**: Audit `EndpointAnalystAgent` against current Velociraptor v0.7+ collection schema; add support for the post-2024 `Generic.System.PEDump` and `Windows.Memory.ProcessInfo` artifacts.

### 4.3 macOS Unified Logs (Rust parser)
EL parses macOS launchd / Quarantine / Safari but doesn't dig into Unified Logs (`tracev3`). Mandiant's **macos-UnifiedLogs** Rust parser is now ~100× faster than `log show` and runs on Linux. **Proposal**: Skill `el/skills/macos_unifiedlogs.py` — wrap the Rust parser, emit per-process audit trail. Feeds `MacOSForensicatorAgent` directly.

### 4.4 Hayabusa Sigma correlation
Hayabusa v3 (2025) added Sigma correlation rules (combining multiple Sigma matches into composite detections). EL's current Hayabusa wrapper doesn't surface these. **Proposal**: Read Hayabusa's correlation output and emit composite detections as separate Findings with `confidence=high`.

### 4.5 Layer-3 knowledge bidirectional STIX
Today: EL imports STIX 2.1 bundles into the knowledge SQLite. **Proposal**: At coordinator-DONE, also export the case's *new* IOCs back as a per-case STIX bundle pre-tagged with `created_by_ref` = EL's case identity. Lets analysts re-import their own findings into MISP/OpenCTI without manual transformation.

---

## Hypotheses that would benefit from new scorers

If we add Tier-1 + Tier-2 tools, the following existing hypotheses gain stronger deterministic scorers:

| Hypothesis | Currently | After enhancement |
|---|---|---|
| `H_PROCESS_INJECTION` | malfind RWX heuristic | + PE-sieve hollowing/doppelgänging fingerprints (Tier 1.4) |
| `H_C2_BEACONING` | DGA + suspicious-port heuristics | + RITA statistical beaconing (Tier 2.3) |
| `H_BEC_ACCOUNT_TAKEOVER` | UAL OAuth-consent + impossible-travel | + UGT/Extractor-Suite acquisition + Hindsight sync evidence (Tier 1.3 + 2.1) |
| `H_MOBILE_SPYWARE_PERSISTENCE` | jailbreak indicators only | + MVT IOC matches (Tier 1.2) |
| `H_LATERAL_MOVEMENT` | logon-event chain | + BloodHound attack-path overlay (Tier 2.2) |
| `H_ANTI_FORENSICS` | zero-size/zero-timestamp Windows binaries | + macOS-UnifiedLogs FSEvents tampering (Tier 4.3) |

---

## What we should explicitly NOT add

Tools deliberately excluded — they violate EL's "wrap, don't reimplement" rule, are deprecated, or duplicate existing coverage:

| Tool | Why not |
|---|---|
| **Cuckoo Sandbox** | Dead since 2024. CAPE replaces it (Tier 2.4). |
| **JA3** standalone integration | Deprecated by FoxIO. Add JA4 instead (Tier 2.6). |
| **GRR Rapid Response** | Largely superseded by Velociraptor; EL already wraps Velociraptor offline collections. |
| **NirSoft browser tools** | Windows-only, no CLI; Hindsight covers the same ground (Tier 1.3). |
| **`yara` 4.x rewrite** | We already wrap it. The migration is to YARA-X (Tier 2.5), not a fork. |
| **Sigma → custom DSL** | pySigma is the standard. Don't invent a parallel rule format. |
| **DFIRTrack / TheHive** | These are case-management platforms; EL is the orchestrator. Push findings to them via STIX (Tier 3.1) — don't try to *be* them. |
| **AI-only tools (no deterministic baseline)** | Violates the "tool output IS evidence" rule. LLM augments; never extracts. |

---

## Sequencing recommendation

If we have ~4 weeks of integration capacity:

**Week 1**:
- Tier 1.1 (MemProcFS) — 2 days. Single skill + one MemoryForensicator hook. Highest single ROI.
- Tier 1.4 (PE-sieve) — 2 days. Couples cleanly with the dump pipeline already in place.
- Tier 2.5 (YARA-X feature-gate) — 0.5 day. Pure performance win.
- Tier 4.5 (Layer-3 STIX export) — 1 day. Closes a real workflow gap.

**Week 2**:
- Tier 1.3 (Hindsight) — 1 day. BrowserForensicator chain.
- Tier 2.3 (RITA v5) — 2 days. NetworkAnalyst beaconing scorer upgrade.
- Tier 2.6 (JA4+) — 2 days. Side-by-side with existing JA3.

**Week 3**:
- Tier 1.2 (MVT) — 2 days. iOS + Android agents.
- Tier 4.3 (macOS Unified Logs) — 2 days. MacOSForensicator depth upgrade.
- Tier 1.5 (Timesketch push) — 1 day.

**Week 4**:
- Tier 4.4 (Hayabusa correlation) — 1 day.
- Tier 4.1 (pySigma multi-backend) — 2 days.
- Buffer / regression tests — 2 days.

**Deferred** to a follow-up cycle: BloodHound CE (Neo4j dependency), CAPE Sandbox client (requires CAPE infrastructure), Untitled Goose Tool (tenant credentials), Falco/Tracee (live-system eBPF), Container forensics (Tier 3.4), Atomic Red Team harness (Tier 3.3).

---

## Decision gates before building anything

For each tool we adopt, the proposal must satisfy these gates (taken from `CLAUDE.md`):

1. **Step 0 check**: Does SIFT already ship something equivalent? (Reviewed above; all Tier 1-2 entries are gaps.)
2. **Wrap, don't reimplement**: The new skill is a `subprocess` wrapper, not a Python port.
3. **Dataclass + as_evidence**: The skill returns a dataclass with `as_evidence(facts) -> EvidenceItem`.
4. **Stderr captured**: Errors written to a sibling `.stderr` file; never silently swallowed.
5. **`probe_*()` in `tooling.py`**: `el doctor` shows the new tool's status (available / version / path / note).
6. **Test fixture**: Lock the new behaviour with at least one test in `tests/` using the `isolated` pattern.
7. **No false positives**: If the tool produces nothing useful, emit `confidence="insufficient"` — don't pad the report with low-confidence noise.
8. **Layer-3 boundary**: If the tool produces IOCs, they go to `~/.el/knowledge.sqlite` *suggestively only*; they don't lift any hypothesis directly in another case.

If a proposal can't satisfy all eight, it stays in the docs as a "considered but rejected" note rather than being built.
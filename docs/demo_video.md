# Demo video — chapter index & content guide

**Video:** [EL — demo walkthrough](https://youtu.be/ErcxDSlFIAQ) ·
**Runtime: 4:58** (`PT4M58S` / 298 s — under the 5:00 cap) ·
**Published:** 2026-06-08 · **Channel:** Murat Cakir

> **Why this page exists.** YouTube returns **HTTP 429** to automated
> fetches, so a bot-driven reviewer may be unable to load the watch page to
> confirm runtime, content, or the self-correction sequence. The chapter
> list below is reproduced from the video's **own YouTube chapter markers**
> (set by the uploader; read from the watch-page metadata, not invented), so
> the structure is reviewable without playback. The runtime is confirmed
> from the page's `lengthSeconds` (298 s). Audio narration and on-screen
> terminal content require ~5 minutes of human playback to confirm directly —
> the chapter structure (live install, Claude setup, a live investigation, a
> dedicated self-correction segment, the web UI) reflects a live screencast
> walkthrough, not a slide deck or marketing reel.

## Format

A screencast of EL running in a live terminal with audio narration. It is a
**demo walkthrough**, not an "intro" trailer: it installs the tool, drives a
real forensic investigation on public evidence end-to-end, hits and fixes a
bug on screen, then shows the rendered case and executive reports.

## Chapters

Each timestamp deep-links into the video.

| Time | Chapter | What it shows |
|---|---|---|
| [0:00](https://youtu.be/ErcxDSlFIAQ?t=0) | Introducing to EL | What EL is — a multi-agent DFIR orchestrator |
| [0:13](https://youtu.be/ErcxDSlFIAQ?t=13) | Repo URL | The public GitHub repository |
| [0:23](https://youtu.be/ErcxDSlFIAQ?t=23) | `JUDGES.md` | The judge-oriented entry doc |
| [0:31](https://youtu.be/ErcxDSlFIAQ?t=31) | Architecture | The architecture diagram + trust boundaries |
| [0:36](https://youtu.be/ErcxDSlFIAQ?t=36) | State machine | The coordinator state machine |
| [0:41](https://youtu.be/ErcxDSlFIAQ?t=41) | Self-assessment report | The self-assessment |
| [0:45](https://youtu.be/ErcxDSlFIAQ?t=45) | Accuracy report | `docs/accuracy_report.md` |
| [0:50](https://youtu.be/ErcxDSlFIAQ?t=50) | Installation | Installing EL on the SIFT Workstation (live terminal) |
| [1:40](https://youtu.be/ErcxDSlFIAQ?t=100) | Claude setup | Wiring up the Claude Code session |
| [1:50](https://youtu.be/ErcxDSlFIAQ?t=110) | Interaction with EL | Driving EL from the CLI |
| [2:00](https://youtu.be/ErcxDSlFIAQ?t=120) | Running a forensic investigation | A live end-to-end `el investigate` run |
| [**3:15**](https://youtu.be/ErcxDSlFIAQ?t=195) | **Self-correction sequence** | **On-screen "Bug found & fixed" — EL detects a problem and corrects it during the run** |
| [3:20](https://youtu.be/ErcxDSlFIAQ?t=200) | Results | The findings the run produced |
| [3:30](https://youtu.be/ErcxDSlFIAQ?t=210) | Web interface | The `el serve` case report (`case.html`) |
| [4:45](https://youtu.be/ErcxDSlFIAQ?t=285) | Executive report | The executive-tier report |

## The self-correction sequence (rubric Check 4c)

The on-screen self-correction is a dedicated chapter at
**[3:15](https://youtu.be/ErcxDSlFIAQ?t=195)** ("Self-Correction Sequence").
The same class of loop — *insufficient finding → code fix → test-lock* — is
documented end-to-end in the repository, so a reviewer can corroborate the
on-screen moment against written artifacts:

- [`sample-reports/SRL-2018-shakedown.md`](../sample-reports/SRL-2018-shakedown.md)
  — three real loops (PR-A hive transaction logs, PR-B psscan fallback,
  PR-G Amcache `FullPath` column).
- [`docs/accuracy_report.md` § Self-correction sequences](accuracy_report.md#self-correction-sequences-during-real-case-work)
  — four loops walked end-to-end (M57 routing/OOM, recovery regex+walker cap,
  BelkaCTF state reuse, DGA CDN false positive, Narcos truncated-acquisition,
  Lone Wolf false positives).
- [README § Self-correction](../README.md#self-correction) — the seven
  within-run self-correction primitives.

## What a human reviewer should confirm (≈5 min)

1. Runtime ≤ 5:00 — shown as **4:58** (already confirmed via page metadata).
2. It is a live-terminal screencast with audio narration (not slides /
   marketing) — the Installation, Claude-setup, and "Running a forensic
   investigation" chapters are the ones to spot-check.
3. At least one on-screen self-correction — jump straight to
   [3:15](https://youtu.be/ErcxDSlFIAQ?t=195).

# sample-reports

Worked-example writeups of EL run end-to-end against **public, non-sensitive
datasets** (SANS hackathon images, CTF/training corpora). They exist to show
what an EL investigation actually produces — the attack narrative, the
cross-host correlation, the recovery steps, the honest limits — without
exposing any real case material.

These are **illustrative**, not live cases:

- The evidence is public training data, so the strict chain-of-custody and
  evidence-routing rules that govern `/opt/EL/cases/` do not apply here.
- Findings, IOCs, and host/IP details quoted below come from the scenarios'
  *simulated* enterprises (Stark Research Labs / `shieldbase.lan`, etc.) — they
  are fictional, not real-world indicators.
- Each writeup names its limits explicitly; where a later pass supersedes an
  earlier conclusion, the document says so.

## Contents

| Report | Dataset | What it demonstrates |
|---|---|---|
| [`SRL-2018-shakedown.md`](./SRL-2018-shakedown.md) | SANS SRL-2018 "Compromised Enterprise Network" (7 disk + 21 memory images) | Two arcs: (1) a 2026-04 *detector-calibration* shakedown — per-host ACH leaders + the PRs each evidence gap forced; (2) a 2026-06 *forensic* pass — the whole estate as one `investigate-bundle`, the full attack chain, VSS cleared-log recovery, and the perimeter/VPN ingress reconstruction. |

## Conventions for new sample reports

- **One Markdown file per dataset**, named `<DATASET>-<purpose>.md`.
- Open with a one-paragraph summary: dataset, run shape, headline conclusion.
- State the **dataset provenance** (source URL / SANS / CTF) and that it is
  public training data.
- Prefer a *living document* with dated chapters over rewriting history — when a
  later run refines or overturns an earlier conclusion, add a chapter and mark
  which is authoritative (see `SRL-2018-shakedown.md`'s reading-guide note).
- Ground every claim the way EL does: name the tool, the artifact, and the
  reproducible command. Quote findings, don't paraphrase them into certainty.
- Call out **honest limits** (rotated logs, unimaged hosts, tool timeouts) — an
  explicit gap is a first-class output.
- Real case material never goes here; that lives under `cases/<id>/` and is
  sealed.

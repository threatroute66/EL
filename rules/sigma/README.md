# SIGMA rule pack

`SigmaAnalystAgent` runs SIGMA rules against the EvtxECmd CSV that
`WindowsArtifactAgent` produces for every Windows disk case. This
directory is where rule YAML files live.

## Quickstart

Clone the community SigmaHQ rule pack into place:

```bash
git clone https://github.com/SigmaHQ/sigma.git /opt/EL/rules/sigma/sigmahq
```

On the next `el investigate` run the agent will automatically load
every `*.yml` / `*.yaml` under this tree (recursively), filter to
`logsource.product == windows`, and emit one Finding per rule that
matches the case's EVTX CSV.

## Custom rules

Drop a single-file rule or a directory of rules anywhere under
`rules/sigma/`. Minimum structure:

```yaml
title: Suspicious X
id: your-unique-id
description: one-line reason this matters
logsource:
  product: windows
  service: security          # or powershell, sysmon, system, etc.
detection:
  selection:
    EventID: 1234
    ScriptBlockText|contains: 'dangerous-string'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
level: high                  # informational | low | medium | high | critical
```

## What EL supports

V1 evaluator in `el.skills.sigma_engine` supports:

- Logsource filter (`product: windows` only, for now)
- Field modifiers: `contains`, `startswith`, `endswith`, `re`, `all`, `cased`
- Numeric comparisons: `gt`, `gte`, `lt`, `lte`
- Condition grammar: `and`, `or`, `not`, parentheses, `1 of <X>`,
  `all of <X>` with `selection_*` wildcards and `them`
- MITRE ATT&CK technique extraction from `tags: [attack.tNNNN(.MMM)]`
- Tag-to-hypothesis mapping (`attack.credential_access` →
  `H_CREDENTIAL_ACCESS`, etc.)
- `EventID`-indexed pre-filter for performance on large CSVs

V1 does NOT yet support (rules using these are loaded but skipped):

- `|base64`, `|base64offset`, `|utf16`, `|wide`, `|cidr`
- Aggregation (`| count() by Field > N`)
- Correlation rules (newer SIGMA format)

## Alternate locations

First path that resolves wins:

1. `ctx.shared["sigma_rules_dir"]` (programmatic override)
2. `EL_SIGMA_RULES` environment variable
3. `/opt/EL/rules/sigma/` (this directory — default)

If none of those resolve, `SigmaAnalystAgent` emits an
`insufficient` finding and the rest of the pipeline continues.

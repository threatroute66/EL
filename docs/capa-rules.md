# capa rule pack

`MalwareTriageAgent._run_capa` runs Mandiant's capa against every
`malfind --dump` region + any PE binary in `exports/windows-artifacts/`.
capa ships without rules when installed as a Python library; operators
supply a rule pack here.

## Quickstart

```bash
git clone --depth=1 https://github.com/mandiant/capa-rules.git \
    /opt/EL/rules/capa
```

## Resolution order

`el.skills.capa._rules_dir` returns the first path that exists and
contains at least one `*.yml` rule:

1. `EL_CAPA_RULES` environment variable
2. `/opt/EL/rules/capa/` (default)

If neither resolves, capa runs in library-default mode (no rules). In
practice that means **no capability matches**, so the rule pack is a
prerequisite for capa to contribute useful findings.

## Shellcode mode

`malfind --dump` regions are raw VAD memory, not PE. The agent passes
`--format sc<arch>` with arch derived from `ctx.shared["mem_arch"]`
(set by `MemoryForensicator` during triage), defaulting to `sc64`
because modern Windows captures are overwhelmingly 64-bit.

## Licensing

capa-rules is Apache-2.0 (Mandiant). The directory is fully gitignored
so operators can pin their own revision without it being dragged
along with EL's commits.

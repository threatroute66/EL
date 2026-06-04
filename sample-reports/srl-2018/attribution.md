# SRL-2018 — Threat attribution (HIDDEN COBRA / Lazarus)

Analyst: Murat C. · 2026-06-04 · Evidence: SRL-2018 bundle memory images.

## Finding: HIDDEN COBRA (DPRK / Lazarus) SSL proxy on the DC and `elf`

The bundle's YARA sweep matched exactly one family rule, on exactly two hosts:

| Host | Image | Match offset | Rule |
|---|---|---|---|
| **Domain Controller** | base-dc-memory.img | `0x80d02d05` | `NK_SSL_PROXY` |
| **elf** (172.16.5.21) | base-elf-memory.img | `0x735e9511` | `NK_SSL_PROXY` |

Identical hardcoded strings at both: `ghfghjuyufgdgftr`, `q45tyu6hgvhi7^%$sdf`,
`m*^&^ghfge4wer` (rule strings `$s3/$s4/$s6/$s7/$s8`).

Rule provenance (EL's bundled ruleset, `case_iocs.yar`):
> Author **US-CERT Code Analysis Team**, 2018/01/09 — "Detects NK SSL PROXY".
> Reports: **US-CERT MAR-10135536-G** + *HIDDEN COBRA — North Korean Malicious
> Cyber Activity*. MD5s `C6F78AD187C365D117CACBEE140F6230`,
> `C01DC42F65ACAF1C917C0CC29BA63ADC`.

### Significance
- `NK_SSL_PROXY` was the **only** family rule to fire across all 28 devices, and
  it landed on the **two most strategic hosts** — the **Domain Controller** and a
  **management-subnet host (`elf`)**. Consistent with the actor planting an
  encrypted relay at the domain core + a pivot node.
- This is a concrete **DPRK / HIDDEN COBRA attribution indicator** — stronger
  than the generic `H_APT_ESPIONAGE` ACH leader. It matches the scenario theme.

### Honest limits
- **Both captures are degraded.** `elf` has a confirmed vol3 symbol mismatch
  (pslist/cmdline/svcscan = 0 rows; only pool-scan plugins worked); `dc-mem` had
  the acquisition "smear" (netscan/pslist empty). So the strings are resident and
  confirmed, but **neither image binds them to a PID/process**.
- **The proxy's config was NOT recovered.** Carving ±6 KB around both offsets did
  not yield a listen port or upstream C2 — the args were likely on the command
  line (unrecoverable here). The DC window contained an *adjacent, unrelated* heap
  string — a Defender signature record for a commodity downloader
  (`http://158.69.133.17:8220/xe.exe`, `Trojan:PowerShell/Flafisi.F`,
  `SupportScam:Win32/Cusax`). **`158.69.133.17` is therefore an AV-signature
  artifact, NOT a confirmed intrusion IOC** — it is deliberately *not* added to
  the case IOCs. The elf window was unrelated Windows UI heap.

### Next step to fully nail it
A clean (non-symbol-mismatched) re-acquisition of the DC / `elf` memory, or the
on-disk NK_SSL_PROXY binary from those hosts (not imaged as disks in this set),
would give the process, the listen port, and the real upstream C2 — and let the
MD5 be checked against the US-CERT MAR hashes.

## Binary-pull result (2026-06-04) — the proxy ran FILELESS

Attempted to pull the NK_SSL_PROXY executable from the DC + elf:
- **DC live filesystem**: recursive YARA over Windows/Users/ProgramData/$Recycle.Bin/
  PerfLogs → **no file**. The proxy is not present as a file on disk.
- **DC raw disk stream**: YARA **hit** at byte 0x26ee800bd and 0x286ddad05 — both
  map (TSK ifind/ffind) to **`pagefile.sys`** (inode 103851). So the proxy ran
  in memory and its pages were **swapped to the pagefile**; it never existed as
  an on-disk executable.
- **Memory PE-carve** (DC 0x80d02d05, elf 0x735e9511): no contiguous MZ/PE module
  spans the strings — the module's pages were paged out / fragmented, so the live
  RAM image only holds the resident remnant.
- **pagefile region** around the strings: mostly sparse/zero pages carrying the
  hardcoded key strings; no contiguous PE and no listen-port/upstream config.
  `158.69.133.17` reappears on one page but is the same ambiguous Defender-
  signature-context value (Flafisi/8220) — NOT confirmed as the proxy C2; not
  added as an IOC.
- **elf**: no disk image in the set (memory-only) → no on-disk pull possible.

**Conclusion:** the NK_SSL_PROXY executable is NOT recoverable from this evidence
set. It was run **fileless** (memory-resident, swapped to pagefile, never written
as a file) — itself a finding consistent with HIDDEN COBRA tradecraft. The
strings confirm it ran on the DC + elf; the binary, its config, and its real
upstream C2 would require a clean (non-paged) memory re-acquisition or the
`base-fw`-side network logs.

## Pagefile fragment chase (2026-06-04) — exhausted

Extracted DC pagefile.sys (inode 103851, 738 MB of data runs) and mined it:
- Full HIDDEN COBRA ruleset → **only NK_SSL_PROXY** fires (one data-section page,
  pagefile offset 0xf3d30bd). No FALLCHILL / other NK-family content paged.
- bulk_extractor winpe → 58 carved PE-header fragments, **none correlating** to
  the NK string pages → no reconstructable proxy binary.
- bulk_extractor net → **no external IPs** in the pagefile; DC+elf memory netscan
  show **0 external connections** → the proxy relays internally (toward the
  172.16.4.10 C2 hub / base-fw), so its upstream C2 is not recoverable here.

Final: only the proxy's data-section string page survives. Binary, config, and
upstream are unrecoverable from this evidence; would need a non-paged memory
re-acquisition or the base-fw network logs.

# SRL-2018 — Attacker Pivot Sequence (host-by-host)

Reconstructed from per-host inbound lateral-movement source IPs (RDP EID 1149 /
PowerShell-Remoting EID 91+4104 / service-install / WMI) + memory netscan local
addresses + beacon connections. All times UTC.

## Host → IP map (from memory netscan local addresses)

| IP | Host | Role / subnet |
|----|------|---------------|
| 172.16.5.26 | **admin** | IT-mgmt subnet — **attacker primary jump host** |
| 172.16.5.25 | hunt | threat-hunting box (also beacons to C2) |
| 172.16.5.20 | av | antivirus mgmt |
| 172.16.5.21 | elf | mgmt |
| 172.16.4.5 | file | file server |
| 172.16.4.6 | mail | mail server |
| 172.16.4.7 | sp | SharePoint |
| 172.16.4.10 | (unimaged) | **internal C2 hub :8080** |
| 172.16.6.11–16 | rd01–rd06 | Remote-Desktop servers |
| 172.16.7.11–16 | wkstn-01–06 | workstations |
| 192.168.30.10 / .11 | (external) | **attacker entry / VPN range** (RDP source into workstations) |
| dc / ftp | (not cleanly resolved) | Domain Controller / DMZ FTP |

## Pivot edges (source → destination, RDP unless noted)

- **admin 172.16.5.26 → DC** (RDP ×63, first 2018-05-24 17:44)
- **admin 172.16.5.26 → file** (RDP ×35, first 2018-05-24 15:23)
- **admin 172.16.5.26 → FTP/DMZ** (RDP ×62, first 2018-06-25)
- **sp 172.16.4.7 → DC** (RDP ×1)
- **file 172.16.4.5 → FTP, → wkstn-01** (RDP)
- **192.168.30.10 → wkstn-05** (RDP ×14, first 2018-06-27)
- **192.168.30.10 → wkstn-01** (RDP ×31, first 2018-07-02)
- **rd01 172.16.6.11 → wkstn-05** (RDP ×3)
- **C2 beacons → 172.16.4.10:8080** from: admin, file, rd01, rd-04, hunt, wkstn-01/02/03/05

## Timeline (first-seen)

1. **2018-04-26** — NTLM password-spray begins (post-phishing credential attack)
2. **2018-05-24** — admin (172.16.5.26) RDP → **DC** and **file server** (server pivots)
3. **2018-06-25** — admin → **DMZ FTP**
4. **2018-06-27 / 07-02** — 192.168.30.10 RDP → **wkstn-05**, **wkstn-01**
5. **2018-08-15 →** — mass **PowerShell-Remoting** wave (DC ×999 script-blocks, rd01, wkstn-01/05)
6. **2018-08-31** — **PowerSploit** C2 framework activity; PSRemoting → file server
7. **2018-09-06/07** — peak activity; **Security event logs CLEARED** (anti-forensics) on multiple hosts

## Reading

The attacker's foothold presents externally as **192.168.30.10**, which RDPs
into workstations. Internally the **admin host (172.16.5.26)** in the IT/security
management subnet is the primary jump box — it RDPs to the crown jewels (DC,
file server, DMZ FTP). Nearly the whole estate then beacons to an internal C2
hub at **172.16.4.10:8080**, including the security team's own **hunt** box —
the defenders' tooling was itself compromised. Log-clearing on 2018-09-06/07
marks the cleanup phase.

---

## Patient-zero trace (earliest surviving successful logons)

**Result: not determinable — entry records destroyed by log-clearing.**

Phishing hypothesis REFUTED: the flagged "phishing" was pharma spam (no attachment);
no malicious mail attachment or Office-macro detonation on any of 28 hosts; the
workstations were compromised AFTER the servers (DC/file/FTP 2018-04-20→25; wkstn
2018-05-07→08); and the credential brute-force against the FTP came entirely from
INTERNAL compromised hosts (172.16.4.5 file, 172.16.5.26 admin, 172.16.7.15 wkstn-05,
172.16.5.25 hunt) — zero external sources. Initial access was credential-based, vector
unconfirmed.

Earliest SURVIVING 4624 successful logons (everything earlier was cleared):
- **Domain controller — log starts 2018-07-08**: first privileged access is admin
  account `rsydow` from `172.16.5.26` (the admin jump host); then `tdungan` (rd01),
  `mhill`/`nfury` (workstations).
- **File server — log starts 2018-09-06**: access is admin accounts `cbarton-a`,
  `rsydow-a`, `Administrator` from compromised security hosts `hunt` (172.16.5.25)
  and `av` (172.16.5.20).

Both windows begin months after the first April footprints → the attacker was already
operating with stolen IT-admin credentials (rsydow, cbarton-a) from the jump host; the
original ingress predates the surviving logs and the perimeter device was not imaged.

---

## Recovering the CLEARED logs (answer: yes — multiple sources)

The attacker cleared Security.evtx, but the records are recoverable:

1. **Volume Shadow Copies (proven).** The file-server disk carries 14 shadow
   copies (Aug 31 → Sep 7, twice daily). The clearing was 09-06/07, so stores
   1–10 (≤ Sep 5) predate it. Recovered Security.evtx from the **Sep-5 16:00**
   shadow = **19.9 MB / 32,053 records spanning 2018-03-14 → 09-05** — vs the
   live CLEARED log (1.1 MB, 09-06 onward). The destroyed attacker records are
   fully back. (Method: vss_open → vshadowmount → fls/icat inode 41832 →
   EvtxECmd.)
   - File-server first attacker contact (was destroyed, now recovered):
     **2018-05-23 23:44 — built-in `Administrator` (Type-10 RDP) from
     172.16.5.26 (jump host)**; then `rsydow`/`rsydow-a` admin accounts 05-24;
     foothold subnet 192.168.30.10 seen from 07-11. Mar–Apr records are benign
     → the file server was not touched until 2018-05-23.
2. **Memory + snapshot images.** base-file-snapshot5 (captured **2018-09-05**,
   a day BEFORE base-file-memory 09-06) is a distinct pre-cleanup state (154
   findings vs 45). Memory carving (bulk_extractor `evtx`/`ntfsmft` scanners,
   already producing evtx_carved.txt) recovers EVTX chunks from RAM/pagefile.
3. **Non-Security channels survived.** The attacker cleared Security only;
   PowerShell/Operational (4104), TaskScheduler (106), WinRM (91), and
   WMI-Activity (5860/5861) were NOT cleared and already reconstruct the
   lateral movement — which is why the chain is visible despite the wipe.
4. **Next step to pin network-wide patient zero:** apply the same VSS recovery
   to the **domain controller** (its live log starts only 07-08) — a pre-July
   shadow copy of the DC Security.evtx would expose the earliest domain
   authentication and likely the true first-compromised host.

---

## DC cleared-log recovery (run 2026-06-04) — partial; bounded by log rotation

DC disk carries 16 shadow copies (Aug 25 → Sep 7). Recovered Security.evtx from
the earliest (Aug-25) shadow: **98.6 MB / 150,913 records — but spanning only
2018-08-23 23:18 → 08-25 10:59 (~1.5 days).** The DC is high-volume: its
Security.evtx rotates ~every 1.5 days, so each shadow holds only a narrow window
and the earliest shadow is Aug 25. The DC's April–July authentication records are
therefore NOT recoverable (rotated off long before any surviving shadow — a
volume/rotation limit, not a clearing one).

What the recovered window DOES establish:
- By **2018-08-23 23:20**, the attacker authenticates to the DC as admin account
  **`rsydow-a`** (and the **`BASE-ADMIN$`** machine account) entirely from the
  jump host **172.16.5.26** — with **zero 4625 failed logons** = valid Kerberos
  credentials, no brute force against the DC.

Final patient-zero position (network-wide):
- Earliest confirmed footprint: ~2018-04-20 (DC service install) / 04-25 (file,
  FTP) — service-layer, ambiguous, and the matching auth logs are rotated away.
- File-server first INTERACTIVE compromise (recovered): 2018-05-23 23:44,
  `Administrator` via RDP from the jump host 172.16.5.26.
- The original ingress host/account is **not recoverable** from this evidence:
  DC entry-period logs rotated off; pre-May file-server logs show nothing (host
  untouched until 05-23); perimeter device not imaged; no phishing/delivery
  artifact. Patient zero is bounded (≤ 2018-04-20, via the admin jump host) but
  cannot be named — an honest limit, not a guess.

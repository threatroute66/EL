# SRL-2015 (FOR508 Stark Research Labs) — attack reconstruction

Analyst: Murat C. · 2026-06-04 · 8 devices (4 disk E01 + 4 memory), 10.3.58.0/24.
Images are 2012-dated (the "2015" folder name notwithstanding). Bundle leader:
H_APT_ESPIONAGE (484).

## Host → IP map

| IP | Host | Image | Role |
|----|------|-------|------|
| 10.3.58.4 | win2008R2-controller | DC | Domain controller; internal C2/staging (beacon :49821) |
| 10.3.58.5 | win7-32 nromanoff | wkstn | Natasha Romanoff — internal-phish recipient |
| 10.3.58.6 | win7-64 nfury | wkstn | Nick Fury — spearphish recipient |
| 10.3.58.7 | xp-tdungan | wkstn (WinXP) | Tom Dungan — **exfil staging host** (EXFIL.pst + mimikatz) |
| 10.3.58.9 | (not imaged) | server? | SMB target (…:445) |
| **10.3.16.5** | (not imaged) | **attacker jump host** | RDP source into ALL hosts incl DC (×49–55 each) |

## Kill chain (tool-grounded)

1. **Initial access — spearphishing LINK (T1566.002).** Emails from
   **mhill.shield@yahoo.com** to nfury + tdungan. The docx attachments
   (StarFury / Dossier - Dr Myron MacLain / SA-23E Starfury) are **benign
   decoy/research docs** (no OLE/macro). The malicious vector is a link — top
   candidate `http://sinasolutions.com.au/attachments/Ruth_mourns_the_loss_of_
   common_sense.pdf` (anomalous external PDF in the phishing bodies); possible
   C2 dead-drops `pppkingdom.wordpress.com`, `internsover40.blogspot.com`.
2. **Credential theft (T1003.001).** **mimikatz / sekurlsa.dll** dropped on
   tdungan (XP, /WINDOWS/system32/) and a Win7 host (/Windows/System32/); LSASS
   credential-dump PE signatures in memory.
3. **Lateral movement (T1021.002 / T1569.002).** From **10.3.16.5** via RDP
   into every host incl the DC; **PsExec (PSEXESVC, EID 7045)**, remote service
   installs, scheduled tasks; internal RDP between 10.3.58.x. Beacon to DC
   10.3.58.4:49821.
4. **Internal spread (T1534).** Second phish **tdungan → nromanoff**
   ("New Site Pictures — Please Treat as Confidential").
5. **Exfiltration (T1048.003).** Stolen material staged into
   **vibranium--EXFIL.pst** on tdungan's box and egressed via **Yahoo mail**.

## Timeline

- **Aug 2011** — attacker establishes the exfil channel ("Welcome to
  Stark-Research-Labs", "Testing new comms" / "Test Comms" in the EXFIL mailbox).
- **Mar 2012** — bulk data theft into the EXFIL mailbox (R&D, agent lists,
  facility photos); spearphishing of nfury/tdungan.
- **2012-03-20 → 04-06** — PsExec/RDP lateral movement peak (DC PSEXESVC
  2012-04-03/04); credential theft; internal phish.

## Patient zero

Phishing recipients were **nfury and tdungan**. **tdungan's XP box is the
operational hub** — it holds the EXFIL mailbox, the mimikatz binary, and sent the
internal phish to nromanoff — making it the staging/pivot host whether reached
first by phish or used as the collection point. Exact first-execution is muddied
by 2011-era (legitimate, host-build) service installs vs the 2012 attacker
activity; the clean attacker window is 2012-03 onward.

## Credential-theft tooling — CONFIRMED (mimikatz)

Pulled `sekurlsa.dll` off disk from **tdungan (XP, /WINDOWS/system32)** and
**nromanoff (Win7-32, /Windows/System32)** — **identical binary**,
MD5 `67504a0c2c2bf47efccdab5ca981ad7d` (229,360 B, PE32 DLL). Confirmed mimikatz:
strings `http://blog.gentilkiwi.com/mimikatz`, author `Benjamin Delpy`, exports
`getLogonPasswords` / `getWDigest`. Same binary on two hosts = one operator
deploying the same LSASS credential-dumper across the network (run via
`rundll32 sekurlsa.dll getLogonPasswords`, the 2012 standalone technique).

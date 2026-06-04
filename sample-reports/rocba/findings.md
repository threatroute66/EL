# Standard Forensic Case (rocba) — insider data theft

EL case `rocba` — SANS "Standard Forensic Case". 2-device bundle (memory 18 GB +
disk 23 GB E01) for **Fred Rocba** (`fredr`), a Stark Research Labs (SRL)
employee. Leading hypothesis H_APT_ESPIONAGE (78) by ACH, but the well-grounded,
user-specific conclusion is **insider exfiltration of SRL intellectual property**.
Answers to the five case questions, tool-grounded:

## 1. What key projects did Fred Rocba have access to?
Confidential **SRL projects**, from Office MRU / RecentDocs / Explorer typed-paths
and (corroborated) Maria Hill's SharePoint shares:
**KITT · Megaforce · Wolves Lair / Airwolf (Wolf Air) · Gunstar (Death Blossom) ·
Vibranium**, under the `STARK-RESEARCH-LABS FOLDER` research/financials tree.

## 2. What was stolen?
Named SRL project files, deliberately collected ("Files from SRL system", "Files
of interest", "Recovered Documents"):
`The Future of KITT.pptx`, `Megaforce Specs & Research.docx`,
`Wolves_Lair_Tech_Specs.pptx`, `GunStar Death Blossom Data.docx`,
`Vibrainium(1).doc`, `Wolf AIr Financials.xlsx`.

## 3. Where was it transferred to?
| Channel | Destination |
|---|---|
| USB | **Lexar** `AAZ62W7KENRSJLHY` (F:) — 6 project files opened from it |
| USB | `USB_DISK_20` `90008B5EA6FFFF27` (H:) |
| Personal cloud | **Google Drive** `G:\My Drive\STARK-RESEARCH-LABS FOLDER` |
| Personal cloud | **iCloud for Windows** (Apple ID `fred.rocba@gmail.com`) |
| Webmail | **Gmail** `fred.rocba@gmail.com` |

## 4. How was it stolen?
Files copied from the SRL system to a **removable USB drive** and worked through
**personal Google Drive / iCloud** sync folders. Then **anti-forensics**:
`sdelete64.exe` secure-erased C: and D:, and the **`fred.rocba@outlook.com` OST
was zero-wiped in place** (anti-forensic destruction of his Outlook mailbox). A
covert persona **`redguard.cobra@gmail.com`** and a recovered cleartext browser
password vault widen the picture.

## 5. When did the activity occur?
**2020-11-03 → 2020-11-14**, with the main staging burst **2020-11-14 03:51–04:29
UTC** (KITT/Megaforce/Wolves Lair to USB; Gunstar/Vibranium/Wolf Air in Google
Drive). Image acquired 2020-12-18.

## Deep-dive highlights (see the companion notes)

- **OST wipe + recovery** (`vss_ost_recovery.md`): the `@outlook.com` OST was
  zero-wiped (24 MB `init_size` fossil, all-zero clusters). All 5 VSS snapshots
  predate-wipe-clean → unrecoverable from shadows; pagefile zeroed; hiberfil
  empty. The wipe predates the earliest shadow copy.
- **Mailbox recovered from memory** (`recovered_mailbox.md`): the wiped
  mailbox's correspondents survived in RAM (`srl-helpdesk@`, `mhill@`, `tdungan@`,
  `nromanoff@`, `nfury@stark-research-labs.com`), proving the account was active.
- **Why that mailbox**: `fred.rocba@outlook.com` owned Fred's **Firefox Sync
  account** — the credential vault that held the reused password and the covert
  `redguard.cobra@gmail.com` login. Wiping it severed the documented tie between
  his real identity and the covert persona; the tie survived in the un-wiped
  gmail mailbox (Google "recovery email for redguard.cobra" alerts).
- **Password**: `C0bracommand`, reused across his Google, the covert
  `redguard.cobra@gmail.com`, `login.live.com` (the wiped account), Netflix,
  Facebook — recovered from the Firefox NSS vault.

## Honest limits
USB drive contents aren't in the evidence set (exfil proven by the staging act);
sdelete destroyed additional evidence; the `@outlook.com` mailbox is recoverable
only server-side (Microsoft, via the recovered `login.live.com` credential or
legal process). EL's ACH leader (espionage) reflects memory injection/auth-log
patterns that are a separate thread from the insider-theft conclusion.

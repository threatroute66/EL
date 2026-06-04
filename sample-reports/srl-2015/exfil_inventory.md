# SRL-2015 — Exfiltration inventory (what was taken)

The attacker (mhill.shield@yahoo.com) staged stolen material into a mailbox
folder literally named **EXFIL** — `vibranium--EXFIL.pst` on tdungan's XP box
(10.3.58.7) — and egressed it via Yahoo mail. 32 messages; recovered via
pffexport. This is the clearest data-loss evidence in the case.

## What was collected for exfil (by theme)

| Category | Subjects in the EXFIL folder |
|---|---|
| **Personnel / cover** | "Agent List - Sensitive", "Backstopped Accounts" (×3 thread) — covert/backstopped identities |
| **Classified** | "For Your Eyes Only" (×3), "Project assignments" |
| **R&D (the crown jewels)** | "Test Success - Alloy Combination" (the Vibranium alloy), "Fuel connectors carrier landing pad", "Carrier landing Pad" |
| **Facility recon** | "New DC HQ And R&D Facility Photos" (×5) |
| **Financial** | "CC Info", "2011 Tax Adjustment Notice" |
| **Channel setup** | "Welcome to Stark-Research-Labs", "Testing new comms"/"Test Comms" (Aug 2011) — the attacker building/validating the exfil channel months before the bulk theft |

## Reading

- The **"Testing new comms" (Aug 2011)** messages show the exfil channel was
  established ~7 months before the March-2012 bulk theft — a patient, planned
  operation.
- The stolen set is comprehensive espionage: **personnel rosters + covert
  identities + classified R&D (Vibranium/alloy, carrier/fuel tech) + facility
  imagery + financial data.** Assume all of it left the network.

## Phishing lures (incoming, from mhill.shield@yahoo.com)

Recovered from nfury's PST: `StarFury.zip` (images + StarFury.docx),
`Dossier - Dr Myron MacLain.docx` (Myron MacLain = the vibranium-alloy
scientist), `SA-23E Mitchell-Hyundyne Starfury.docx`, `Earthforce SA-26
Thunderbolt Star Fury.docx`, `The Shield Background and Ongoing Research.docx`.
All are benign Office docs (no OLE/macro) — themed decoys/research, NOT the
exploit. Initial access was the spearphishing **link** (see pivot_map.md).

## Follow-ups

- Enumerate the actual attachments/bodies inside each EXFIL message for the
  precise documents exfiltrated.
- Resolve/scan the phishing link `sinasolutions.com.au/.../Ruth_mourns_..pdf`
  and the blog dead-drops against threat intel.
- The 10.3.16.5 attacker jump host and 10.3.58.9 SMB target were not imaged.

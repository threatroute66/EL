# Recovered Mailbox — fred.rocba@outlook.com (from memory)

Analyst: Murat C. · Examined: 2026-06-03 UTC
Evidence: Rocba-Memory.raw (18 GB, read-only) + rocba-cdrive.e01
Companion: [vss_ost_recovery.md](vss_ost_recovery.md) (the wipe + VSS exhaustion).

## Summary

The on-disk OST for `fred.rocba@outlook.com` was zero-wiped and no pre-wipe
shadow copy survives (see companion note). Recovery therefore pivoted to the
**memory image**, which — even though `outlook.exe` was not running at capture —
retained the account's identity, sync state, correspondents, and a small
Outlook-Web cache. This is partial reconstruction from volatile artifacts, NOT
a recovered mailbox file; confidence is annotated per item.

## 1. Account was active (high confidence)

The wiped account was a live, syncing Outlook/M365 account — so substantive
mail existed before the wipe. Recovered from RAM:

- `<AutoDiscoverSMTPAddress>fred.rocba@outlook.com</AutoDiscoverSMTPAddress>` — Outlook AutoDiscover
- EWS (Exchange Web Services) sync-log fragments timestamped `2020-11-14 08:xx`
- Stored credential structures (`AuthMembername`, `UserName`/`WTRes`) and an
  account-profile JSON blob carrying the display name + address
- iCloud-for-Windows tied the same identity to Apple ID `fred.rocba@gmail.com`

## 2. Correspondents (medium confidence)

Addresses recovered adjacent to the account's OST/EWS/profile structures in
memory (`be_memory/email_histogram.txt`), noise-filtered. Hit counts are RAM
occurrences, not message counts — they indicate who the account interacted with:

| Correspondent | Hits | Note |
|---|---|---|
| frocba@stark-research-labs.com | 1836 | Fred's SRL corporate identity (same person) |
| mhill@stark-research-labs.com | 123 | SRL colleague |
| srl-helpdesk@outlook.com | 108 | SRL helpdesk |
| tdungan@stark-research-labs.com | 96 | SRL colleague |
| nromanoff@stark-research-labs.com | 91 | SRL — also sent Fred's "Job Offer" (see email_forensicator) |
| nfury@stark-research-labs.com | 67 | SRL colleague |
| srl-projects@stark-research-labs.com | 23 | SRL project distribution |
| u.key@spadertech.com | 16 | External — sent "SRL VPN Setup" / IT onboarding |
| leslie_parks@outlook.com | 8 | see §3 (likely sample data) |
| suisserien90@outlook.com | 7 | external personal contact |

Forensic value: the wiped account's working relationships (SRL staff + the
spadertech onboarding contact) are reconstructable despite the wipe.

## 3. Outlook-Web cached message subjects (LOW confidence — likely sample data)

Three message records recovered from the in-memory Outlook-Web client cache
(`recovered_outlook_messages.csv`):

| Date (UTC) | From | Subject |
|---|---|---|
| 2020-04-13T22:55:37Z | leslie_parks@outlook.com | Meeting Declined |
| 2020-04-13T22:55:37Z | leslie_parks@outlook.com | Park Report with a long subject name |
| 2020-04-13T22:55:37Z | leslie_parks@outlook.com | Pawnee Commons Budget Plan |

⚠ Caveat: the sender display name (`AVeryLongPersonsNameThatIsLong LastName`),
the Pawnee/Parks-themed subjects, and the identical placeholder timestamp are
the hallmarks of Microsoft's built-in **Outlook-Web sample/demo mailbox**, not
substantive correspondence. Treat as cache-template content, not evidence,
absent independent corroboration.

## What was NOT recovered

The body/contents of Fred's real @outlook.com mail. The OST was wiped, all VSS
snapshots predate-wipe-clean, pagefile zeroed, and hiberfil (`WAKE`) held no
mail pages. The authoritative copy remains the server-side @outlook.com mailbox
(recoverable via the recovered `login.live.com` credential or legal process to
Microsoft — requires authorization), and the two healthy OSTs (gmail 941 msgs,
stark-research-labs 101 msgs) likely share overlapping threads.

## 4. WHY the @outlook.com mailbox was the wipe target (cross-mailbox, high confidence)

Recovered by re-exporting the two **intact** OSTs (pffexport) and reading the
message bodies — the wipe failed to sever the link because the evidence
survived in the mailboxes Fred did NOT wipe.

**(a) The wiped @outlook.com account owned Fred's Firefox Sync account.**
gmail/Inbox/Message00747 (Firefox Accounts, 2020-11-03 02:04 UTC, "Confirm
secondary email") body:
> "A request to use fred.rocba@gmail.com as a secondary email address has been
> made from the following Firefox Account: **fred.rocba@outlook.com** — Firefox
> on Windows 10."

Firefox Sync = the saved-login vault EL already recovered (7 cleartext
passwords + the covert `redguard.cobra@gmail.com` login). So the wiped mailbox
was the registered identity of the credential store / covert-persona vault.

**(b) Hard link between Fred and the covert persona — survived in gmail.**
gmail/Inbox/Message00767 + a repeat 2020-11-10 (Google, "Security alert for your
linked Google Account"):
> "Your account **fred.rocba@gmail.com is listed as the recovery email for
> redguard.cobra@gmail.com**. New sign-in to your linked account
> redguard.cobra@gmail.com … from a new Windows device."

→ Fred's gmail is the recovery email for the covert `redguard.cobra` persona,
and that persona was signed into from his Windows machine (Nov 5 & Nov 10).

**(c) Spader Technologies is SRL's IT contractor, not the adversary.**
gmail/Inbox/Message00010 (Ulysses Key, u.key@spadertech.com, 2020-10-26):
> "I work for Spader Technologies and we provide … IT services to Stark
> Enterprises, including onboarding … Your domain\username: SHIELDBASE\frocba,
> Password: to be sent separately via text … email frocba@stark-research-labs.com."

Benign onboarding (though it documents Fred's AD creds — a recon prize).

**Inference (now well-supported):** the @outlook.com mailbox was the control
hub of Fred's covert identity/credential infrastructure — it owned the Firefox
Account that synced the password vault and the `redguard.cobra` covert-persona
login, and would have held that infrastructure's setup/verification trail.
Wiping it was an attempt to sever the documented tie between his real identity
and the covert persona + credential store, while leaving the ordinary-looking
gmail and corporate mailboxes intact. The attempt failed: the tie is fully
reconstructable from the survivors (a, b above).

**Covert-infra timeline (UTC):** Oct 26-27 legit SRL onboarding → Nov 03
Firefox Account (fred.rocba@outlook.com) links gmail as secondary → Nov 05 &
10 redguard.cobra signed in from Fred's Windows device (gmail = recovery) →
Nov 14 exfil staging (USB/Google Drive/iCloud) + @outlook.com OST wiped +
sdelete C:/D:.

## 5. Project-access provenance + covert-persona trace (corporate mailbox)

Reading message bodies in the intact `frocba@stark-research-labs.com.ost`:

**How Fred got the projects (legitimate grant, then exfiltrated):** Maria Hill
(`mhill`) shared the exfiltrated projects with Fred via SharePoint/M365:
- 2020-11-02 "German-KITT-Specs" shared
- 2020-11-04 folder **"KITT"** shared
- 2020-11-07 folder **"Megaforce"** shared
- 2020-11-14 SharePoint reminder "Megaforce shared with you" (exfil day)

And he sat on the **"Gunstar Project"** thread (Oct 17–Nov 2) with Nick Fury
(`nfury`), Maria Hill, and the `SRL-Projects` distribution list. Verbatim:
- M. Hill: "You should see the German version of KITT. Highly classified by the
  BND … simply amazing technology." / "I'll send you over some specs."
- N. Fury: "I have tasked Bucky Barnes to put together a collection plan for
  HUMINT and OSINT on our normal competition. I have also assigned Jarvis to
  explore cyber options."
- F. Rocba: "This is fascinating -- I haven't seen tech like this since KITT."

So the projects later staged to USB/Drive (KITT, Megaforce, Gunstar) were ones
Fred had *legitimate* M365/SharePoint access to via Maria Hill — access granted
days before the Nov 14 exfil.

**Covert-persona trace — negative (honest):** `redguard.cobra@gmail.com` was
NEVER a sender or recipient in either mailbox (0 occurrences); it appears only
in Google's recovery/sign-in alerts. No staged SRL project file appears as an
email attachment anywhere — the only attachments are the SRL job offer, the
Spader VPN-setup PDF, and a research PDF. **Conclusion:** the project files were
NOT exfiltrated by email, and the covert persona was not used as a mail drop
(at least not via these accounts). The persona's role was identity/credential
infrastructure (Firefox vault + linked Google account, §4), consistent with the
established exfil channels being USB + Google Drive + iCloud, not email.

## Method (reproducible)

```
bulk_extractor -E email -o analysis/ost-recovery/be_memory  Rocba-Memory.raw
# correspondents: be_memory/email_histogram.txt (filter @outlook/@stark/@spader)
python sweep2.py   # literal-anchor 'www.outlook.com' + bounded regex → recovered_outlook_messages.csv
```

Dead-end carve targets confirmed: pagefile.sys (2.4 GB, all-zero), hiberfil.sys
(6.8 GB, WAKE state — 1 email feature, no mailbox pages).

## Note on folding into the case ledger

This is documented analyst work (the case was already sealed). Going forward the
new `artifact_recovery` agent emits the wipe + recovery as first-class Findings
automatically on `el investigate`, so a re-run would carry this into the report
and ACH rather than living only in this note.

# OST Recovery Examination — fred.rocba@outlook.com.ost

Analyst: Murat C.  ·  Examined: 2026-06-03 UTC  ·  Evidence: rocba-cdrive.e01 (read-only)

## Conclusion
fred.rocba@outlook.com.ost (MFT inode 124086) is NOT corrupt — it was zero-wiped.
Recovery from Volume Shadow Copies is NOT possible: all 5 snapshots on the volume
already show the file 100% zero-filled. The wipe predates the earliest snapshot
(2020-11-14 12:46:15 UTC).

## Evidence
- Live image: $DATA non-resident, size=33,497,088, init_size=24,973,312 (24 MB once
  initialized) — but allocated clusters read all-zero (0 non-zero bytes in 32 MB).
  Fresh icat from source confirms (not an extraction error). OST mtime 2020-11-14 14:11:49.
- VSS: 5 shadow copies enumerated (libvshadow) after repairing the 7-sector-short image
  tail (synthesized NTFS backup VBR via dm-linear overlay; evidence untouched):
  | Store | Snapshot creation (UTC) | OST mtime (UTC) | OST content |
  |-------|-------------------------|-----------------|-------------|
  | vss1  | 2020-11-14 12:46:15     | 12:33:54        | all zero    |
  | vss2  | 2020-11-14 13:11:18     | 12:33:54        | all zero    |
  | vss3  | 2020-11-14 13:32:17     | 12:33:54        | all zero    |
  | vss4  | 2020-11-14 13:48:07     | 13:42:10        | all zero    |
  | vss5  | 2020-11-14 14:03:05     | 14:02:11        | all zero    |
- Advancing OST mtime across snapshots with persistently zero content = repeated
  zero-touch, consistent with the sdelete64.exe anti-forensic activity found on this host.

## Method (reproducible)
1. ewfmount -X allow_other rocba-cdrive.e01  (raw NTFS, single volume, offset 0)
2. losetup -r over ewf1; dm-linear concat + synthesized backup VBR at sector 170764287
3. vshadowinfo / vshadowmount -X allow_other  -> vss1..vss5
4. fls/istat/icat inode 124086 per snapshot; non-zero byte count per file.

## Remaining recovery avenues (not VSS)
- Memory image (Rocba-Memory.raw, 18 GB) + pagefile.sys (3 GB) + hiberfil.sys (6.8 GB):
  carve for cached OST pages / message fragments (outlook.exe not running at capture, but
  OST file object present in kernel FileScan).
- Server-side @outlook.com mailbox (authoritative) via recovered login.live.com credential
  (Firefox vault) or legal process to Microsoft — requires authorization.
- Cross-reference healthy OSTs: gmail.com (941 msgs) + stark-research-labs.com (101 msgs)
  for overlapping threads.

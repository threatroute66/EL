# SANS SIFT Workstation: Exhaustive Tool and Command Reference

*Build reference date: SANS tools page last updated 24 April 2026; underlying build `teamdfir/sift-saltstack` rolling release (latest tagged build in the April 2026 release line). Base OS: Ubuntu 22.04 LTS (Jammy). Legacy 20.04 Focal builds still function but are deprecated.*

---

## Introduction

The **SIFT Workstation** is a free, open-source collection of incident response and digital forensic tools originally created by Rob T. Lee and the SANS DFIR faculty in 2007 to support FOR508 and now maintained as the most widely downloaded open-source DFIR platform (SANS cites 60,000+ annual downloads and 200+ bundled tools). It is distributed as a pre-built OVA virtual appliance (≈8.8 GB) and can also be layered onto a standalone Ubuntu 22.04 LTS host — or onto Windows via WSL — by invoking the **Cast** installer against the `teamdfir/sift` distribution definition. Cast (`ekristen/cast`, a Go binary) replaced the Node.js-based **SIFT CLI** (`teamdfir/sift-cli`), which was officially deprecated on 1 March 2023 and archived but still functional for legacy workflows.

SIFT is authored/maintained by Rob T. Lee (SANS Fellow) with community contributors via `teamdfir/sift-saltstack`, the SaltStack state tree that declaratively defines every package, Python module, and helper script installed on the appliance. Default credentials on the VM are `sansforensics` / `forensics`. A separate experimental initiative announced in early 2026, **Protocol SIFT**, layers AI-agent orchestration (Model Context Protocol) on top of SIFT for research purposes only — SANS explicitly states it is **not** forensically sound, **not** court-admissible, and **not** a replacement for the core SIFT Workstation.

This document is an exhaustive, category-organized reference to the tools that ship on, or are canonically associated with, the current SIFT build. Within each section, tools are listed alphabetically. Entries flagged **[default]** are installed by the SaltStack state tree out of the box; entries flagged **[commonly added]** are DFIR tools that SIFT users routinely install post-boot and that appear on SANS cheat sheets, in FOR508/FOR500/FOR572/FOR526/FOR585 lab material, or on the SIFT/REMnux combined build — but are not provisioned by default. Command names reflect the exact invocation on the command line.

---

## Table of contents

1. File system analysis and disk imaging
2. Memory forensics
3. Network forensics and packet analysis
4. Timeline analysis and super-timeline
5. Windows Registry analysis
6. Windows artifact analysis (event logs, prefetch, shellbags, LNK, jump lists, MFT, USN, Amcache, SRUM, ShimCache)
7. Browser forensics
8. Email forensics
9. Mobile forensics
10. Malware analysis and reverse engineering
11. Log analysis
12. Hashing and integrity verification
13. Carving and data recovery
14. Encryption, password, and cryptography tools
15. Metadata and file-type analysis
16. Linux/Unix artifact analysis
17. macOS artifact analysis
18. Cloud forensics
19. Scripting and DFIR Python/Perl libraries
20. Mounting and virtualization utilities
21. Miscellaneous and general-purpose tools
22. SIFT CLI, Cast, and update notes

---

## 1. File system analysis and disk imaging

- **affuse** [default] — AFFLIBv3 — FUSE mount helper that exposes AFF/AFD/AFM forensic images as raw image files, enabling any downstream tool to treat an AFF container like a single flat disk image.
- **affinfo** [default] — AFFLIBv3 — Prints metadata embedded in Advanced Forensic Format images, including hashes, case notes, and acquisition parameters.
- **afconvert** [default] — AFFLIBv3 — Converts images between raw, AFF, AFD, and AFM variants, preserving acquisition metadata.
- **Autopsy** [default] — Basis Technology — Java-based graphical front-end to The Sleuth Kit providing case management, keyword search, hash lookups, timeline, ingest modules, and multi-user collaboration for full disk investigations.
- **avfs** [default] — A Virtual File System — Transparently exposes archive contents (zip, tar, iso, etc.) as browsable directories, useful for walking nested containers without extraction.
- **blkcalc** [default] — The Sleuth Kit — Translates between addresses in an image containing unallocated data (`blkls` output) and the original image, letting analysts locate unallocated fragments back in the source.
- **blkcat** [default] — The Sleuth Kit — Outputs the contents of a specific data block (cluster/sector) from a file system image.
- **blkls** [default] — The Sleuth Kit — Extracts unallocated space or all data units from a file system into a single stream, the standard first step for free-space carving.
- **blkstat** [default] — The Sleuth Kit — Reports allocation status and metadata for a given data block.
- **dc3dd** [default] — DoD Cyber Crime Center — Forensic-grade imaging tool (a dd patch) with on-the-fly hashing (MD5/SHA-family), split output, progress reporting, and verification.
- **dcfldd** [default] — Nicholas Harbour — Earlier forensic dd variant with simultaneous hashing, pattern wiping, and verification, retained for compatibility with established workflows.
- **dd** [default] — GNU coreutils — Baseline block-level copy utility used for creating raw images and performing sector-level operations.
- **disktype** [default] — Detects the format of disks, partitions, and image files including file systems, boot sectors, encrypted containers, and archive formats for rapid image triage.
- **ewfacquire** [default] — libewf — Acquires a physical/logical device into EnCase EWF (E01) format with compression, splitting, and hashing.
- **ewfexport** [default] — libewf — Exports an EWF image back to raw or to a different EWF configuration.
- **ewfinfo** [default] — libewf — Reports EWF metadata (acquisition date, examiner, hashes, segment layout) for evidence verification.
- **ewfmount** [default] — libewf — FUSE-mounts an EWF (possibly split) image as a raw device node, enabling Linux tooling to treat E01 files natively.
- **ewfverify** [default] — libewf — Recomputes and compares hashes stored in an EWF to verify image integrity.
- **extundelete** [default] — Recovers deleted files from ext3/ext4 file systems by walking the journal and inode tables.
- **fls** [default] — The Sleuth Kit — Lists files and directories (including deleted entries) in a file system, and produces TSK bodyfile output that feeds `mactime`.
- **fsstat** [default] — The Sleuth Kit — Displays file-system-level details (type, label, block size, cluster layout) for an image or volume.
- **guestfish** [commonly added] — libguestfs — Interactive shell for libguestfs, allowing scripted read-write access to arbitrary VM disk formats (qcow2, VMDK, VHD).
- **guestmount** [commonly added] — libguestfs — Read-only or read-write FUSE mount of VM disks using a libvirt appliance, broad format support beyond what kernel drivers provide.
- **hfind** [default] — The Sleuth Kit — Looks up hashes in NSRL, HashKeeper, or custom hash databases to flag known-good or known-bad files during triage.
- **icat** [default] — The Sleuth Kit — Extracts the contents of a file by inode/MFT record number, bypassing allocation status so deleted content can be recovered.
- **ils** [default] — The Sleuth Kit — Lists inode/MFT metadata (allocated or unallocated) with time information, useful for finding orphaned deleted files.
- **imagemounter** [default] — Lists/mounts disk images and containers, unpacking nested partitions, LVM volumes, and encrypted layers automatically; explicitly referenced in the SANS SIFT feature list.
- **istat** [default] — The Sleuth Kit — Prints detailed metadata for a single inode/MFT entry including timestamps, attributes, data runs, and parent references.
- **jcat** [default] — The Sleuth Kit — Displays the contents of a file-system journal block.
- **jls** [default] — The Sleuth Kit — Lists the entries in a file-system journal (ext3/4, NTFS $LogFile) to reconstruct recent metadata changes.
- **kpartx** [default] — multipath-tools — Creates device mappings for each partition inside a loop-mounted image, exposing them as `/dev/mapper/*` nodes.
- **libbde / bdemount / bdeinfo** [default] — libyal — Parse and FUSE-mount BitLocker Drive Encryption volumes given a recovery key, password, or startup key.
- **libesedb-tools (esedbexport, esedbinfo)** [default] — libyal — Parse and export records from Microsoft Extensible Storage Engine databases (Windows.edb, WebCacheV01.dat, SRUDB.dat, ntds.dit).
- **libevt-tools** [default] — libyal — Parses legacy Windows (pre-Vista) `.evt` event-log files.
- **libevtx-tools (including evtxexport)** [default] — libyal — CLI parser and exporter for modern Windows `.evtx` event logs.
- **libfsapfs-tools (fsapfsinfo, fsapfsmount)** [default] — libyal — Parse and mount Apple APFS volumes, including snapshots, on Linux.
- **libfvde / fvdemount / fvdeinfo** [default] — libyal — Parse and mount Apple FileVault 2-encrypted HFS+/Core Storage volumes given a recovery key or password.
- **libolecf-tools** [default] — libyal — Parses Microsoft OLE Compound File containers (legacy Office, thumbs.db, MSI internals).
- **libregf-tools** [default] — libyal — Parses Windows Registry (REGF) hives, exposing keys, values, and security descriptors.
- **libvmdk / vmdkinfo / vmdkmount** [default] — libyal — Inspect and mount VMware VMDK descriptor+flat images, including split/sparse variants.
- **libvhdi-tools** [commonly added] — libyal — Parse and mount Microsoft VHD/VHDX virtual-disk images; installed via pip/libyal on demand.
- **libvshadow-tools (vshadowmount, vshadowinfo)** [default] — libyal — Enumerate and mount Windows Volume Shadow Copies carved out of an image or mounted disk.
- **losetup** [default] — util-linux — Attaches a raw image to a loopback device, the foundation of most Linux-side image mounting workflows.
- **mmcat** [default] — The Sleuth Kit — Outputs the raw contents of a given partition/volume within an image.
- **mmls** [default] — The Sleuth Kit — Displays partition layout (DOS, GPT, Mac, BSD, Solaris) to identify offsets for mounting.
- **mmstat** [default] — The Sleuth Kit — Reports the partition-table type of an image.
- **mount** [default] — util-linux — Standard Linux mount utility, used with `-o ro,loop,noexec` for forensically safe image mounting.
- **qemu-img** [default] (`qemu-utils`) — QEMU — Converts, inspects, creates, and resizes virtual-disk images (raw, qcow2, VMDK, VHD/VHDX, VDI).
- **safecopy** [default] — Forensic-aware block copier that handles damaged media by using configurable retry/skip strategies, producing partial images and bad-block maps.
- **sigfind** [default] — The Sleuth Kit — Searches binary images for a user-supplied hex signature at configurable offsets, useful for locating boot sectors or carving anchors.
- **sleuthkit** [default] — Brian Carrier — The umbrella Debian package that installs the full set of Sleuth Kit CLI utilities listed throughout this section.
- **sorter** [default] — The Sleuth Kit — Categorizes files in an image by type using magic/extension and optional hash lookups, producing per-category bundles for review.
- **srch_strings** [default] — The Sleuth Kit / binutils variant — String extraction with byte-offset reporting tuned for forensic use over raw images and unallocated space.
- **TestDisk** [default] — CGSecurity — Partition-table and boot-sector recovery tool that rebuilds damaged partition metadata and makes non-booting disks bootable again.
- **tsk_comparedir** [default] — The Sleuth Kit — Compares a directory tree on a live file system to the same tree in an image, useful for detecting rootkits that hide files.
- **tsk_gettimes** [default] — The Sleuth Kit — Generates TSK bodyfile output across all files in an image for timeline creation.
- **tsk_loaddb** [default] — The Sleuth Kit — Loads file-system metadata into a SQLite case database (the Autopsy format) for scripted or GUI analysis.
- **tsk_recover** [default] — The Sleuth Kit — Recovers allocated and/or unallocated files from an image into a target directory.
- **vmfs-tools** [default] — Read VMware VMFS datastores from Linux for ESXi evidence analysis.
- **xmount** [default] — Pinguin.lu — On-the-fly converting mount that exposes raw/EWF/AFF images as alternative formats (VDI, VMDK, VHD), enabling direct boot of evidence in analysis VMs.
- **xfsprogs** [default] — XFS utilities for inspection and repair of XFS-formatted evidence volumes.

## 2. Memory forensics

- **aeskeyfind** [default] — Princeton — Scans memory dumps for candidate AES-128/192/256 key schedules to recover keys from volatile acquisitions.
- **AVML** [commonly added] — Microsoft — User-mode Linux memory acquisition tool that produces LiME-format images without requiring a kernel module or matching kernel headers.
- **bulk_extractor** [default] — Simson Garfinkel — Feature extractor that scans memory images, disk images, pcap, and individual files for emails, URLs, PAN/credit cards, network packets, EXIF data, and more, producing indexed feature files for rapid triage.
- **dpapick** [default] (python package) — Python toolkit to parse Windows DPAPI blobs and master keys, often used against credentials extracted from memory or mounted user profiles.
- **haystack** [default] (python package) — Memory-introspection library for extracting C-structure instances from a process memory image, used by research memory plugins.
- **LiME** [commonly added] — 504ensicsLabs — Loadable kernel module that dumps full physical memory on Linux and Android, widely used as the canonical Linux acquisition path.
- **MemProcFS** [commonly added] — Ulf Frisk — Mounts a memory image (or live RAM via PCILeech) as a virtual file system, exposing processes, modules, handles, and registry as files.
- **Rekall** [commonly added] — Google (archived) — Memory forensic framework derived from Volatility with its own profile scheme and live-analysis mode; retained in DFIR curricula for legacy coverage.
- **rsakeyfind** [default] — Princeton — Scans memory dumps for candidate RSA private keys, counterpart to `aeskeyfind`.
- **Volatility 2 (`vol.py`)** [default] — Volatility Foundation — Classic Python 2 memory-forensic framework installed from source by the `sift.python-packages.volatility` state, with the SANS DFIR community-plugin set and Hotoloti's `mimikatz.py` plugin layered in.
- **Volatility 3 (`vol`)** [commonly added] — Volatility Foundation — Python 3 rewrite using symbol tables (ISF) rather than profiles; the modern default for Windows/Linux/macOS memory triage, installed via `pip` on current SIFT builds.

## 3. Network forensics and packet analysis

- **arp-scan** [default] — Scans the local network using ARP to enumerate live hosts and MACs.
- **capinfos** [default] — Wireshark suite — Summarizes pcap/pcapng metadata (capture duration, packet count, encapsulation, hashes).
- **chaosreader** [commonly added] — Brendan Gregg — Reassembles sessions (HTTP, FTP, Telnet, VoIP, images) from pcaps into per-session HTML reports.
- **cryptcat** [default] — Encrypted variant of netcat using Twofish, used in controlled evidence transfers over untrusted networks.
- **dnstop** [commonly added] — Curses TUI summarizing DNS queries by source, TLD, or query type, from live interfaces or pcap.
- **driftnet** [default] — Extracts and displays images observed in network traffic in real time or from pcap.
- **dsniff** [default] — Classic suite (dsniff, arpspoof, dnsspoof, macof, mailsnarf, msgsnarf, urlsnarf, webspy) for auditing network traffic and demonstrating layer-2 attacks in lab scenarios.
- **editcap** [default] — Wireshark suite — Slices, filters, deduplicates, and converts pcap/pcapng files.
- **etherape** [default] — Graphical network visualizer showing live or pcap flows as a dynamic link graph.
- **ettercap-graphical** [default] — Man-in-the-middle framework with ARP/DNS/SSH/SSL dissectors; in DFIR labs primarily used to analyze captured MITM artifacts.
- **mergecap** [default] — Wireshark suite — Concatenates multiple pcaps into a single file with timestamp merging.
- **nbtscan** [default] — Scans NetBIOS over TCP/IP to enumerate Windows share and machine names.
- **netsed** [default] — Stream-editor proxy that rewrites bytes on the wire, useful for analyzing protocol-handling bugs.
- **NetworkMiner** [commonly added] — Netresec — GUI passive network forensic analyzer that reconstructs hosts, files, credentials, and sessions from pcap.
- **net-tools** [default] — Legacy suite (`netstat`, `arp`, `route`, `ifconfig`) used on mounted Linux evidence.
- **nfdump** [default] — Netflow collector/processor for analyzing NetFlow v5/v9/IPFIX data.
- **ngrep** [default] — Jordan Ritter — BPF+regex search across live traffic or pcap payloads, ideal for quick pattern hunts.
- **nikto** [default] — Web-server vulnerability scanner retained for triage of compromised web hosts.
- **ntopng-style tools via `etherape`, `tcptrack`** [default] — Live traffic summarization.
- **p0f** [default] — Passive OS fingerprinter that classifies hosts from observed packets.
- **RITA (Real Intelligence Threat Analytics)** [commonly added] — Active Countermeasures — Analyzes Zeek logs for beaconing, long connections, and DNS tunneling indicative of C2.
- **Snort** [commonly added] — Cisco — Signature-based IDS frequently used to replay rules over captured traffic.
- **socat** [default] — Universal bidirectional data relay used extensively in network forensic pipelines and controlled replay.
- **ssldump** [default] — SSL/TLS record-layer parser for pcap, with session-key decryption when keys are supplied.
- **sslsniff** [default] — TLS MITM/analysis tool for research scenarios.
- **Suricata** [commonly added] — OISF — High-performance IDS/IPS/NSM with EVE JSON logging and file extraction from pcap.
- **tcpdump** [default] — libpcap-based CLI capture/analysis utility; the baseline packet tool pulled in as a core dependency.
- **tcpflow** [default] — Simson Garfinkel — Reassembles TCP streams into per-flow files for content analysis.
- **tcpick** [default] — Stream reassembly with terminal display and file carving of TCP payloads.
- **tcpreplay** [default] — Replays pcap traffic at line rate against IDS sensors or lab networks.
- **tcpslice** [default] — Slices pcap files by time range.
- **tcpstat** [default] — Summary statistics (packet/byte rates) for live or offline captures.
- **tcptrace** [default] — Long-form TCP connection analysis with RTT graphs and retransmission accounting.
- **tcptrack** [default] — ncurses live display of active TCP connections.
- **tcpxtract** [default] — Carves files from reassembled TCP streams using magic signatures.
- **tshark / Wireshark** [default] — Wireshark Foundation — The GUI and terminal-mode packet dissectors, with thousands of protocol dissectors, stream-follow, and statistical modes.
- **Zeek** (formerly Bro) [commonly added] — Zeek Project — Protocol-aware network monitor producing structured per-protocol logs; foundational for hunting on pcap.

## 4. Timeline analysis and super-timeline

- **log2timeline.py** [default] (`plaso-tools`, `python3-plaso`) — Plaso — Extracts timestamped events from entire disk images, VSS, individual artifacts, and cloud log exports into a Plaso storage file, the standard first stage of super-timeline creation.
- **mactime** [default] — The Sleuth Kit — Produces sorted MAC-time timelines from `fls`/`ils` bodyfile output.
- **pinfo.py** [default] — Plaso — Reports on the contents and parsers used in a Plaso storage file.
- **psort.py** [default] — Plaso — Filters, deduplicates, tags, and converts a Plaso storage file into formats like l2tcsv, l2ttln, JSON, Elasticsearch, and Timesketch.
- **psteal.py** [default] — Plaso — One-shot pipeline combining `log2timeline` + `psort` for rapid timeline creation.
- **Timeline Explorer** [commonly added] — Eric Zimmerman — Windows GUI CSV/Excel viewer purpose-built for large DFIR timeline outputs with filtering, tagging, and column-based analysis.
- **Timesketch** [commonly added / python package] — Google — Collaborative web-based timeline-analysis platform backed by OpenSearch for team tagging, filtering, and analyzer runs over Plaso/CSV timelines; the SIFT salt tree includes a `timesketch` python-packages state.

## 5. Windows Registry analysis

- **AmcacheParser** [commonly added] — Eric Zimmerman — Parses `Amcache.hve` for program-execution evidence, SHA-1 hashes, and first-run metadata.
- **amcache.py** [default] — SIFT venv at `/opt/amcache` — Python parser for Amcache.hve built around `python-registry`.
- **AppCompatCacheParser** [commonly added] — Eric Zimmerman — Extracts ShimCache/AppCompatCache entries from the SYSTEM hive.
- **libparse-win32registry-perl** [default] — Perl module providing the Parse::Win32Registry API consumed by RegRipper and the keydet89 scripts.
- **libregf-python3** [default] — libyal — Python bindings for REGF hive parsing used by Plaso and analyst scripts.
- **libregf-tools** [default] — libyal — CLI utilities (`regfexport`, `regfinfo`) for exporting and inspecting registry hives.
- **python-registry** [default] — Willi Ballenthin — Pure-Python hive parser (and helper scripts such as `shellbags.py`, `amcache.py`, `userassist.py`) underpinning much SIFT scripting.
- **RECmd** [commonly added] — Eric Zimmerman — Command-line registry parser with batch/plugin files to extract autoruns, user activity, and system configuration.
- **regripper / rip.pl** [default] — Harlan Carvey — Perl-based hive parser with a plugin-per-artifact architecture; installed via the SIFT scripts state from `keydet89/RegRipper2.8` and cross-compatible with Windows `rip.exe` under wine.
- **Registry Explorer** [commonly added] — Eric Zimmerman — GUI hive viewer with transaction-log replay, bookmarks, and plugin-driven views.
- **yarp** [commonly added] — MSuhanov — Python library for parsing hives with deleted-key carving and transaction-log recovery, leveraged by `dfir_ntfs` and custom scripts.

## 6. Windows artifact analysis

### Event logs (EVTX/EVT)

- **Chainsaw** [commonly added] — WithSecure/Countercept — Rust-based EVTX and MFT hunter applying Sigma rules and built-in detections to surface malicious activity.
- **EvtxECmd** [commonly added] — Eric Zimmerman — High-fidelity EVTX parser producing CSV/JSON/XML with custom "maps" enriching key security events.
- **evtx_dump** (`omerbenamram/evtx`) [commonly added] — Fast Rust EVTX parser producing JSON/XML/CSV, commonly used to feed Chainsaw/Hayabusa.
- **evtxexport / evtxinfo** [default] (`libevtx-tools`) — libyal — Exports EVTX records and prints file-level metadata.
- **evtparse.pl / evtxparse.pl** [default] — keydet89 Perl scripts shipped by the SIFT scripts state for quick EVT/EVTX extraction in Perl-driven pipelines.
- **EVTX-HUNTER** [commonly added] — Community EVTX analyzer that surfaces suspicious/rare events for triage.
- **Hayabusa** [commonly added] — Yamato-Security — Rust-based Windows event-log threat hunter with curated rules plus Sigma support for large-scale triage.
- **python-evtx** (`evtx_dump.py`) [default, via plaso deps] — Willi Ballenthin — Pure-Python EVTX parser useful in scripted pipelines where .NET tools are unavailable.

### Prefetch, Amcache, ShimCache, SRUM, Timeline

- **AmcacheParser / amcache.py** — see Registry section above.
- **AppCompatCacheParser** — see Registry section.
- **libscca-python3** [commonly added] — libyal — Python bindings parsing Windows Prefetch (SCCA) format.
- **PECmd** [commonly added] — Eric Zimmerman — Parses Prefetch files to recover program execution history, run counts, and loaded files/DLLs.
- **pref.pl** [default] — keydet89 Perl script for Prefetch parsing.
- **SrumECmd** [commonly added] — Eric Zimmerman — Parses SRUM ESE database (SRUDB.dat) for per-app network usage, energy data, and user activity.
- **WxTCmd** [commonly added] — Eric Zimmerman — Parses `ActivitiesCache.db` (Windows Timeline) to recover application, document, and browsing activity.

### MFT, USN Journal, LogFile

- **analyzeMFT** [commonly added via pip] — David Kovar — Python `$MFT` parser emitting CSV/bodyfile/JSON.
- **bodyfile.pl** [default] — keydet89 — Perl helper generating bodyfile output from MFT artifacts.
- **MFTECmd** [commonly added] — Eric Zimmerman — Parser for `$MFT`, `$Boot`, `$J` (USN Journal), `$SDS`, and `$LogFile` producing rich file-system timelines.
- **mft.pl** [default] — keydet89 — Perl script for MFT record parsing.
- **mft2csv** [commonly added via pip] — Converts `$MFT` to CSV for analyst review.
- **usnj.pl** [default] — keydet89 — Perl USN Journal parser.

### LNK and Jump Lists

- **idxparse.pl** [default] — keydet89 — Perl script for parsing IE `index.dat` / IDX artifacts.
- **jl.pl** [default] — keydet89 — Perl parser for Jump List streams.
- **JLECmd** [commonly added] — Eric Zimmerman — Parses automatic and custom destination Jump Lists for file/app interaction history.
- **LECmd** [commonly added] — Eric Zimmerman — Parses LNK shortcuts for target paths, MAC times, volume and MAC addresses.
- **lnk.pl** [default] — keydet89 — Perl LNK parser.

### Shellbags, Recycle Bin, other user-activity

- **parse.pl** [default] — keydet89 — General-purpose parser wrapper used with RegRipper-style plugins.
- **RBCmd** [commonly added] — Eric Zimmerman — Parses Recycle Bin `$I`/INFO2 metadata to recover original path, size, and deletion timestamps.
- **recbin.pl** [default] — keydet89 — Perl Recycle Bin parser.
- **regslack.pl / regtime.pl** [default] — keydet89 — Perl scripts recovering slack data from hives and producing registry timelines.
- **rifiuti2** [commonly added] — abelcheung — Parses Recycle Bin INFO2 and $I metadata across Windows versions.
- **SBECmd** [commonly added] — Eric Zimmerman — Parses Shellbags from NTUSER.DAT/UsrClass.dat for folders and removable devices browsed.
- **shellbags.py** [default, via python-registry] — Willi Ballenthin — Pure-Python shellbag parser.

### Windows-wide collection/parsing frameworks

- **KAPE** [commonly added] — Kroll / Eric Zimmerman — Triage collection and parsing framework using Targets to pull artifacts and Modules to run EZ Tools and other parsers against the output; Windows-native but runnable under wine.

## 7. Browser forensics

- **chromium-browser** [default] — Canonical/Google — Installed browser that doubles as an environment for live-mode browser forensic testing and exporting artifacts.
- **dumpzilla** [commonly added] — Python-based Firefox/Iceweasel artifact extractor covering history, cookies, bookmarks, downloads, saved passwords, sessions, and add-ons.
- **Firefox / Chrome forensic SQLite scripts** [commonly added] — Community-maintained scripts for parsing `places.sqlite`, `History`, and `Cookies` stores in ad-hoc analysis.
- **Hindsight** [commonly added] — obsidianforensics — Python forensic parser for Chromium-based browsers (Chrome, Edge, Brave, Opera) recovering history, downloads, cookies, cache, and autofill into CSV/XLSX/SQLite with a web UI.
- **libmsiecf tools (msiecfexport, msiecfinfo)** [default] — libyal — Parse legacy Internet Explorer `index.dat` cache and history files.

## 8. Email forensics

- **libpff / libpff-dev / python3-pypff** [default] — libyal — Libraries and bindings for Microsoft Outlook PST/OST personal-folder files.
- **pffexport** [default] (`pff-tools`) — libyal — Exports all messages, attachments, and folder structure from PST/OST files to disk.
- **pffinfo** [default] (`pff-tools`) — libyal — Prints PST/OST container metadata.
- **pst-utils (readpst, lspst, pst2ldif)** [default] — libpst project — Converts PST to mbox/EML/LDIF for analyst review.
- **mbox2eml** [commonly added] — Community script splitting mbox archives into individual EML files.

## 9. Mobile forensics

- **ALEAPP** [commonly added] — abrignoni — Android Logs, Events, And Protobuf Parser producing consolidated HTML/CSV reports from Android filesystem or backup extractions.
- **android-sdk-platform-tools** [default] — Google — Provides `adb`, `fastboot`, and related utilities for Android acquisition and live device interaction.
- **ideviceinfo / libimobiledevice suite** [commonly added] — libimobiledevice project — CLI tools (`ideviceinfo`, `idevicebackup2`, `idevicesyslog`, `ifuse`, etc.) for pairing, backing up, and retrieving data from iOS devices.
- **iLEAPP** [commonly added] — abrignoni — iOS Logs, Events, And Properties Parser producing reports from iTunes backups, full-filesystem extractions, and sysdiagnose bundles.
- **libplist-utils** [default] — libimobiledevice — CLI tools to convert Apple plist files between XML and binary forms.
- **mvt-android** [commonly added] — Amnesty International — Mobile Verification Toolkit for Android, performing IOC-based analysis of backups, bug reports, and SMS archives.
- **mvt-ios** [commonly added] — Amnesty International — MVT for iOS, originally developed for Pegasus hunts; performs forensic acquisition/analysis of backups, filesystem dumps, and sysdiagnose archives.

## 10. Malware analysis and reverse engineering

- **bless** [default] — GTK hex editor for large binary files.
- **capa** [commonly added] — Mandiant FLARE — Identifies malware capabilities by matching rules against decoded features (APIs, strings, constants), producing a behavior summary without full reversing.
- **ClamAV (clamscan, clamd, freshclam)** [default] — Cisco Talos — Open-source signature-based antivirus engine used for flagging known malware in images and extracted files.
- **Detect It Easy (DiE)** [commonly added] — horsicq — Packer/compiler/protector identifier with hex viewer and extensible signatures.
- **FLOSS** [commonly added] — Mandiant FLARE — Automatically extracts obfuscated, stack, and decoded strings from malware binaries missed by plain `strings`.
- **gdb** [default] — GNU — Debugger for native binaries, routinely used in Linux malware triage.
- **ghex** [default] — GNOME hex editor.
- **Ghidra** [commonly added] — NSA — Full-featured reversing suite with disassembler, decompiler, and scripting.
- **hexedit** [default] — Terminal hex editor.
- **libbcprov-java** [default] — Bouncy Castle crypto library, used by Java-based analysis tools like Autopsy/Ghidra plugins.
- **outguess** [default] — Steganography tool, used to test or recover hidden payloads in JPEG/PNM.
- **packerid** [default] — sooshie — Python venv at `/opt/packerid` identifying packers, protectors, and compilers via PE signatures; pulls in `pefile` and `capstone`.
- **pedis / peres / pescan / readpe / pepack / pestr / cpload / ofs2rva / rva2ofs** [default] (`pev`) — pev suite — Disassemble, enumerate resources, and statically analyze Windows PE executables.
- **peframe** [commonly added] — Static PE analyzer summarizing headers, sections, suspicious APIs, strings, and YARA hits.
- **pefile / python3-pefile** [default] — Python library for parsing PE files, underpinning many SIFT scripts.
- **radare2** [default] — radare project — Reverse-engineering framework for disassembly, debugging, patching, and binary diffing.
- **rizin / cutter** [commonly added] — rizin project — Rizin is the maintained radare2 fork; Cutter is its Qt GUI.
- **ssdeep** [default] — Jesse Kornblum — Context-triggered piecewise (fuzzy) hashing for malware similarity matching.
- **strings** [default] (binutils) — Extracts printable strings from binaries, memory dumps, and raw images for quick triage.
- **upx-ucl** [default] — Ultimate Packer for eXecutables, used both to unpack UPX-packed samples and as an identifier.
- **vbindiff** [default] — Visual binary diff for side-by-side byte comparison of two files.
- **Wine** [default] — Runs Windows PE binaries on Linux, enabling execution of RegRipper's `rip.exe`, Eric Zimmerman tools, and other Windows-native utilities inside SIFT.
- **yarGen** [commonly added] — Neo23x0 — Auto-generates YARA rules from known-bad samples with goodware exclusion.
- **YARA** [default] (`python3-yara`) — VirusTotal — Pattern-matching engine for describing and detecting malware families via rules.

## 11. Log analysis

- **epic5** [default] — IRC client retained for chat/log replay.
- **grepcidr** [default] — CIDR-aware grep for log filtering by network.
- **jq** [default] — JSON processor used heavily for Suricata EVE logs, AWS CloudTrail, and Elastic output parsing.
- **lft** [default] — Layer-four traceroute retained for correlating network logs.
- **silversearcher-ag** [default] — Fast recursive code/log searcher.
- **Standard Unix log tools** [default] — `grep`, `awk`, `sed`, `sort`, `uniq`, `cut`, `tr`, `tail`, `head`, `wc`, `less` — the backbone of ad-hoc log analysis on SIFT.
- **Timesketch / Plaso** — see Timeline section.

## 12. Hashing and integrity verification

- **hashdeep** [default] — Jesse Kornblum — Recursive hashing across directory trees, with audit mode against known hash sets and multi-algorithm output.
- **hfind** [default] — The Sleuth Kit — Hash lookup against NSRL and custom databases.
- **md5deep / sha1deep / sha256deep / tigerdeep / whirlpooldeep** [default] — Part of `hashdeep` — Single-algorithm variants for recursive hashing.
- **md5sum / sha1sum / sha224sum / sha256sum / sha384sum / sha512sum / b2sum** [default] — GNU coreutils — Core single-file hashing utilities.
- **ssdeep** [default] — See Malware section.
- **TLSH** [commonly added] — Trend Micro — Locality-sensitive fuzzy hash algorithm for file/malware similarity.

## 13. Carving and data recovery

- **bulk_extractor** [default] — See Memory/Network sections; also the canonical feature-carver for strings, network artifacts, and PAN/credit-card data.
- **ddrescue** [default] (`gddrescue`) — GNU — Damaged-media image recovery with bad-block mapping.
- **extundelete** [default] — See File System section; recovers deleted ext-family files.
- **foremost** [default] — AFOSI — Header/footer-based file carver for raw images.
- **gzrt** [default] — Gzip recovery toolkit for partially corrupt gzip streams.
- **magicrescue** [commonly added] — Carves files using "magic" recipes for specific formats.
- **PhotoRec** [default] — CGSecurity (ships with `testdisk`) — Signature-based carver that recovers hundreds of file types from images and raw media.
- **scalpel** [default] — Golden Richard — Higher-performance foremost variant with configurable signature database.
- **TestDisk** [default] — See File System section; partition/boot recovery.

## 14. Encryption, password, and cryptography tools

- **aeskeyfind / rsakeyfind** [default] — See Memory section.
- **ccrypt** [default] — Symmetric file encryption with Rijndael; useful when handling evidence archives distributed under ccrypt.
- **chntpw** [commonly added] — Petter Nordahl-Hagen — Offline Windows SAM/registry editor for resetting local passwords or enabling accounts on mounted images.
- **cmospwd** [default] — Recovers BIOS/CMOS passwords from stored dumps.
- **cryptsetup** [default] — Manages LUKS/dm-crypt encrypted volumes, required for mounting encrypted Linux evidence.
- **dislocker** [default] — BitLocker decryption that exposes BitLocker volumes as raw NTFS; complements `libbde`.
- **hashcat** [commonly added] — GPU-accelerated password recovery supporting hundreds of hash and cipher types.
- **hydra / hydra-gtk** [default] — THC — Parallelized online password-guessing for SSH, RDP, SMB, HTTP, and dozens more protocols.
- **John the Ripper (`john`)** [commonly added] — Openwall — Password cracker with rule-based and wordlist attacks; retained in DFIR curricula though not in the current init.sls.
- **ncrack** [commonly added] — Nmap project — Network authentication cracker complementary to hydra.
- **ophcrack / ophcrack-cli** [default] — Objectif Sécurité — Rainbow-table-based Windows LM/NTLM password cracker.
- **samdump2** [default] — Extracts NT/LM hashes from offline Windows SAM hives using the SYSTEM hive's SYSKEY.
- **stunnel4** [default] — TLS wrapper for integrating legacy tools with encrypted channels during evidence collection.

## 15. Metadata and file-type analysis

- **binwalk** [commonly added] — ReFirmLabs — Firmware analysis tool identifying, extracting, and carving embedded files/filesystems from binary blobs.
- **exif** [default] — Command-line EXIF reader/writer for JPEG metadata.
- **exiftool** [commonly added] — Phil Harvey — De facto standard for reading/writing metadata across thousands of file formats; added by virtually all SIFT users.
- **file** [default] — GNU/BSD magic-number file identifier.
- **mediainfo** [commonly added] — MediaArea — Extracts codec, container, and tag metadata from audio/video.
- **pdftk-java** [default] — PDF manipulation (split, merge, stamp, metadata inspection).
- **trid** [commonly added] — Marco Pontello — Large-signature file-type identifier complementing `file`, especially for carved/unknown data.

## 16. Linux/Unix artifact analysis

- **at / crontab parsing via grep** [default] — Investigate scheduled tasks on Linux evidence.
- **e2fsprogs** [default] — `debugfs`, `dumpe2fs`, `tune2fs`, `e2image` — ext2/3/4 inspection, journal access, and metadata imaging.
- **exfat-fuse / exfat-extras** [default] — Mount and inspect exFAT volumes.
- **extundelete** [default] — See File System section.
- **ntfs-3g** [default] — Read/write NTFS support with forensic-safe `ro,show_sys_files,streams_interface=windows` options.
- **Standard Unix evidence utilities** [default] — `lastlog`, `who`, `last`, `utmpdump`, shell-history introspection, and `find`-based artifact discovery against mounted Linux evidence using the default shell toolkit.
- **xfsprogs** [default] — See File System section.

## 17. macOS artifact analysis

- **libfsapfs-tools (fsapfsinfo, fsapfsmount)** [default] — libyal — Parse and mount APFS volumes and snapshots.
- **libfvde-tools (fvdeinfo, fvdemount)** [default] — libyal — Parse/mount FileVault 2-encrypted Core Storage / HFS+ volumes.
- **libplist-utils (plistutil)** [default] — Convert Apple plist files between binary and XML.
- **plutil (plutil.pl)** [default] — HearthSim extract-scripts — Perl plist parser installed via the SIFT scripts state.
- **SANS FOR518 reference sheet (Dec 2024)** — Shipped alongside SIFT as PDF reference; lists the expected tool chain for macOS/iOS forensics.

## 18. Cloud forensics

- **AWS CLI (`aws`)** [default] — Amazon — CLI for AWS APIs used to acquire EBS snapshots, CloudTrail logs, S3 objects, and IAM metadata.
- **Azure CLI (`az`)** [commonly added] — Microsoft — CLI for Azure Resource Manager covering disk snapshots, activity logs, and Defender exports.
- **CloudSploit** [commonly added] — Aqua — Open-source posture/scanning tool flagging misconfigurations across AWS/Azure/GCP.
- **dfir-iris** [commonly added] — DFIR-IRIS team — Collaborative IR case-management with timeline, IOC, asset, and evidence tracking.
- **gsutil** [commonly added] — Google — CLI for Google Cloud Storage evidence collection and export.
- **Turbinia** [commonly added] — Google — Cloud-scale forensic-processing framework distributing Plaso/Volatility/grep jobs across workers for very large evidence volumes.
- **Velociraptor** [commonly added] — Rapid7/Velocidex — Endpoint monitoring, digital-forensic collection, and threat-hunting platform with a VQL query language, widely deployed alongside SIFT for fleet collection.

## 19. Scripting and DFIR Python/Perl libraries

### Core interpreters and build tooling

- **build-essential, g++, gcc, flex, pkg-config, libffi-dev, libssl-dev, libxml2-dev, libxslt-dev, libfuse-dev, libncurses, libnet1, python3-dev, python3-setuptools, python3-setuptools-rust, python3-wheel, python3-virtualenv** [default] — Compilers, headers, and Python build tooling enabling local compilation of forensic source distributions.
- **default-jre, openjdk** [default] — Java runtime/JDK supporting Autopsy, Ghidra, and Java-based analyzers.
- **ipython3** [default] — Interactive Python shell preferred for ad-hoc DFIR scripting.
- **perl + libdatetime-perl + libtext-csv-perl + libencode-perl + libparse-win32registry-perl** [default] — Perl stack supporting RegRipper and keydet89 Perl scripts.
- **python3** [default] — Primary scripting interpreter for most SIFT tooling.

### DFIR Python libraries (SaltStack `python-packages` tree)

- **artifacts** [default, via Plaso] — Log2Timeline/Google — YAML knowledge base of forensic artifact locations consumed by Plaso, Velociraptor, GRR, and Turbinia.
- **colorama, construct, distorm3, lxml, openpyxl, pillow, pycoin, pycrypto, pysocks, requests, simplejson, yara-python** [default] — Supporting Python libraries for terminal color, binary parsing, disassembly, XML/Office parsing, imaging, cryptography, HTTP, JSON, and YARA bindings used by SIFT scripts.
- **defang** [default] — Python toolkit for defanging IOCs in reports.
- **dfDateTime** [default, via Plaso] — Log2Timeline — Timezone/date-time abstraction.
- **dfVFS** [default] (`python3-dfvfs`) — Log2Timeline/Google — Digital Forensics Virtual File System for uniform access across file-system and container formats.
- **dfWinReg** [default, via Plaso] — Log2Timeline — Registry abstraction above pyregf/yarp.
- **dnspython3** [default] — DNS protocol library used for passive DNS analysis scripts.
- **dpapick** [default] — See Memory section.
- **haystack** [default] — See Memory section.
- **impacket** [commonly added] — Fortra/SecureAuth — Python library and scripts for SMB, Kerberos, MSRPC, DCERPC; extensively used for parsing Kerberos tickets, replaying authentication, and inspecting AD artifacts.
- **ioc_writer** [default] — Mandiant — Emits OpenIOC 1.1 XML for IOC exchange.
- **libyal Python bindings** [many default; others commonly added] — `libewf-python3`, `libregf-python3`, `libvshadow-python3`, `python3-pypff` are in the default package list; `pyvmdk`, `pyvhdi`, `pyqcow`, `pyfwnt`, `pylnk`, `pymsiecf`, `pyolecf`, `pyscca`, `pyesedb`, `pywrc`, `pyusnjrnl`, `pyluksde`, `pybde`, `pyfvde` are pulled in as Plaso dependencies or added via pip for scripted access to their respective formats.
- **machinae** [default] — HurricaneLabs — IOC enrichment tool against 30+ open-source intel sources.
- **pefile / python3-pefile** [default] — Python PE parser.
- **python-evtx** [default, via Plaso] — Willi Ballenthin — Python EVTX parser.
- **python-registry** [default] — Willi Ballenthin — Pure-Python REGF parser with helper scripts.
- **python3-debian, python3-redis, python3-tk, python3-xlsxwriter, python3-fuse, python3-pyqt5, python3-flowgrep** [default] — Supporting Debian packages that back DFIR tooling (database clients, GUI bindings, FUSE bindings, XLSX export, packet flow analysis).
- **timesketch** [default, python-packages state] — Google — Collaborative timeline platform (client and server components).

### SIFT-specific helpers

- **amcache** [default] — SIFT venv at `/opt/amcache/bin` wrapping `amcache.py` against `python-registry`.
- **keydet-tools suite** [default] — Harlan Carvey's `keydet89/Tools` repo, installed into `/usr/share/perl5`, providing `bodyfile.pl`, `evtparse.pl`, `evtxparse.pl`, `idxparse.pl`, `jl.pl`, `lnk.pl`, `mft.pl`, `parse.pl`, `pref.pl`, `recbin.pl`, `regslack.pl`, `regtime.pl`, `usnj.pl` and related modules.
- **packerid** [default] — SIFT venv at `/opt/packerid` running sooshie/packerid for PE packer identification.
- **plutil.pl** [default] — HearthSim extract-scripts — Perl plist parser.
- **vshot** [default] — SIFT helper script automating Volume Shadow Copy triage on top of `libvshadow` and `bulk_extractor`.

## 20. Mounting and virtualization utilities

- **avfs** [default] — See File System section.
- **bdemount** [default] — BitLocker FUSE mount via libbde.
- **dislocker** [default] — Alternative BitLocker FUSE mount.
- **docker** [default] — Container runtime used to execute containerized DFIR tools (for example Timesketch, dfir-iris, Velociraptor) without polluting the base OS.
- **ewfmount** [default] — EWF (E01) FUSE mount via libewf.
- **fvdemount** [default] — FileVault 2 FUSE mount via libfvde.
- **fsapfsmount** [default] — APFS FUSE mount via libfsapfs.
- **imount** [default] — Historical SIFT wrapper script for forensically safe read-only mounting.
- **kpartx** [default] — Exposes partitions inside loop-mounted images.
- **libguestfs (guestmount/guestfish)** [commonly added] — See File System section.
- **losetup / mount** [default] — Base Linux loop/mount stack.
- **nbd-client** [default] — Network Block Device client used for remote image mounting and with qemu-nbd.
- **open-iscsi** [default] — iSCSI initiator for attaching remote SAN-hosted evidence.
- **qemu / qemu-utils (`qemu-img`, `qemu-nbd`, `qemu-system-*`)** [default] — QEMU — Emulator/virtualizer and tooling; `qemu-nbd` exposes VM disks via NBD for mounting, and full `qemu-system` binaries support booting evidence under emulation.
- **samba / cifs-utils / winbind** [default] — Samba stack for mounting SMB shares and parsing SMB evidence.
- **vshadowmount** [default] — Volume Shadow Copy FUSE mount via libvshadow.
- **xmount** [default] — On-the-fly format conversion mount.

## 21. Miscellaneous and general-purpose tools

- **apache2** [default] — Web server used to host **CyberChef** locally at `http://localhost/cyberchef` for browser-based data manipulation (decoding, extraction, CyberChef recipes).
- **bless** [default] — GTK hex editor.
- **cabextract** [default] — Extract Microsoft CAB archives.
- **CyberChef** [default, hosted by apache2] — GCHQ — The "cyber Swiss-army knife" served locally for encoding, decoding, decryption, compression, and data transformation recipes.
- **epic5** [default] — IRC client.
- **ent** [default] — Tests byte-stream randomness/entropy (useful for detecting encryption/compression).
- **exfat-extras / exfat-fuse** [default] — exFAT support.
- **fdupes** [default] — Identifies duplicate files across directory trees.
- **feh, gthumb** [default] — Fast image viewers for reviewing carved images.
- **ghex, hexedit, vbindiff, xxd** [default] — Hex viewers/editors/diff.
- **git** [default] — VCS; used for installing tools from source and cloning investigation notes.
- **graphviz, xdot** [default] — Graph rendering for call graphs, entity diagrams, and timeline visualization.
- **htop** [default] — Interactive process viewer.
- **kdiff3** [default] — 3-way file comparison and merging.
- **magnus** [default] — GTK screen magnifier for examining small details in images/screenshots.
- **netpbm** [default] — Image-format conversion suite used in carving pipelines.
- **okular** [default] — KDE document viewer supporting PDF/PostScript/CHM for evidence review.
- **onboard, orca** [default] — On-screen keyboard and screen reader for accessibility.
- **p7zip-full, rar, unrar, tofrodos** [default] — Archive extraction and line-ending conversion.
- **phonon** [default] — Multimedia backend used by KDE-based analysis tools.
- **powershell** [default] — Microsoft — PowerShell 7+ on Linux, enabling execution of PowerShell-based DFIR scripts (AD auditing, O365 parsing) inside SIFT.
- **pv** [default] — Pipe viewer for progress monitoring of long imaging/hashing pipelines.
- **SANS DFIR posters and cheat sheets** [default] — The `sift.config.user.pdfs` state downloads: DFIR Threat Intelligence Poster, Network Forensics Poster, SIFT & REMnux Poster, Smartphone Forensics Poster, SIFT Workstation Cheat Sheet, Windows-to-Unix Cheat Sheet, Hex & Regex Forensics Cheat Sheet.
- **tcl, blt, virtuoso-minimal** [default] — Tcl/Tk runtime and supporting libraries.
- **transmission** [default] — BitTorrent client used for retrieving large public datasets (malware corpora, forensic images).
- **tree, less, grep, awk, sed, hexdump, dd** [default] — Core GNU utilities used throughout every DFIR workflow.
- **vim** [default] — Editor used for scripting and annotating artifacts.
- **zenity** [default] — GTK dialog utility used by wrapper scripts for simple interactive prompts.

## 22. SIFT CLI, Cast, and update notes

**Cast (recommended).** The Go-based installer `ekristen/cast` is now the primary install path for SIFT. A typical invocation is `sudo cast install teamdfir/sift` for a full desktop build or `sudo cast install --mode=server teamdfir/sift-saltstack` for a headless/WSL build. Cast performs signature verification, pulls the latest saltstack release (built monthly), and applies it against Ubuntu 22.04 Jammy.

**Legacy SIFT CLI (`sift`).** The Node.js `sift-cli` was deprecated on 1 March 2023 and the repository archived, but the signed Linux binary still functions. Subcommands are `list-upgrades`, `install`, `update`, `upgrade`, `self-upgrade`, `version`, and `debug`, with `--mode=` accepting `desktop`, `server`, `complete` (legacy), or `packages-only` (legacy), plus `--pre-release`, `--version=`, `--user=`, `--no-cache`, and `--verbose`. The final pre-release was `v1.14.0-rc1` (19 Jan 2022).

**Update cadence.** The `teamdfir/sift-saltstack` repository publishes rolling releases (183+ to date, typically monthly); the SANS tools page re-publishes updated OVAs multiple times per year. The April 2026 OVA was dated 24 April 2026 and built from the March–April 2026 saltstack release line.

**Base OS.** Current builds target Ubuntu 22.04 LTS (Jammy); 20.04 Focal builds still exist but are formally deprecated; 26.04 support is tracked in repository issue #676 without a committed schedule.

**Credentials.** Default VM login is `sansforensics` / `forensics`. Escalate with `sudo su -`.

**Documentation.** There is no separate `sift.readthedocs.io`; the canonical documentation is the SANS tools page at `https://www.sans.org/tools/sift-workstation/`, the `teamdfir/sift-saltstack` README, and the SANS SIFT Cheat Sheet (v4.0, most recently published 23 October 2025 on `https://www.sans.org/posters/sift-cheat-sheet`). Companion SANS posters referenced on the appliance include Hunt Evil (updated June 2024, re-promoted 2025), Memory Forensics Cheat Sheet (Oct 2025), CTI Cheat Sheet v1.1 (Dec 2025), Malware Analysis Tips & Tricks (Mar 2025), Windows Forensic Analysis Playbook (Mar 2026), and the FOR518 macOS/iOS Reference Sheet (Dec 2024).

**Protocol SIFT.** In early 2026 SANS announced Protocol SIFT, an experimental AI-orchestration layer exposing the 200+ SIFT tools to agents via Model Context Protocol. It is installed only on demand by running the install script from `teamdfir/protocol-sift` and is **explicitly not forensically sound, not court-admissible, and not a replacement for core SIFT**. The companion "Find Evil!" hackathon ran 15 April – 15 June 2026 with a US$22,000+ prize pool for teams building autonomous IR agents on Protocol SIFT.

---

## Conclusion: the shape of SIFT in 2026

SIFT in April 2026 remains what it has always been — a curated Ubuntu LTS image packed with the classic open-source DFIR stack — but two structural shifts matter for practitioners. First, installation and updates have migrated from the Node-based SIFT CLI to **Cast**, making SIFT one of several "cast-compatible" distributions alongside REMnux and enabling consistent WSL, VM, and bare-metal provisioning from the same saltstack tree. Second, **SANS is bifurcating its SIFT narrative**: the `sift-saltstack` tree still authoritatively defines the forensically-sound base (Sleuth Kit, Plaso, Volatility 2, libyal, RegRipper, bulk_extractor, Autopsy, libewf/afflib, libbde/libfvde, YARA, ClamAV, CyberChef, and the keydet89 Perl scripts), while the newer generation of DFIR tools (Chainsaw, Hayabusa, Velociraptor, Timesketch, Turbinia, iLEAPP/ALEAPP, MVT, Hindsight, capa/FLOSS, Volatility 3, hashcat, the full Eric Zimmerman toolset, KAPE) remain **analyst-added** rather than default, and Protocol SIFT layers an explicitly experimental, non-admissible AI capability above everything.

The practical takeaway is that the SIFT VM you download in 2026 will give you every baseline primitive needed to mount, parse, carve, timeline, and triage Windows/Linux/macOS evidence out of the box, but a modern incident-response posture on SIFT still requires a deliberate, documented layer of post-install tooling — and for court-bound work, only the base image and its validated tools should be in scope.
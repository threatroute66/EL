"""Skill: IOC extractor.

Regex library that pulls indicators from arbitrary tool output. Pure Python.
Defanged inputs (1.1.1[.]1, hxxp://, evil[dot]com) are normalised before
matching. Output is grouped by indicator type and de-duplicated.

This is the foundation for STIX/MISP emission and for Threat Hunter pivots.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path


_DEFANG = [
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"hxxp(s?)://", re.IGNORECASE), r"http\1://"),
]


def refang(s: str) -> str:
    for pat, repl in _DEFANG:
        s = pat.sub(repl, s)
    return s


_IPV4 = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})(?![\d.])")
# IPv6: require at least 3 colons OR a compressed "::" — otherwise we match
# H:MM:SS timestamps, MAC fragments, and other false positives. Hex chunks
# must include at least one >2-char block to disambiguate from time formats.
_IPV6 = re.compile(
    r"(?<![\w:])"
    r"(?:"
    r"[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){3,7}"      # 4+ blocks (full IPv6)
    r"|"
    r"(?:[A-Fa-f0-9]{1,4}:)+:[A-Fa-f0-9]{0,4}(?::[A-Fa-f0-9]{1,4})*"   # ::-compressed
    r"|::[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*"        # leading ::
    r")"
    r"(?![\w:])"
)
_DOMAIN = re.compile(r"(?<![\w.-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,24})(?![\w-])")
_URL = re.compile(r"https?://[^\s'\"<>()]+", re.IGNORECASE)
_MD5 = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")
_SHA1 = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")
_SHA256 = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
_REGKEY = re.compile(r"(?:HKLM|HKCU|HKU|HKCR|HKCC|HKEY_[A-Z_]+)\\[\\\w .${}()-]{3,}", re.IGNORECASE)
_WINPATH = re.compile(r"(?:[A-Z]:\\(?:[^\\<>:\"|?*\r\n]+\\)*[^\\<>:\"|?*\r\n]+)")
# Bitcoin wallet addresses. Legacy (P2PKH / P2SH) uses Base58 (no 0/O/I/l),
# starts with '1' or '3', total length 26–35. Bech32 (native segwit) uses
# the HRP 'bc' + '1' separator + data charset and totals 42–62 chars in
# practice. Seen on BelkaCTF Kidnapper — dealer's wallets embedded in
# user notes and mbox attachments.
_BTC_LEGACY = re.compile(r"(?<![A-Za-z0-9])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])")
_BTC_BECH32 = re.compile(r"(?<![a-z0-9])bc1[ac-hj-np-z02-9]{25,60}(?![a-z0-9])")

_FILE_EXT_TLDS = {
    "pcap", "pcapng", "exe", "ex", "dll", "sys", "bin", "raw", "mem", "vmem", "lime",
    "dmp", "kdmp", "json", "txt", "csv", "log", "xml", "yaml", "yml", "toml",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "odt",
    "zip", "gz", "tar", "bz2", "xz", "rar", "7z", "iso", "img",
    "e01", "l01", "ad1", "ewf", "vhd", "vhdx", "vmdk", "ova", "ovf",
    "evtx", "etl", "wim", "reg", "lnk", "jpg", "jpeg", "png", "gif", "htm", "html",
    # Web assets — these slipped through on M57-Jean's fls bodyfile as
    # "domains" (default.css, style.css, index.html, etc.)
    "css", "scss", "less", "sass", "svg", "webp", "ico", "bmp", "tiff", "tif",
    "woff", "woff2", "ttf", "eot", "otf",
    "mp3", "mp4", "wav", "avi", "mov", "webm", "flv", "ogg", "m4a", "m4v",
    "map",           # source maps (foo.js.map)
    "md", "rst",
    "swp", "swo",    # vim swap files
    "class", "jar", "war",
    "srt", "vtt",    # captions
    "db", "db3", "sqlite", "sqlite3", "cache", "dat",
    # Not real TLDs but commonly appear in PageSpeed / CDN URL fragments
    "ce", "skimlinks",
    "py", "pyc", "sh", "bat", "ps1", "vbs", "js", "cmd", "rb", "go",
    "ini", "conf", "cfg", "tmp", "bak", "old",
    # Server-side web scripting filenames — URL path basenames like
    # c.php, r.php, click.aspx, search.jsp turn into "<c>.<php>" domains
    # and flood the cross-case overlap noise. Observed in batch-2.
    "php", "php3", "php4", "php5", "phtml",
    "asp", "aspx", "ashx", "asmx",
    "cgi", "pl", "cfm", "jsp", "jspx", "do", "action",
    "shtml", "shtm",
    # Outlook / mail formats
    "eml", "msg", "pst", "ost", "ics", "vcf",
    # Windows internals + Volatility plugin noise that surface as fake domains
    "drv", "pdb", "etl", "service", "ocx", "cpl", "msc", "mui",
    "cmdline", "dlllist", "malfind", "netscan", "netstat", "pslist",
    "psscan", "pstree", "svcscan", "filescan", "modules", "modscan",
    "envars", "hivelist", "registry", "userassist", "handles",
    # Windows filename extensions that leaked into SRL-2015/SRL-2018
    # combined-report cross-host IOC tables as fake "domains" (e.g.
    # roman.fon, batang.ttc, 6.1.1.0.mum, cabundle.cer, netlogon.ftl,
    # datastore.edb, sysmain.sdb, locale.nls, stdole2.tlb, vscan.bof,
    # prefetch *.pf, ESENT *.jfm / *.chk / *.btr).
    "pf",                   # Windows Prefetch
    "fon", "ttc", "ttcf",   # old Windows fonts + TrueType collection
    "mum",                  # Windows Update manifest
    "cat",                  # Security Catalog
    "cer", "crt", "p7b", "p7s", "p12", "pfx",  # certs masquerading as TLDs
    "sig",                  # signature blobs
    "hve",                  # registry hive backups
    "nls",                  # National Language Support
    "sdb",                  # Application Compatibility Shim DB
    "cab",                  # Windows Cabinet
    "edb", "jfm", "chk", "btr",  # ESENT / JET Blue database + log files
    "tlb",                  # Type Library
    "evt",                  # legacy Windows Event Log
    "pri", "winmd", "xbf",  # modern Windows packaging/metadata
    "manifest", "msstyles", "inf",
    "ftl",                  # Netlogon.ftl and friends
    "bof",                  # Cobalt-Strike / generic .bof (beacon object file)
    "mca", "wid", "mcs", "acm", "tsp", "srd", "jtx",
    # Misc extensions observed as fake TLDs in extraction output
    "data", "mo", "po",
}
_NOISE_DOMAINS = {
    # SRL-2018 vol3 vadyarascan validation — IOC extractor was lifting
    # `microsoft.windows`, `process.cpp`, `rescache.hit` from binary
    # strings and generating yara rules that fired 24,607 / 38 / 64
    # times in lsass+csrss alone, drowning the real attacker C2 hits
    # (shieldbase.lan, 1.3.33.17). Block them at extraction time.
    "microsoft.windows", "process.cpp", "rescache.hit",
    "microsoft.com", "microsoft.net", "windows.com", "schemas.microsoft.com",
    "openxmlformats.org", "w3.org", "google.com", "googleapis.com", "gstatic.com",
    "office.com", "live.com", "msftncsi.com", "windowsupdate.com",
    "in-addr.arpa", "ip6.arpa",
    "net.tcp", "net.pipe", "net.msmq",
    "mscorlib.dll", "system.runtime",
    "www.openssl.org",
    # Protocol/parser field names that regex sees as <word>.<word> "domains".
    # Observed in Zeek/tshark JSON outputs on every pcap case in batch-1.
    "http.host", "http.request", "http.response", "http.method", "http.uri",
    "http.user_agent", "http.referer", "http.cookie", "http.status",
    "tls.handshake", "tls.record", "tls.server_name", "tls.certificate",
    "tls.version", "tls.cipher",
    "dns.query", "dns.response", "dns.answer", "dns.qry",
    "tcp.port", "tcp.flags", "tcp.seq", "tcp.ack", "tcp.srcport", "tcp.dstport",
    "udp.port", "udp.srcport", "udp.dstport",
    "ip.src", "ip.dst", "ip.addr", "ip.proto", "ip.ttl",
    "ssl.handshake", "ssl.record",
    "x509sat.printablestring", "x509sat.utf8string", "x509sat.ia5string",
    "x509ce.keyusage", "x509ce.extkeyusage", "x509ce.basicconstraints",
    "x509af.algorithm", "x509af.signature",
    "pkix1explicit.rdnsequence",
    # Windows/Akamai CDN "domains" that surface from binary strings but
    # carry no investigative value (they're part of Windows Update's
    # delivery network).
    "winhttp.winhttprequest",
}
# Additional suffixes that indicate a fake "domain" extracted from a
# protocol field path like "http.request.method" — drop anything whose
# first label is one of these (Zeek/tshark namespace prefixes).
_NOISE_DOMAIN_PREFIXES = (
    "http.", "https.", "tls.", "ssl.", "dns.", "tcp.", "udp.",
    "ip.", "ipv4.", "ipv6.", "eth.", "icmp.",
    "x509sat.", "x509ce.", "x509af.", "x509ocsp.", "x509ext.",
    "pkix1.", "pkix1explicit.", "pkix1implicit.",
)

# X.509 / OpenSSL OID-name strings that the regex sees as `<word>.<word>`
# domains. From real OpenSSL-bearing memory dumps (nrom-01).
_X509_OPENSSL_LABELS = {
    "name.fullname", "name.relativename", "value.bykey", "value.byname",
    "value.good", "value.implicitlyca", "value.parameters", "value.revoked",
    "value.set", "value.single", "value.unknown",
    "p.onbasis", "p.other", "p.ppbasis", "p.prime", "p.tpbasis",
    "d.cpsuri", "d.data", "d.digest", "d.directoryname", "d.dnsname",
    "d.edipartyname", "d.encrypted", "d.enveloped", "d.ipaddress", "d.other",
    "d.othername", "d.registeredid", "d.sign", "d.usernotice",
    "cert.pem", "faq.html",
}

# Well-known cryptographic constants that look like SHA-256 hashes but are
# fixed curve generator coordinates / standard parameters embedded in OpenSSL,
# Bitcoin, and other crypto libraries. Surface as IOCs only if explicitly asked.
_CRYPTO_CONSTANTS = {
    # secp256k1 (Bitcoin) generator G
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    # secp256k1 group order n
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    # secp256r1 / NIST P-256 generator G
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    # secp256r1 prime p
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    # secp384r1 prime p (truncated to first 64 chars when parsed)
    # NIST P-384 / P-521 — surface only if non-noise contexts demand it
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
}
_PRIVATE_IPS = (
    "0.", "10.", "127.", "169.254.", "224.", "239.", "255.",
    "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def _filter_ipv4(ips: Iterable[str]) -> set[str]:
    out = set()
    for ip in ips:
        if any(ip.startswith(p) for p in _PRIVATE_IPS):
            continue
        # Drop version-number patterns: X.0.0.0 (e.g. "Software 3.0.0.0" from
        # version banners). Real public IPs ending in .0.0.0 are technically
        # valid but rarely appear as C2 indicators in practice.
        octets = ip.split(".")
        if len(octets) == 4 and octets[1:] == ["0", "0", "0"]:
            continue
        out.add(ip)
    return out


_WINDOWS_INTERNALS_PREFIXES = (
    "ntkrnlmp", "winspool", "fontdrvhost", "diagnosticshub", "macompatsvc",
    "system32", "syswow64", "dwm", "csrss", "lsass", "svchost",
    "rundll32", "regsvr32", "wininit", "smss", "wuauserv",
)


def _filter_domains(domains: Iterable[str]) -> set[str]:
    out = set()
    for d in domains:
        d = d.lower().rstrip(".")
        if d in _NOISE_DOMAINS:
            continue
        if d in _X509_OPENSSL_LABELS:
            continue
        if any(d.endswith("." + n) for n in _NOISE_DOMAINS):
            continue
        if any(d.startswith(p) for p in _NOISE_DOMAIN_PREFIXES):
            continue
        if "." not in d:
            continue
        tld = d.rsplit(".", 1)[-1]
        if tld.isdigit() or tld in _FILE_EXT_TLDS:
            continue
        # Drop fragments that look like memory-dumped strings (1.xxx, 2.xxx, ...)
        head = d.split(".", 1)[0]
        if head.isdigit() and len(head) <= 3 and any(c == "x" for c in tld):
            continue
        # Drop Windows internals that masquerade as FQDNs
        if any(d.startswith(p) for p in _WINDOWS_INTERNALS_PREFIXES):
            continue
        # Require domain label structure: at least one label of >=3 chars
        labels = d.split(".")
        if not any(len(l) >= 3 and not l.isdigit() for l in labels):
            continue
        out.add(d)
    return out


_EMPTY_IOCS = {k: set() for k in ("ipv4", "ipv6", "domain", "url", "md5", "sha1",
                                   "sha256", "email", "regkey", "winpath", "btc")}


def _filter_btc_legacy(addrs: set[str]) -> set[str]:
    """Base58 regex yields plenty of noise (random tokens, short hex strings,
    bearer tokens). Real BTC legacy addresses are mixed alphanumeric with at
    least one digit AND both cases AND one uppercase in the body."""
    out: set[str] = set()
    for a in addrs:
        body = a[1:]
        if not any(c.isdigit() for c in body):
            continue
        if not any(c.isupper() for c in body):
            continue
        if not any(c.islower() for c in body):
            continue
        out.add(a)
    return out


def extract(text: str, drop_noise: bool = True,
            source_kind: str | None = None) -> dict[str, set[str]]:
    """Extract IOCs from arbitrary text.

    `source_kind` restricts which IOC classes are attempted based on the
    source type — avoids the class of FP where a file-path listing gets
    every `foo.css` / `foo.html` / `foo.ini` basename emitted as a
    "domain". Known kinds:

        "fs_paths"  — fls bodyfiles, mactime CSVs. Path listings contain
                       plenty of filename.extension shapes but vanishingly
                       few real FQDNs/URLs/emails. We skip domain, url,
                       email regex entirely and keep hashes + ipv4/ipv6
                       + registry keys + win paths.
        "network"   — pcap/HTTP/DNS extracts. Full IOC set.
        "log"       — EVTX/syslog/log text. Full IOC set.
        None        — legacy behaviour: full IOC set.
    """
    if not text:
        return {k: set() for k in _EMPTY_IOCS}
    t = refang(text)

    if source_kind == "fs_paths":
        # Filesystem path listings: only extract indicator classes that
        # genuinely appear in them. Domains/URLs/emails here are almost
        # entirely filename-extension or path-fragment FPs.
        ipv4 = set(_IPV4.findall(t))
        ipv6 = {m for m in _IPV6.findall(t) if ":" in m and len(m) > 4}
        md5 = {h.lower() for h in _MD5.findall(t)}
        sha1 = {h.lower() for h in _SHA1.findall(t)} - md5
        sha256 = {h.lower() for h in _SHA256.findall(t)} - _CRYPTO_CONSTANTS
        regkey = set(m.rstrip("\\") for m in _REGKEY.findall(t))
        winpath = set(_WINPATH.findall(t))
        if drop_noise:
            ipv4 = _filter_ipv4(ipv4)
            sha1 = sha1 - {h for h in sha1 if len(h) != 40}
        return {"ipv4": ipv4, "ipv6": ipv6, "domain": set(), "url": set(),
                "md5": md5, "sha1": sha1, "sha256": sha256, "email": set(),
                "regkey": regkey, "winpath": winpath, "btc": set()}

    ipv4 = set(_IPV4.findall(t))
    ipv6 = {m for m in _IPV6.findall(t) if ":" in m and len(m) > 4}
    domain = set(_DOMAIN.findall(t))
    url = set(_URL.findall(t))
    # Hashes are case-insensitive in practice; case-fold for dedup.
    # Drop well-known crypto library constants (curve generators, NIST primes)
    # that look like real SHA-256 hashes but are fixed parameters from OpenSSL,
    # Bitcoin's secp256k1, and similar libraries.
    md5 = {h.lower() for h in _MD5.findall(t)}
    sha1 = {h.lower() for h in _SHA1.findall(t)} - md5
    sha256 = {h.lower() for h in _SHA256.findall(t)} - _CRYPTO_CONSTANTS
    email = set(_EMAIL.findall(t))
    regkey = set(m.rstrip("\\") for m in _REGKEY.findall(t))
    winpath = set(_WINPATH.findall(t))
    btc_legacy = set(_BTC_LEGACY.findall(t))
    btc_bech32 = set(_BTC_BECH32.findall(t))

    if drop_noise:
        ipv4 = _filter_ipv4(ipv4)
        domain = _filter_domains(domain)
        sha1 = sha1 - {h for h in sha1 if len(h) != 40}
        url = {u for u in url if not any(_filter_domains({u.split('/')[2]}) == set() for _ in [0])}
        btc_legacy = _filter_btc_legacy(btc_legacy)
    btc = btc_legacy | btc_bech32

    return {"ipv4": ipv4, "ipv6": ipv6, "domain": domain, "url": url,
            "md5": md5, "sha1": sha1, "sha256": sha256, "email": email,
            "regkey": regkey, "winpath": winpath, "btc": btc}


def apply_umbrella_filter(iocs: dict[str, set[str] | list[str]],
                            *, threshold: int = 50_000
                            ) -> dict[str, set[str] | list[str]]:
    """Strip popular domains (and the URLs / IPs anchored to them)
    from a freshly-extracted IOC dict using the Cisco Umbrella
    top-1M allowlist. Operates in-place on a *copy* — original
    input is unchanged.

    Opt-in noise filter: callers that want long-tail-only
    indicators (network_analyst before emitting domain-bearing
    findings; coordinator before writing the IOC catalog) call
    this once. When no Umbrella CSV is staged
    (``EL_UMBRELLA_TOP1M`` unset and the default path missing),
    the cached allowlist is empty and this is a no-op — the
    return is identical to the input. Default-to-fire-findings.
    """
    from el.skills.umbrella_allowlist import cached
    al = cached()
    if not al.loaded:
        return {k: (set(v) if isinstance(v, set) else list(v))
                for k, v in iocs.items()}
    out: dict[str, set[str] | list[str]] = {}
    for k, v in iocs.items():
        if k == "domain":
            kept = {d for d in v
                    if not al.is_top(d, threshold=threshold)}
            out[k] = kept if isinstance(v, set) else list(kept)
        elif k == "url":
            kept_u: set[str] = set()
            for u in v:
                # Pull host from `scheme://host/...`; fall back to the
                # raw URL if it's malformed (regex shouldn't but be
                # defensive).
                host = u.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
                if not al.is_top(host, threshold=threshold):
                    kept_u.add(u)
            out[k] = kept_u if isinstance(v, set) else list(kept_u)
        else:
            out[k] = set(v) if isinstance(v, set) else list(v)
    return out


# Path shapes that are exclusively filesystem path listings — for these we
# want to apply source_kind="fs_paths" so domain/url/email regex are skipped.
_FS_PATH_FILENAMES = {
    "fls.txt", "mactime.txt", "mactime.csv",
    "directory-listing.txt",  # triage's directory inventory
}
_FS_PATH_PATTERNS = ("fls_", "mactime_")  # e.g. fls_o63.txt, mactime_part1.csv


# Paths that MUST NOT be re-scanned for IOCs. These are downstream outputs
# of EL itself (ACH matrix, report markdown, STIX bundle, YARA rules) or
# global state (the knowledge DB). Re-scanning them creates a feedback
# loop where the case's own upstream output becomes input for the next
# pass, amplifying every extraction anomaly.
#
# Observed degradation (pre-fix): Cool EK (560 KB pcap) produced a 229 MB
# iocs.json in ~40 s because the 98 MB global knowledge.sqlite and a 12 MB
# ach_matrix.json were re-parsed as text on every post-red-reviewer pass.
_SKIP_FILENAMES = {
    "ach_matrix.json",        # ACH engine's own matrix (downstream)
    "knowledge.sqlite",       # global cross-case store (binary, Layer-3)
    "stix-bundle.json",       # STIX output (downstream)
    "report.md",              # report markdown (downstream)
    "transitions.json",       # coordinator state log
    "manifest.json",          # intake manifest
    "seal.json",              # case seal manifest
    "iocs.json",              # our own output from the previous pass
    "CLAUDE.md",              # per-case auto-gen doc
    "case_iocs.yar",          # threat_hunter's auto-generated rules
}
# Directory names — any path UNDER these (relative to case dir) is skipped.
_SKIP_PARENT_DIRS = {
    "reports",                # case_dir/reports/
    "_archives",              # cases/_archives/
}
# Magic-byte prefixes for binary formats that regex-scanning produces only
# junk from. Also guards against someone pointing extract_from_paths at a
# case archive or raw image accidentally.
_BINARY_MAGICS = (
    b"SQLite format 3\x00",   # sqlite3
    b"\x1f\x8b",              # gzip
    b"PK\x03\x04",            # zip / .tar.gz sidecar
    b"KUZU ",                 # Kùzu graph db
)
# Size cap — any evidence path bigger than this is skipped. Real textual
# evidence (tshark JSON, EVTX CSV, bulk_extractor output) stays well under
# this. 10 MB is a loose bound.
_MAX_EVIDENCE_BYTES = 10 * 1024 * 1024


def _source_kind_for(path: Path) -> str | None:
    """Classify a path for IOC extraction. Returns a source_kind string
    suitable for extract()'s argument. None = no restriction (legacy)."""
    name = path.name.lower()
    if name in _FS_PATH_FILENAMES:
        return "fs_paths"
    for pat in _FS_PATH_PATTERNS:
        if name.startswith(pat):
            return "fs_paths"
    return None


def _should_skip_path(path: Path) -> tuple[bool, str]:
    """Return (skip, reason). Cheap checks first."""
    name = path.name
    if name in _SKIP_FILENAMES:
        return True, f"downstream output ({name})"
    for parent in path.parents:
        if parent.name in _SKIP_PARENT_DIRS:
            return True, f"under skipped dir ({parent.name})"
    try:
        st = path.stat()
    except OSError:
        return True, "stat failed"
    if st.st_size > _MAX_EVIDENCE_BYTES:
        return True, f"size > {_MAX_EVIDENCE_BYTES} bytes ({st.st_size})"
    if st.st_size == 0:
        return True, "empty"
    # Binary magic sniff
    try:
        with path.open("rb") as f:
            head = f.read(16)
        for magic in _BINARY_MAGICS:
            if head.startswith(magic):
                return True, f"binary ({magic!r})"
    except OSError:
        return True, "read failed"
    return False, ""


def extract_from_paths(paths: Iterable[str | Path]) -> dict[str, set[str]]:
    """Read each path, pick an appropriate source_kind, union the IOCs.

    Paths are read at most once — duplicates in the input are deduplicated
    before extraction to avoid re-scanning large bodyfiles N times (observed:
    27-finding run × several refs to mactime.txt blew past 9 min in STIX).

    Downstream EL outputs (ach_matrix.json, knowledge.sqlite, stix-bundle.json,
    report.md, the global knowledge DB, files > 10 MB, binary formats) are
    skipped — re-scanning them produces a feedback loop where the case's
    own output becomes input for the next pass, amplifying every extraction
    anomaly (observed: Cool EK produced a 229 MB iocs.json with 40 k
    hallucinated URLs because a 98 MB knowledge.sqlite was re-scanned).
    """
    merged: dict[str, set[str]] = {}
    seen_paths: set[Path] = set()
    for p in paths:
        pth = Path(p)
        if pth in seen_paths:
            continue
        seen_paths.add(pth)
        skip, _reason = _should_skip_path(pth)
        if skip:
            continue
        try:
            text = pth.read_text(errors="ignore")
        except Exception:
            continue
        kind = _source_kind_for(pth)
        for k, v in extract(text, source_kind=kind).items():
            merged.setdefault(k, set()).update(v)
    return merged


# Structured-fact keys that carry actor-relevant IPs the path-level
# extractor's _filter_ipv4 would otherwise drop as RFC1918. Set by
# `lateral_movement_analyst` (RDP / WinRM source IPs) and any future
# agent that wants to surface internal-network pivots as IOCs in
# enterprise APT cases — the SRL-2018 dmz-ftp pattern, where
# `172.16.5.26 → rsydow → dmz-ftp` is the load-bearing pivot.
_FACT_IP_KEYS = ("source_ip", "source_ips", "src_ip", "src_ips",
                  "target_host", "remote_host")


def extract_from_finding_facts(findings) -> dict[str, set[str]]:
    """Walk findings' evidence.extracted_facts for IP-shaped values
    in `_FACT_IP_KEYS`. Returns the same {kind: set} shape as
    `extract_from_paths` so callers can union the results.

    Bypasses `_filter_ipv4` so RFC1918 lateral-pivot IPs land in the
    case IOC catalog. Public IPs surfaced this way are a strict
    superset of what the path scan finds; merging is set-union.
    """
    out: dict[str, set[str]] = {"ipv4": set(), "ipv6": set()}
    ipv4_re = _IPV4
    ipv6_re = _IPV6
    for f in findings:
        for ev in getattr(f, "evidence", []) or []:
            facts = getattr(ev, "extracted_facts", None) or {}
            for key in _FACT_IP_KEYS:
                v = facts.get(key)
                vals: list[str] = []
                if isinstance(v, str) and v:
                    vals = [v]
                elif isinstance(v, list):
                    vals = [x for x in v if isinstance(x, str) and x]
                for s in vals:
                    if ipv4_re.fullmatch(s):
                        out["ipv4"].add(s)
                    elif ipv6_re.fullmatch(s):
                        out["ipv6"].add(s)
                    else:
                        # Some agents pass "ip×count" or "ip (×n)";
                        # extract the leading address.
                        m = ipv4_re.search(s)
                        if m:
                            out["ipv4"].add(m.group(0))
    return out

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
    # Outlook / mail formats
    "eml", "msg", "pst", "ost", "ics", "vcf",
    # Windows internals + Volatility plugin noise that surface as fake domains
    "drv", "pdb", "etl", "service", "ocx", "cpl", "msc", "mui",
    "cmdline", "dlllist", "malfind", "netscan", "netstat", "pslist",
    "psscan", "pstree", "svcscan", "filescan", "modules", "modscan",
    "envars", "hivelist", "registry", "userassist", "handles",
}
_NOISE_DOMAINS = {
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
                                   "sha256", "email", "regkey", "winpath")}


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
                "regkey": regkey, "winpath": winpath}

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

    if drop_noise:
        ipv4 = _filter_ipv4(ipv4)
        domain = _filter_domains(domain)
        sha1 = sha1 - {h for h in sha1 if len(h) != 40}
        url = {u for u in url if not any(_filter_domains({u.split('/')[2]}) == set() for _ in [0])}

    return {"ipv4": ipv4, "ipv6": ipv6, "domain": domain, "url": url,
            "md5": md5, "sha1": sha1, "sha256": sha256, "email": email,
            "regkey": regkey, "winpath": winpath}


# Path shapes that are exclusively filesystem path listings — for these we
# want to apply source_kind="fs_paths" so domain/url/email regex are skipped.
_FS_PATH_FILENAMES = {
    "fls.txt", "mactime.txt", "mactime.csv",
    "directory-listing.txt",  # triage's directory inventory
}
_FS_PATH_PATTERNS = ("fls_", "mactime_")  # e.g. fls_o63.txt, mactime_part1.csv


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


def extract_from_paths(paths: Iterable[str | Path]) -> dict[str, set[str]]:
    """Read each path, pick an appropriate source_kind, union the IOCs.

    Paths are read at most once — duplicates in the input are deduplicated
    before extraction to avoid re-scanning large bodyfiles N times (observed:
    27-finding run × several refs to mactime.txt blew past 9 min in STIX).
    """
    merged: dict[str, set[str]] = {}
    seen_paths: set[Path] = set()
    for p in paths:
        pth = Path(p)
        if pth in seen_paths:
            continue
        seen_paths.add(pth)
        try:
            text = pth.read_text(errors="ignore")
        except Exception:
            continue
        kind = _source_kind_for(pth)
        for k, v in extract(text, source_kind=kind).items():
            merged.setdefault(k, set()).update(v)
    return merged

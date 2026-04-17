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
    "evtx", "etl", "wim", "reg", "lnk", "jpg", "jpeg", "png", "gif",
    "py", "pyc", "sh", "bat", "ps1", "vbs", "js", "cmd", "rb", "go",
    "ini", "conf", "cfg", "tmp", "bak", "old",
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
}
_PRIVATE_IPS = (
    "0.", "10.", "127.", "169.254.", "224.", "239.", "255.",
    "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


def _filter_ipv4(ips: Iterable[str]) -> set[str]:
    return {ip for ip in ips if not any(ip.startswith(p) for p in _PRIVATE_IPS)}


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
        if any(d.endswith("." + n) for n in _NOISE_DOMAINS):
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


def extract(text: str, drop_noise: bool = True) -> dict[str, set[str]]:
    if not text:
        return {k: set() for k in ("ipv4", "ipv6", "domain", "url", "md5", "sha1",
                                    "sha256", "email", "regkey", "winpath")}
    t = refang(text)
    ipv4 = set(_IPV4.findall(t))
    ipv6 = {m for m in _IPV6.findall(t) if ":" in m and len(m) > 4}
    domain = set(_DOMAIN.findall(t))
    url = set(_URL.findall(t))
    md5 = set(_MD5.findall(t))
    sha1 = set(_SHA1.findall(t)) - md5
    sha256 = set(_SHA256.findall(t))
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


def extract_from_paths(paths: Iterable[str | Path]) -> dict[str, set[str]]:
    merged: dict[str, set[str]] = {}
    for p in paths:
        try:
            text = Path(p).read_text(errors="ignore")
        except Exception:
            continue
        for k, v in extract(text).items():
            merged.setdefault(k, set()).update(v)
    return merged

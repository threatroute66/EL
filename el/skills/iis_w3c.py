"""Skill: parse IIS W3C Extended log format + flag web-shell / recon patterns.

IIS logs at `C:\\inetpub\\logs\\LogFiles\\W3SVC<siteid>\\u_ex*.log` are
the authoritative record of HTTP activity on a Windows web server —
every case where the attacker landed through an .aspx upload, ran a
webshell, or pivoted via the admin panel leaves first-order evidence
in these files that EVTX alone doesn't capture. Current EL:
`disk_forensicator` extracts them as opaque artefacts; nothing parses.

Format (W3C Extended):

    #Software: Microsoft Internet Information Services 10.0
    #Version: 1.0
    #Date: 2025-01-01 00:00:00
    #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port
             cs-username c-ip cs(User-Agent) cs(Referer) sc-status …
    2025-01-01 00:00:01 10.0.0.1 POST /api/upload.aspx - 443 - 1.2.3.4 …

Space-separated fields declared by a `#Fields:` line that may change
mid-file (IIS re-emits the header on restart). Parser is strict about
re-reading `#Fields:`, tolerant of unquoted single-token values.

Detectors are pure rule-based:

- ``W3C_WEBSHELL_URI_SHAPE`` — URI-stem basename matches a known
  webshell / file-drop token (cmd.aspx, shell.aspx, c99.php, r57.php,
  ma.jsp, tunnel.aspx, …) OR query string contains encoded command
  tokens (`cmd=`, `exec=`, `eval=`, base64-decode cradles).

- ``W3C_SCRIPTED_CLIENT`` — User-Agent matches an automation token
  (go-http-client, python-requests, curl, wget, powershell, nmap,
  sqlmap, dirb, gobuster, masscan, nuclei). Legit sometimes; flagged
  medium confidence so the analyst can correlate with other signals.

- ``W3C_UPLOAD_POST_BURST`` — ≥3 POSTs to the same URI stem ending in
  `.aspx`/`.asp`/`.ashx`/`.php`/`.jsp` from a single c-ip, where at
  least one returned `200`. Web-shell upload + subsequent reuse.

- ``W3C_ADMIN_URI_HIT`` — successful (2xx/3xx) request to a well-
  known admin / config path (/admin/, /wp-admin/, /phpmyadmin/,
  /manager/, /.env, /.git/, /config.php) from a public c-ip.

- ``W3C_VERB_TUNNEL`` — high rate of PROPFIND / PUT / DELETE /
  OPTIONS / TRACE (methods commonly abused as tunnels).

Pure functions, standard-library only. `scan_path(path)` streams a
file line-by-line so gigabyte-scale logs don't materialise in memory.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


# Webshell / dropper file-name tokens observed across public webshell
# collections (b374k, china-chopper, c99, r57, weevely) and the SANS
# webshell detection cheat-sheet. URI basename match only.
_WEBSHELL_BASENAMES = frozenset({
    "cmd.aspx", "cmd.asp", "cmd.ashx", "cmd.jsp", "cmd.php",
    "shell.aspx", "shell.asp", "shell.ashx", "shell.jsp", "shell.php",
    "c99.php", "r57.php", "wso.php", "b374k.php", "weevely.php",
    "china.aspx", "chopper.aspx", "china.php",
    "tunnel.aspx", "reverse.aspx", "upload.aspx", "uploader.aspx",
    "ma.jsp", "cmdjsp.jsp", "jspspy.jsp",
    "backdoor.aspx", "bd.aspx", "simpleshell.aspx",
    "iiscmd.aspx", "iis_cmd.aspx",
    "eval.php", "test.php", "info.php",   # low signal, kept — infosec
})

# Query-string tokens that show up in webshell URIs + RFI / LFI probes.
_WEBSHELL_QUERY_TOKENS = (
    "cmd=", "exec=", "eval=", "query=", "shell=",
    "system(", "passthru(", "shell_exec(",
    "base64_decode(", "FromBase64String(",
    "%00",              # null-byte inclusion
    "../../",           # path traversal
    "..%2f..%2f",
    "etc/passwd", "boot.ini", "web.config",
)

# Scripted-client UAs. Split into strong (always flag medium) and
# weak (only flag on 2xx burst) per SIFT network SKILL guidance.
_UA_STRONG = (
    "sqlmap", "nikto", "nmap scripting engine", "masscan",
    "zgrab", "zmap", "nuclei", "gobuster", "dirbuster", "dirb",
    "wpscan", "ffuf", "hydra", "metasploit",
)
_UA_WEAK = (
    "curl/", "wget/", "go-http-client", "python-requests",
    "python-urllib", "libwww-perl", "powershell", "invoke-webrequest",
    "httpclient", "java/", "okhttp", "axios/", "ruby", "requests",
)

# Admin / config paths that should not be reachable from public IPs.
_ADMIN_PATHS = (
    "/admin/", "/administrator/", "/wp-admin/", "/wp-login.php",
    "/phpmyadmin/", "/pma/", "/myadmin/",
    "/manager/html", "/manager/status",
    "/.env", "/.git/", "/.svn/", "/.aws/",
    "/config.php", "/setup.php", "/install.php",
    "/owa/", "/ecp/", "/autodiscover/",     # Exchange admin panels
    "/rpc/", "/ews/exchange.asmx",
)

# Suspicious verbs — RFC-defined but almost always abusive in public-
# web contexts.
_VERB_TUNNEL = ("PROPFIND", "PUT", "DELETE", "OPTIONS", "TRACE",
                 "MKCOL", "COPY", "MOVE", "LOCK")

_PRIVATE_IPV4 = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|"
    r"169\.254\.|100\.6[4-9]\.|100\.[7-9]\d\.|100\.1[01]\d\.|100\.12[0-7]\.)"
)


def _is_private(ip: str) -> bool:
    return bool(_PRIVATE_IPV4.match(ip or ""))


@dataclass
class Hit:
    pattern_id: str
    description: str
    matches: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    attack_techniques: list[tuple[str, str]] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.matches)


@dataclass
class ScanResult:
    path: Path
    total_lines: int = 0
    parsed_rows: int = 0
    hits: list[Hit] = field(default_factory=list)


def _norm_field(name: str) -> str:
    # IIS uses cs(User-Agent) / cs(Referer) — normalise to cs-user-agent /
    # cs-referer so downstream lookups are stable across header variants.
    n = name.strip().lower()
    n = n.replace("(", "-").replace(")", "")
    return n


def _split_row(line: str) -> list[str]:
    # IIS doesn't quote fields — values are single tokens, '-' for empty.
    return line.rstrip("\r\n").split(" ")


def scan_path(path: Path, *, max_rows: int = 500_000) -> ScanResult:
    """Stream one W3C-formatted log file; return collected Hits.

    Parameters
    ----------
    path : Path
        Target u_ex*.log file.
    max_rows : int
        Safety cap — IIS logs on busy servers run into tens of millions
        of lines. We stop after `max_rows`; detectors still emit on
        what was seen.
    """
    path = Path(path)
    result = ScanResult(path=path)
    if not path.is_file():
        return result

    # Per-source POST tracker for UPLOAD_POST_BURST
    uploads: dict[tuple[str, str], list[tuple[str, int]]] = defaultdict(list)
    webshell_uri: list[str] = []
    scripted_strong: list[str] = []
    scripted_weak_200: list[str] = []
    admin_hits: list[str] = []
    verb_tunnel: Counter = Counter()

    fields: list[str] = []
    with path.open("r", errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            if lineno > max_rows:
                break
            result.total_lines += 1
            if not raw.strip():
                continue
            if raw.startswith("#"):
                if raw.lower().startswith("#fields:"):
                    fields = [_norm_field(t) for t in raw[len("#Fields:"):].split()]
                continue
            if not fields:
                continue
            row = _split_row(raw)
            if len(row) < len(fields):
                continue
            result.parsed_rows += 1

            def g(name: str) -> str:
                try:
                    return row[fields.index(name)]
                except (ValueError, IndexError):
                    return ""

            method = g("cs-method").upper()
            uri = g("cs-uri-stem")
            query = g("cs-uri-query")
            c_ip = g("c-ip")
            ua = g("cs-user-agent").lower()
            status = g("sc-status")

            uri_basename = uri.rsplit("/", 1)[-1].lower() if uri else ""

            # Webshell-shape URI
            if uri_basename in _WEBSHELL_BASENAMES or (
                query and any(tok in query.lower()
                              for tok in _WEBSHELL_QUERY_TOKENS)
            ):
                if len(webshell_uri) < 50:
                    webshell_uri.append(
                        f"{c_ip} {method} {uri}"
                        + (f"?{query[:120]}" if query and query != "-" else "")
                        + f" → {status}"
                    )

            # Scripted client
            if ua and ua != "-":
                if any(t in ua for t in _UA_STRONG):
                    if len(scripted_strong) < 50:
                        scripted_strong.append(f"{c_ip} UA={ua[:100]} {method} {uri}")
                elif any(t in ua for t in _UA_WEAK) and status.startswith("2"):
                    if len(scripted_weak_200) < 50:
                        scripted_weak_200.append(
                            f"{c_ip} UA={ua[:100]} {method} {uri} → {status}"
                        )

            # Admin-path success from public IP
            uri_low = uri.lower() if uri else ""
            if (uri_low and any(uri_low.startswith(p) for p in _ADMIN_PATHS)
                    and status and (status.startswith(("2", "3")))
                    and c_ip and not _is_private(c_ip)):
                if len(admin_hits) < 50:
                    admin_hits.append(f"{c_ip} {method} {uri} → {status}")

            # Upload POST burst bookkeeping
            script_exts = (".aspx", ".asp", ".ashx", ".php", ".jsp", ".jspx")
            if (method == "POST" and uri_low.endswith(script_exts) and c_ip):
                uploads[(c_ip, uri)].append((status, lineno))

            # Verb-tunnel counter
            if method in _VERB_TUNNEL:
                verb_tunnel[method] += 1

    # Assemble hits
    if webshell_uri:
        result.hits.append(Hit(
            pattern_id="W3C_WEBSHELL_URI_SHAPE",
            description=(
                "HTTP request whose URI basename matches a known "
                "webshell / file-drop token OR whose query string "
                "carries eval / cmd / base64 / path-traversal cradles"
            ),
            matches=webshell_uri,
            hypotheses=["H_APT_ESPIONAGE", "H_INITIAL_ACCESS_WEB_SHELL"],
            attack_techniques=[
                ("T1505.003", "Server Software Component: Web Shell"),
                ("T1190", "Exploit Public-Facing Application"),
            ],
        ))

    if scripted_strong:
        result.hits.append(Hit(
            pattern_id="W3C_SCRIPTED_CLIENT_OFFENSIVE",
            description=(
                "User-Agent matches an offensive-security tool "
                "(sqlmap, nikto, nmap NSE, nuclei, hydra, masscan, "
                "gobuster). Always worth flagging — these UAs do not "
                "appear in legitimate traffic to production sites."
            ),
            matches=scripted_strong,
            hypotheses=["H_SCAN_RECON"],
            attack_techniques=[
                ("T1595", "Active Scanning"),
                ("T1190", "Exploit Public-Facing Application"),
            ],
        ))

    if scripted_weak_200:
        result.hits.append(Hit(
            pattern_id="W3C_SCRIPTED_CLIENT_GENERIC",
            description=(
                "Generic scripted-client User-Agent "
                "(curl / wget / go-http-client / python-requests / "
                "powershell) received a 2xx response. Legit tooling "
                "sometimes — pair with destination URI + volume."
            ),
            matches=scripted_weak_200,
            hypotheses=["H_SCAN_RECON"],
            attack_techniques=[("T1595", "Active Scanning")],
        ))

    if admin_hits:
        result.hits.append(Hit(
            pattern_id="W3C_ADMIN_URI_HIT",
            description=(
                "Successful (2xx/3xx) request to a well-known admin / "
                "config path from a public IP (/admin, /wp-admin, "
                "/phpmyadmin, /manager, /.env, /.git, Exchange OWA/ECP). "
                "Unauthenticated success means either the guard is off "
                "or the attacker already has creds."
            ),
            matches=admin_hits,
            hypotheses=["H_APT_ESPIONAGE"],
            attack_techniques=[
                ("T1190", "Exploit Public-Facing Application"),
                ("T1078", "Valid Accounts"),
            ],
        ))

    upload_burst: list[str] = []
    for (src, uri), rows in uploads.items():
        if len(rows) < 3:
            continue
        if not any(s.startswith("2") for s, _ in rows):
            continue
        upload_burst.append(
            f"{src} POST {uri} — {len(rows)} hits, "
            f"statuses: {','.join(sorted({s for s, _ in rows}))}"
        )
    if upload_burst:
        result.hits.append(Hit(
            pattern_id="W3C_UPLOAD_POST_BURST",
            description=(
                "≥3 POST requests from a single source to the same "
                "script URI (.aspx/.php/.jsp/.ashx) with at least one "
                "2xx response. Shape of web-shell upload + reuse."
            ),
            matches=upload_burst,
            hypotheses=["H_APT_ESPIONAGE",
                        "H_INITIAL_ACCESS_WEB_SHELL"],
            attack_techniques=[
                ("T1505.003", "Server Software Component: Web Shell"),
            ],
        ))

    if sum(verb_tunnel.values()) >= 50:
        summary = ", ".join(f"{v}×{n}" for v, n in
                             verb_tunnel.most_common(5))
        result.hits.append(Hit(
            pattern_id="W3C_VERB_TUNNEL",
            description=(
                "Heavy use of methods commonly abused as tunnels "
                "(PROPFIND, PUT, DELETE, OPTIONS, TRACE, MKCOL, "
                "COPY, MOVE, LOCK). Legit in WebDAV contexts; "
                "suspicious otherwise."
            ),
            matches=[summary],
            hypotheses=["H_APT_ESPIONAGE"],
            attack_techniques=[
                ("T1190", "Exploit Public-Facing Application"),
            ],
        ))

    return result


def scan_tree(root: Path, *, max_files: int = 200) -> list[ScanResult]:
    """Walk `inetpub/logs/LogFiles/W3SVC*/` and scan every u_ex*.log."""
    root = Path(root)
    results: list[ScanResult] = []
    if not root.is_dir():
        return results
    files = sorted(root.rglob("u_ex*.log"))[:max_files]
    for f in files:
        results.append(scan_path(f))
    return results


__all__ = ["Hit", "ScanResult", "scan_path", "scan_tree"]

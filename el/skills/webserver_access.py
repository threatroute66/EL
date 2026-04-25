"""Skill: parse nginx / Apache access logs and flag web-shell, recon,
and 4xx-burst patterns.

Companion to :mod:`el.skills.iis_w3c` — same detector taxonomy, but
parses the Common / Combined Log Format Linux web servers default
to. Closes the gap-doc Linux-depth bullet "Webserver access-log
anomaly detector (nginx/Apache)" — the existing
``linux_artifacts`` skill copies ``access.log`` files into
``cases/<id>/raw/linux_artifacts/var_log/{nginx,apache2,httpd}/``;
this skill turns them into structured Hits ready for the
``linux_forensicator`` to emit findings against.

Combined Log Format (default for nginx/Apache):

    1.2.3.4 - - [01/Jan/2025:00:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "https://ref" "Mozilla/5.0 ..."

Common Log Format (older, no UA / referer):

    1.2.3.4 - - [01/Jan/2025:00:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024

Detectors mirror the IIS taxonomy so the cross-platform analyst sees
the same pattern_id family regardless of stack:

- ``WEB_WEBSHELL_URI_SHAPE`` — URI basename matches a known webshell /
  file-drop token OR query string carries cmd / eval / base64 /
  path-traversal cradles.
- ``WEB_SCRIPTED_CLIENT_OFFENSIVE`` — UA matches sqlmap / nikto /
  nuclei / gobuster / hydra / masscan.
- ``WEB_SCRIPTED_CLIENT_GENERIC`` — UA matches curl / wget / python-
  requests / go-http-client AND request returned 2xx.
- ``WEB_ADMIN_URI_HIT`` — successful (2xx/3xx) hit to admin / config
  paths from a public IP (/admin, /wp-admin, /phpmyadmin, /.env,
  /.git, /manager).
- ``WEB_4XX_RECON_BURST`` — single c-ip producing ≥30 4xx responses
  across distinct URIs (directory-busting / fuzzing shape).
- ``WEB_VERB_TUNNEL`` — heavy PROPFIND / PUT / DELETE / OPTIONS /
  TRACE / MKCOL etc.
- ``WEB_UPLOAD_POST_BURST`` — ≥3 POSTs from the same c-ip to the same
  script-URI (.php / .jsp / .cgi / .pl) with at least one 2xx.
"""
from __future__ import annotations

import gzip
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


# Combined / Common log format. The trailing referer + UA pair is
# optional (Common Log Format omits it).
_LINE_RE = re.compile(
    r'^(?P<host>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\S+)\s+'
    r'(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Detector tables — kept aligned with iis_w3c.py for cross-stack
# parity. Linux-only additions (.cgi, .pl, .py shells) bolted on.
_WEBSHELL_BASENAMES = frozenset({
    "cmd.php", "cmd.jsp", "cmd.cgi", "cmd.pl", "cmd.py",
    "shell.php", "shell.jsp", "shell.cgi", "shell.pl", "shell.py",
    "c99.php", "r57.php", "wso.php", "b374k.php", "weevely.php",
    "china.php", "chopper.php",
    "tunnel.php", "reverse.php", "upload.php", "uploader.php",
    "ma.jsp", "cmdjsp.jsp", "jspspy.jsp",
    "backdoor.php", "bd.php", "simpleshell.php",
    "eval.php", "test.php", "info.php", "phpinfo.php",
    "adminer.php", "alfa.php", "alfashell.php",
})

_WEBSHELL_QUERY_TOKENS = (
    "cmd=", "exec=", "eval=", "query=", "shell=",
    "system(", "passthru(", "shell_exec(",
    "base64_decode(",
    "%00",
    "../../",
    "..%2f..%2f",
    "etc/passwd", "etc/shadow", "boot.ini", "wp-config.php",
)

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

_ADMIN_PATHS = (
    "/admin/", "/administrator/", "/wp-admin/", "/wp-login.php",
    "/phpmyadmin/", "/pma/", "/myadmin/",
    "/manager/html", "/manager/status",
    "/.env", "/.git/", "/.svn/", "/.aws/", "/.ssh/",
    "/config.php", "/setup.php", "/install.php",
    "/server-status", "/server-info",
)

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


def _parse_request(req: str) -> tuple[str, str, str]:
    """Split the ``"GET /uri HTTP/1.1"`` request field into
    (method, full_uri, version). Returns blank tuple on malformed."""
    parts = req.split(" ")
    if len(parts) < 2:
        return "", "", ""
    method = parts[0]
    uri = parts[1]
    version = parts[2] if len(parts) >= 3 else ""
    return method, uri, version


def _split_uri(uri: str) -> tuple[str, str]:
    """Split a request-target into (path, query) at the first '?'."""
    if "?" in uri:
        path, query = uri.split("?", 1)
        return path, query
    return uri, ""


def _open(path: Path):
    """Transparent gzip-aware open. Web servers rotate via logrotate
    which gzips by default."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    return path.open("r", errors="replace")


def scan_path(path: Path,
               *, max_rows: int = 500_000,
               recon_4xx_min: int = 30,
               recon_4xx_distinct_uris: int = 10,
               ) -> ScanResult:
    """Stream one nginx/Apache access log; return collected Hits.

    ``recon_4xx_min`` and ``recon_4xx_distinct_uris`` gate the
    directory-busting detector — a single source needs that many
    4xx responses across that many distinct URIs before firing.
    Defaults are tuned to gobuster / dirb burst shape.
    """
    path = Path(path)
    result = ScanResult(path=path)
    if not path.is_file():
        return result

    uploads: dict[tuple[str, str], list[tuple[str, int]]] = defaultdict(list)
    webshell_uri: list[str] = []
    scripted_strong: list[str] = []
    scripted_weak_200: list[str] = []
    admin_hits: list[str] = []
    verb_tunnel: Counter = Counter()
    # 4xx-recon bookkeeping: src → (count, distinct URI set)
    fourxx: dict[str, tuple[int, set[str]]] = defaultdict(
        lambda: (0, set()))

    script_exts = (".php", ".jsp", ".cgi", ".pl", ".py", ".aspx")

    with _open(path) as f:
        for lineno, raw in enumerate(f, 1):
            if lineno > max_rows:
                break
            result.total_lines += 1
            line = raw.rstrip("\r\n")
            if not line:
                continue
            m = _LINE_RE.match(line)
            if not m:
                continue
            result.parsed_rows += 1
            host = m.group("host") or ""
            method, uri, _ver = _parse_request(m.group("request") or "")
            status = m.group("status") or ""
            ua = (m.group("ua") or "").lower()

            uri_path, query = _split_uri(uri)
            uri_basename = (uri_path.rsplit("/", 1)[-1].lower()
                            if uri_path else "")
            uri_low = uri_path.lower()
            method_u = method.upper()

            # Webshell-shape URI
            if uri_basename in _WEBSHELL_BASENAMES or (
                query and any(tok in query.lower()
                              for tok in _WEBSHELL_QUERY_TOKENS)
            ):
                if len(webshell_uri) < 50:
                    webshell_uri.append(
                        f"{host} {method_u} {uri_path}"
                        + (f"?{query[:120]}" if query else "")
                        + f" → {status}"
                    )

            # Scripted client
            if ua and ua != "-":
                if any(t in ua for t in _UA_STRONG):
                    if len(scripted_strong) < 50:
                        scripted_strong.append(
                            f"{host} UA={ua[:100]} {method_u} {uri_path}")
                elif any(t in ua for t in _UA_WEAK) and status.startswith("2"):
                    if len(scripted_weak_200) < 50:
                        scripted_weak_200.append(
                            f"{host} UA={ua[:100]} {method_u} {uri_path} → {status}")

            # Admin-path success from public IP
            if (uri_low and any(uri_low.startswith(p) for p in _ADMIN_PATHS)
                    and status and status.startswith(("2", "3"))
                    and host and not _is_private(host)):
                if len(admin_hits) < 50:
                    admin_hits.append(f"{host} {method_u} {uri_path} → {status}")

            # Upload POST burst
            if (method_u == "POST" and uri_low.endswith(script_exts)
                    and host):
                uploads[(host, uri_path)].append((status, lineno))

            # Verb-tunnel counter
            if method_u in _VERB_TUNNEL:
                verb_tunnel[method_u] += 1

            # 4xx recon burst — only count public IPs (otherwise
            # localhost / monitoring crawlers floor the signal)
            if (status.startswith("4") and host and not _is_private(host)):
                count, uris = fourxx[host]
                uris = uris | {uri_path}
                fourxx[host] = (count + 1, uris)

    # Assemble hits
    if webshell_uri:
        result.hits.append(Hit(
            pattern_id="WEB_WEBSHELL_URI_SHAPE",
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
            pattern_id="WEB_SCRIPTED_CLIENT_OFFENSIVE",
            description=(
                "User-Agent matches an offensive-security tool "
                "(sqlmap, nikto, nmap NSE, nuclei, hydra, masscan, "
                "gobuster). Always worth flagging — these UAs do "
                "not appear in legitimate traffic to production sites."
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
            pattern_id="WEB_SCRIPTED_CLIENT_GENERIC",
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
            pattern_id="WEB_ADMIN_URI_HIT",
            description=(
                "Successful (2xx/3xx) request to a well-known admin / "
                "config path from a public IP (/admin, /wp-admin, "
                "/phpmyadmin, /manager, /.env, /.git, /.aws, /.ssh)."
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
            pattern_id="WEB_UPLOAD_POST_BURST",
            description=(
                "≥3 POST requests from a single source to the same "
                "script URI (.php/.jsp/.cgi/.pl/.py/.aspx) with at "
                "least one 2xx response. Shape of web-shell upload + reuse."
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
            pattern_id="WEB_VERB_TUNNEL",
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

    recon_hits: list[str] = []
    for src, (count, uris) in fourxx.items():
        if count >= recon_4xx_min and len(uris) >= recon_4xx_distinct_uris:
            recon_hits.append(
                f"{src} — {count} 4xx across {len(uris)} distinct URIs"
            )
    if recon_hits:
        result.hits.append(Hit(
            pattern_id="WEB_4XX_RECON_BURST",
            description=(
                "Single source IP produced a high count of 4xx "
                "responses across many distinct URIs — directory-"
                "busting / fuzzer shape (gobuster, dirb, ffuf)."
            ),
            matches=recon_hits,
            hypotheses=["H_SCAN_RECON"],
            attack_techniques=[("T1595", "Active Scanning")],
        ))

    return result


def scan_tree(root: Path, *, max_files: int = 200) -> list[ScanResult]:
    """Walk ``var/log/{nginx,apache2,httpd}/`` and scan every
    ``access.log*`` file (including rotated .gz)."""
    root = Path(root)
    results: list[ScanResult] = []
    if not root.is_dir():
        return results
    files: list[Path] = []
    for sub in ("nginx", "apache2", "httpd"):
        d = root / sub
        if d.is_dir():
            files.extend(sorted(d.glob("access.log*")))
    if not files:
        # Caller passed the log dir directly.
        files = sorted(root.glob("access.log*"))
    for f in files[:max_files]:
        results.append(scan_path(f))
    return results


__all__ = ["Hit", "ScanResult", "scan_path", "scan_tree"]

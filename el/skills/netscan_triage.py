"""Skill: Triage Volatility 3 windows.netscan.NetScan rows.

vol3 netscan (pool-tag scan) survives the EPROCESS / tcpip symbol
mismatch that takes out netstat on many Win10+ images, so it is often
the only network visibility available from a memory capture. Yet its
rows were previously used only for the raw "N rows parsed" finding,
never to drive hypotheses.

Two deterministic detectors:

1. `detect_repeat_endpoint_beacon` — group by (ForeignAddr, ForeignPort);
   flag endpoints that this host talked to ≥N times. Real intrusions
   produce a tight cluster of connections to the same C2 IP+port
   (SRL-2018 wkstn-01 → 172.16.4.10:8080 × 16; wkstn-05 → same IP × 6)
   because the beacon cycle repeats. Lateral-movement admin ports are
   delegated to the second detector so we don't double-flag.

2. `detect_lateral_admin_port_session` — any connection from this host
   to an admin/remote-access port (WinRM 5985/5986, RDP 3389, SMB 445,
   RPC 135, SSH 22, VNC 5900, Telnet 23). Cheap lateral-movement
   corroboration; parallels EID-4624-Type-10 / EID-91 on the disk side.

Pure functions. No I/O, no network lookups. Input is the list of netscan
dicts from `vol3.PluginRun.rows`.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field

# Curated CIDR blocks for the major cloud / CDN providers. A Windows 10 host
# running OneDrive, Office 365, Edge, Windows Update + telemetry (and, in the
# Lone Wolf scenario, Dropbox / Box / Google Drive / S3 clients) makes a steady
# stream of repeated HTTPS connections to these networks — which trips the
# repeat-endpoint beacon heuristic and falsely reads as C2. We do NOT suppress
# such hits outright (attackers do host C2 on Azure/AWS) — instead the caller
# downgrades them to low confidence with a "consistent with legitimate cloud
# traffic" caveat and does not lift H_C2_BEACONING. Conservative, well-published
# ranges only; an unlisted cloud IP simply keeps the normal beacon treatment.
_BENIGN_CLOUD_CIDRS: tuple[tuple[str, str], ...] = (
    # Microsoft / Azure / Office 365 / Bing
    ("13.64.0.0/11", "Microsoft"), ("13.104.0.0/14", "Microsoft"),
    ("20.33.0.0/16", "Microsoft"), ("20.34.0.0/15", "Microsoft"),
    ("20.36.0.0/14", "Microsoft"), ("20.40.0.0/13", "Microsoft"),
    ("20.48.0.0/12", "Microsoft"), ("20.64.0.0/10", "Microsoft"),
    ("20.128.0.0/16", "Microsoft"), ("40.64.0.0/10", "Microsoft"),
    ("40.74.0.0/15", "Microsoft"), ("52.96.0.0/12", "Microsoft"),
    ("52.112.0.0/14", "Microsoft"), ("52.120.0.0/14", "Microsoft"),
    ("52.160.0.0/11", "Microsoft"), ("65.52.0.0/14", "Microsoft"),
    ("104.40.0.0/13", "Microsoft"), ("131.253.1.0/24", "Microsoft"),
    ("131.253.61.0/24", "Microsoft"), ("191.232.0.0/13", "Microsoft"),
    ("204.79.195.0/24", "Microsoft"), ("204.79.197.0/24", "Microsoft"),
    ("2620:1ec::/36", "Microsoft"), ("2a01:111::/32", "Microsoft"),
    # Akamai (CDN for Microsoft, Apple, etc.)
    ("2.16.0.0/13", "Akamai"), ("23.0.0.0/12", "Akamai"),
    ("23.192.0.0/11", "Akamai"), ("104.64.0.0/10", "Akamai"),
    ("184.24.0.0/13", "Akamai"),
    # Google
    ("8.8.4.0/24", "Google"), ("8.8.8.0/24", "Google"),
    ("142.250.0.0/15", "Google"), ("172.217.0.0/16", "Google"),
    ("172.253.0.0/16", "Google"), ("216.58.192.0/19", "Google"),
    ("2607:f8b0::/32", "Google"),
    # AWS (S3 / general)
    ("3.0.0.0/9", "AWS"), ("13.32.0.0/15", "AWS"), ("52.216.0.0/15", "AWS"),
    ("54.224.0.0/12", "AWS"), ("99.84.0.0/16", "AWS"),
    # Cloudflare / Fastly / Dropbox
    ("104.16.0.0/13", "Cloudflare"), ("172.64.0.0/13", "Cloudflare"),
    ("2606:4700::/32", "Cloudflare"), ("151.101.0.0/16", "Fastly"),
    ("162.125.0.0/16", "Dropbox"), ("2620:100:6000::/40", "Dropbox"),
)

# Pre-parse once.
_BENIGN_CLOUD_NETS = tuple(
    (ipaddress.ip_network(cidr), name) for cidr, name in _BENIGN_CLOUD_CIDRS)
# Web-service ports where cloud/CDN traffic legitimately clusters.
_CLOUD_WEB_PORTS = frozenset({80, 443, 8443})


def benign_cloud_provider(addr: str, port: int) -> str | None:
    """Return the provider name if (addr, port) is a repeated HTTPS/HTTP
    connection to a well-known cloud/CDN range — i.e. the shape of legitimate
    OneDrive / Office365 / browser / CDN traffic rather than C2. None otherwise.
    Only web ports qualify; an Azure IP on an odd port stays suspicious."""
    if port not in _CLOUD_WEB_PORTS:
        return None
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    for net, name in _BENIGN_CLOUD_NETS:
        if ip.version == net.version and ip in net:
            return name
    return None


# Admin / remote-access ports. Presence of ANY of these in an outbound
# (non-loopback) netscan row is suggestive of lateral movement in flight.
LATERAL_ADMIN_PORTS: dict[int, str] = {
    22: "ssh",
    23: "telnet",
    135: "rpc_dcom",
    139: "netbios_ssn",
    445: "smb",
    3389: "rdp",
    5900: "vnc",
    5985: "winrm_http",
    5986: "winrm_https",
}

# Well-known / registered ports that map to a legitimate service the
# analyst will recognise on sight. NOT exhaustive — just what shows up
# in enterprise memory captures and shouldn't be called "unknown port."
# Sources: IANA + the ports directly observed across the SRL-2015,
# SRL-2018, and flaws.cloud corpora.
KNOWN_PORT_SERVICES: dict[int, str] = {
    **LATERAL_ADMIN_PORTS,
    # Web
    80: "http", 443: "https", 8080: "http_alt", 8443: "https_alt",
    8000: "http_alt", 8888: "http_alt",
    # Mail
    25: "smtp", 465: "smtps", 587: "submission",
    110: "pop3", 995: "pop3s", 143: "imap", 993: "imaps",
    # DNS / Directory / Time
    53: "dns", 88: "kerberos", 123: "ntp", 389: "ldap", 636: "ldaps",
    3268: "ldap_gc", 3269: "ldaps_gc",
    # File / DB / Message
    21: "ftp", 20: "ftp_data", 69: "tftp",
    1433: "mssql", 1434: "mssql_monitor",
    3306: "mysql", 5432: "postgres", 6379: "redis",
    27017: "mongodb", 9200: "elasticsearch",
    5672: "amqp", 15672: "amqp_mgmt",
    61613: "stomp",            # ActiveMQ — seen in SRL-2018
    808: "ms_net_tcp",         # .NET / WCF — SharePoint legitimate
    # Windows service ports
    464: "kerberos_pwd", 593: "rpc_http", 1701: "l2tp",
    1812: "radius", 5355: "llmnr",
    # Monitoring
    161: "snmp", 162: "snmp_trap", 514: "syslog",
    # VPN / tunnels
    500: "isakmp", 4500: "ipsec_nat", 1194: "openvpn",
}


def port_category(port: int) -> tuple[str, str | None]:
    """Classify a destination port into one of four categories + optional
    service label. Returns (category, service_hint_or_None).

    Categories
    ----------
    - ``"known"``        : listed in KNOWN_PORT_SERVICES (analyst-recognised)
    - ``"well_known"``   : 0–1023 but not in our curated map (still
                           reserved by IANA for system services)
    - ``"registered"``   : 1024–49151 with no entry in our map (IANA
                           registered range but unknown to us — this is
                           the bucket that includes 22233, 4444, 31337,
                           and plenty of malware-default ports)
    - ``"ephemeral"``    : 49152–65535 (dynamic/private range; usually
                           client-side, rarely meaningful as a dst port)

    Designed to be embedded into a finding claim so the analyst sees
    ``22233 (registered, no known service)`` rather than just ``22233``.
    """
    try:
        port = int(port)
    except (TypeError, ValueError):
        return ("registered", None)
    if port <= 0 or port > 65535:
        return ("registered", None)
    svc = KNOWN_PORT_SERVICES.get(port)
    if svc:
        return ("known", svc)
    if port <= 1023:
        return ("well_known", None)
    if port <= 49151:
        return ("registered", None)
    return ("ephemeral", None)


def port_annotation(port: int) -> str:
    """Short human-readable annotation for a port, suitable for inclusion
    in a finding claim. Examples:
        5985  -> 'winrm_http'
        8080  -> 'http_alt'
        22233 -> 'unregistered service (registered range)'
        60123 -> 'ephemeral'
    """
    cat, svc = port_category(port)
    if svc:
        return svc
    if cat == "well_known":
        return "unknown well-known port"
    if cat == "registered":
        return "unregistered service (registered range)"
    return "ephemeral"

# Endpoints to skip in the beacon detector: loopback, link-local,
# multicast, unspecified, and the "*" wildcard netscan uses for listening
# sockets. NOT filtering RFC1918 — attacker C2 frequently lives on the
# internal network in the SRL-2018-style compromise.
_BENIGN_FOREIGN = {
    "", "*", "-", "0.0.0.0", "::", "127.0.0.1", "::1",
}


# Calibration item from docs/SRL-2018-shakedown.md #1 + #4: when the
# destination is RFC1918 (or RFC4193 ULA), these ports are legitimate
# internal directory / collaboration services. Servers chatter to these
# constantly (Exchange ↔ DC LDAP/GC, SharePoint inter-server WCF) and
# the chatter trips the repeat-endpoint threshold. Suppress when
# (RFC1918 destination AND port in this set). Still flagged for
# external destinations — APT C2 on :389 to a public IP is a real
# signal.
_INTERNAL_DIRECTORY_PORTS = {
    88,    # Kerberos
    389,   # LDAP
    636,   # LDAPS
    3268,  # Global Catalog (LDAP)
    3269,  # Global Catalog (LDAPS)
    808,   # SharePoint inter-server WCF (legacy net.tcp default)
}


def _is_listen_or_bogon(addr: str) -> bool:
    if not addr:
        return True
    addr = addr.strip()
    if addr in _BENIGN_FOREIGN:
        return True
    if addr.startswith(("127.", "169.254.", "224.", "239.", "255.",
                        "ff00:", "fe80:")):
        return True
    return False


def _is_rfc1918(addr: str) -> bool:
    """RFC1918 IPv4 + RFC4193 IPv6 ULA. Matches by string prefix to
    avoid pulling in `ipaddress`-module overhead per row on multi-
    thousand-row netscans."""
    if not addr:
        return False
    a = addr.strip()
    if a.startswith("10."):
        return True
    if a.startswith("192.168."):
        return True
    if a.startswith("172."):
        # 172.16.0.0/12 — second octet 16-31
        try:
            second = int(a.split(".", 2)[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    if a.startswith(("fd", "fc")) and ":" in a:
        return True   # ULA
    return False


# --- Detector 1: beacon ---------------------------------------------------

@dataclass
class BeaconHit:
    foreign_addr: str
    foreign_port: int
    count: int
    proto: str
    states: dict[str, int] = field(default_factory=dict)
    local_ports: list[int] = field(default_factory=list)
    pids: list[int] = field(default_factory=list)
    cloud_provider: str = ""   # set when the endpoint is a known cloud/CDN range

    @property
    def benign_cloud(self) -> bool:
        """True when this beacon is repeated web traffic to a known cloud/CDN
        provider — the shape of OneDrive/Office365/browser/CDN sync, not C2.
        The caller downgrades these to low confidence without lifting C2."""
        return bool(self.cloud_provider)

    @property
    def weak_web_residue(self) -> bool:
        """True for a beacon that has the shape of leftover ordinary web
        browsing in a memory snapshot — and is therefore weak C2 evidence:

          * a standard web port (80/443/8443),
          * a PUBLIC destination (internal :443 beacons could be a real
            service/C2 and are left to fire),
          * a low repeat count (< 10 — sustained C2 in a RAM snapshot tends
            to leave many beacon-interval connections), AND
          * no ESTABLISHED / SYN session (only CLOSED/CLOSE_WAIT/TIME_WAIT
            residue — an in-flight session is a stronger signal).

        The caller downgrades these to low confidence without lifting
        H_C2_BEACONING. This is the unavoidable cost of distinguishing
        'legitimate web service polled a handful of times' from
        'low-volume HTTPS C2' on a benign host without threat intel — a
        genuinely low-volume HTTPS C2 to a fresh public IP is still surfaced
        here, just at low confidence rather than as a leading hypothesis.
        Surfaced on the benign 2018 Lone Wolf laptop (2026-06), whose only
        residual 'C2' signal was two such browsing-leftover clusters.
        Distinct from `benign_cloud`, which names a specific provider.
        """
        if self.cloud_provider:
            return False   # already handled, and provider-labelled
        if self.foreign_port not in _CLOUD_WEB_PORTS:
            return False
        if self.count >= 10:
            return False
        try:
            ip = ipaddress.ip_address(self.foreign_addr)
        except ValueError:
            return False
        if not ip.is_global:
            return False
        active = {"ESTABLISHED", "SYN_SENT", "SYN_RCVD"}
        return not any(s in active for s in self.states)

    @property
    def is_low_signal(self) -> bool:
        """Either a known cloud/CDN endpoint or a weak web-residue cluster —
        the caller emits these at low confidence and does NOT lift C2."""
        return self.benign_cloud or self.weak_web_residue

    @property
    def port_label(self) -> str:
        return port_annotation(self.foreign_port)

    @property
    def port_category(self) -> str:
        return port_category(self.foreign_port)[0]


def detect_repeat_endpoint_beacon(rows: list[dict],
                                    min_count: int = 4) -> list[BeaconHit]:
    """Cluster rows by (ForeignAddr, ForeignPort); return clusters with
    count ≥ `min_count`. Skips loopback / link-local / listening sockets
    and the admin ports covered by the lateral-session detector."""
    groups: dict[tuple[str, int], list[dict]] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        fa = (r.get("ForeignAddr") or "").strip()
        fp = r.get("ForeignPort")
        if not fa or fp in (None, 0, ""):
            continue
        if _is_listen_or_bogon(fa):
            continue
        try:
            port = int(fp)
        except (TypeError, ValueError):
            continue
        if port in LATERAL_ADMIN_PORTS:
            continue
        # Internal directory/collaboration chatter — Exchange ↔ DC
        # LDAP/GC, inter-server SharePoint WCF — trips repeat-endpoint
        # trivially on server-class hosts. Only suppress when the
        # destination is RFC1918; APT C2 on :389 to a public IP is
        # still a strong signal.
        if port in _INTERNAL_DIRECTORY_PORTS and _is_rfc1918(fa):
            continue
        groups.setdefault((fa, port), []).append(r)

    out: list[BeaconHit] = []
    for (fa, port), hits in groups.items():
        if len(hits) < min_count:
            continue
        states = Counter((h.get("State") or "") for h in hits)
        proto = hits[0].get("Proto") or ""
        local_ports = sorted({int(h["LocalPort"]) for h in hits
                              if isinstance(h.get("LocalPort"), (int, float, str))
                              and str(h.get("LocalPort")).isdigit()})
        pids = sorted({int(h["PID"]) for h in hits
                       if isinstance(h.get("PID"), (int, float))})
        out.append(BeaconHit(
            foreign_addr=fa, foreign_port=port, count=len(hits),
            proto=proto, states=dict(states),
            local_ports=local_ports, pids=pids,
            cloud_provider=benign_cloud_provider(fa, port) or "",
        ))
    # Strongest signal first
    out.sort(key=lambda b: -b.count)
    return out


# --- Detector 2: lateral admin-port session -------------------------------

@dataclass
class LateralHit:
    foreign_addr: str
    foreign_port: int
    service: str
    count: int
    proto: str
    states: dict[str, int] = field(default_factory=dict)
    established: int = 0
    pids: list[int] = field(default_factory=list)


def detect_lateral_admin_port_session(rows: list[dict]) -> list[LateralHit]:
    """Return one LateralHit per (ForeignAddr, admin_port) the host spoke
    to. Includes CLOSED + ESTABLISHED; ESTABLISHED count surfaced
    separately so the caller can escalate confidence when there was an
    in-flight session."""
    groups: dict[tuple[str, int], list[dict]] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        fa = (r.get("ForeignAddr") or "").strip()
        fp = r.get("ForeignPort")
        if not fa or fp in (None, 0, ""):
            continue
        if _is_listen_or_bogon(fa):
            continue
        try:
            port = int(fp)
        except (TypeError, ValueError):
            continue
        if port not in LATERAL_ADMIN_PORTS:
            continue
        groups.setdefault((fa, port), []).append(r)

    out: list[LateralHit] = []
    for (fa, port), hits in groups.items():
        states = Counter((h.get("State") or "") for h in hits)
        established = sum(1 for h in hits
                          if (h.get("State") or "").upper() == "ESTABLISHED")
        proto = hits[0].get("Proto") or ""
        pids = sorted({int(h["PID"]) for h in hits
                       if isinstance(h.get("PID"), (int, float))})
        out.append(LateralHit(
            foreign_addr=fa, foreign_port=port,
            service=LATERAL_ADMIN_PORTS[port],
            count=len(hits), proto=proto, states=dict(states),
            established=established, pids=pids,
        ))
    # ESTABLISHED sessions are the sharpest signal; otherwise by count
    out.sort(key=lambda l: (-l.established, -l.count))
    return out

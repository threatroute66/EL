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

from collections import Counter
from dataclasses import dataclass, field


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

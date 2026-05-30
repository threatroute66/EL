"""macOS network history — DHCP leases + Wi-Fi known networks.

Builds a places/movement picture from two read-only plist sources:

  * ``/private/var/db/dhcpclient/leases/<iface>*.plist`` — the last DHCP
    lease per interface: leased IP, lease start, and crucially the
    **router's MAC** (``RouterHardwareAddress``) and the SSID the lease was
    obtained on. The router MAC + SSID pins the device to a specific physical
    network.
  * ``/Library/Preferences/com.apple.wifi.known-networks.plist`` — every
    remembered Wi-Fi network with ``AddedAt`` / ``JoinedByUserAt`` /
    ``JoinedBySystemAt`` / ``UpdatedAt`` timestamps (legacy
    ``com.apple.airport.preferences.plist`` is read as a fallback on older
    macOS). The join timestamps are a movement timeline — when the device
    first/last associated with each named network.

No SIFT-bundled CLI structures these into a timeline, so this is a native
plist parser in the spirit of the other macOS extractors. Read-only: the
plists are only ever opened for reading.
"""
from __future__ import annotations

import hashlib
import json
import plistlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from el.schemas.finding import EvidenceItem


class MacOSNetworkHistoryError(Exception):
    pass


_SSID_KEY_PREFIX = "wifi.network.ssid."


def _fmt_dt(value) -> str:
    """Format a plist datetime (naive == UTC) to 'YYYY-MM-DD HH:MM:SS'."""
    if not isinstance(value, datetime):
        return ""
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _fmt_mac(value) -> str:
    """Format a raw hardware-address byte string as colon-separated hex."""
    if isinstance(value, (bytes, bytearray)) and len(value) >= 1:
        return ":".join(f"{b:02x}" for b in value)
    if isinstance(value, str):
        return value
    return ""


@dataclass
class DHCPLease:
    interface: str = ""
    ip_address: str = ""
    router_ip: str = ""
    router_mac: str = ""
    ssid: str = ""
    lease_start_utc: str = ""
    lease_length: int = 0
    client_id: str = ""
    source_path: str = ""

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class KnownNetwork:
    ssid: str = ""
    added_utc: str = ""
    joined_by_user_utc: str = ""
    joined_by_system_utc: str = ""
    updated_utc: str = ""
    bssids: list[str] = field(default_factory=list)
    source_path: str = ""

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class NetworkHistoryRun:
    macos_root: Path
    leases: list[DHCPLease] = field(default_factory=list)
    networks: list[KnownNetwork] = field(default_factory=list)
    output_path: Path | None = None
    output_sha256: str = ""

    @property
    def total(self) -> int:
        return len(self.leases) + len(self.networks)

    def timeline(self) -> list[tuple[str, str, str]]:
        """Chronological ``(utc, event, detail)`` across leases + joins.
        Events with no timestamp are dropped. Sorted ascending by time."""
        ev: list[tuple[str, str, str]] = []
        for l in self.leases:
            if l.lease_start_utc:
                ev.append((l.lease_start_utc, "dhcp_lease",
                           f"{l.ssid or l.interface} via router {l.router_mac}"))
        for n in self.networks:
            for utc, kind in ((n.added_utc, "wifi_added"),
                              (n.joined_by_user_utc, "wifi_joined_by_user"),
                              (n.joined_by_system_utc, "wifi_joined_by_system")):
                if utc:
                    ev.append((utc, kind, n.ssid))
        return sorted(ev, key=lambda e: e[0])

    def networks_joined_on(self, date_utc: str) -> list[KnownNetwork]:
        """Known networks with any join/added timestamp on *date_utc*
        ('YYYY-MM-DD'). Answers 'which network was joined on day X'."""
        out = []
        for n in self.networks:
            stamps = (n.added_utc, n.joined_by_user_utc,
                      n.joined_by_system_utc, n.updated_utc)
            if any(s[:10] == date_utc for s in stamps if s):
                out.append(n)
        return out

    def as_evidence(self, *, facts: dict | None = None) -> EvidenceItem:
        extra = facts or {}
        return EvidenceItem(
            tool="el.macos_network_history", version="0.1.0",
            command=f"parse dhcp leases + known networks -- {self.macos_root}",
            output_sha256=self.output_sha256 or ("0" * 64),
            output_path=str(self.output_path or self.macos_root),
            extracted_facts={
                "macos_root": str(self.macos_root),
                "dhcp_lease_count": len(self.leases),
                "known_network_count": len(self.networks),
                "ssids": [n.ssid for n in self.networks],
                "router_macs": sorted({l.router_mac for l in self.leases
                                       if l.router_mac}),
                **extra,
            },
        )


# --- discovery ------------------------------------------------------------

def find_dhcp_leases(macos_root: Path) -> list[Path]:
    macos_root = Path(macos_root)
    for rel in (("private", "var", "db", "dhcpclient", "leases"),
                ("var", "db", "dhcpclient", "leases")):
        d = macos_root.joinpath(*rel)
        if d.is_dir():
            return sorted(p for p in d.glob("*.plist") if p.is_file())
    # macos_root may itself be the leases dir.
    if macos_root.is_dir() and macos_root.name == "leases":
        return sorted(p for p in macos_root.glob("*.plist") if p.is_file())
    return []


def find_known_networks(macos_root: Path) -> Path | None:
    macos_root = Path(macos_root)
    for rel in (("Library", "Preferences",
                 "com.apple.wifi.known-networks.plist"),):
        p = macos_root.joinpath(*rel)
        if p.is_file():
            return p
    direct = macos_root / "com.apple.wifi.known-networks.plist"
    return direct if direct.is_file() else None


def find_airport_prefs(macos_root: Path) -> Path | None:
    macos_root = Path(macos_root)
    p = macos_root.joinpath("Library", "Preferences", "SystemConfiguration",
                            "com.apple.airport.preferences.plist")
    return p if p.is_file() else None


# --- parsers --------------------------------------------------------------

def parse_dhcp_lease(path: Path) -> DHCPLease | None:
    path = Path(path)
    try:
        d = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    if not isinstance(d, dict):
        return None
    # interface from filename: "en0.plist" / "en0-1,aa,bb...plist"
    iface = path.stem.split("-", 1)[0].split(",", 1)[0]
    return DHCPLease(
        interface=iface,
        ip_address=str(d.get("IPAddress") or ""),
        router_ip=str(d.get("RouterIPAddress") or ""),
        router_mac=_fmt_mac(d.get("RouterHardwareAddress")),
        ssid=str(d.get("SSID") or ""),
        lease_start_utc=_fmt_dt(d.get("LeaseStartDate")),
        lease_length=int(d.get("LeaseLength") or 0),
        client_id=_fmt_mac(d.get("ClientIdentifier")),
        source_path=str(path),
    )


def _ssid_from(key: str, value: dict) -> str:
    s = value.get("SSID")
    if isinstance(s, (bytes, bytearray)):
        try:
            return s.decode("utf-8")
        except UnicodeDecodeError:
            return s.hex()
    if isinstance(s, str) and s:
        return s
    if key.startswith(_SSID_KEY_PREFIX):
        return key[len(_SSID_KEY_PREFIX):]
    return key


def parse_known_networks(path: Path) -> list[KnownNetwork]:
    path = Path(path)
    try:
        d = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return []
    if not isinstance(d, dict):
        return []
    out: list[KnownNetwork] = []
    for key, value in d.items():
        if not isinstance(value, dict):
            continue
        if not (key.startswith(_SSID_KEY_PREFIX)
                or "AddedAt" in value or "JoinedByUserAt" in value):
            continue
        bssids = []
        bss = value.get("BSSList")
        if isinstance(bss, list):
            for b in bss:
                if isinstance(b, dict) and b.get("BSSID"):
                    bssids.append(str(b["BSSID"]))
        out.append(KnownNetwork(
            ssid=_ssid_from(key, value),
            added_utc=_fmt_dt(value.get("AddedAt")),
            joined_by_user_utc=_fmt_dt(value.get("JoinedByUserAt")),
            joined_by_system_utc=_fmt_dt(value.get("JoinedBySystemAt")),
            updated_utc=_fmt_dt(value.get("UpdatedAt")),
            bssids=bssids,
            source_path=str(path),
        ))
    return out


def parse_airport_prefs(path: Path) -> list[KnownNetwork]:
    """Legacy fallback: com.apple.airport.preferences.plist RememberedNetworks
    / KnownNetworks with SSIDString + LastConnected."""
    path = Path(path)
    try:
        d = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return []
    if not isinstance(d, dict):
        return []
    out: list[KnownNetwork] = []
    containers = []
    for k in ("RememberedNetworks", "KnownNetworks"):
        v = d.get(k)
        if isinstance(v, list):
            containers.extend(v)
        elif isinstance(v, dict):
            containers.extend(v.values())
    for net in containers:
        if not isinstance(net, dict):
            continue
        ssid = net.get("SSIDString") or net.get("SSID_STR") or ""
        if isinstance(ssid, (bytes, bytearray)):
            try:
                ssid = ssid.decode("utf-8")
            except UnicodeDecodeError:
                ssid = ssid.hex()
        out.append(KnownNetwork(
            ssid=str(ssid),
            updated_utc=_fmt_dt(net.get("LastConnected")),
            source_path=str(path),
        ))
    return out


def parse(macos_root: Path, output_dir: Path | None = None
          ) -> NetworkHistoryRun:
    """Locate + parse DHCP leases and Wi-Fi known networks under *macos_root*.
    Writes a JSONL dump under *output_dir* when given. Returns a possibly-empty
    run (no artifacts present is a valid outcome)."""
    macos_root = Path(macos_root)
    if not macos_root.exists():
        raise MacOSNetworkHistoryError(f"path not found: {macos_root}")

    run = NetworkHistoryRun(macos_root=macos_root)
    for lp in find_dhcp_leases(macos_root):
        lease = parse_dhcp_lease(lp)
        if lease:
            run.leases.append(lease)

    kn = find_known_networks(macos_root)
    if kn is not None:
        run.networks.extend(parse_known_networks(kn))
    else:
        ap = find_airport_prefs(macos_root)
        if ap is not None:
            run.networks.extend(parse_airport_prefs(ap))

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "network_history.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for l in run.leases:
                f.write(json.dumps({"type": "dhcp_lease", **l.as_dict()},
                                   sort_keys=True) + "\n")
            for n in run.networks:
                f.write(json.dumps({"type": "known_network", **n.as_dict()},
                                   sort_keys=True) + "\n")
        run.output_path = out
        run.output_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()

    return run

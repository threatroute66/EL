"""Skill: NetFlow / IPFIX / sFlow ingestion via nfdump.

Wraps the `nfdump` CLI (part of the nfdump package, installed on
SIFT by default). Supports the binary nfcapd file format used by
nfcapd/sfcapd collectors.

Use cases:
  · Historical flow review alongside a pcap — different scale
    (days/weeks of flow data vs. minutes of pcap)
  · Cross-host pivot reconstruction when pcap coverage is gappy
  · Top-talker, beacon-pattern, and port-scan detection at flow scale

nfcapd files start with the magic `NFCAPD` or 0xA50C (the file
version header). We detect both so triage can route correctly.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


_NFCAPD_MAGIC_ASCII = b"NFCAPD"        # nfcapd vN header marker
_NFCAPD_MAGIC_LE    = b"\xa5\x0c"      # little-endian LFN header magic


@dataclass
class Flow:
    ts_first: str                    # ISO-ish (format: "YYYY-MM-DD HH:MM:SS.sss")
    ts_last: str
    duration_ms: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packets: int
    bytes_: int
    flags: str = ""                  # TCP flags aggregate ("S A F P ...")
    input_if: int = 0
    output_if: int = 0


@dataclass
class NfdumpRun:
    source_path: Path
    out_path: Path
    rc: int
    flow_count: int = 0
    flows: list[Flow] = field(default_factory=list)


class NetflowError(RuntimeError):
    pass


def _which() -> str | None:
    return shutil.which("nfdump")


def is_nfcapd_file(path: str | Path) -> bool:
    """Sniff the first 16 bytes for nfcapd/lfn header magic."""
    p = Path(path)
    try:
        with p.open("rb") as f:
            head = f.read(16)
    except OSError:
        return False
    if head.startswith(_NFCAPD_MAGIC_ASCII):
        return True
    # LFN (legacy nfdump) files start with the 2-byte version 0x0ca5 LE
    if head[:2] == _NFCAPD_MAGIC_LE:
        return True
    return False


def parse_nfcapd(nfcapd_path: str | Path,
                  out_path: str | Path,
                  timeout: int = 300,
                  max_flows: int = 100_000) -> NfdumpRun:
    """Run `nfdump -r <nfcapd> -o csv` and parse the CSV output into
    Flow records. Caps at `max_flows` to keep memory bounded on
    multi-GB capture sets."""
    src = Path(nfcapd_path)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    run = NfdumpRun(source_path=src, out_path=out, rc=-1)
    if not src.is_file():
        return run
    exe = _which()
    if not exe:
        return run
    # CSV: `-o csv` produces:
    #   ts, te, td, sa, da, sp, dp, pr, flg, fwd, stos, ipkt,
    #   opkt, ibyt, obyt, ...
    try:
        r = subprocess.run(
            [exe, "-r", str(src), "-o", "csv", "-q"],
            capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return run
    stdout = r.stdout or b""
    out.write_bytes(stdout)
    run.rc = r.returncode
    lines = stdout.decode("utf-8", errors="replace").splitlines()
    header: list[str] = []
    for line in lines:
        if not line:
            continue
        if not header:
            # First non-empty line is typically the CSV header from nfdump
            if line.startswith("ts,") or line.startswith("Date"):
                header = [h.strip() for h in line.split(",")]
                continue
        if "Summary:" in line or line.startswith("No matched flows"):
            break
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 12:
            continue
        try:
            idx = {h: i for i, h in enumerate(header)}
            def _col(key: str, default: str = ""):
                i = idx.get(key)
                return parts[i] if i is not None and i < len(parts) else default
            try:
                pkt = int(_col("ipkt", "0") or "0")
            except ValueError:
                pkt = 0
            try:
                byt = int(_col("ibyt", "0") or "0")
            except ValueError:
                byt = 0
            try:
                dur_f = float(_col("td", "0") or "0")
            except ValueError:
                dur_f = 0.0
            run.flows.append(Flow(
                ts_first=_col("ts", ""),
                ts_last=_col("te", ""),
                duration_ms=int(dur_f * 1000),
                src_ip=_col("sa", ""), src_port=int(_col("sp", "0") or "0"),
                dst_ip=_col("da", ""), dst_port=int(_col("dp", "0") or "0"),
                protocol=_col("pr", ""),
                packets=pkt, bytes_=byt,
                flags=_col("flg", ""),
            ))
            if len(run.flows) >= max_flows:
                break
        except (ValueError, IndexError):
            continue
    run.flow_count = len(run.flows)
    return run


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

@dataclass
class FlowBeacon:
    src_ip: str
    dst_ip: str
    dst_port: int
    count: int
    first_ts: str
    last_ts: str
    total_bytes: int


@dataclass
class PortScan:
    src_ip: str
    dst_ip: str
    distinct_ports: int
    first_ts: str
    last_ts: str


def top_beacons(flows: list[Flow],
                min_count: int = 10) -> list[FlowBeacon]:
    """Find (src, dst, port) tuples repeated many times — beacon
    signature. min_count default 10: lower than the netscan detector
    because flow data aggregates longer timeframes than memory."""
    groups: dict[tuple[str, str, int], list[Flow]] = {}
    for f in flows:
        key = (f.src_ip, f.dst_ip, f.dst_port)
        groups.setdefault(key, []).append(f)
    out: list[FlowBeacon] = []
    for (src, dst, port), gf in groups.items():
        if len(gf) < min_count:
            continue
        gf.sort(key=lambda x: x.ts_first)
        out.append(FlowBeacon(
            src_ip=src, dst_ip=dst, dst_port=port,
            count=len(gf),
            first_ts=gf[0].ts_first, last_ts=gf[-1].ts_first,
            total_bytes=sum(x.bytes_ for x in gf),
        ))
    out.sort(key=lambda b: -b.count)
    return out


def detect_port_scans(flows: list[Flow],
                       distinct_port_threshold: int = 30) -> list[PortScan]:
    """Flag (src, dst) pairs where src hit ≥ threshold distinct
    dst ports — vertical port scan."""
    groups: dict[tuple[str, str], set[int]] = {}
    ts_range: dict[tuple[str, str], tuple[str, str]] = {}
    for f in flows:
        key = (f.src_ip, f.dst_ip)
        groups.setdefault(key, set()).add(f.dst_port)
        first, last = ts_range.get(key, (f.ts_first, f.ts_last))
        first = min(first, f.ts_first) if first else f.ts_first
        last = max(last, f.ts_last) if last else f.ts_last
        ts_range[key] = (first, last)
    out: list[PortScan] = []
    for (src, dst), ports in groups.items():
        if len(ports) < distinct_port_threshold:
            continue
        first, last = ts_range[(src, dst)]
        out.append(PortScan(
            src_ip=src, dst_ip=dst,
            distinct_ports=len(ports),
            first_ts=first, last_ts=last,
        ))
    out.sort(key=lambda p: -p.distinct_ports)
    return out


def top_talkers(flows: list[Flow], n: int = 20) -> list[tuple[str, int, int]]:
    """Return (src_ip, flow_count, total_bytes) sorted by bytes desc."""
    agg: dict[str, tuple[int, int]] = {}
    for f in flows:
        c, b = agg.get(f.src_ip, (0, 0))
        agg[f.src_ip] = (c + 1, b + f.bytes_)
    rows = [(ip, c, b) for ip, (c, b) in agg.items()]
    rows.sort(key=lambda r: -r[2])
    return rows[:n]


__all__ = [
    "Flow", "NfdumpRun", "FlowBeacon", "PortScan", "NetflowError",
    "is_nfcapd_file", "parse_nfcapd",
    "top_beacons", "detect_port_scans", "top_talkers",
]

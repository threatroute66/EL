"""Skill: PowerShell EID 4104 (ScriptBlock Logging) decoded triage.

PR-E and SIGMA count 4104 events but don't look inside the payload.
Attackers put their actual commands in ScriptBlockText — usually
wrapped in `-EncodedCommand <base64>` or `IEX (FromBase64String(...))`
to defeat simple audit parsing. This skill:

1. Pulls every 4104 row out of the EvtxECmd CSV.
2. Lifts ScriptBlockText out of the prefix EvtxECmd adds
   ("ScriptBlockText: <content>").
3. Scans for inline base64 / gzip+base64 blobs, decodes them, and
   pattern-matches the plaintext against a library of malicious
   tokens (Mimikatz, AMSI bypass, IEX+DownloadString cradles,
   common C2 framework strings).

Output is a list of `PSHit` rows — one per script-block matching a
pattern family. The agent turns those into Findings with appropriate
hypothesis tags (H_CREDENTIAL_ACCESS for Mimikatz, H_APT_ESPIONAGE
for AMSI bypass / encoded cradles, H_LIVING_OFF_THE_LAND for plain
cradles).

Pure functions. Standard-library base64 + zlib only.
"""
from __future__ import annotations

import base64
import csv
import re
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


# Malicious pattern library. Keys are family names; values are regex
# patterns tested (case-insensitive) against both the raw script-block
# text and every base64-decoded substring we can extract.
_PATTERNS: dict[str, tuple[str, ...]] = {
    "mimikatz": (
        r"\binvoke-?mimikatz\b",
        r"\bsekurlsa\s*::",
        r"\bkerberos\s*::",
        r"\blsadump\s*::",
        r"\bcrypto\s*::",
        r"\bpth\s*::",
        r"\bmisc\s*::\s*memssp\b",
    ),
    "amsi_bypass": (
        r"AmsiUtils\b",
        r"amsiInitFailed",
        r"System\.Management\.Automation\.AmsiUtils",
        r"\bPatchAmsi\b",
        r"\[Ref\]\.Assembly\.GetType\(",
    ),
    "download_cradle": (
        r"\(New-Object\s+Net\.WebClient\)\.DownloadString\(",
        r"\(New-Object\s+Net\.WebClient\)\.DownloadFile\(",
        r"\bIEX\s*\(\s*\(",
        r"\bIEX\s*\(\s*New-Object\b",
        r"\bInvoke-Expression\b.*(DownloadString|DownloadFile)",
        r"\bInvoke-WebRequest\b.*\.Content",
        r"\bStart-BitsTransfer\b",
        r"\bcertutil\b.*-urlcache",
    ),
    "encoded_command": (
        r"-(?:EncodedCommand|Enc|E|EncodedArguments)\s+[A-Za-z0-9+/=]{32,}",
        r"\bFromBase64String\s*\(",
    ),
    "c2_framework": (
        r"\bEmpire\b.*Launcher",
        r"\bCobalt\s*Strike\b",
        r"\bCovenant\b",
        r"\bpowersploit\b",
        r"\bpowerview\b",
        r"\bpowercat\b",
        r"\bSharphound\b",
        r"\bBloodHound\b",
        r"\bRubeus\b",
    ),
    "persistence": (
        r"\bRegister-ScheduledTask\b",
        r"\bNew-ScheduledTaskAction\b",
        r"\bSet-ItemProperty\b.*CurrentVersion\\Run",
        r"\bNew-Service\b",
        r"\bReg\s+add\b.*CurrentVersion\\Run",
    ),
    "obfuscation": (
        # Invoke-Obfuscation-style marker sets; tuned to avoid false
        # positives on legitimate scripts that happen to use backticks
        # or string-concatenation.
        r"(?:`[A-Z]){5,}",                      # >= 5 tick-escaped chars
        r"(?:\"\+\"|\+'){6,}",                  # >= 6 string-split tokens
        r"\bchar\](?:\s*\d+){5,}",              # [char]+ [char]+ ...
    ),
}


# Hypothesis tags per family.
_FAMILY_HYPOTHESES: dict[str, list[str]] = {
    "mimikatz":        ["H_CREDENTIAL_ACCESS", "H_APT_ESPIONAGE"],
    "amsi_bypass":     ["H_APT_ESPIONAGE", "H_DEFENSE_EVASION",
                         "H_LIVING_OFF_THE_LAND"],
    "download_cradle": ["H_LIVING_OFF_THE_LAND",
                         "H_C2_OR_REVERSE_SHELL"],
    "encoded_command": ["H_APT_ESPIONAGE", "H_DEFENSE_EVASION"],
    "c2_framework":    ["H_C2_OR_REVERSE_SHELL",
                         "H_LATERAL_MOVEMENT", "H_APT_ESPIONAGE"],
    "persistence":     ["H_PERSISTENCE_SCHEDULED_TASK",
                         "H_PERSISTENCE_SERVICE"],
    "obfuscation":     ["H_DEFENSE_EVASION", "H_APT_ESPIONAGE"],
}


@dataclass
class PSHit:
    family: str
    matched_pattern: str
    event_count: int = 0
    sample_text: str = ""
    first_seen: str = ""
    last_seen: str = ""
    top_computers: list[tuple[str, int]] = field(default_factory=list)
    top_users: list[tuple[str, int]] = field(default_factory=list)
    decoded_samples: list[str] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


# MITRE ATT&CK mappings per family
_FAMILY_ATTACK: dict[str, list[tuple[str, str]]] = {
    "mimikatz":        [("T1003.001", "OS Credential Dumping: LSASS Memory"),
                         ("T1059.001", "PowerShell")],
    "amsi_bypass":     [("T1562.001", "Impair Defenses: Disable or Modify Tools")],
    "download_cradle": [("T1059.001", "PowerShell"),
                         ("T1105", "Ingress Tool Transfer")],
    "encoded_command": [("T1059.001", "PowerShell"),
                         ("T1027", "Obfuscated Files or Information")],
    "c2_framework":    [("T1059.001", "PowerShell"),
                         ("T1071.001", "Application Layer Protocol: Web Protocols")],
    "persistence":     [("T1053.005", "Scheduled Task/Job: Scheduled Task")],
    "obfuscation":     [("T1027", "Obfuscated Files or Information")],
}


# Keys in the EvtxECmd row that may carry ScriptBlockText. PayloadData2
# is the usual location on Win10+; keep the others as fallbacks because
# EvtxECmd map files occasionally route fields differently.
_PAYLOAD_KEYS = ("PayloadData2", "PayloadData1", "PayloadData3",
                  "PayloadData4")


_SCRIPT_BLOCK_PREFIXES = (
    "ScriptBlockText:", "ScriptBlock:", "Message:",
)


def _extract_script_block(row: dict) -> str:
    """Concatenate every PayloadData column that starts with a known
    ScriptBlock prefix OR holds raw PowerShell content (defensive —
    EvtxECmd sometimes omits the prefix on long blocks)."""
    for key in _PAYLOAD_KEYS:
        v = row.get(key)
        if not v:
            continue
        for prefix in _SCRIPT_BLOCK_PREFIXES:
            if v.startswith(prefix):
                return v[len(prefix):].strip()
    # Fallback: PayloadData2 raw (most common placement for 4104)
    v = row.get("PayloadData2") or ""
    return v.strip()


_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _attempt_decode(text: str) -> list[str]:
    """Find plausible base64 blobs in `text`, try to decode them as
    UTF-16LE (PowerShell -EncodedCommand default), UTF-8, and
    gzipped variants. Return a list of decoded strings (may be empty)."""
    out: list[str] = []
    for m in _B64_BLOB_RE.finditer(text):
        blob = m.group(0)
        if len(blob) < 40:
            continue
        pad = (4 - len(blob) % 4) % 4
        try:
            raw = base64.b64decode(blob + "=" * pad, validate=False)
        except Exception:
            continue
        for decoded in _try_decode_variants(raw):
            if decoded and decoded not in out:
                out.append(decoded)
                if len(out) >= 10:           # cap per row to keep memory bounded
                    return out
    return out


def _try_decode_variants(raw: bytes) -> list[str]:
    """Try the common PowerShell encodings over the same blob."""
    out: list[str] = []
    # 1. Plain UTF-16LE (what -EncodedCommand uses)
    try:
        s = raw.decode("utf-16-le")
        if s.isprintable() or any(c.isalpha() for c in s):
            out.append(s)
    except UnicodeDecodeError:
        pass
    # 2. Plain UTF-8
    try:
        s = raw.decode("utf-8")
        if s.isprintable() or any(c.isalpha() for c in s):
            out.append(s)
    except UnicodeDecodeError:
        pass
    # 3. gzip / deflate (the FromBase64String(...) | IO.Compression.GZipStream idiom)
    for wbits in (31, -15, 15):         # gzip, raw, zlib
        try:
            decompressed = zlib.decompress(raw, wbits)
        except zlib.error:
            continue
        for variant in ("utf-16-le", "utf-8"):
            try:
                s = decompressed.decode(variant)
                if s.isprintable() or any(c.isalpha() for c in s):
                    out.append(s)
                    break
            except UnicodeDecodeError:
                continue
    return out


def _scan_text(text: str, haystack_label: str,
                hits_by_family: dict[str, list[tuple[str, str]]]) -> None:
    for family, patterns in _PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                hits_by_family[family].append((pat, haystack_label))
                break                  # one pattern per family per text is enough


def iter_4104_rows(csv_path: Path):
    """Stream rows from EvtxECmd CSV where EventId == 4104."""
    with csv_path.open(encoding="utf-8", errors="ignore", newline="") as f:
        for row in csv.DictReader(f):
            try:
                eid = int((row.get("EventId") or "").strip())
            except ValueError:
                continue
            if eid == 4104:
                yield row


def run(csv_path: Path) -> list[PSHit]:
    """Scan every 4104 event in the CSV; return aggregated `PSHit`
    rows, one per family that matched. Decoded sample strings are
    preserved for the Finding so analysts can see what the attacker's
    base64 unpacked to."""
    from collections import defaultdict
    family_counter: dict[str, int] = defaultdict(int)
    family_times: dict[str, list[str]] = defaultdict(list)
    family_computers: dict[str, Counter] = defaultdict(Counter)
    family_users: dict[str, Counter] = defaultdict(Counter)
    family_samples: dict[str, list[str]] = defaultdict(list)
    family_pattern: dict[str, str] = {}
    family_decoded: dict[str, list[str]] = defaultdict(list)

    if not Path(csv_path).is_file():
        return []

    for row in iter_4104_rows(Path(csv_path)):
        text = _extract_script_block(row)
        if not text:
            continue
        per_family: dict[str, list[tuple[str, str]]] = \
            {k: [] for k in _PATTERNS}
        _scan_text(text, "raw", per_family)

        # If we see an encoded-command marker OR long base64 blobs,
        # try to decode and scan each decoded string too.
        decoded_variants = _attempt_decode(text)
        for decoded in decoded_variants:
            _scan_text(decoded, "decoded", per_family)

        for family, matches in per_family.items():
            if not matches:
                continue
            family_counter[family] += 1
            ts = row.get("TimeCreated") or ""
            if ts:
                family_times[family].append(ts)
            comp = (row.get("Computer") or "").strip()
            if comp:
                family_computers[family][comp] += 1
            user = (row.get("UserName") or "").strip()
            if user:
                family_users[family][user] += 1
            if not family_pattern.get(family):
                family_pattern[family] = matches[0][0]
            if len(family_samples[family]) < 3:
                family_samples[family].append(text[:300])
            # Save one decoded sample per family so the analyst sees
            # what the base64 unpacked to
            if (decoded_variants
                    and any(lbl == "decoded" for _, lbl in matches)
                    and len(family_decoded[family]) < 3):
                for d in decoded_variants:
                    if re.search(_PATTERNS[family][0], d, re.IGNORECASE):
                        family_decoded[family].append(d[:300])
                        break

    out: list[PSHit] = []
    for family, count in family_counter.items():
        times = sorted(family_times[family])
        out.append(PSHit(
            family=family,
            matched_pattern=family_pattern.get(family, ""),
            event_count=count,
            sample_text=family_samples[family][0] if family_samples[family] else "",
            first_seen=times[0] if times else "",
            last_seen=times[-1] if times else "",
            top_computers=family_computers[family].most_common(5),
            top_users=family_users[family].most_common(5),
            decoded_samples=family_decoded[family],
            attack=_FAMILY_ATTACK.get(family, []),
        ))
    # Highest-priority families first
    priority = {"mimikatz": 0, "c2_framework": 1, "amsi_bypass": 2,
                "encoded_command": 3, "download_cradle": 4,
                "persistence": 5, "obfuscation": 6}
    out.sort(key=lambda h: priority.get(h.family, 99))
    return out


def hypotheses_for(family: str) -> list[str]:
    return list(_FAMILY_HYPOTHESES.get(family, []))


__all__ = [
    "PSHit",
    "iter_4104_rows", "run", "hypotheses_for",
    "_PATTERNS", "_FAMILY_HYPOTHESES",
]

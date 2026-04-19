"""Skill: Windows process-profile anomaly detection.

Hunt-Evil page 1 ("Find Evil — Know Normal") lists the expected profile
for ~12 core Windows processes: parent process, instance count, image
path, user account, start time. This skill encodes those rules and
returns anomalies as dataclass hits for the memory_forensicator agent.

Scope: parent-process NAME check + instance-count check. These are the
two fields Volatility 3's `windows.pslist` provides directly and require
no additional plugin runs. Image-path / user-account checks need
`windows.cmdline` / `windows.getsids` output and are out of scope for
this PR — the matrix below reserves fields for them.

Pure functions. No I/O, no network. Input is a list of pslist-shaped
dicts (keys: PID, PPID, ImageFileName, SessionId, CreateTime, ExitTime).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field


# --- Expected-profile matrix ----------------------------------------------

@dataclass(frozen=True)
class ExpectedProfile:
    name: str                         # lowercase image name
    expected_parents: tuple[str, ...] # expected parent image names; () = any
    exact_count: int | None = None    # None = no constraint
    max_count: int | None = None      # upper bound (e.g. lsass.exe ≤ 1)
    min_count: int | None = None      # lower bound (e.g. csrss.exe ≥ 2)
    parent_may_exit: bool = False     # parent often exits → PPID missing OK
    notes: str = ""


# Core Windows process matrix (Win10-era values per Hunt Evil v4.7).
_MATRIX: tuple[ExpectedProfile, ...] = (
    ExpectedProfile(
        name="wininit.exe",
        expected_parents=("smss.exe",),
        exact_count=1,
        parent_may_exit=True,         # smss.exe child exits after session
        notes="Starts Session 0; singleton",
    ),
    ExpectedProfile(
        name="services.exe",
        expected_parents=("wininit.exe",),
        exact_count=1,
        notes="SCM; singleton under wininit",
    ),
    ExpectedProfile(
        name="lsass.exe",
        expected_parents=("wininit.exe",),
        exact_count=1,
        notes="Local Security Authority; singleton under wininit. "
              "Any masquerade / duplication is strong credential-access signal.",
    ),
    ExpectedProfile(
        name="lsaiso.exe",
        expected_parents=("wininit.exe",),
        max_count=1,                  # 0 or 1 (Credential Guard optional)
        notes="Only present if Credential Guard enabled",
    ),
    ExpectedProfile(
        name="winlogon.exe",
        expected_parents=("smss.exe",),
        min_count=1,
        parent_may_exit=True,
        notes="≥1 per session",
    ),
    ExpectedProfile(
        name="csrss.exe",
        expected_parents=("smss.exe",),
        min_count=2,                  # Session 0 + Session 1 minimum
        parent_may_exit=True,
        notes="≥2 instances; masqueraded csrss. parented elsewhere is classic",
    ),
    ExpectedProfile(
        name="smss.exe",
        expected_parents=("system",),
        exact_count=1,                # Only the master; children exit
        notes="Master session-manager singleton; child-smss exit after session",
    ),
    ExpectedProfile(
        name="services.exe",         # duplicate ignored by dedup below
        expected_parents=("wininit.exe",),
        exact_count=1,
    ),
    ExpectedProfile(
        name="explorer.exe",
        expected_parents=("userinit.exe",),
        parent_may_exit=True,         # userinit exits after launching explorer
        notes="1+ per logged-on user; parent userinit exits",
    ),
    ExpectedProfile(
        name="svchost.exe",
        expected_parents=("services.exe",),
        min_count=3,                  # modern Win10 has many; but >0 at least
        notes="Parent MUST be services.exe most of the time; "
              "explorer or cmd or random EXE parent is masquerade",
    ),
    ExpectedProfile(
        name="runtimebroker.exe",
        expected_parents=("svchost.exe",),
        notes="UWP broker; parent svchost",
    ),
    ExpectedProfile(
        name="taskhostw.exe",
        expected_parents=("svchost.exe",),
        notes="Task host; parent svchost",
    ),
)


# Dedup by name (the matrix has a duplicate services.exe for doc clarity)
def _expected_for(name: str) -> ExpectedProfile | None:
    for p in _MATRIX:
        if p.name == name:
            return p
    return None


# --- Anomaly detection ----------------------------------------------------

@dataclass
class ProcessAnomaly:
    image_name: str
    reason: str                       # "unexpected_parent" / "count_high" / ...
    details: str
    suspected_pids: list[int] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    attack: list[tuple[str, str]] = field(default_factory=list)


def _hypotheses_for(image_name: str) -> list[str]:
    """Which hypotheses a masquerade/anomaly of this process most directly
    points at. lsass.exe is specifically credential-access. System core
    processes generally imply APT / injection if abnormal."""
    name = image_name.lower()
    if name == "lsass.exe":
        return ["H_CREDENTIAL_ACCESS", "H_PROCESS_INJECTION"]
    if name in ("services.exe", "wininit.exe", "winlogon.exe", "csrss.exe",
                "lsaiso.exe"):
        return ["H_PROCESS_INJECTION", "H_APT_ESPIONAGE"]
    if name == "svchost.exe":
        return ["H_LIVING_OFF_THE_LAND", "H_PROCESS_INJECTION"]
    return ["H_PROCESS_INJECTION"]


def _attack_for(image_name: str) -> list[tuple[str, str]]:
    name = image_name.lower()
    if name == "lsass.exe":
        return [("T1003.001", "OS Credential Dumping: LSASS Memory"),
                ("T1036.005", "Masquerading: Match Legitimate Name or Location")]
    return [("T1036.005", "Masquerading: Match Legitimate Name or Location")]


def analyze(pslist_rows: list[dict]) -> list[ProcessAnomaly]:
    """Walk pslist rows and return Hunt-Evil-shaped anomalies.

    Every row must have at minimum `ImageFileName`, `PID`, `PPID`. Missing
    rows are silently skipped so callers don't have to pre-clean the list.
    """
    # PID → ImageFileName lookup (lowercased)
    by_pid: dict[int, str] = {}
    for r in pslist_rows:
        pid = r.get("PID")
        name = (r.get("ImageFileName") or "").lower()
        if pid is None or not name:
            continue
        by_pid[pid] = name

    # Group rows by name for count checks
    by_name: dict[str, list[dict]] = {}
    for r in pslist_rows:
        name = (r.get("ImageFileName") or "").lower()
        if not name:
            continue
        by_name.setdefault(name, []).append(r)

    out: list[ProcessAnomaly] = []

    for profile in _MATRIX:
        # Skip duplicate entries in the matrix declaration
        if profile is not _expected_for(profile.name):
            continue
        rows = by_name.get(profile.name, [])
        n = len(rows)

        # Count checks
        if profile.exact_count is not None and n != profile.exact_count:
            # exception: exact_count with parent_may_exit tolerates 0 too when
            # looking at a crash dump taken mid-reboot — but 0 on wininit/lsass/
            # services is still suspicious because those are running at any
            # normal capture time.
            if n == 0:
                reason = "process_missing"
                detail = (f"Expected singleton {profile.name!r} not present in "
                          f"pslist. Memory capture likely taken before session "
                          f"start, OR the process was terminated (credential-"
                          f"access operators sometimes kill lsass.exe after "
                          f"dumping).")
            else:
                reason = "count_high" if n > profile.exact_count else "count_low"
                detail = (f"Expected exactly {profile.exact_count} instance(s) "
                          f"of {profile.name!r}, found {n}. "
                          + (profile.notes or ""))
            out.append(ProcessAnomaly(
                image_name=profile.name, reason=reason, details=detail,
                suspected_pids=[r.get("PID") for r in rows if r.get("PID")],
                hypotheses=_hypotheses_for(profile.name),
                attack=_attack_for(profile.name),
            ))
            # Don't also flag parent anomalies when the count itself is broken
            continue

        if profile.max_count is not None and n > profile.max_count:
            out.append(ProcessAnomaly(
                image_name=profile.name, reason="count_high",
                details=(f"Expected ≤{profile.max_count} instance(s) of "
                         f"{profile.name!r}, found {n}. "
                         + (profile.notes or "")),
                suspected_pids=[r.get("PID") for r in rows if r.get("PID")],
                hypotheses=_hypotheses_for(profile.name),
                attack=_attack_for(profile.name),
            ))
            continue

        if profile.min_count is not None and n < profile.min_count and n > 0:
            out.append(ProcessAnomaly(
                image_name=profile.name, reason="count_low",
                details=(f"Expected ≥{profile.min_count} instance(s) of "
                         f"{profile.name!r}, found {n}. "
                         + (profile.notes or "")),
                suspected_pids=[r.get("PID") for r in rows if r.get("PID")],
                hypotheses=_hypotheses_for(profile.name),
                attack=_attack_for(profile.name),
            ))
            continue

        # Parent-name checks — one anomaly per row with wrong parent
        if n == 0 or not profile.expected_parents:
            continue
        wrong_parents: list[tuple[int, int, str]] = []  # (pid, ppid, parent_name)
        for r in rows:
            pid = r.get("PID")
            ppid = r.get("PPID")
            parent_name = by_pid.get(ppid, "")
            # When parent is missing from pslist AND expected parent is known
            # to exit (smss, userinit), that's benign — skip.
            if not parent_name and profile.parent_may_exit:
                continue
            if parent_name and parent_name not in profile.expected_parents:
                wrong_parents.append((pid, ppid, parent_name))
        if wrong_parents:
            samples = ", ".join(
                f"PID {pid} (PPID {ppid} = {pn!r})"
                for pid, ppid, pn in wrong_parents[:5])
            expected = "/".join(profile.expected_parents)
            out.append(ProcessAnomaly(
                image_name=profile.name, reason="unexpected_parent",
                details=(f"{len(wrong_parents)} instance(s) of "
                         f"{profile.name!r} with unexpected parent — "
                         f"expected {expected}; got: {samples}. "
                         + (profile.notes or "")),
                suspected_pids=[pid for pid, _, _ in wrong_parents],
                hypotheses=_hypotheses_for(profile.name),
                attack=_attack_for(profile.name),
            ))
    return out

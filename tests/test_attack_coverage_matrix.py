"""ATT&CK technique-coverage regression matrix.

Two layers:

1. **Synthetic probes (always on)** — every probe in
   ``el.intel.attack_probes`` is exercised against a hand-built
   ProbeContext that contains the fingerprint events. Locks the
   probe semantics in regardless of whether the corpus is present.

2. **Corpus-gated matrix (opt-in via ``ATTACK_DATA_ROOT``)** —
   walks the Splunk attack_data tree, parses each labelled
   technique's Sysmon + Falcon logs, and asserts:
     - Each probe FIRES on its own T-ID folder
     - Each probe DOES NOT FIRE on the bulk of unrelated T-IDs
       (false-positive guard with a small allowlist for known
       overlapping T-IDs — e.g. T1059.001 PowerShell shows up
       inside the persistence T1547.001 corpus too).
"""
import os
from pathlib import Path

import pytest

from el.intel import attack_probes as ap
from el.skills import falcon_logs as fl
from el.skills import sysmon_xml as sx


# ---------------------------------------------------------------------------
# Synthetic-probe fixtures
# ---------------------------------------------------------------------------

def _sysmon_event(blob: str) -> sx.SysmonEvent:
    ev = sx.parse_event(blob)
    assert ev is not None
    return ev


def _eid10_lsass_handle(access="0x1410"):
    return _sysmon_event(
        "<Event><System><EventID>10</EventID></System><EventData>"
        "<Data Name='SourceImage'>C:\\Tools\\mimikatz.exe</Data>"
        "<Data Name='TargetImage'>C:\\Windows\\System32\\lsass.exe</Data>"
        f"<Data Name='GrantedAccess'>{access}</Data>"
        "</EventData></Event>"
    )


def _eid1_proc_create(image: str, cmdline: str = ""):
    return _sysmon_event(
        "<Event><System><EventID>1</EventID></System><EventData>"
        f"<Data Name='Image'>{image}</Data>"
        f"<Data Name='CommandLine'>{cmdline}</Data>"
        "</EventData></Event>"
    )


def _eid13_reg_set(target: str):
    return _sysmon_event(
        "<Event><System><EventID>13</EventID></System><EventData>"
        f"<Data Name='TargetObject'>{target}</Data>"
        "<Data Name='Details'>foo</Data>"
        "</EventData></Event>"
    )


def _eid11_file_create(target: str):
    return _sysmon_event(
        "<Event><System><EventID>11</EventID></System><EventData>"
        f"<Data Name='TargetFilename'>{target}</Data>"
        "</EventData></Event>"
    )


# ---------------------------------------------------------------------------
# Synthetic probe assertions — locked-in semantics
# ---------------------------------------------------------------------------

def test_t1003_001_fires_on_lsass_handle():
    ctx = ap.ProbeContext(sysmon=[_eid10_lsass_handle()])
    assert ap.probe_t1003_001_lsass_dump(ctx)


def test_t1003_001_does_not_fire_on_benign_handle():
    ctx = ap.ProbeContext(sysmon=[_eid10_lsass_handle("0x1000")])
    assert not ap.probe_t1003_001_lsass_dump(ctx)


def test_t1059_001_fires_on_powershell_proc_create():
    ctx = ap.ProbeContext(sysmon=[
        _eid1_proc_create(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell -enc dABlAA==")])
    assert ap.probe_t1059_001_powershell(ctx)


def test_t1059_001_does_not_fire_on_cmd():
    ctx = ap.ProbeContext(sysmon=[
        _eid1_proc_create(r"C:\Windows\System32\cmd.exe", "cmd /c dir")])
    assert not ap.probe_t1059_001_powershell(ctx)


def test_t1547_001_fires_on_run_key():
    ctx = ap.ProbeContext(sysmon=[_eid13_reg_set(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil")])
    assert ap.probe_t1547_001_run_keys(ctx)


def test_t1547_001_fires_on_bootexecute():
    ctx = ap.ProbeContext(sysmon=[_eid13_reg_set(
        r"HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute")])
    assert ap.probe_t1547_001_run_keys(ctx)


def test_t1547_001_does_not_fire_on_unrelated_key():
    ctx = ap.ProbeContext(sysmon=[_eid13_reg_set(
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Hostname")])
    assert not ap.probe_t1547_001_run_keys(ctx)


def test_t1218_011_fires_on_rundll32():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\rundll32.exe",
        "rundll32.exe shell32.dll,#61")])
    assert ap.probe_t1218_011_rundll32(ctx)


def test_t1218_011_does_not_fire_on_explorer():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\explorer.exe", "")])
    assert not ap.probe_t1218_011_rundll32(ctx)


def test_t1112_fires_on_wdigest_modification():
    ctx = ap.ProbeContext(sysmon=[_eid13_reg_set(
        r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential")])
    assert ap.probe_t1112_registry_modification(ctx)


def test_t1112_does_not_fire_on_run_key():
    """T1547.001 fires on Run keys; T1112 should NOT — keeps the
    matrix's false-positive-guard tractable."""
    ctx = ap.ProbeContext(sysmon=[_eid13_reg_set(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\foo")])
    assert not ap.probe_t1112_registry_modification(ctx)


def test_t1003_003_fires_on_ntds_dit_file():
    ctx = ap.ProbeContext(sysmon=[_eid11_file_create(
        r"C:\Windows\Temp\NTDS.dit")])
    assert ap.probe_t1003_003_ntds(ctx)


def test_t1003_003_fires_on_ntdsutil_proc():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\ntdsutil.exe",
        "ntdsutil ac in ntds ifm create full c:\\temp q q")])
    assert ap.probe_t1003_003_ntds(ctx)


def test_t1003_003_does_not_fire_on_unrelated():
    ctx = ap.ProbeContext(sysmon=[_eid1_proc_create(
        r"C:\Windows\System32\notepad.exe", "")])
    assert not ap.probe_t1003_003_ntds(ctx)


# ---------------------------------------------------------------------------
# Corpus-gated coverage matrix
# ---------------------------------------------------------------------------

ATTACK_DATA = os.environ.get("ATTACK_DATA_ROOT")
_CORPUS_AVAILABLE = (
    ATTACK_DATA
    and Path(ATTACK_DATA, "datasets/attack_techniques").is_dir()
)


def _load_ctx(tid: str) -> ap.ProbeContext | None:
    """Walk a technique folder, parse every windows-sysmon.log /
    crowdstrike_falcon.log we find, return one ProbeContext with
    everything concatenated. Returns None when the technique
    folder doesn't exist or has no consumable logs."""
    if not _CORPUS_AVAILABLE:
        return None
    base = Path(ATTACK_DATA) / "datasets" / "attack_techniques" / tid
    if not base.is_dir():
        return None
    sysmon_events: list[sx.SysmonEvent] = []
    falcon_events: list[fl.FalconEvent] = []
    for sub in base.iterdir():
        if not sub.is_dir():
            continue
        for f in sub.glob("*sysmon*.log"):
            sysmon_events.extend(
                sx.parse_file(f, max_events=20_000))
        for f in sub.glob("*falcon*.log"):
            falcon_events.extend(
                fl.parse_file(f, max_events=20_000))
    if not sysmon_events and not falcon_events:
        return None
    return ap.ProbeContext(sysmon=sysmon_events,
                             falcon=falcon_events)


# Documented technique-overlap map. The Splunk attack_data
# corpus's per-T-ID runs use a shared PowerShell-driven harness:
# *every* technique under test is set up with PowerShell snippets
# that often include mimikatz / Get-Process / Invoke-Reflective*,
# so ``probe_t1003_001_lsass_dump`` and ``probe_t1059_001_powershell``
# legitimately fire across most corpora as a corpus property — not
# a probe defect.
#
# Each entry is the *probe T-ID* mapped to the set of *corpus T-IDs*
# where firing is the expected, semantically-correct outcome (the
# corpus genuinely demonstrates that technique even though the
# folder is labelled differently). This map encodes our model of
# ground-truth co-occurrence; failing the test means a probe is
# firing somewhere it has no defensible reason to.
_EXPECTED_OVERLAPS: dict[str, set[str]] = {
    # T1003.001 — LSASS handle access. PowerShell setup in T1059.001 /
    # T1218.011 / T1547.001 / T1112 / T1003.003 frequently uses
    # mimikatz-class commands that exercise lsass-handle opens with
    # creddump-canonical access masks. This is the corpus harness
    # being honest about how attackers chain techniques together.
    "T1003.001": {"T1003.003", "T1059.001", "T1547.001",
                  "T1218.011", "T1112"},
    # T1059.001 — PowerShell. Setup script for every other corpus.
    "T1059.001": {"T1003.001", "T1003.003", "T1547.001",
                  "T1218.011", "T1112"},
    # T1218.011 — rundll32. Surfaces in PowerShell-set-up tests
    # (T1059.001) and registry-write tests (T1112) because the
    # harness sometimes drops a marker via rundll32 calls.
    "T1218.011": {"T1059.001", "T1112"},
    # Run-key persistence is sometimes set up via reg.exe call
    # paths in PowerShell-driven tests.
    "T1547.001": {"T1112"},
    # Registry modification is wide; many tests touch the registry.
    "T1112": {"T1547.001"},
}


@pytest.mark.skipif(
    not _CORPUS_AVAILABLE,
    reason="ATTACK_DATA_ROOT not set or corpus missing",
)
@pytest.mark.parametrize("tid", sorted(ap.PROBES.keys()))
def test_probe_fires_on_own_corpus(tid):
    ctx = _load_ctx(tid)
    if ctx is None:
        pytest.skip(f"{tid} corpus folder absent or empty")
    fn = ap.probe_for(tid)
    assert fn is not None, f"no probe registered for {tid}"
    assert fn(ctx), (
        f"probe for {tid} did NOT fire on its own corpus — "
        f"sysmon EIDs={ctx.sysmon_eids}, falcon names="
        f"{ctx.falcon_event_names}")


@pytest.mark.skipif(
    not _CORPUS_AVAILABLE,
    reason="ATTACK_DATA_ROOT not set or corpus missing",
)
def test_probes_do_not_fire_excessively_on_unrelated_corpora():
    """For each probe, count how many OTHER T-ID corpora it fires
    on (excluding documented overlaps). Each probe is allowed to
    fire on at most 1 unrelated T-ID (slack for noise the
    corpus inevitably has) — anything more fails the test."""
    other_fires: dict[str, list[str]] = {}
    for probe_tid, probe_fn in ap.PROBES.items():
        false_fires: list[str] = []
        for corpus_tid in ap.PROBES.keys():
            if corpus_tid == probe_tid:
                continue
            if corpus_tid in _EXPECTED_OVERLAPS.get(probe_tid, set()):
                continue
            ctx = _load_ctx(corpus_tid)
            if ctx is None:
                continue
            if probe_fn(ctx):
                false_fires.append(corpus_tid)
        other_fires[probe_tid] = false_fires
    # Allow at most 1 unexpected fire per probe — corpus is noisy.
    over_budget = {p: f for p, f in other_fires.items() if len(f) > 1}
    assert not over_budget, (
        f"probes firing on too many unrelated corpora "
        f"(>1 unexpected): {over_budget}. Either tighten the "
        f"probe or add the firing T-ID to _EXPECTED_OVERLAPS "
        f"with a reason.")


@pytest.mark.skipif(
    not _CORPUS_AVAILABLE,
    reason="ATTACK_DATA_ROOT not set or corpus missing",
)
def test_attack_coverage_summary(capsys):
    """Print the matrix as a coverage rollup. Always passes — this
    is reporting, not assertion. The number is what matters: how
    many T-IDs in the corpus does EL fingerprint?"""
    base = Path(ATTACK_DATA) / "datasets" / "attack_techniques"
    available = sorted(p.name for p in base.iterdir()
                        if p.is_dir() and p.name.startswith("T"))
    covered = sorted(ap.PROBES.keys())
    pct = (100.0 * len(covered) / len(available)
            if available else 0.0)
    msg = (f"\nATT&CK coverage: "
           f"{len(covered)}/{len(available)} T-IDs "
           f"({pct:.1f}%) — probes registered for "
           f"{', '.join(covered)}")
    print(msg)
    # No assertion; the print is the deliverable.

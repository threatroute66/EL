"""Contract for ArtifactRecoveryAgent: bodyfile candidate selection, magic
validation, and the detect→recover orchestration with the subprocess skills
monkeypatched (no real TSK/libvshadow).
"""
from __future__ import annotations

from pathlib import Path

from el.agents.artifact_recovery import (
    ArtifactRecoveryAgent, Candidate, parse_bodyfile_targets,
    expected_magic, header_matches, find_log_entry, select_pre_clearing,
)
from el.agents.base import AgentContext
from el.schemas.finding import EvidenceItem
from el.skills import wipe_detect

# fls -m bodyfile rows (MD5|path|inode|mode|uid|gid|size|atime|mtime|ctime|crtime)
BODYFILE = """\
0|/Users/fredr/AppData/Local/Microsoft/Outlook/fred.rocba@outlook.com.ost|124086-128-4|r/rrwxrwxrwx|0|0|33497088|1|1|1|1
0|/Users/fredr/AppData/Local/Microsoft/Outlook/fred.rocba@gmail.com.ost|124042-128-4|r/rrwxrwxrwx|0|0|16818176|1|1|1|1
0|/Users/fredr/Pictures/holiday.jpg|55501-128-1|r/rrwxrwxrwx|0|0|204800|1|1|1|1
0|/Windows/System32/winevt/Logs/Security.evtx|9001-128-2|r/rrwxrwxrwx|0|0|1118208|1|1|1|1
0|/Users/fredr/AppData/Local/Microsoft/Outlook/fred.rocba@outlook.com.ost ($FILE_NAME)|124086-48-2|r/r|0|0|0|1|1|1|1
"""


def test_bodyfile_selects_only_high_value_paths():
    cands = parse_bodyfile_targets(BODYFILE, offset_sectors=0)
    paths = [c.relpath for c in cands]
    assert any(p.endswith("outlook.com.ost") for p in paths)
    assert any(p.endswith("gmail.com.ost") for p in paths)
    assert any(p.endswith("Security.evtx") for p in paths)
    # the JPG is not high-value; the $FILE_NAME annotation row is skipped
    assert not any("holiday.jpg" in p for p in paths)
    assert not any("($FILE_NAME)" in p for p in paths)


def test_bodyfile_dedupes_and_carries_offset():
    cands = parse_bodyfile_targets(BODYFILE + BODYFILE, offset_sectors=2048)
    # duplicate rows collapse; offset threads through
    keys = {(c.relpath, c.inode) for c in cands}
    assert len(keys) == len(cands)
    assert all(c.offset_sectors == 2048 for c in cands)


def test_magic_validation():
    assert expected_magic("x.ost") == b"!BDN"
    assert expected_magic("Security.evtx") == b"ElfFile\x00"
    assert expected_magic("NTUSER.DAT") == b"regf"
    assert expected_magic("notes.txt") is None
    # header_matches: right magic passes, wrong magic fails, unknown-type any
    assert header_matches(b"!BDNxxxx", "a.ost")
    assert not header_matches(b"\x00\x00\x00\x00", "a.ost")
    assert header_matches(b"anything", "notes.txt")
    assert not header_matches(b"", "notes.txt")


def test_non_disk_case_is_silent_noop():
    ctx = AgentContext(case_id="c", case_dir=Path("/tmp/nope"),
                       input_path=Path("/tmp/x"), manifest={}, shared={})
    assert ArtifactRecoveryAgent().run(ctx) == []


# --- orchestration with monkeypatched skills -------------------------------

def _wired_ctx(tmp_path):
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "disk_forensicator").mkdir(parents=True)
    (case_dir / "analysis" / "disk_forensicator" / "fls.txt").write_text(BODYFILE)
    raw = tmp_path / "disk.raw"
    raw.write_bytes(b"\x00" * 1024)        # ewfmount fake returns this path
    return AgentContext(
        case_id="rocba", case_dir=case_dir,
        input_path=raw, manifest={},
        shared={"partitions": [{"start_sector": 0}], "sector_size": 512,
                "raw_input_path": str(raw)})


# istat text the fake skill returns per inode. The wiped OST is the only
# allocated+non-resident+init>0 stream whose content reads zero on the live FS.
_WIPED = ("Allocated File\nType: $DATA (128-4)   Name: N/A   "
          "Non-Resident   size: 33497088  init_size: 24973312\n")
_INTACT = ("Allocated File\nType: $DATA (128-4)   Name: N/A   "
           "Non-Resident   size: 16818176  init_size: 16818176\n")


class _FakeRun:
    def __init__(self, path): self.stdout_path = path


def _is_live(image) -> bool:
    """The live image path ends in disk.raw; snapshot devices live under a
    vss mount dir (…-artrec-vss/vssN)."""
    return str(image).endswith("disk.raw")


def _install_fakes(monkeypatch, *, snap_has_content: bool):
    import el.agents.artifact_recovery as ar
    from el.skills import vss_diff

    def fake_istat(image, inode, out_dir, offset=None, label=None, timeout=120):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        p = Path(out_dir) / f"{label or inode}.txt"
        p.write_text(_WIPED if str(inode).startswith("124086") else _INTACT)
        return _FakeRun(p)

    def fake_zero(image, inode, offset=None, **k):
        if not str(inode).startswith("124086"):
            return False
        if _is_live(image):
            return True                     # the OST is zeroed on the live FS
        return not snap_has_content         # snapshot: zero unless it has content

    def fake_icat(dev, inode, dest, offset=None, timeout=900):
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        Path(dest).write_bytes(b"!BDN" + b"\x11" * 4096)   # valid OST header
        return 4100

    monkeypatch.setattr(ar.sk, "istat", fake_istat)
    monkeypatch.setattr(ar.sk, "content_is_zero", fake_zero)
    monkeypatch.setattr(ar.sk, "icat_extract", fake_icat)
    monkeypatch.setattr(ar.sk, "ewfmount", lambda image, *a, **k: image)
    monkeypatch.setattr(ar.sk, "ewfumount", lambda *a, **k: None)

    class Snap:
        def __init__(self, n): self.number = n; self.creation_utc = f"2020-11-14T1{n}:00Z"
    class Vol:
        device = Path("/dev/mapper/elvss_test"); repaired = True
        snapshots = [Snap(1), Snap(2)]
    def fake_vshadowmount(device, mount_dir, **k):
        mount_dir.mkdir(parents=True, exist_ok=True)
        for n in (1, 2):                    # materialise the vssN device files
            (mount_dir / f"vss{n}").write_bytes(b"")
    monkeypatch.setattr(vss_diff, "vss_open", lambda *a, **k: Vol())
    monkeypatch.setattr(vss_diff, "vss_close", lambda *a, **k: None)
    monkeypatch.setattr(vss_diff, "vshadowmount", fake_vshadowmount)
    monkeypatch.setattr(vss_diff, "fusermount_unmount", lambda *a, **k: None)
    monkeypatch.setattr(ar.ArtifactRecoveryAgent, "_find_inode",
                        lambda self, dev, basename, analysis: "124086-128-4")


def test_wiped_ost_detected_and_recovered(tmp_path, monkeypatch):
    """OST wiped on the live FS, but a snapshot still holds valid content →
    high-confidence recovery, header-validated."""
    _install_fakes(monkeypatch, snap_has_content=True)
    findings = ArtifactRecoveryAgent().run(_wired_ctx(tmp_path))
    assert any("Artifact wipe [wiped_in_place]" in f.claim and f.confidence == "high"
               for f in findings)
    assert any(f.confidence == "high" and "RECOVERED" in f.claim
               and "snapshot #2" in f.claim for f in findings)   # newest first


def test_wiped_ost_vss_exhausted_emits_carve_pivot(tmp_path, monkeypatch):
    """rocba reality: OST wiped AND every snapshot already zeroed → an honest
    VSS-exhausted note + the carve pivot, never a high-confidence recovery."""
    _install_fakes(monkeypatch, snap_has_content=False)
    monkeypatch.delenv("EL_ARTIFACT_CARVE", raising=False)
    findings = ArtifactRecoveryAgent().run(_wired_ctx(tmp_path))
    assert any("Artifact wipe [wiped_in_place]" in f.claim for f in findings)
    assert any("VSS exhausted" in f.claim for f in findings)
    assert any("Carve pivot" in f.claim and f.confidence == "insufficient"
               for f in findings)
    assert not any("RECOVERED" in f.claim for f in findings)


# --- cleared-log recovery --------------------------------------------------

# fls -m bodyfile rows incl. size (field 7): a CLEARED (small) Security.evtx
_LOG_BODYFILE = (
    "0|/Windows/System32/winevt/Logs/Security.evtx|41832-128-2|"
    "r/rrwxrwxrwx|0|0|1118208|1|1|1|1\n"
    "0|/Windows/System32/winevt/Logs/System.evtx|41833-128-2|"
    "r/rrwxrwxrwx|0|0|2097152|1|1|1|1\n"
)


def test_find_log_entry_reads_inode_and_size():
    ent = find_log_entry(_LOG_BODYFILE, "winevt/Logs/Security.evtx")
    assert ent is not None
    relpath, inode, size = ent
    assert relpath.endswith("Security.evtx")
    assert inode == "41832-128-2"
    assert size == 1118208            # the cleared (small) live size
    assert find_log_entry(_LOG_BODYFILE, "winevt/Logs/Nope.evtx") is None


def test_select_pre_clearing_picks_newest_substantially_larger():
    live = 1118208
    # snapshots 11-14 are post-clearing (~live); 9-10 are pre-clearing (large)
    snaps = [(14, 1118208), (13, 1120000), (12, 1118208),
             (11, 1118208), (10, 19992576), (9, 19000000)]
    assert select_pre_clearing(live, snaps) == 10        # newest large one
    # all near-live (no clearing recoverable) → None
    assert select_pre_clearing(live, [(14, 1118208), (13, 1200000)]) is None
    # a small delta above ratio but under the absolute floor → None
    assert select_pre_clearing(live, [(14, int(live * 1.6))]) is None  # +0.6MB < 4MB


def _cleared_log_ctx(tmp_path):
    case_dir = tmp_path / "case"
    (case_dir / "analysis" / "disk_forensicator").mkdir(parents=True)
    (case_dir / "analysis" / "disk_forensicator" / "fls.txt").write_text(_LOG_BODYFILE)
    raw = tmp_path / "dc.raw"; raw.write_bytes(b"\x00" * 512)
    return AgentContext(
        case_id="srl", case_dir=case_dir, input_path=raw, manifest={},
        shared={"partitions": [{"start_sector": 0}], "sector_size": 512,
                "raw_input_path": str(raw)})


def _istat_text(size, nonres=True):
    res = "Non-Resident" if nonres else "Resident"
    return (f"Allocated File\nType: $DATA (128-2)   Name: N/A   {res}   "
            f"size: {size}  init_size: {size}\n")


def test_recover_cleared_log_from_pre_clearing_shadow(tmp_path, monkeypatch):
    """The fix: a cleared Security.evtx is recovered from the newest pre-clearing
    shadow copy, EVTX-validated, as a high-confidence finding."""
    import el.agents.artifact_recovery as ar
    from el.skills import vss_diff

    class Snap:
        def __init__(self, n): self.number = n; self.creation_utc = f"2018-09-{n:02d}T16:00Z"
    class Vol:
        device = Path("/dev/mapper/x"); repaired = False
        snapshots = [Snap(n) for n in (9, 10, 11, 12, 13, 14)]

    def fake_vshadowmount(device, mount_dir, **k):
        mount_dir.mkdir(parents=True, exist_ok=True)
        for n in (9, 10, 11, 12, 13, 14):
            (mount_dir / f"vss{n}").write_bytes(b"")

    # istat: snapshots 9 & 10 hold the large pre-clearing log; 11-14 are cleared
    def fake_istat(image, inode, out_dir, offset=None, label=None, timeout=120):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        n = int(str(image).rsplit("vss", 1)[-1]) if "vss" in str(image) else 0
        size = 19992576 if n in (9, 10) else 1118208
        p = Path(out_dir) / f"{label or 'istat'}.txt"; p.write_text(_istat_text(size))
        class R: stdout_path = p
        return R()

    def fake_icat(dev, inode, dest, offset=None, timeout=900):
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        Path(dest).write_bytes(b"ElfFile\x00" + b"\x11" * 4096)   # valid EVTX magic
        return 19992576

    monkeypatch.setattr(vss_diff, "vss_open", lambda *a, **k: Vol())
    monkeypatch.setattr(vss_diff, "vss_close", lambda *a, **k: None)
    monkeypatch.setattr(vss_diff, "vshadowmount", fake_vshadowmount)
    monkeypatch.setattr(vss_diff, "fusermount_unmount", lambda *a, **k: None)
    monkeypatch.setattr(ar.sk, "istat", fake_istat)
    monkeypatch.setattr(ar.sk, "icat_extract", fake_icat)

    ctx = _cleared_log_ctx(tmp_path)
    agent = ArtifactRecoveryAgent()
    out = agent._recover_cleared_logs(ctx, Path(str(ctx.input_path)), 512,
                                      ctx.case_dir / "analysis" / "artifact_recovery")
    recs = [f for f in out if f.confidence == "high" and "RECOVERED cleared event log" in f.claim]
    assert recs, [f.claim for f in out]
    # newest pre-clearing copy is snapshot #10
    assert any("snapshot #10" in f.claim for f in recs)
    assert any("H_LOG_CLEARED" in f.hypotheses_supported for f in recs)


def test_cleared_log_insufficient_when_no_pre_clearing_shadow(tmp_path, monkeypatch):
    """Honest gap: clearing predates the shadow set (all snapshots ~ live size)
    → insufficient, not a fabricated recovery."""
    import el.agents.artifact_recovery as ar
    from el.skills import vss_diff

    class Snap:
        def __init__(self, n): self.number = n; self.creation_utc = f"t{n}"
    class Vol:
        device = Path("/dev/mapper/x"); repaired = False
        snapshots = [Snap(n) for n in (12, 13, 14)]

    def fake_vshadowmount(device, mount_dir, **k):
        mount_dir.mkdir(parents=True, exist_ok=True)
        for n in (12, 13, 14): (mount_dir / f"vss{n}").write_bytes(b"")

    def fake_istat(image, inode, out_dir, offset=None, label=None, timeout=120):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        p = Path(out_dir) / f"{label or 'istat'}.txt"; p.write_text(_istat_text(1118208))
        class R: stdout_path = p
        return R()

    monkeypatch.setattr(vss_diff, "vss_open", lambda *a, **k: Vol())
    monkeypatch.setattr(vss_diff, "vss_close", lambda *a, **k: None)
    monkeypatch.setattr(vss_diff, "vshadowmount", fake_vshadowmount)
    monkeypatch.setattr(vss_diff, "fusermount_unmount", lambda *a, **k: None)
    monkeypatch.setattr(ar.sk, "istat", fake_istat)

    ctx = _cleared_log_ctx(tmp_path)
    out = ArtifactRecoveryAgent()._recover_cleared_logs(
        ctx, Path(str(ctx.input_path)), 512, ctx.case_dir / "analysis" / "artifact_recovery")
    assert out and all(f.confidence == "insufficient" for f in out)
    assert not any("RECOVERED" in f.claim for f in out)

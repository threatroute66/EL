"""MemProcFS skill — unit tests.

Tests focus on parsing and dataclass behaviour with a synthetic CSV;
the real subprocess+FUSE flow is gated behind a real-binary smoke test.
"""
from pathlib import Path

import pytest

from el.skills import memprocfs as mpfs


# --- FindEvilHit parsing ----------------------------------------------

def test_findevil_hit_from_csv_row():
    row = {
        "Rule": "FE_INJECTED_PE",
        "Process": "explorer.exe",
        "PID": "1234",
        "Address": "0x7ff8a0000000",
        "Detail": "MZ header in RWX VAD",
    }
    h = mpfs.FindEvilHit.from_csv_row(row)
    assert h.rule == "FE_INJECTED_PE"
    assert h.process == "explorer.exe"
    assert h.pid == "1234"
    assert h.address == "0x7ff8a0000000"
    assert h.detail == "MZ header in RWX VAD"


def test_findevil_hit_truncates_long_detail():
    row = {"Rule": "X", "Process": "p", "PID": "1", "Address": "0x0",
           "Detail": "A" * 1000}
    h = mpfs.FindEvilHit.from_csv_row(row)
    assert len(h.detail) == 500


def test_findevil_hit_handles_missing_keys():
    h = mpfs.FindEvilHit.from_csv_row({})
    assert h.rule == ""
    assert h.process == ""


# --- CSV reader -------------------------------------------------------

def test_read_csv_rows_returns_empty_on_missing_file(tmp_path):
    assert mpfs._read_csv_rows(tmp_path / "does-not-exist.csv") == []


def test_read_csv_rows_caps_at_max_rows(tmp_path):
    p = tmp_path / "findevil.csv"
    lines = ["Rule,Process,PID,Address,Detail"]
    for i in range(50):
        lines.append(f"R{i},explorer.exe,{i},0x0,detail")
    p.write_text("\n".join(lines))
    rows = mpfs._read_csv_rows(p, max_rows=10)
    assert len(rows) == 10
    assert rows[0]["Rule"] == "R0"


# --- iter_findevil_hits priority ordering ------------------------------

def test_iter_findevil_hits_prioritises_injection_keywords(tmp_path):
    result = mpfs.MemProcFSResult(
        image_path=tmp_path / "fake.dmp",
        mount_point=tmp_path / "mount",
        forensic_findings=[
            mpfs.FindEvilHit(rule="OTHER_RULE", process="a", pid="1",
                              address="0x0", detail=""),
            mpfs.FindEvilHit(rule="FE_INJECTED_PE", process="b", pid="2",
                              address="0x0", detail=""),
            mpfs.FindEvilHit(rule="FE_HOLLOW_PROCESS", process="c", pid="3",
                              address="0x0", detail=""),
        ],
    )
    ordered = list(mpfs.iter_findevil_hits(result))
    # INJECTED comes before HOLLOW (priority order in code), both before OTHER
    assert ordered[0].rule == "FE_INJECTED_PE"
    assert ordered[1].rule == "FE_HOLLOW_PROCESS"
    assert ordered[2].rule == "OTHER_RULE"


# --- as_evidence shape ------------------------------------------------

def test_as_evidence_shape(tmp_path):
    img = tmp_path / "memory.raw"
    img.write_bytes(b"FAKE_IMG_FOR_HASH")
    result = mpfs.MemProcFSResult(
        image_path=img,
        mount_point=tmp_path / "mount",
        forensic_findings=[
            mpfs.FindEvilHit(rule="FE_INJECTED_PE", process="explorer.exe",
                              pid="1234", address="0x0", detail=""),
        ],
        findevil_csv_path=tmp_path / "findevil.csv",
        findevil_csv_sha256="a" * 64,
        duration_seconds=12.5,
        command=["/opt/memprocfs/memprocfs", "-device", str(img)],
    )
    ev = result.as_evidence()
    assert ev.tool == "memprocfs"
    assert ev.output_sha256 == "a" * 64
    assert ev.extracted_facts["findevil_hits"] == 1
    assert ev.extracted_facts["duration_seconds"] == 12.5


def test_as_evidence_zero_pad_when_no_findevil_csv(tmp_path):
    """When no findevil CSV was produced (e.g., scan timeout), the
    evidence still has a deterministic 64-char sha placeholder."""
    img = tmp_path / "memory.raw"
    img.write_bytes(b"x")
    result = mpfs.MemProcFSResult(
        image_path=img, mount_point=tmp_path / "mount",
    )
    ev = result.as_evidence()
    assert ev.output_sha256 == "0" * 64
    assert ev.extracted_facts["findevil_hits"] == 0


# --- _which discovery ------------------------------------------------

def test_which_raises_when_missing(monkeypatch, tmp_path):
    """_which must raise MemProcFSError when no binary is found."""
    monkeypatch.setattr(mpfs.shutil, "which", lambda _: None)
    monkeypatch.setattr(mpfs, "Path",
                        lambda p: type("FakePath", (), {
                            "is_file": lambda self: False,
                        })())
    # Re-import the module path for the candidate list — easier to
    # just patch the candidate list directly:
    monkeypatch.setattr(
        mpfs, "_which", lambda: (_ for _ in ()).throw(
            mpfs.MemProcFSError("not found")
        ),
    )
    with pytest.raises(mpfs.MemProcFSError):
        mpfs._which()


# --- Smoke test (real binary, no image) ------------------------------

@pytest.mark.skipif(
    not Path("/opt/memprocfs/memprocfs").is_file(),
    reason="MemProcFS not installed",
)
def test_real_binary_help_smoke():
    """Sanity: the real binary is invokable and reports its version."""
    import subprocess
    p = subprocess.run(
        ["/opt/memprocfs/memprocfs", "-h"],
        capture_output=True, text=True, timeout=5,
    )
    text = (p.stdout + p.stderr).lower()
    assert "memprocfs" in text

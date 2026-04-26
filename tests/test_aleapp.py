"""ALEAPP wrapper skill — Android Logs Events and Protobuf Parser.

Synthetic tests use monkeypatched subprocess so the suite doesn't
depend on a real ALEAPP install. A corpus-gated smoke test runs
the real wrapper against ``/tmp/ALEAPP`` (cloned earlier in the
session) when available; without that the corpus tests skip.
"""
import csv
import os
import subprocess
from pathlib import Path

import pytest

from el.skills import aleapp as al


# --- mode detection ----------------------------------------------------

def test_detect_mode_directory_is_fs(tmp_path):
    assert al.detect_mode(tmp_path) == "fs"


def test_detect_mode_tar_extension(tmp_path):
    p = tmp_path / "android.tar"; p.touch()
    assert al.detect_mode(p) == "tar"


def test_detect_mode_zip_extension(tmp_path):
    p = tmp_path / "android.zip"; p.touch()
    assert al.detect_mode(p) == "zip"


def test_detect_mode_gz_extension(tmp_path):
    p = tmp_path / "android.gz"; p.touch()
    assert al.detect_mode(p) == "gz"


def test_detect_mode_unknown_falls_back_to_fs(tmp_path):
    p = tmp_path / "weird.xyz"; p.touch()
    assert al.detect_mode(p) == "fs"


# --- availability ------------------------------------------------------

def test_is_aleapp_available_false_for_missing_dir(tmp_path,
                                                     monkeypatch):
    monkeypatch.setenv("EL_ALEAPP_DIR", str(tmp_path / "nope"))
    assert al.is_aleapp_available() is False


def test_is_aleapp_available_true_when_script_present(tmp_path,
                                                        monkeypatch):
    fake = tmp_path / "ALEAPP"
    fake.mkdir()
    (fake / "aleapp.py").write_text("# fake")
    monkeypatch.setenv("EL_ALEAPP_DIR", str(fake))
    assert al.is_aleapp_available() is True


# --- run() error paths -------------------------------------------------

def test_run_raises_when_aleapp_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("EL_ALEAPP_DIR", str(tmp_path / "absent"))
    with pytest.raises(al.ALeappError, match="not installed"):
        al.run(tmp_path / "in", tmp_path / "out", mode="fs")


def test_run_raises_on_invalid_mode(tmp_path, monkeypatch):
    fake = tmp_path / "ALEAPP"; fake.mkdir()
    (fake / "aleapp.py").write_text("# fake")
    monkeypatch.setenv("EL_ALEAPP_DIR", str(fake))
    with pytest.raises(al.ALeappError, match="invalid mode"):
        al.run(tmp_path / "in", tmp_path / "out", mode="bogus")


def test_run_propagates_subprocess_timeout(tmp_path, monkeypatch):
    fake = tmp_path / "ALEAPP"; fake.mkdir()
    (fake / "aleapp.py").write_text("# fake")
    monkeypatch.setenv("EL_ALEAPP_DIR", str(fake))

    def raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="aleapp", timeout=1)

    monkeypatch.setattr(al.subprocess, "run", raise_timeout)
    in_path = tmp_path / "in"; in_path.mkdir()
    out_path = tmp_path / "out"
    with pytest.raises(al.ALeappError, match="timed out"):
        al.run(in_path, out_path, mode="fs", timeout=1)


def test_run_collects_tsv_exports(tmp_path, monkeypatch):
    """Mock subprocess.run so the wrapper just creates the
    expected report directory + a TSV; verify _walk_tsv_exports
    collects it as an ArtifactTable."""
    fake = tmp_path / "ALEAPP"; fake.mkdir()
    (fake / "aleapp.py").write_text("# fake")
    monkeypatch.setenv("EL_ALEAPP_DIR", str(fake))

    def fake_run_proc(cmd, check, capture_output, timeout, text):
        # Synthesise the report dir + one TSV
        out_dir = Path(cmd[cmd.index("-o") + 1])
        report = out_dir / "ALEAPP_Reports_20250101-000000"
        tsv = report / "_TSV_Exports"
        tsv.mkdir(parents=True)
        with (tsv / "Contacts.tsv").open(
                "w", newline="") as f:
            w = csv.writer(f, delimiter="\t")
            w.writerow(["name", "phone"])
            w.writerow(["Alice", "555-0100"])
            w.writerow(["Bob", "555-0101"])
        return subprocess.CompletedProcess(
            args=cmd, returncode=0,
            stdout="ALEAPP v3.2 starting\n", stderr="")

    monkeypatch.setattr(al.subprocess, "run", fake_run_proc)
    in_path = tmp_path / "in"; in_path.mkdir()
    out_path = tmp_path / "out"
    r = al.run(in_path, out_path)
    assert r.rc == 0
    assert r.version == "v3.2"
    assert len(r.tables) == 1
    t = r.tables[0]
    assert t.name == "Contacts.tsv"
    assert t.headers == ["name", "phone"]
    assert t.total_rows == 2
    assert t.populated is True


def test_run_truncates_long_table(tmp_path, monkeypatch):
    fake = tmp_path / "ALEAPP"; fake.mkdir()
    (fake / "aleapp.py").write_text("# fake")
    monkeypatch.setenv("EL_ALEAPP_DIR", str(fake))

    def fake_run_proc(cmd, **kw):
        out_dir = Path(cmd[cmd.index("-o") + 1])
        tsv = out_dir / "ALEAPP_Reports_x" / "_TSV_Exports"
        tsv.mkdir(parents=True)
        with (tsv / "SMS.tsv").open(
                "w", newline="") as f:
            w = csv.writer(f, delimiter="\t")
            w.writerow(["ts", "body"])
            for i in range(10_000):
                w.writerow([str(i), f"msg-{i}"])
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(al.subprocess, "run", fake_run_proc)
    in_path = tmp_path / "in"; in_path.mkdir()
    out_path = tmp_path / "out"
    r = al.run(in_path, out_path)
    t = r.tables[0]
    assert t.total_rows == 10_000
    assert len(t.rows) == 5_000           # default cap
    assert t.truncated is True


# --- find_table / populated_table_names --------------------------------

def test_find_table_substring_match():
    run = al.ALeappRun(
        input_path=Path("/in"), out_dir=Path("/out"),
        report_dir=Path("/out/r"),
        stdout_path=Path("/out/stdout"),
        stderr_path=Path("/out/stderr"), rc=0,
        tables=[
            al.ArtifactTable(name="Contacts.tsv", path=Path("/x"),
                              total_rows=10),
            al.ArtifactTable(name="SMS Messages.tsv", path=Path("/y"),
                              total_rows=200),
        ])
    assert al.find_table(run, "sms").name == "SMS Messages.tsv"
    assert al.find_table(run, "missing") is None


def test_populated_table_names_sorted_and_filtered():
    run = al.ALeappRun(
        input_path=Path("/in"), out_dir=Path("/out"),
        report_dir=Path("/r"),
        stdout_path=Path("/sout"), stderr_path=Path("/serr"),
        rc=0,
        tables=[
            al.ArtifactTable(name="Z.tsv", path=Path("/z"),
                              total_rows=1),
            al.ArtifactTable(name="Empty.tsv", path=Path("/e"),
                              total_rows=0),
            al.ArtifactTable(name="A.tsv", path=Path("/a"),
                              total_rows=5),
        ])
    assert al.populated_table_names(run) == ["A.tsv", "Z.tsv"]


# --- corpus smoke ------------------------------------------------------

@pytest.mark.skipif(
    not Path("/tmp/ALEAPP/aleapp.py").is_file(),
    reason="ALEAPP not cloned at /tmp/ALEAPP",
)
def test_aleapp_available_when_cloned(monkeypatch):
    monkeypatch.setenv("EL_ALEAPP_DIR", "/tmp/ALEAPP")
    assert al.is_aleapp_available() is True


@pytest.mark.skipif(
    not Path("/tmp/ALEAPP/aleapp.py").is_file()
    or os.environ.get("EL_RUN_ALEAPP_E2E") != "1",
    reason="set EL_RUN_ALEAPP_E2E=1 to run the slow corpus walk",
)
def test_aleapp_e2e_against_corpus_dir(tmp_path, monkeypatch):
    """Slow end-to-end test against a folder of Android extracted
    files. Disabled by default — operator opts in with
    EL_RUN_ALEAPP_E2E=1 because the walk takes minutes even on a
    minimal directory and ALEAPP imports many parser modules at
    startup."""
    monkeypatch.setenv("EL_ALEAPP_DIR", "/tmp/ALEAPP")
    in_path = tmp_path / "android"; in_path.mkdir()
    # Minimal seed — empty data dir is enough for ALEAPP to start
    # and produce an empty report.
    (in_path / "data").mkdir()
    out_path = tmp_path / "out"
    r = al.run(in_path, out_path, mode="fs", timeout=120)
    assert r.rc in (0, 1)                  # ALEAPP returns 1 on empty
    assert r.report_dir.exists()

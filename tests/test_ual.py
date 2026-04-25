"""User Access Logging (UAL) parser — test the TSV reader on a
simulated esedbexport CLIENTS table.

Closes the gap-doc Windows-artifact deferred row "User Access Log
(UAL) on Windows Server" (line 107). Real-image validation would
need a Server 2012+ disk image; we don't have one in the corpus,
so this layer is unit-tested on a synthetic TSV mirroring the
libesedb output schema.
"""
from pathlib import Path

from el.skills import ual


_HEADERS = (
    "AuthenticatedUserName\tClientName\tAddress\tRoleGuid"
    "\tTotalAccesses\tInsertDate\tLastAccess"
)


def _stage(tmp_path, rows):
    out_subdir = tmp_path / "Current.mdb.export"
    out_subdir.mkdir()
    f = out_subdir / "CLIENTS.0"
    with f.open("w") as fh:
        fh.write(_HEADERS + "\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
    return out_subdir


def test_parse_clients_table_extracts_canonical_columns(tmp_path):
    out = _stage(tmp_path, [
        ("CONTOSO\\admin", "DC01", "10.0.0.5",
         "{guid-1}", "42", "2026-04-01 09:00:00", "2026-04-25 17:30:00"),
        ("CONTOSO\\bob", "WS-3", "10.0.0.42",
         "{guid-1}", "8", "2026-04-10 12:00:00", "2026-04-25 17:00:00"),
    ])
    rows = ual._parse_clients_table(out)
    assert len(rows) == 2
    # Sorted by total_accesses desc
    assert rows[0].username == "CONTOSO\\admin"
    assert rows[0].total_accesses == 42
    assert rows[0].address == "10.0.0.5"
    assert rows[1].total_accesses == 8


def test_parse_handles_missing_columns(tmp_path):
    """libesedb sometimes drops columns — the parser must produce
    rows with empty fields, not crash."""
    out = tmp_path / "Current.mdb.export"
    out.mkdir()
    (out / "CLIENTS.0").write_text(
        "Address\tTotalAccesses\n10.0.0.5\t42\n10.0.0.6\t1\n"
    )
    rows = ual._parse_clients_table(out)
    assert len(rows) == 2
    assert rows[0].address == "10.0.0.5"
    assert rows[0].total_accesses == 42
    assert rows[0].username == ""   # column not present


def test_parse_skips_non_clients_files(tmp_path):
    out = tmp_path / "Current.mdb.export"
    out.mkdir()
    (out / "ROLE_ACCESS.0").write_text("anything\n")
    (out / "VIRTUALMACHINES.0").write_text("anything\n")
    assert ual._parse_clients_table(out) == []


def test_export_database_handles_missing_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(ual.shutil, "which", lambda _: None)
    try:
        ual.export_database(tmp_path / "x.mdb", tmp_path)
    except ual.UalError as e:
        assert "esedbexport" in str(e)
    else:
        raise AssertionError("expected UalError when esedbexport absent")

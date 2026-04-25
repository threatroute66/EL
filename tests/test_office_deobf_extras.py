"""Office deobfuscator extras: pcodedmp / xlmdeobfuscator / pdf-parser
wrappers.

Closes gap-doc Malware-RE bullet "VBA / XLM / PDF object-stream
deobfuscators (olevba, pcodedmp, xlmdeobfuscator, rtfobj, pdfparser)"
(line 142). The olevba + rtfobj halves were already shipped earlier;
this commit adds the three missing wrappers with the same shape so a
future malware_triage chain can call them uniformly.

All three wrappers gracefully degrade when the underlying tool isn't
installed (returns *Analysis dataclass with available=False). Tests
monkeypatch the binary lookup + subprocess so they don't require any
real install.
"""
import subprocess
from pathlib import Path

import pytest

from el.skills import office_deobf as oh


# --- pcodedmp ------------------------------------------------------------

def test_pcode_unavailable_when_binary_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "_pcodedmp_bin", lambda: None)
    r = oh.analyze_pcode(tmp_path / "x.docm")
    assert r.available is False
    assert "pcodedmp" in r.error


def test_pcode_detects_disasm_lines(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "_pcodedmp_bin", lambda: "/fake/pcodedmp")
    fake_stdout = (
        "Processing file: x.docm\nModule: ThisDocument\n"
        + "\n".join(f"Line {i}: ImnLdLcl 0x0000{i:04x}" for i in range(20))
    )
    fake = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=fake_stdout, stderr="")
    monkeypatch.setattr(oh.subprocess, "run", lambda *a, **kw: fake)
    target = tmp_path / "x.docm"; target.touch()
    r = oh.analyze_pcode(target, out_dir=tmp_path / "out")
    assert r.available is True
    assert r.has_pcode is True
    assert r.line_count > 8
    # raw_path written under out_dir
    assert Path(r.raw_path).is_file()


def test_pcode_handles_no_macros(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "_pcodedmp_bin", lambda: "/fake/pcodedmp")
    fake = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="Processing file: clean.docx\n",
        stderr="")
    monkeypatch.setattr(oh.subprocess, "run", lambda *a, **kw: fake)
    r = oh.analyze_pcode(tmp_path / "clean.docx")
    assert r.has_pcode is False


# --- xlmdeobfuscator -----------------------------------------------------

def test_xlm_unavailable_when_binary_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "_xlmdeobf_bin", lambda: None)
    r = oh.analyze_xlm(tmp_path / "x.xlsm")
    assert r.available is False


def test_xlm_counts_decoded_cells(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "_xlmdeobf_bin", lambda: "/fake/xlmdeobf")
    fake_stdout = (
        "[*] xlmdeobfuscator started\n"
        "CELL:Sheet1!A1 , 1 , =FORMULA(A2,A3)\n"
        "CELL:Sheet1!A2 , 2 , =EXEC(\"calc.exe\")\n"
        "CELL:Sheet1!A3 , 3 , =CALL(\"shell32\",\"ShellExecuteA\",...)\n"
    )
    fake = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=fake_stdout, stderr="")
    monkeypatch.setattr(oh.subprocess, "run", lambda *a, **kw: fake)
    target = tmp_path / "macro.xlsm"; target.touch()
    r = oh.analyze_xlm(target, out_dir=tmp_path / "out")
    assert r.has_xlm is True
    assert r.decoded_lines == 3


# --- pdf-parser ---------------------------------------------------------

def test_pdf_unavailable_when_binary_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "_pdfparser_bin", lambda: None)
    r = oh.analyze_pdf(tmp_path / "x.pdf")
    assert r.available is False


def test_pdf_surfaces_suspicious_keywords(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "_pdfparser_bin", lambda: "/fake/pdf-parser")
    fake_stdout = (
        "Comment: 1\n"
        "  obj 1 0 obj\n  obj 2 0 obj\n  obj 3 0 obj\n"
        "/JavaScript /JS /OpenAction /Launch /EmbeddedFile\n"
    )
    fake = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=fake_stdout, stderr="")
    monkeypatch.setattr(oh.subprocess, "run", lambda *a, **kw: fake)
    target = tmp_path / "x.pdf"; target.touch()
    r = oh.analyze_pdf(target)
    assert r.object_count == 3
    assert "/JavaScript" in r.suspicious_keywords
    assert "/Launch" in r.suspicious_keywords


def test_pdf_handles_clean_doc(monkeypatch, tmp_path):
    monkeypatch.setattr(oh, "_pdfparser_bin", lambda: "/fake/pdf-parser")
    fake = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout="obj 1 0 obj\nobj 2 0 obj\n", stderr="")
    monkeypatch.setattr(oh.subprocess, "run", lambda *a, **kw: fake)
    r = oh.analyze_pdf(tmp_path / "clean.pdf")
    assert r.suspicious_keywords == []

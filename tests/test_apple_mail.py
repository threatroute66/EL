"""Apple Mail (.emlx) parser tests — synthetic emlx fixtures."""
import plistlib
from pathlib import Path

import pytest

from el.skills import apple_mail as am


def _emlx_bytes(rfc822: bytes, meta: dict | None = None) -> bytes:
    """Assemble a real-shaped emlx: '<len>\\n' + message + trailing plist."""
    out = f"{len(rfc822)}\n".encode() + rfc822
    if meta is not None:
        out += plistlib.dumps(meta)
    return out


_RFC = (
    "From: Daniel Jones <djones.iss.secure@gmail.com>\r\n"
    "To: Alex Maurie <amaurie.iss.secure@gmail.com>\r\n"
    "Cc: hr@iss.example\r\n"
    "Subject: Introduction\r\n"
    "Date: Tue, 9 Dec 2025 08:00:00 -0500\r\n"
    "Message-ID: <intro-001@mail>\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Alex, Welcome to ISS! Tasks will follow shortly.\r\n"
).encode()


def _write_msg(d: Path, name: str, meta: dict) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(_emlx_bytes(_RFC, meta))
    return p


def test_parse_emlx_headers_and_body(tmp_path):
    p = _write_msg(tmp_path, "1.emlx",
                   {"flags": 8590195841, "color": "800080",
                    "date-last-viewed": 1765315556, "conversation-id": 48,
                    "gmail-label-ids": [6, 5]})
    m = am.parse_emlx(p)
    assert m.from_name == "Daniel Jones"
    assert m.from_addr == "djones.iss.secure@gmail.com"
    assert m.subject == "Introduction"
    assert m.to == ["amaurie.iss.secure@gmail.com"]
    assert m.cc == ["hr@iss.example"]
    assert m.message_id == "<intro-001@mail>"
    # Tue, 9 Dec 2025 08:00:00 -0500  ->  UTC 13:00:00
    assert m.date_utc == "2025-12-09 13:00:00"
    assert "Welcome to ISS" in m.body_snippet


def test_parse_emlx_trailing_plist_state(tmp_path):
    p = _write_msg(tmp_path, "1.emlx",
                   {"flags": 8590195841, "color": "800080",
                    "date-last-viewed": 1765315556, "conversation-id": 48,
                    "gmail-label-ids": [6, 5]})
    m = am.parse_emlx(p)
    assert m.mail_flags == ["read"]            # low byte 0x81 -> read
    assert m.color == "800080"                 # purple tag
    assert m.date_last_viewed_utc == "2025-12-09 21:25:56"
    assert m.conversation_id == 48
    assert m.gmail_label_ids == [6, 5]


def test_flag_bit_decoding(tmp_path):
    for flags, expect in [(1, ["read"]), (16, ["flagged"]),
                          (17, ["read", "flagged"]),
                          (4, ["answered"]), (2, ["deleted"]), (0, [])]:
        p = _write_msg(tmp_path / str(flags), "1.emlx", {"flags": flags})
        assert am.parse_emlx(p).mail_flags == expect


def test_html_body_stripped(tmp_path):
    rfc = (
        "From: a@b.com\r\nSubject: x\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<html><body><p>Hello&nbsp;<b>World</b></p></body></html>\r\n"
    ).encode()
    p = tmp_path / "h.emlx"
    p.write_bytes(_emlx_bytes(rfc, {"flags": 0}))
    m = am.parse_emlx(p)
    assert "<" not in m.body_snippet
    assert "Hello" in m.body_snippet and "World" in m.body_snippet


def test_partial_emlx_flagged(tmp_path):
    p = _write_msg(tmp_path, "9.partial.emlx", {"flags": 1})
    assert am.parse_emlx(p).is_partial is True


def test_emlx_without_byte_count_still_parses(tmp_path):
    # Some exports drop the leading count; the parser should fall back.
    p = tmp_path / "raw.emlx"
    p.write_bytes(_RFC)
    m = am.parse_emlx(p)
    assert m.subject == "Introduction"


def test_find_mail_root(tmp_path):
    root = tmp_path / "fs"
    mail = root / "Users" / "alex" / "Library" / "Mail"
    (mail / "V10").mkdir(parents=True)
    assert am.find_mail_root(root) == mail


def test_find_mail_root_none_without_store(tmp_path):
    root = tmp_path / "fs"
    (root / "Users" / "alex" / "Library" / "Mail").mkdir(parents=True)
    assert am.find_mail_root(root) is None      # no V* store


def test_parse_walk_output_and_aggregates(tmp_path):
    mbox = tmp_path / "Mail" / "V10" / "acct.mbox" / "u" / "Data" / "Messages"
    _write_msg(mbox, "1.emlx", {"flags": 1})
    _write_msg(mbox, "2.emlx", {"flags": 16})
    run = am.parse(tmp_path / "Mail", output_dir=tmp_path / "out")

    assert run.total == 2 and run.error_count == 0
    assert run.output_path.is_file()
    assert run.output_sha256 and run.output_sha256 != "0" * 64
    top = dict(run.top_correspondents())
    assert top["djones.iss.secure@gmail.com"] == 2
    assert run.search("welcome to iss")           # body match
    ev = run.as_evidence()
    assert ev.extracted_facts["message_count"] == 2
    assert ev.tool == "el.apple_mail"


def test_parse_missing_root_raises(tmp_path):
    with pytest.raises(am.AppleMailError):
        am.parse(tmp_path / "nope")


def test_agent_emits_apple_mail_finding(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents import macos_forensicator as mf
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "disk.E01"
    src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-mac-mail")
    with open_ledger(m.case_dir):
        pass

    exports = Path(m.case_dir) / "exports" / "macos-artifacts"
    mbox = (exports / "Users" / "alex" / "Library" / "Mail" / "V10"
            / "acct.mbox" / "u" / "Data" / "Messages")
    _write_msg(mbox, "1.emlx", {"flags": 1})

    monkeypatch.setattr(mf.mt, "run_all", lambda _p: [])

    ctx = AgentContext(case_id="t-mac-mail", case_dir=Path(m.case_dir),
                       input_path=src, manifest=m.__dict__,
                       shared={"macos_artifacts_dir": str(exports)})
    findings = mf.MacOSForensicatorAgent().run(ctx)
    assert any("Apple Mail:" in f.claim
               and "djones.iss.secure@gmail.com" in f.claim
               for f in findings)

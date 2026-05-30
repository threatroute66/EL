"""iOS Messages (sms.db) parser + IOSForensicatorAgent wiring tests."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from el.skills import ios_messages as im

_MAC_OFFSET = 978307200


def _typedstream(text: bytes) -> bytes:
    return (b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x84\x84NSMutableAttributedString"
            b"\x00\x84\x84\x08NSObject\x00\x85\x92\x84\x84\x84NSString\x01\x94"
            b"\x84\x01\x2b" + bytes([len(text)]) + text)


def _ns_2001(dt: datetime) -> int:
    unix = dt.replace(tzinfo=timezone.utc).timestamp()
    return int((unix - _MAC_OFFSET) * 1_000_000_000)


def _make_sms_db(path: Path):
    c = sqlite3.connect(str(path))
    c.executescript("""
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
        CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, chat_identifier TEXT);
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY, date INTEGER,
            is_from_me INTEGER, text TEXT, attributedBody BLOB,
            handle_id INTEGER, service TEXT);
        CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
    """)
    c.execute("INSERT INTO handle VALUES (1,'+15551112222')")
    c.execute("INSERT INTO handle VALUES (2,'coworker@work.com')")
    c.execute("INSERT INTO chat VALUES (1,'chat-A')")
    d1 = _ns_2001(datetime(2025, 11, 4, 17, 19, 8))
    d2 = _ns_2001(datetime(2025, 11, 5, 9, 0, 0))
    d3 = _ns_2001(datetime(2025, 11, 6, 10, 30, 0))
    # msg1: text in attributedBody only (text col NULL) -> must be decoded
    c.execute("INSERT INTO message VALUES (1,?,0,NULL,?,1,'iMessage')",
              (d1, _typedstream(b"Worried about Daniel, have you heard from him?")))
    # msg2: plain text column, sent by me
    c.execute("INSERT INTO message VALUES (2,?,1,'I am ok thanks',NULL,1,'iMessage')",
              (d2,))
    # msg3: from a different contact
    c.execute("INSERT INTO message VALUES (3,?,0,'Meeting at 3',NULL,2,'SMS')",
              (d3,))
    c.execute("INSERT INTO chat_message_join VALUES (1,1)")
    c.commit()
    c.close()


def test_parse_decodes_text_and_dates(tmp_path):
    db = tmp_path / "sms.db"
    _make_sms_db(db)
    run = im.parse(db, output_dir=tmp_path / "out")
    assert run.total == 3 and run.sent == 1 and run.received == 2
    by_id = {m.rowid: m for m in run.messages}
    # attributedBody decoded
    assert "Worried about Daniel" in by_id[1].text
    assert by_id[1].date_utc == "2025-11-04 17:19:08"
    assert by_id[1].contact == "+15551112222"
    assert by_id[1].chat == "chat-A"
    # plain text column
    assert by_id[2].text == "I am ok thanks" and by_id[2].is_from_me


def test_top_contacts_and_find(tmp_path):
    db = tmp_path / "sms.db"
    _make_sms_db(db)
    run = im.parse(db)
    top = dict(run.top_contacts())
    assert top["+15551112222"] == 2 and top["coworker@work.com"] == 1
    hits = run.find("daniel")
    assert len(hits) == 1 and hits[0].rowid == 1
    assert run.find("ok", sent_only=True)        # only the sent message


def test_date_range_and_evidence(tmp_path):
    db = tmp_path / "sms.db"
    _make_sms_db(db)
    run = im.parse(db, output_dir=tmp_path / "out")
    assert run.date_range() == ("2025-11-04 17:19:08", "2025-11-06 10:30:00")
    assert run.output_path.is_file()
    ev = run.as_evidence()
    assert ev.extracted_facts["message_count"] == 3
    assert ev.tool == "el.ios_messages"


def test_date_seconds_variant():
    # Pre-iOS-11 dates are seconds (not ns) since 2001.
    secs = int(datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp() - _MAC_OFFSET)
    assert im._date_to_utc(secs) == "2020-01-01 00:00:00"


def test_find_sms_db(tmp_path):
    root = tmp_path / "fs"
    smsdir = root / "private" / "var" / "mobile" / "Library" / "SMS"
    smsdir.mkdir(parents=True)
    (smsdir / "sms.db").write_bytes(b"x")
    assert im.find_sms_db(root) == smsdir / "sms.db"


def test_missing_db_raises(tmp_path):
    with pytest.raises(im.IOSMessagesError):
        im.parse(tmp_path / "nope.db")


# --- agent wiring -----------------------------------------------------------

def test_agent_emits_messages_finding(tmp_path, monkeypatch):
    from el.agents.base import AgentContext
    from el.agents.ios_forensicator import IOSForensicatorAgent
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "iphone.tar"
    src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id="t-ios-msg")
    with open_ledger(m.case_dir):
        pass

    root = tmp_path / "fs"
    smsdir = root / "private" / "var" / "mobile" / "Library" / "SMS"
    smsdir.mkdir(parents=True)
    _make_sms_db(smsdir / "sms.db")

    ctx = AgentContext(case_id="t-ios-msg", case_dir=Path(m.case_dir),
                       input_path=root, manifest=m.__dict__)
    findings = IOSForensicatorAgent()._run_messages(ctx, root)
    assert findings and "iOS Messages:" in findings[0].claim
    assert "3 message" in findings[0].claim

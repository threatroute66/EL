"""Verify chromium_leveldb is wired into the browser + android agents."""
import struct
from pathlib import Path


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _make_leveldb(d: Path, key: bytes, val: bytes):
    """Write a minimal LevelDB store (CURRENT + one .log with a put)."""
    d.mkdir(parents=True, exist_ok=True)
    (d / "CURRENT").write_text("MANIFEST-000001\n")
    entry = b"\x01" + _varint(len(key)) + key + _varint(len(val)) + val
    batch = struct.pack("<Q", 1) + struct.pack("<I", 1) + entry
    rec = b"\x00\x00\x00\x00" + struct.pack("<H", len(batch)) + b"\x01" + batch
    (d / "000003.log").write_bytes(rec)


def _ctx(tmp_path, monkeypatch, case_id, input_path):
    from el.agents.base import AgentContext
    from el.evidence import intake as intake_mod
    from el.evidence.ledger import open_ledger
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ev"
    src.write_bytes(b"x")
    m = intake_mod.intake(src, case_id=case_id)
    with open_ledger(m.case_dir):
        pass
    return AgentContext(case_id=case_id, case_dir=Path(m.case_dir),
                        input_path=input_path, manifest=m.__dict__)


def test_browser_agent_parses_local_storage(tmp_path, monkeypatch):
    from el.agents.browser_forensicator import BrowserForensicatorAgent
    root = tmp_path / "profile"
    ls = root / "Default" / "Local Storage" / "leveldb"
    _make_leveldb(ls, b"_https://x.com\x00token", b"\x01secret-value")
    ctx = _ctx(tmp_path, monkeypatch, "t-br-ldb", root)
    findings = BrowserForensicatorAgent()._run_leveldb(ctx, [root])
    assert findings and "LevelDB web-storage" in findings[0].claim
    assert findings[0].evidence[0].extracted_facts["total_records"] >= 1


def test_android_agent_parses_webview_storage(tmp_path, monkeypatch):
    from el.agents.android_forensicator import AndroidForensicatorAgent
    src = tmp_path / "fs"
    ls = (src / "data" / "data" / "com.example.app" / "app_webview"
          / "Default" / "Local Storage" / "leveldb")
    _make_leveldb(ls, b"_https://app\x00k", b"\x01v")
    scan = [p for p in src.glob("data/data/*/app_webview/Default") if p.is_dir()]
    assert scan
    ctx = _ctx(tmp_path, monkeypatch, "t-an-ldb", src)
    findings = AndroidForensicatorAgent()._run_leveldb(ctx, scan)
    assert findings and "LevelDB web-storage" in findings[0].claim
    assert findings[0].hypotheses_supported == ["H_DISK_ARTIFACTS"]


def test_run_leveldb_noop_when_empty(tmp_path, monkeypatch):
    from el.agents.browser_forensicator import BrowserForensicatorAgent
    ctx = _ctx(tmp_path, monkeypatch, "t-empty-ldb", tmp_path)
    assert BrowserForensicatorAgent()._run_leveldb(ctx, [tmp_path / "nope"]) == []

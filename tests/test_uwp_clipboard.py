"""Windows Cloud-Clipboard / UWP-Clipboard ingest.

Closes the gap-doc PowerShell-breadth deferred row "Windows
Cloud-Clipboard (UWP state)". Pinned + recent clipboard items live
under `%LOCALAPPDATA%\\Microsoft\\Windows\\Clipboard\\`; this skill
parses copies of that subtree.
"""
from pathlib import Path

import pytest

from el.skills import uwp_clipboard as cb


def _stage_clipboard(tmp_path: Path, *,
                     pinned: dict[str, bytes] | None = None,
                     recent: dict[str, bytes] | None = None) -> Path:
    """Materialise a `Clipboard/` directory tree the way Windows lays
    it out: per-item GUID dirs containing format files."""
    user_dir = tmp_path / "alice"
    cb_root = user_dir / "Clipboard"
    cb_root.mkdir(parents=True)
    if pinned:
        for label, content in pinned.items():
            d = cb_root / "Pinned" / label
            d.mkdir(parents=True)
            (d / "Plain text.txt").write_bytes(content)
    if recent:
        for label, content in recent.items():
            d = cb_root / label
            d.mkdir()
            (d / "Plain text.txt").write_bytes(content)
    return user_dir


def test_parse_subtree_emits_one_item_per_format_file(tmp_path):
    user_dir = _stage_clipboard(
        tmp_path,
        pinned={"AAAA-1234": b"super-secret-password"},
        recent={"BBBB-5678": b"http://example.com/abc"},
    )
    items = cb.parse_clipboard_subtree(user_dir / "Clipboard",
                                         user="alice")
    assert len(items) == 2
    by_pinned = {i.pinned: i for i in items}
    assert by_pinned[True].sample == "super-secret-password"
    assert by_pinned[False].sample == "http://example.com/abc"
    assert all(i.user == "alice" for i in items)


def test_walk_extracted_clipboard_aggregates_users(tmp_path):
    """walk_extracted_clipboard expects the layout produced by
    `extract_windows_artifacts`: <exports>/<user>/Clipboard/."""
    exports = tmp_path / "uwp-clipboard"
    for u in ("alice", "bob"):
        ud = exports / u / "Clipboard"
        ud.mkdir(parents=True)
        d = ud / "Pinned" / "GUID-1"
        d.mkdir(parents=True)
        (d / "Plain text.txt").write_bytes(f"pin-{u}".encode())
    items = cb.walk_extracted_clipboard(exports)
    users = {i.user for i in items}
    assert users == {"alice", "bob"}
    assert all(i.pinned for i in items)


def test_utf16_decoding_for_windows_native_text(tmp_path):
    """Real Windows clipboard files are UTF-16-LE little-endian. The
    skill must decode them into a readable sample, not return bytes."""
    user_dir = tmp_path / "u"
    cb_root = user_dir / "Clipboard"
    d = cb_root / "Pinned" / "abc"
    d.mkdir(parents=True)
    (d / "Plain text.txt").write_bytes(
        "shieldbase.lan".encode("utf-16-le"))
    items = cb.parse_clipboard_subtree(cb_root, user="u")
    assert any("shieldbase.lan" in (i.sample or "") for i in items)


def test_non_text_format_returns_empty_sample(tmp_path):
    """Image / RTF format files don't decode as text; sample stays
    empty, but the item still surfaces (size + mtime + format label
    are the forensic value)."""
    user_dir = tmp_path / "u"
    cb_root = user_dir / "Clipboard"
    d = cb_root / "Pinned" / "imgGuid"
    d.mkdir(parents=True)
    # PNG header magic — guaranteed not text-decodable
    (d / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\xde\xad\xbe\xef" * 30)
    items = cb.parse_clipboard_subtree(cb_root, user="u")
    assert len(items) == 1
    assert items[0].format_label == "image.png"
    assert items[0].sample == ""
    assert items[0].size > 100


def test_missing_root_returns_empty_list(tmp_path):
    assert cb.parse_clipboard_subtree(tmp_path / "nope") == []
    assert cb.walk_extracted_clipboard(tmp_path / "nope") == []

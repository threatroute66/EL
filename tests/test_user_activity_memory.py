"""Skill: el.skills.user_activity_memory — pure-function tests.

Covers the three decoders that have no other home in the repo:

  * Office MRU ``[F…][T<filetime>][O…]*<path>`` → (iso, path)
  * Drive-letter ↔ USB-serial via MountedDevices' hex+ASCII REG_BINARY
    dump format
  * The corporate-staging detector — both the positive case
    (USB letter + project fragment) and the easy false-positive
    rejections (USB letter without a project fragment;
    project fragment on an internal letter).
"""
from __future__ import annotations

import pytest

from el.skills import user_activity_memory as ua


# ---------------------------------------------------------------------------
# Office MRU FILETIME decoder
# ---------------------------------------------------------------------------

def test_office_mru_decodes_filetime_to_utc():
    # FILETIME 0x01D6BA3ECAC9A680 corresponds to a known Office MRU sample
    # observed in the rocba-memory pivot — verify deterministic decode.
    iso, path = ua.parse_office_mru_value(
        "[F00000000][T01D6BA3ECAC9A680][O00000000]*"
        r"G:\My Drive\STARK-RESEARCH-LABS FOLDER\SRL-Projects - Gunstar"
        r"\GunStar Death Blossom Data.docx"
    )
    assert iso.startswith("2020-11-14T04:29:50")
    assert iso.endswith("+00:00")
    assert path.endswith(r"\GunStar Death Blossom Data.docx")


def test_office_mru_quoted_value_strips_quotes():
    # vol3 wraps REG_SZ values in double-quotes in the JSON dump.
    iso, path = ua.parse_office_mru_value(
        '"[F00000000][T01D6BA3E007514A0][O00000000]*'
        r'F:\Files of interest\Recovered Documents\Wolves_Lair_Tech_Specs.pptx"'
    )
    assert iso.startswith("2020-11-14T")
    assert path.endswith(r"\Wolves_Lair_Tech_Specs.pptx")


def test_office_mru_returns_none_for_folder_id_stubs():
    # Office writes FOLDERID_Desktop / FOLDERID_Documents as siblings
    # of real items — they're not MRU entries and must not decode.
    for stub in (
        r'"C:\Users\fredr\OneDrive\Desktop\"',
        '',
        'random text',
        '[T01D6BA3E][O00000000]*missing F prefix',
    ):
        assert ua.parse_office_mru_value(stub) is None


def test_office_mru_zero_filetime_returns_none():
    # Zero FILETIME is the "never opened" sentinel — drop it.
    assert ua.parse_office_mru_value(
        "[F0][T0][O0]*x.docx"
    ) is None


# ---------------------------------------------------------------------------
# Office MRU tree walk
# ---------------------------------------------------------------------------

def _printkey_node(*, key="", name="", data="", typ="REG_SZ",
                    lwt="2020-11-14T00:00:00+00:00", children=()):
    return {
        "Key": key, "Name": name, "Data": data, "Type": typ,
        "Last Write Time": lwt,
        "__children": list(children),
    }


def test_walk_office_mru_extracts_app_and_account():
    base_key = (
        r"\??\C:\Users\fredr\ntuser.dat\SOFTWARE\Microsoft\Office\16.0\Word"
        r"\User MRU\ADAL_71509F4C\File MRU"
    )
    tree = [_printkey_node(key=base_key, name="*", typ="Key",
                            children=[_printkey_node(
                                key=base_key, name="Item 1", data=(
                                    "[F0][T01D6BA3ECAC9A680][O0]*"
                                    r"G:\My Drive\STARK-RESEARCH-LABS FOLDER"
                                    r"\SRL-Projects - Gunstar\x.docx"
                                ),
                            )])]
    entries = ua.walk_office_mru(tree)
    assert len(entries) == 1
    e = entries[0]
    assert e.app == "Word"
    assert e.account == "ADAL"
    assert e.account_id == "ADAL_71509F4C"
    assert e.kind == "File"
    assert e.opened_utc.startswith("2020-11-14T04:29:50")
    assert e.path.endswith(r"\x.docx")


def test_walk_office_mru_skips_non_mru_keys():
    # User MRU keys store HashAlgorithm too — must not be decoded.
    tree = [_printkey_node(
        key=r"...\Office\16.0\Word\User MRU\ADAL_71509F4C\File MRU",
        name="HashAlgorithm", data='"SHA512"',
    )]
    assert ua.walk_office_mru(tree) == []


# ---------------------------------------------------------------------------
# MountedDevices ASCII column + USB regex
# ---------------------------------------------------------------------------

def _vol3_binary_dump(text: bytes) -> str:
    """Recreate the vol3 hex+ASCII REG_BINARY display format for a
    raw byte sequence so we can exercise _extract_ascii_column +
    parse_mounted_devices on plausible inputs.

    Format per row::

        hh hh ... hh hh   <ascii column with NULs as dots>
    """
    out_lines: list[str] = []
    # Pad to 16 bytes
    pad = (-len(text)) % 16
    text = text + b"\x00" * pad
    for i in range(0, len(text), 16):
        chunk = text[i:i+16]
        hex_col = " ".join(f"{b:02x}" for b in chunk)
        ascii_col = "".join(
            (chr(b) if 32 <= b < 127 else ".") for b in chunk
        )
        out_lines.append(f"{hex_col}  {ascii_col}")
    return '"\n' + "\n".join(out_lines) + '"'


def test_parse_mounted_devices_decodes_usb_letter():
    # UTF-16LE encoded device path observed on the rocba memory image.
    raw = (
        "_??_USBSTOR#Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_1100"
        "#AAZ62W7KENRSJLHY&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8}"
    ).encode("utf-16-le")
    tree = [_printkey_node(
        key=r"MountedDevices", name="", typ="Key",
        children=[_printkey_node(
            key=r"MountedDevices", name=r"\DosDevices\F:",
            data=_vol3_binary_dump(raw), typ="REG_BINARY",
        )],
    )]
    mappings = ua.parse_mounted_devices(tree)
    assert len(mappings) == 1
    m = mappings[0]
    assert m.letter == "F"
    assert m.usb_vendor.lower() == "lexar"
    assert m.usb_serial == "AAZ62W7KENRSJLHY"
    assert "lexar" in m.backing.lower()


def test_parse_mounted_devices_marks_internal_drives_non_usb():
    raw = b"DMIO:ID:internal-disk".ljust(48, b"\x00")
    tree = [_printkey_node(
        key=r"MountedDevices", name="", typ="Key",
        children=[_printkey_node(
            key=r"MountedDevices", name=r"\DosDevices\C:",
            data=_vol3_binary_dump(raw), typ="REG_BINARY",
        )],
    )]
    [m] = ua.parse_mounted_devices(tree)
    assert m.letter == "C"
    assert m.usb_serial == ""
    assert "non-USB" in m.backing


def test_parse_mounted_devices_skips_volume_guid_entries():
    # \??\Volume{GUID} entries are valid in the key but not letter-mapped.
    raw = b"\x00" * 32
    tree = [_printkey_node(
        key=r"MountedDevices", name="", typ="Key",
        children=[_printkey_node(
            key=r"MountedDevices",
            name=r"\??\Volume{f02b9866-6d7f-348b-ad99-2a55aa54a000}",
            data=_vol3_binary_dump(raw), typ="REG_BINARY",
        )],
    )]
    assert ua.parse_mounted_devices(tree) == []


# ---------------------------------------------------------------------------
# Insider-staging detector
# ---------------------------------------------------------------------------

def _entry(path: str, opened_utc: str = "2020-11-14T04:30:00+00:00"
            ) -> ua.OfficeMRUEntry:
    return ua.OfficeMRUEntry(
        app="Word", account="ADAL", account_id="ADAL_X",
        kind="File", path=path, opened_utc=opened_utc,
    )


def _removable(letter: str, serial: str = "AAZ62W7KENRSJLHY"
                ) -> dict[str, ua.DriveLetterMapping]:
    return {letter: ua.DriveLetterMapping(
        letter=letter, backing="USB", usb_vendor="Lexar",
        usb_product="USB Flash Drive", usb_serial=serial,
    )}


def test_detect_staging_positive_case():
    signals = ua.detect_removable_staging(
        [_entry(
            r"F:\Files of interest\SRL-Projects - Megaforce"
            r"\Megaforce\Megaforce Specs & Research.docx"
        )],
        _removable("F"),
    )
    assert len(signals) == 1
    assert signals[0].letter == "F"
    assert signals[0].usb_serial == "AAZ62W7KENRSJLHY"


def test_detect_staging_requires_both_signals():
    # Project fragment on the system disk — NOT a staging signal.
    assert ua.detect_removable_staging(
        [_entry(r"C:\Users\fredr\Stark Research Labs\Gunstar\x.docx")],
        _removable("F"),
    ) == []
    # Removable letter but no project fragment — NOT a staging signal.
    assert ua.detect_removable_staging(
        [_entry(r"F:\My personal photos\holiday.jpg")],
        _removable("F"),
    ) == []


def test_detect_staging_case_insensitive_fragment_match():
    signals = ua.detect_removable_staging(
        [_entry(r"F:\SRL-PROJECTS - GUNSTAR\death-blossom.docx")],
        _removable("F"),
    )
    assert len(signals) == 1


# ---------------------------------------------------------------------------
# Hive enumeration
# ---------------------------------------------------------------------------

def test_find_user_hives_extracts_username():
    hivelist_rows = [
        {"FileFullPath": r"\??\C:\Users\fredr\ntuser.dat", "Offset": 100},
        {"FileFullPath": r"\??\C:\Users\fredr\AppData\Local\Microsoft"
                            r"\Windows\UsrClass.dat", "Offset": 200},
        {"FileFullPath": r"\SystemRoot\System32\Config\SOFTWARE",
         "Offset": 300},
        {"FileFullPath": r"\??\C:\Users\Default\ntuser.dat", "Offset": 400},
    ]
    hives = ua.find_user_hives(hivelist_rows)
    users = sorted(h.user for h in hives)
    assert "fredr" in users
    assert "Default" in users
    # SOFTWARE hive must not slip into the per-user list.
    assert all("System32" not in h.file_full_path for h in hives)

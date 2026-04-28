"""Phase 4 tests: bundle-aware executive report rendering.

Locks in:
  * Bundle detection branches the renderer correctly (per-device
    case-details table, device chips on findings, per-device
    conclusion sub-table, optional cross-device IOC section).
  * Single-host cases continue to render the original layout.
  * The cross-device IOC section only surfaces indicators that
    appear on 2+ devices.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from el.bundle import (
    BundleManifest,
    DeviceEntry,
    create_bundle_layout,
    create_device_layout,
    make_device_case_id,
    save as save_bundle,
)
from el.bundle_synth import synthesize_bundle
from el.evidence.ledger import insert as ledger_insert
from el.reporting.executive import render_executive_html
from el.schemas.finding import EvidenceItem, Finding


def _ev() -> EvidenceItem:
    return EvidenceItem(
        tool="x", version="1", command="y", output_sha256="0" * 64,
        output_path="/tmp/z",
    )


@pytest.fixture
def two_device_bundle(tmp_path):
    """Build a tiny but real two-device bundle with findings + per-
    device iocs.json files, then run synthesis."""
    bundle_id = "BUNDLE-RPT"
    cd = create_bundle_layout(tmp_path / "cases", bundle_id)

    # Device A
    dev_a = create_device_layout(cd, "laptop")
    a_cid = make_device_case_id(bundle_id, "laptop")
    ledger_insert(dev_a, Finding(
        case_id=a_cid, agent="lateral_movement_analyst",
        claim="Laptop did suspicious thing one", confidence="high",
        evidence=[_ev()],
        hypotheses_supported=["H_LATERAL_MOVEMENT"],
    ))
    # Pre-set extracted_facts so chronological list picks it up.
    f_a = Finding(
        case_id=a_cid, agent="disk_forensicator",
        claim="Laptop did suspicious thing two",
        confidence="high",
        evidence=[EvidenceItem(
            tool="x", version="1", command="y", output_sha256="0" * 64,
            output_path="/tmp/z",
            extracted_facts={"ts_utc": "2024-04-01T10:00:00+00:00"},
        )],
    )
    ledger_insert(dev_a, f_a)
    # Per-device iocs.json
    (dev_a / "iocs.json").write_text(json.dumps({
        "ipv4": ["10.0.0.1", "10.0.0.99"],   # 10.0.0.1 also on phone
        "domain": ["evil.example.com"],       # also on phone
    }))
    # Per-device manifest.json so bundle aggregation has data.
    (dev_a / "manifest.json").write_text(json.dumps({
        "case_id": a_cid, "intake_utc": "2024-04-01T00:00:00+00:00",
        "input_path": "/tmp/laptop.E01", "input_size_bytes": 1024,
        "input_sha256": "a" * 64, "input_sha1": "", "input_md5": "",
        "input_magic": "ewf", "case_dir": str(dev_a),
    }))

    # Device B
    dev_b = create_device_layout(cd, "phone")
    b_cid = make_device_case_id(bundle_id, "phone")
    ledger_insert(dev_b, Finding(
        case_id=b_cid, agent="ios_forensicator",
        claim="Phone did suspicious thing", confidence="high",
        evidence=[EvidenceItem(
            tool="x", version="1", command="y", output_sha256="0" * 64,
            output_path="/tmp/z",
            extracted_facts={"ts_utc": "2024-04-01T11:00:00+00:00"},
        )],
        hypotheses_supported=["H_LATERAL_MOVEMENT"],
    ))
    (dev_b / "iocs.json").write_text(json.dumps({
        "ipv4": ["10.0.0.1", "10.0.0.50"],   # 10.0.0.1 shared
        "domain": ["evil.example.com",        # shared
                    "phone-only.example.com"],  # phone-only — must NOT surface
        "email": ["target@phone.example.com"],
    }))
    (dev_b / "manifest.json").write_text(json.dumps({
        "case_id": b_cid, "intake_utc": "2024-04-01T00:00:00+00:00",
        "input_path": "/tmp/phone-fs", "input_size_bytes": 2048,
        "input_sha256": "b" * 64, "input_sha1": "", "input_md5": "",
        "input_magic": "directory", "case_dir": str(dev_b),
    }))

    bundle = BundleManifest(
        bundle_id=bundle_id,
        devices=[
            DeviceEntry(name="laptop", case_id=a_cid,
                         input_path="/tmp/laptop.E01",
                         input_size_bytes=1024, input_sha256="a" * 64,
                         case_dir=str(dev_a)),
            DeviceEntry(name="phone", case_id=b_cid,
                         input_path="/tmp/phone-fs",
                         input_size_bytes=2048, input_sha256="b" * 64,
                         case_dir=str(dev_b)),
        ],
    )
    save_bundle(cd, bundle)
    synthesize_bundle(cd)
    return cd


# ---------------------------------------------------------------------------
# Bundle-mode rendering
# ---------------------------------------------------------------------------

def test_bundle_renders_per_device_case_details(two_device_bundle):
    out = render_executive_html(two_device_bundle)
    html = out.read_text()
    # Per-device table heading is present
    assert "Devices in this bundle" in html
    # Both device names appear
    assert "laptop" in html
    assert "phone" in html
    # Bundle-level metadata
    assert "Bundle device count" in html


def test_bundle_renders_device_chip_on_findings(two_device_bundle):
    out = render_executive_html(two_device_bundle)
    html = out.read_text()
    # Each device chip uses the .device-chip class
    chips = re.findall(r"<span class='device-chip'>([^<]+)</span>", html)
    # Both devices contributed timestamped findings → both chips appear
    assert "laptop" in chips
    assert "phone" in chips


def test_bundle_per_device_summary_in_conclusion(two_device_bundle):
    out = render_executive_html(two_device_bundle)
    html = out.read_text()
    assert "Per-device summary" in html


def test_cross_device_iocs_only_shared_appear(two_device_bundle):
    out = render_executive_html(two_device_bundle)
    html = out.read_text()
    # Cross-device section is present
    assert "Cross-device correlation" in html
    # Shared indicators surface
    assert "10.0.0.1" in html
    assert "evil.example.com" in html
    # Device-only indicators MUST NOT appear in the cross-device section.
    # Slice the html to the cross-device section so we don't false-positive
    # against any other place these strings might appear.
    m = re.search(r"<h2>Cross-device correlation</h2>(.*?)(?=<h2>|</body>)",
                  html, re.DOTALL)
    assert m, "cross-device section missing"
    cross = m.group(1)
    assert "10.0.0.99" not in cross   # laptop-only
    assert "10.0.0.50" not in cross   # phone-only
    assert "phone-only.example.com" not in cross
    assert "target@phone.example.com" not in cross


def test_cross_device_iocs_section_omitted_when_no_overlap(tmp_path):
    """If no IOC crossed device boundaries, the section vanishes
    rather than emitting an empty placeholder."""
    bundle_id = "BUNDLE-NOOVERLAP"
    cd = create_bundle_layout(tmp_path / "cases", bundle_id)
    dev_a = create_device_layout(cd, "a")
    dev_b = create_device_layout(cd, "b")
    a_cid = make_device_case_id(bundle_id, "a")
    b_cid = make_device_case_id(bundle_id, "b")
    ledger_insert(dev_a, Finding(
        case_id=a_cid, agent="x", claim="a-only", confidence="high",
        evidence=[_ev()],
    ))
    ledger_insert(dev_b, Finding(
        case_id=b_cid, agent="x", claim="b-only", confidence="high",
        evidence=[_ev()],
    ))
    (dev_a / "iocs.json").write_text(json.dumps({"ipv4": ["1.2.3.4"]}))
    (dev_b / "iocs.json").write_text(json.dumps({"ipv4": ["5.6.7.8"]}))
    for dd in (dev_a, dev_b):
        (dd / "manifest.json").write_text(json.dumps({
            "case_id": "x", "intake_utc": "2024-01-01T00:00:00+00:00",
            "input_path": "/tmp", "input_size_bytes": 10,
            "input_sha256": "", "input_sha1": "", "input_md5": "",
            "input_magic": "", "case_dir": str(dd),
        }))
    bundle = BundleManifest(
        bundle_id=bundle_id,
        devices=[
            DeviceEntry(name="a", case_id=a_cid, input_path="/tmp/a",
                         case_dir=str(dev_a)),
            DeviceEntry(name="b", case_id=b_cid, input_path="/tmp/b",
                         case_dir=str(dev_b)),
        ],
    )
    save_bundle(cd, bundle)
    synthesize_bundle(cd)
    out = render_executive_html(cd)
    html = out.read_text()
    assert "Cross-device correlation" not in html


# ---------------------------------------------------------------------------
# Single-host regression: existing layout is unchanged
# ---------------------------------------------------------------------------

def test_single_host_layout_unchanged(tmp_path, monkeypatch):
    """A single-host case must NOT pick up any of the bundle-mode
    sections — no device chips, no per-device summary, no cross-
    device correlation. This protects the analyst flow from drift."""
    from el.evidence import intake as intake_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    src = tmp_path / "ev.bin"
    src.write_bytes(b"hello\n")
    m = intake_mod.intake(src, case_id="single-host-test")
    cd = Path(m.case_dir)
    out = render_executive_html(cd)
    html = out.read_text()
    assert "Devices in this bundle" not in html
    assert "Per-device summary" not in html
    assert "Cross-device correlation" not in html
    # The CSS class definition lives in the embedded stylesheet (the
    # class is small and harmless), but no <span class='device-chip'>
    # element should be emitted on a single-host case.
    assert "<span class='device-chip'>" not in html

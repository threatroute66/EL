"""Phase 3 contract tests for the bundle pipeline.

Tests the layering:

  * el/bundle.py — pure schemas + path helpers (no I/O of evidence)
  * el/bundle_synth.py — synthesis pass that merges per-device
    findings into the bundle ledger and recomputes ACH
  * `el investigate-bundle` CLI — orchestrates intake + per-device
    coordinator runs + synthesis

Layer-3 contract: a bundle is one investigation. Per-device sub-cases
share the bundle's case_id (with a `:device` suffix), so
knowledge.sqlite recognises them as one case via parse_device_case_id.
Cross-bundle overlap stays "suggestive only" via existing
knowledge_lookup behaviour.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from el.bundle import (
    BUNDLE_FILENAME,
    BundleManifest,
    DeviceEntry,
    aggregate_manifest,
    bundle_path,
    create_bundle_layout,
    create_device_layout,
    device_dir,
    is_bundle,
    load,
    make_device_case_id,
    parse_device_case_id,
    save,
    write_aggregated_manifest,
)
from el.bundle_synth import synthesize_bundle
from el.evidence.ledger import insert as ledger_insert, list_findings
from el.schemas.finding import EvidenceItem, Finding


# ---------------------------------------------------------------------------
# Pure-helper tests (no I/O)
# ---------------------------------------------------------------------------

def test_make_and_parse_device_case_id_roundtrip():
    cid = make_device_case_id("BelkaCTF6", "laptop")
    assert cid == "BelkaCTF6:laptop"
    parsed = parse_device_case_id(cid)
    assert parsed == ("BelkaCTF6", "laptop")


def test_parse_device_case_id_returns_none_for_single_host():
    """Single-host case_ids have no separator — parser returns None
    so callers can short-circuit bundle-only logic."""
    assert parse_device_case_id("just-a-case-id") is None
    assert parse_device_case_id("") is None


def test_parse_device_case_id_rejects_malformed():
    """Empty bundle_id or device portion is rejected."""
    assert parse_device_case_id(":laptop") is None
    assert parse_device_case_id("BelkaCTF6:") is None


# ---------------------------------------------------------------------------
# Layout creation
# ---------------------------------------------------------------------------

def test_create_bundle_layout_makes_dir_tree(tmp_path):
    cd = create_bundle_layout(tmp_path / "cases", "BUNDLE-A")
    assert cd == tmp_path / "cases" / "BUNDLE-A"
    for sub in ("analysis", "exports", "reports", "raw", "devices"):
        assert (cd / sub).is_dir()


def test_create_bundle_layout_is_idempotent(tmp_path):
    cd1 = create_bundle_layout(tmp_path / "cases", "BUNDLE-A")
    cd2 = create_bundle_layout(tmp_path / "cases", "BUNDLE-A")
    assert cd1 == cd2  # same path, no error on second call


def test_create_device_layout_under_bundle(tmp_path):
    bundle = create_bundle_layout(tmp_path / "cases", "BUNDLE-A")
    dd = create_device_layout(bundle, "laptop")
    assert dd == bundle / "devices" / "laptop"
    for sub in ("analysis", "exports", "reports", "raw"):
        assert (dd / sub).is_dir()


# ---------------------------------------------------------------------------
# Manifest save/load + is_bundle marker
# ---------------------------------------------------------------------------

def test_bundle_manifest_save_and_load(tmp_path):
    bundle = BundleManifest(
        bundle_id="BUNDLE-A",
        devices=[DeviceEntry(
            name="laptop", case_id="BUNDLE-A:laptop",
            input_path="/tmp/x.E01", input_size_bytes=1024,
            input_sha256="00" * 32, case_dir="/tmp/cases/BUNDLE-A/devices/laptop",
        )],
    )
    cd = create_bundle_layout(tmp_path / "cases", "BUNDLE-A")
    save(cd, bundle)
    assert is_bundle(cd)
    loaded = load(cd)
    assert loaded is not None
    assert loaded.bundle_id == "BUNDLE-A"
    assert len(loaded.devices) == 1
    assert loaded.devices[0].name == "laptop"


def test_load_returns_none_for_non_bundle(tmp_path):
    """Single-host case dir has no bundle.json — load() returns None
    so call sites can branch without raising."""
    (tmp_path / "manifest.json").write_text("{}")  # not a bundle
    assert load(tmp_path) is None
    assert not is_bundle(tmp_path)


def test_aggregate_manifest_sums_device_sizes(tmp_path):
    bundle = BundleManifest(
        bundle_id="BUNDLE-A",
        devices=[
            DeviceEntry(name="a", case_id="BUNDLE-A:a", input_path="/x",
                         input_size_bytes=1000, case_dir="/tmp/a"),
            DeviceEntry(name="b", case_id="BUNDLE-A:b", input_path="/y",
                         input_size_bytes=2500, case_dir="/tmp/b"),
        ],
    )
    agg = aggregate_manifest(bundle, tmp_path)
    assert agg["case_id"] == "BUNDLE-A"
    assert agg["device_count"] == 2
    assert agg["input_size_bytes"] == 3500
    assert agg["input_magic"] == "bundle"


def test_write_aggregated_manifest(tmp_path):
    bundle = BundleManifest(bundle_id="B")
    cd = create_bundle_layout(tmp_path / "cases", "B")
    p = write_aggregated_manifest(bundle, cd)
    assert p.exists()
    assert p.name == "manifest.json"


# ---------------------------------------------------------------------------
# Synthesis pass
# ---------------------------------------------------------------------------

def _ev() -> EvidenceItem:
    return EvidenceItem(
        tool="x", version="1", command="y", output_sha256="0" * 64,
        output_path="/tmp/z",
    )


def _build_two_device_bundle(tmp_path) -> tuple[Path, BundleManifest]:
    """Spin up a bundle with two devices, each containing a small set
    of pre-inserted findings. No real intake / coordinator — we test
    synthesis in isolation."""
    bundle_id = "BUNDLE-X"
    cd = create_bundle_layout(tmp_path / "cases", bundle_id)

    # Device A: 2 findings supporting H_LATERAL_MOVEMENT
    dev_a = create_device_layout(cd, "laptop")
    a_case = make_device_case_id(bundle_id, "laptop")
    for i in range(2):
        ledger_insert(dev_a, Finding(
            case_id=a_case, agent="lateral_movement_analyst",
            claim=f"laptop finding {i}", confidence="high",
            evidence=[_ev()],
            hypotheses_supported=["H_LATERAL_MOVEMENT"],
        ))

    # Device B: 1 finding supporting H_LATERAL_MOVEMENT, 1 H_CREDENTIAL_ACCESS
    dev_b = create_device_layout(cd, "phone")
    b_case = make_device_case_id(bundle_id, "phone")
    ledger_insert(dev_b, Finding(
        case_id=b_case, agent="lateral_movement_analyst",
        claim="phone finding lat", confidence="high", evidence=[_ev()],
        hypotheses_supported=["H_LATERAL_MOVEMENT"],
    ))
    ledger_insert(dev_b, Finding(
        case_id=b_case, agent="cred_analyst",
        claim="phone finding cred", confidence="high", evidence=[_ev()],
        hypotheses_supported=["H_CREDENTIAL_ACCESS"],
    ))

    bundle = BundleManifest(
        bundle_id=bundle_id,
        devices=[
            DeviceEntry(name="laptop", case_id=a_case,
                         input_path="/tmp/laptop.E01",
                         case_dir=str(dev_a)),
            DeviceEntry(name="phone", case_id=b_case,
                         input_path="/tmp/phone-fs",
                         case_dir=str(dev_b)),
        ],
    )
    save(cd, bundle)
    return cd, bundle


def test_synthesis_copies_all_device_findings(tmp_path):
    """Every per-device finding ends up in the bundle ledger
    regardless of which hypothesis it supports — synthesis is
    indiscriminate; ACH later decides what scores."""
    cd, _ = _build_two_device_bundle(tmp_path)
    bundle = synthesize_bundle(cd)
    # 2 from laptop + 2 from phone = 4
    assert bundle.total_findings == 4
    # And the bundle ledger reads back the same count.
    rows = list_findings(cd, case_id=bundle.bundle_id)
    assert len(rows) == 4


def test_synthesis_stamps_device_tag(tmp_path):
    cd, _ = _build_two_device_bundle(tmp_path)
    bundle = synthesize_bundle(cd)
    rows = list_findings(cd, case_id=bundle.bundle_id)
    devices_seen = {f.device for f in rows}
    assert devices_seen == {"laptop", "phone"}
    # Every finding has a device tag (no None leaks)
    assert None not in devices_seen


def test_synthesis_recomputes_case_id_to_bundle(tmp_path):
    cd, bundle_pre = _build_two_device_bundle(tmp_path)
    bundle = synthesize_bundle(cd)
    rows = list_findings(cd, case_id=bundle.bundle_id)
    # Every synthesised finding now bears the bundle id, not the
    # device sub-case id.
    for f in rows:
        assert f.case_id == bundle.bundle_id


def test_synthesis_ach_sums_across_devices(tmp_path):
    """The 'sum is fine for bundle ACH' agreement: every hypothesis
    score at the bundle level equals the sum of the per-device
    scores for that hypothesis. We check this directly rather than
    asserting on which hypothesis leads — the scorer's internal
    multi-tag rollups (e.g. H_APT_ESPIONAGE gathering signal from
    several supporting tags) make 'leading' not always trivial to
    predict from finding tags alone."""
    from el.intel.ach import score_findings
    cd, _ = _build_two_device_bundle(tmp_path)

    # Per-device scores BEFORE synthesis
    a_rank, _ = score_findings(list_findings(cd / "devices" / "laptop",
                                              case_id="BUNDLE-X:laptop"))
    b_rank, _ = score_findings(list_findings(cd / "devices" / "phone",
                                              case_id="BUNDLE-X:phone"))
    a_scores = {r.hyp_id: r.score for r in a_rank}
    b_scores = {r.hyp_id: r.score for r in b_rank}

    bundle = synthesize_bundle(cd)
    bundle_rank, _ = score_findings(list_findings(cd, case_id=bundle.bundle_id))
    bundle_scores = {r.hyp_id: r.score for r in bundle_rank}

    # For every hypothesis touched by either device, the bundle
    # score equals the per-device sum.
    for hyp in set(a_scores) | set(b_scores):
        a = a_scores.get(hyp, 0)
        b = b_scores.get(hyp, 0)
        assert bundle_scores.get(hyp, 0) == a + b, (
            f"hypothesis {hyp}: expected sum {a + b}, "
            f"got {bundle_scores.get(hyp, 0)}"
        )

    # And the bundle has SOME leading hypothesis (something is
    # supported by the test fixture).
    assert bundle.leading_hypothesis is not None
    assert bundle.leading_score > 0


def test_synthesis_updates_per_device_leading_hypothesis(tmp_path):
    cd, _ = _build_two_device_bundle(tmp_path)
    bundle = synthesize_bundle(cd)
    laptop = bundle.device("laptop")
    phone = bundle.device("phone")
    assert laptop is not None and phone is not None
    # Each device has *some* leading hypothesis — synthesis is
    # supposed to populate the field for the executive report.
    assert laptop.leading_hypothesis is not None
    assert phone.leading_hypothesis is not None


def test_synthesis_writes_aggregated_manifest(tmp_path):
    cd, _ = _build_two_device_bundle(tmp_path)
    synthesize_bundle(cd)
    mf = cd / "manifest.json"
    assert mf.exists()
    import json as _json
    data = _json.loads(mf.read_text())
    assert data["case_id"] == "BUNDLE-X"
    assert data["device_count"] == 2


def test_synthesis_raises_for_non_bundle(tmp_path):
    """Calling synthesis on a non-bundle dir should fail loudly."""
    (tmp_path / "manifest.json").write_text("{}")
    with pytest.raises(FileNotFoundError):
        synthesize_bundle(tmp_path)


# ---------------------------------------------------------------------------
# CLI end-to-end (uses the real intake + coordinator on a tiny dummy file)
# ---------------------------------------------------------------------------

def test_cli_investigate_bundle_two_devices(tmp_path, monkeypatch):
    """End-to-end: build a 2-device bundle from two trivial files,
    let the coordinator run with default agents (which mostly
    short-circuit on unrecognised content), then verify the bundle
    layout + synthesis output."""
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod

    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    a = tmp_path / "evA.bin"
    b = tmp_path / "evB.bin"
    a.write_bytes(b"alpha\n")
    b.write_bytes(b"beta\n")

    runner = CliRunner()
    result = runner.invoke(app, [
        "investigate-bundle", "BUNDLE-CLI",
        "--device", f"a:{a}",
        "--device", f"b:{b}",
    ])
    assert result.exit_code == 0, result.output

    bundle_dir = tmp_path / "cases" / "BUNDLE-CLI"
    assert (bundle_dir / BUNDLE_FILENAME).exists()
    # Both devices have their sub-case dirs populated
    assert (bundle_dir / "devices" / "a" / "manifest.json").exists()
    assert (bundle_dir / "devices" / "b" / "manifest.json").exists()
    # Synthesis produced the bundle's top-level findings.sqlite +
    # aggregated manifest.
    assert (bundle_dir / "findings.sqlite").exists()
    assert (bundle_dir / "manifest.json").exists()


def test_cli_investigate_bundle_rejects_bad_device_spec(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    runner = CliRunner()
    result = runner.invoke(app, [
        "investigate-bundle", "B",
        "--device", "no-colon-spec",
    ])
    assert result.exit_code != 0


def test_cli_investigate_bundle_rejects_duplicate_device_names(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from el.cli import app
    from el.evidence import intake as intake_mod
    monkeypatch.setattr(intake_mod, "CASE_ROOT", tmp_path / "cases")
    a = tmp_path / "x.bin"; a.write_bytes(b"x\n")
    runner = CliRunner()
    result = runner.invoke(app, [
        "investigate-bundle", "B",
        "--device", f"laptop:{a}",
        "--device", f"laptop:{a}",
    ])
    assert result.exit_code != 0

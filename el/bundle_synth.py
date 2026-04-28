"""Bundle synthesis — merge per-device findings into the bundle ledger.

After every device in a bundle has been investigated by the existing
single-host coordinator, this module:

  1. Walks each device's `findings.sqlite`.
  2. Re-stamps each Finding with case_id=<bundle_id> and device=<name>
     so the unified ledger groups by device but identifies as one case.
  3. Inserts the re-stamped findings into the bundle's top-level
     `findings.sqlite`.
  4. Recomputes ACH on the unified ledger — this is the bundle-case
     "score sum" semantics: a hypothesis with 5 supporters on the
     laptop and 3 on the phone scores 8, not max(5,3).
  5. Updates `bundle.json` with the synthesised leading hypothesis,
     score, and finding count.

Layer-3 contract preservation: the bundle has its own case_id, so
knowledge.sqlite continues to treat cross-bundle overlap as
"suggestive only". Per-device sub-cases (case_id = bundle:device)
are recognised as part of the bundle by parse_device_case_id().

Original finding_ids are preserved so the bundle's executive report
can hyperlink back to the per-device analyst report (case.html).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from el.bundle import (
    BundleManifest,
    DeviceEntry,
    aggregate_manifest,
    load as load_bundle,
    save as save_bundle,
    write_aggregated_manifest,
)
from el.evidence.ledger import insert as ledger_insert, list_findings
from el.intel.ach import score_findings
from el.schemas.finding import Finding


def _restamp(f: Finding, *, bundle_id: str, device_name: str) -> Finding:
    """Return a copy of `f` with case_id swapped to the bundle and
    device tag set. finding_id stays the same so the original
    per-device case.html still resolves."""
    return f.model_copy(update={
        "case_id": bundle_id,
        "device": device_name,
    })


def synthesize_bundle(bundle_case_dir: Path | str) -> BundleManifest:
    """Run the synthesis pass on a bundle case dir.

    Reads `bundle.json`, walks each device's findings.sqlite, copies
    re-stamped findings into the bundle's top-level findings.sqlite,
    recomputes ACH, and updates bundle.json with the result.

    Returns the updated BundleManifest.
    """
    case_dir = Path(bundle_case_dir)
    bundle = load_bundle(case_dir)
    if bundle is None:
        raise FileNotFoundError(
            f"not a bundle case (no bundle.json): {case_dir}"
        )

    # Step 1+2+3: walk every device, copy each finding into the
    # bundle ledger with re-stamped case_id + device tag.
    total_copied = 0
    for dev in bundle.devices:
        dev_dir = Path(dev.case_dir)
        if not (dev_dir / "findings.sqlite").exists():
            continue
        # list_findings filters by case_id when given — pass the
        # device's own sub-case_id so we get exactly that device's
        # findings, not anything that may have ended up there from
        # a prior unrelated case.
        rows = list_findings(dev_dir, case_id=dev.case_id)
        for f in rows:
            stamped = _restamp(f, bundle_id=bundle.bundle_id,
                                 device_name=dev.name)
            ledger_insert(case_dir, stamped)
            total_copied += 1

    # Step 4: recompute ACH on the unified ledger.
    bundle_findings = list_findings(case_dir, case_id=bundle.bundle_id)
    ranking, _diag = score_findings(bundle_findings)
    leader = ranking[0] if ranking else None

    # Step 5: update bundle.json with synthesised state. Also refresh
    # per-device leading-hypothesis fields from each device's ledger
    # in case they weren't recorded at investigate-time.
    for dev in bundle.devices:
        dev_dir = Path(dev.case_dir)
        if not (dev_dir / "findings.sqlite").exists():
            continue
        dev_rows = list_findings(dev_dir, case_id=dev.case_id)
        dev_rank, _ = score_findings(dev_rows)
        if dev_rank:
            dev.leading_hypothesis = dev_rank[0].hyp_id
            dev.leading_score = dev_rank[0].score

    bundle.synthesized_utc = datetime.now(timezone.utc)
    bundle.total_findings = total_copied
    bundle.leading_hypothesis = leader.hyp_id if leader else None
    bundle.leading_score = leader.score if leader else 0
    save_bundle(case_dir, bundle)

    # Refresh the aggregated manifest.json so renderers see the
    # most up-to-date device list + sizes.
    write_aggregated_manifest(bundle, case_dir)

    return bundle


__all__ = ["synthesize_bundle"]

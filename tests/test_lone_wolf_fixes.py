"""Regression tests pinning the three Lone Wolf fixes.

All assertions use STRINGS QUOTED VERBATIM from the Lone Wolf 2018
solution guide (Moore) — these are the exact tokens the Magnet AXIOM /
Autopsy workflow surfaced and that EL's parsers must also surface to
arrive at substantively the same conclusion as the Moore report.

Fix coverage:
  (1) ioc_extract.AWS regexes — rootkey.csv cleartext access+secret
  (2) pre_attack_planning_lexicon — weapon/ammo/opsec/intent/destination
  (3) cross_cloud_mirror — files mirrored across ≥3 cloud-sync dirs
  + H_PRE_ATTACK_PLANNING + H_MULTI_CLOUD_MIRROR hypothesis scoring
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from datetime import datetime, timezone

import pytest

from el.skills import (
    ioc_extract as iex,
    pre_attack_planning_lexicon as papl,
    cross_cloud_mirror as ccm,
)
from el.schemas.finding import Finding, EvidenceItem
from el.intel.hypotheses import HYPOTHESES


# ---------------------------------------------------------------------------
# Fix 1 — AWS IOC regex (rootkey.csv / Brother Chat handoff)
# ---------------------------------------------------------------------------

def test_aws_access_key_from_lone_wolf_rootkey_csv():
    """The exact AKIA string from Moore's report (p.22, rootkey.csv)
    must be extracted as an AWS access key."""
    txt = ("AWSAccessKeyId=AKIAJQCL74OG6U6JRXKQ\n"
           "AWSSecretKey=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\n")
    r = iex.extract(txt)
    assert "AKIAJQCL74OG6U6JRXKQ" in r["aws_access_key"]
    assert "0LN7omxlC0wZRpSBcxqJUg2ixxgx+PFPo930GxxH" in r["aws_secret_key"]


def test_aws_secret_requires_assignment_context():
    """A bare 40-char base64-ish token without `AWSSecretKey=` prefix
    must NOT be classified as a secret — too noisy otherwise."""
    bare = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"  # 40 chars
    r = iex.extract(bare)
    assert not r["aws_secret_key"]


def test_aws_access_key_handles_sts_temporary():
    """STS temporary keys begin with ASIA — must also match."""
    r = iex.extract("session id ASIA1234567890ABCDEF asia normal text")
    assert "ASIA1234567890ABCDEF" in r["aws_access_key"]


def test_aws_access_key_rejects_lowercase_imposter():
    """`akiaXXXX...` (lowercase) is not a valid AWS access key prefix —
    real AKIA IDs are uppercase. Don't FP on test corpora that quote
    them in prose with mixed case."""
    r = iex.extract("the akiajqcl74og6u6jrxkq value from rootkey")
    assert not r["aws_access_key"]


def test_aws_access_key_handles_brother_chat_prose():
    """Brother Chat (Appendix D) quotes the key inline with prose —
    must still extract."""
    chat = ("Aws.amazon.com there is an s3 bucket there under the gmail "
            "address and password. not super sure how it all works, but "
            "there is a public/private key thing too "
            "AWSAccessKeyId=AKIAJQCL74OG6U6JRXKQ "
            "AWSSecretKey=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 "
            "I think thats everything.")
    r = iex.extract(chat)
    assert "AKIAJQCL74OG6U6JRXKQ" in r["aws_access_key"]
    assert "0LN7omxlC0wZRpSBcxqJUg2ixxgx+PFPo930GxxH" in r["aws_secret_key"]


# ---------------------------------------------------------------------------
# Fix 2 — pre-attack-planning lexicon (Planning.docx / Manifesto / autofill)
# ---------------------------------------------------------------------------

PLANNING_DOCX_QUOTE = """
Plan
    Must have a good escape route
    Must be in Gun Free zone.
    Gun (black market).
        Norther VA Gun Works 7518 Fullerton Rd # K, Springfield, VA 22153
        NOVA 412 W Broad Street Falls Church, VA 22046
    Ammo.
        9mm is 1000 for $360
        Kel-Tec Sub 2000 9mm $400.
    Latex gloves
    Velcro tear away clothing?
    Escape
        No Extradition countries
        Indonesia (Nicer, but more expensive)
        Vietnam
        Can live very well on 100 a day, for 9 years.
    Press Release once home free.
"""

MANIFESTO_QUOTE = """
You will soon see when the blood has been shed and the defenseless
bodies stacked high. I will do what I must. No matter who is hurt,
the collateral damage will be worth it.
I will be the change. I will be the revolutionary. I will be the
history maker. I will fight. I will be the Lone Wolf.
"""

CLOUDY_THOUGHTS_QUOTE = """
I don't know if this plan will work. Plans never survive first contact.
Even if I'm killed at the site, I know that what im doing is just and right.
I am saving everything to the cloud on several accounts.
The only record will remain in the cloud and Paul will have the only other keys.
"""


def test_planning_docx_fires_at_high_signal():
    """Moore's quoted Planning.docx text fires 4+ categories → high."""
    m = papl.scan_text(PLANNING_DOCX_QUOTE)
    assert m is not None
    assert m.signal_strength == "high"
    assert m.categories_fired >= 3
    # Spot-check the specific tokens the report relies on
    assert any("kel-tec sub 2000" in w for w in m.weapon_hits)
    assert any("escape route" in o or "no extradition" in o
               or "latex gloves" in o for o in m.opsec_hits)


def test_manifesto_alone_does_not_fire_single_category():
    """Cloudy Manifesto text alone fires ONLY the intent category — even
    with 4+ intent hits, the ≥2-category rule means it correctly
    returns no-match in isolation. Manifesto + Planning together is
    what crosses the threshold (covered by `test_planning_docx_*`)."""
    m = papl.scan_text(MANIFESTO_QUOTE)
    # Either no match or weak signal (filtered) — single category
    # alone shouldn't escalate even with multiple intent markers.
    assert m is None or m.signal_strength == "weak"


def test_manifesto_plus_planning_fires_high():
    """The actual case shape — manifesto + planning text together
    crosses 4+ categories → high signal."""
    m = papl.scan_text(MANIFESTO_QUOTE + "\n" + PLANNING_DOCX_QUOTE)
    assert m is not None
    assert m.signal_strength == "high"
    intent_lower = [s.lower() for s in m.intent_hits]
    assert any(s in intent_lower for s in
                ("lone wolf", "the lone wolf", "blood has been shed"))


def test_cloudy_thoughts_alone_does_not_fire():
    """Cloudy Thoughts text alone (no weapons / ammo / destinations)
    has only `even if i'm killed` from intent — single category, single
    hit. Must NOT fire (signal_strength = weak / categories < 2)."""
    m = papl.scan_text(CLOUDY_THOUGHTS_QUOTE)
    # Either no match returned, or weak signal (filtered)
    assert m is None or m.signal_strength == "weak"


def test_benign_firearm_enthusiast_does_not_fire():
    """Range-day enthusiast post must NOT trigger — no opsec / no intent
    / no destinations. False positive on this would be deadly."""
    text = ("Took the Glock 19 to the range today. Great session. "
            "Got a new holster from Vedder. Plinked some 9mm at "
            "the indoor lanes.")
    assert papl.scan_text(text) is None


def test_chrome_autofill_synthetic_fires():
    """Composite of Chrome Autofill (Indonesia, Bali, fn p90, 9mm sbr,
    cloudy-thoughts, fnp90, fn 5.7) + Chrome Searches firearms terms.
    Crosses weapon + destination + opsec → high."""
    text = ("Indonesia Bali Candidasa fn p90 fnp90 mp40 9mm sbr "
            "cloudy-thoughts rootkey.csv mp5 "
            "shooting range near me police response times "
            "do the cops track web searches")
    m = papl.scan_text(text)
    assert m is not None
    assert m.signal_strength == "high"
    assert m.weapon_hits
    assert m.opsec_hits


# ---------------------------------------------------------------------------
# Fix 3 — cross-cloud-mirror detector
# ---------------------------------------------------------------------------

def _make_profile(tmp_path: Path, providers: list[str],
                   mirrored_files: dict[str, bytes],
                   unique_files: dict[str, dict[str, bytes]] | None = None
                   ) -> Path:
    """Helper: build a Users/jcloudy/ tree with the given cloud-sync
    directories. `mirrored_files` go into ALL providers; `unique_files`
    is provider→{name: bytes}."""
    profile = tmp_path / "Users" / "jcloudy"
    profile.mkdir(parents=True)
    for provider in providers:
        d = profile / provider
        d.mkdir()
        for name, data in mirrored_files.items():
            (d / name).write_bytes(data)
        if unique_files and provider in unique_files:
            for name, data in unique_files[provider].items():
                (d / name).write_bytes(data)
    return profile


def test_lone_wolf_4_provider_mirror_fires(tmp_path):
    """Box + Dropbox + OneDrive + Google Drive holding the same docs
    → fires at the 3-provider threshold (4 here)."""
    payload = b"The Cloudy Manifesto contents..." * 100
    profile = _make_profile(
        tmp_path,
        providers=["Box Sync", "Dropbox", "OneDrive", "Google Drive"],
        mirrored_files={
            "The Cloudy Manifesto.docx": payload,
            "Planning.docx": payload * 2,
            "Operation 2nd Hand Smoke.pptx": payload * 5,
        },
    )
    result = ccm.scan(profile)
    assert len(result.cloud_roots) == 4
    assert len(result.mirrored) == 3
    # Each mirrored cluster should span all 4 providers
    for m in result.mirrored:
        assert m.provider_count == 4


def test_2_provider_mirror_below_threshold(tmp_path):
    """Only Dropbox + OneDrive mirror → below default 3-provider
    threshold; no clusters surfaced."""
    profile = _make_profile(
        tmp_path,
        providers=["Dropbox", "OneDrive"],
        mirrored_files={"manifesto.docx": b"X" * 5000},
    )
    result = ccm.scan(profile)
    assert result.mirrored == []


def test_noise_files_skipped(tmp_path):
    """desktop.ini and Box Sync.lnk are dropped everywhere — must NOT
    fire even when present in N providers."""
    profile = _make_profile(
        tmp_path,
        providers=["Box Sync", "Dropbox", "OneDrive", "Google Drive"],
        mirrored_files={
            "desktop.ini": b"[General]\nVersion=1\n" * 100,
            "Box Sync.lnk": b"\x4c\x00\x00\x00\x01\x14\x02\x00" * 100,
        },
    )
    result = ccm.scan(profile)
    assert result.mirrored == []


def test_small_files_skipped(tmp_path):
    """Files under 1 KB skipped — sync-state metadata is tiny by
    construction and would flood the cluster set otherwise."""
    profile = _make_profile(
        tmp_path,
        providers=["Box Sync", "Dropbox", "OneDrive", "Google Drive"],
        mirrored_files={"tiny.txt": b"hi"},   # 2 bytes
    )
    result = ccm.scan(profile)
    assert result.mirrored == []


def test_unique_files_not_clustered(tmp_path):
    """Files unique to each provider must NOT form a mirror cluster."""
    profile = _make_profile(
        tmp_path,
        providers=["Box Sync", "Dropbox", "OneDrive", "Google Drive"],
        mirrored_files={},
        unique_files={
            "Box Sync":     {"only_box.txt":      b"box" * 1000},
            "Dropbox":      {"only_dropbox.txt":  b"db" * 1000},
            "OneDrive":     {"only_onedrive.txt": b"od" * 1000},
            "Google Drive": {"only_drive.txt":    b"gd" * 1000},
        },
    )
    result = ccm.scan(profile)
    assert result.mirrored == []


def test_user_profile_discovery_skips_system_accounts(tmp_path):
    """Public / Default / All Users user-profile dirs must be excluded."""
    for u in ("jcloudy", "Public", "Default", "All Users",
              "DefaultAppData", "Guest"):
        (tmp_path / "Users" / u).mkdir(parents=True)
    profiles = ccm.find_user_profiles(tmp_path)
    assert {p.name for p in profiles} == {"jcloudy"}


# ---------------------------------------------------------------------------
# Hypothesis scoring — H_PRE_ATTACK_PLANNING + H_MULTI_CLOUD_MIRROR
# ---------------------------------------------------------------------------

def _hypothesis(hyp_id: str):
    for h in HYPOTHESES:
        if h.hyp_id == hyp_id:
            return h
    raise KeyError(hyp_id)


def _mk_finding(claim: str, *, tags: list[str] | None = None,
                agent: str = "windows_artifact",
                confidence: str = "high") -> Finding:
    return Finding(
        case_id="t", agent=agent, claim=claim, confidence=confidence,
        evidence=[EvidenceItem(tool="t", version="1", command="t",
                                output_sha256="0" * 64,
                                output_path="/tmp/t")],
        hypotheses_supported=tags or [],
        created_utc=datetime.now(timezone.utc),
    )


def test_pre_attack_planning_hypothesis_lifts_on_explicit_tag():
    h = _hypothesis("H_PRE_ATTACK_PLANNING")
    f = _mk_finding("Pre-attack planning lexicon match in Planning.docx",
                    tags=["H_PRE_ATTACK_PLANNING"])
    assert h.score(f) == 3


def test_pre_attack_planning_hypothesis_lifts_on_multi_cloud_mirror():
    h = _hypothesis("H_PRE_ATTACK_PLANNING")
    f = _mk_finding("Multi-cloud evidence mirror in user profile 'jcloudy'",
                    tags=["H_MULTI_CLOUD_MIRROR"])
    assert h.score(f) == 3


def test_pre_attack_planning_hypothesis_lifts_on_aws_keys():
    h = _hypothesis("H_PRE_ATTACK_PLANNING")
    f = _mk_finding(
        "AWS access key cleartext in 'rootkey.csv' under profile 'jcloudy'",
        tags=["H_PRE_ATTACK_PLANNING"])
    # The "rootkey.csv" claim phrase adds +2 on top of the explicit tag +3
    assert h.score(f) >= 5


def test_pre_attack_planning_hypothesis_neutral_on_unrelated():
    h = _hypothesis("H_PRE_ATTACK_PLANNING")
    f = _mk_finding("Suricata EVE: 12 alerts across 3 sources",
                    tags=["H_C2_BEACONING"])
    assert h.score(f) == 0


def test_benign_hypothesis_refuted_by_pre_attack_planning_tag():
    """The null hypothesis must be refuted when planning evidence is
    present — otherwise a clean malware scan could tie / beat the
    planning finding."""
    h = _hypothesis("H_BENIGN_NO_INCIDENT")
    f = _mk_finding("Pre-attack planning lexicon match in Manifesto.docx",
                    tags=["H_PRE_ATTACK_PLANNING"])
    assert h.score(f) <= -3


def test_benign_hypothesis_refuted_by_multi_cloud_mirror_tag():
    h = _hypothesis("H_BENIGN_NO_INCIDENT")
    f = _mk_finding("Multi-cloud evidence mirror in user profile 'jcloudy'",
                    tags=["H_MULTI_CLOUD_MIRROR"])
    assert h.score(f) <= -3

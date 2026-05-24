"""T4-1 tests: Heuer ACH consistency matrix + Diamond Model projection."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from el.reporting.ach_matrix import build_ach_matrix_markdown
from el.reporting.diamond import build_diamond_markdown
from el.schemas.finding import EvidenceItem, Finding, RedReview


def _finding(fid: str, claim: str = "x",
              deltas: dict[str, int] | None = None,
              supports: list[str] | None = None,
              evidence_facts: dict | None = None) -> Finding:
    ev = [EvidenceItem(
        tool="t", version="0", command="c", output_sha256="0" * 64,
        output_path="/x", extracted_facts=evidence_facts or {},
    )]
    return Finding(
        finding_id=fid, case_id="c", agent="t", confidence="high",
        claim=claim, evidence=ev,
        hypotheses_supported=supports or [],
        ach_score_delta=deltas or {},
        created_utc=datetime.now(timezone.utc),
    )


def _rank(hyp_id: str, name: str, score: int) -> SimpleNamespace:
    return SimpleNamespace(
        hyp_id=hyp_id, name=name, score=score,
        supporting_findings=[], refuting_findings=[],
    )


# ---------------------------------------------------------------------------
# ACH matrix
# ---------------------------------------------------------------------------

def test_matrix_renders_columns_in_ranking_order():
    ranking = [
        _rank("H_APT_ESPIONAGE", "Targeted intrusion", 22),
        _rank("H_LATERAL_MOVEMENT", "Lateral movement", 18),
        _rank("H_C2_BEACONING", "C2 beaconing", 6),
    ]
    f1 = _finding("01ABC", deltas={"H_APT_ESPIONAGE": 3,
                                     "H_LATERAL_MOVEMENT": 2,
                                     "H_C2_BEACONING": 0})
    f2 = _finding("01DEF", deltas={"H_APT_ESPIONAGE": -1,
                                     "H_C2_BEACONING": 3})
    lines = build_ach_matrix_markdown([f1, f2], ranking)
    matrix_text = "\n".join(lines)
    # Header order matches ranking order
    assert matrix_text.index("APT_ESPIONAGE") < matrix_text.index(
        "LATERAL_MOVEMENT") < matrix_text.index("C2_BEACONING")


def test_matrix_cells_use_signed_deltas_and_dashes():
    ranking = [_rank("H_A", "A", 5), _rank("H_B", "B", 3)]
    f = _finding("01Z", deltas={"H_A": 3, "H_B": 0})
    lines = build_ach_matrix_markdown([f], ranking)
    row = next(l for l in lines if "01Z" in l)
    assert "+3" in row
    assert "--" in row


def test_matrix_skips_findings_without_nonzero_deltas():
    ranking = [_rank("H_A", "A", 5)]
    f = _finding("01Z", deltas={"H_A": 0})
    assert build_ach_matrix_markdown([f], ranking) == []


def test_matrix_sorts_by_max_absolute_delta():
    ranking = [_rank("H_A", "A", 5), _rank("H_B", "B", 5)]
    small = _finding("01SMALL", deltas={"H_A": 1})
    big = _finding("01BIG", deltas={"H_A": -5})
    lines = build_ach_matrix_markdown([small, big], ranking)
    # The big-delta row appears first in the body
    body = [l for l in lines if l.startswith("| `01")]
    assert body[0].startswith("| `01BIG")


def test_matrix_escapes_pipe_in_claim_text():
    ranking = [_rank("H_A", "A", 5)]
    f = _finding("01Z", claim="contains | a pipe | char",
                  deltas={"H_A": 1})
    lines = build_ach_matrix_markdown([f], ranking)
    # The pipe in the claim must be backslash-escaped so it doesn't
    # break the markdown table row
    assert any(r"contains \| a pipe \| char" in l for l in lines)


def test_matrix_empty_ranking_returns_empty():
    assert build_ach_matrix_markdown(
        [_finding("x", deltas={"H_A": 3})], []) == []


# ---------------------------------------------------------------------------
# Diamond Model
# ---------------------------------------------------------------------------

def test_diamond_emits_adversary_capability_infrastructure_victim():
    ranking = [_rank("H_C2_BEACONING", "C2 beaconing", 9)]
    iocs = {
        "ipv4": ["203.0.113.10", "10.0.0.5"],           # public + internal
        "domain": ["evil.example.com"],
    }
    f = _finding(
        "01X", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001", "T1105"]},
    )
    lines = build_diamond_markdown([f], ranking, iocs,
                                     manifest={"case_id": "wkstn-01"})
    text = "\n".join(lines)
    # All four headers present
    for header in ("Adversary", "Capability", "Infrastructure",
                    "Victim"):
        assert header in text
    # IPs + domain land in Infrastructure (both internal + external)
    inf_idx = text.find("**Infrastructure**")
    inf_cell = text[inf_idx:text.find("**Victim**")]
    assert "203.0.113.10" in inf_cell
    assert "10.0.0.5" in inf_cell
    assert "evil.example.com" in inf_cell
    # Techniques land in Capability
    assert "T1071.001" in text
    # IPs + domain MUST NOT appear in Adversary — that was the
    # M57-Jean/LoneWolf duplication bug. The Adversary cell carries
    # the empty-state message because this case has no email IOCs.
    adv_idx = text.find("**Adversary**")
    adv_cell = text[adv_idx:text.find("**Capability**")]
    assert "203.0.113.10" not in adv_cell
    assert "evil.example.com" not in adv_cell
    assert "no attribution surface" in adv_cell
    # case_id MUST NOT appear in Victim — it's EL's internal handle,
    # not a real victim host. Regression for the M57-Jean bug where
    # the Victim quarter said "m57-jean-judges" instead of
    # "jean@m57.biz". When no real victim principals are extractable,
    # the row renders as "_none_".
    assert "wkstn-01" not in text
    assert "_none_" in text   # no email findings + no top_X → empty row


def test_diamond_uses_manifest_hostname_when_present():
    """If the manifest carries a real hostname (not the case_id), it
    DOES qualify as a Victim host. Different field name (`hostname`)
    so a real ComputerName from the registry hive can populate
    Victim without re-introducing the case_id bug."""
    ranking = [_rank("H_C2_BEACONING", "C2 beaconing", 9)]
    f = _finding("01X", supports=["H_C2_BEACONING"],
                  evidence_facts={"attack_techniques": ["T1071.001"]})
    lines = build_diamond_markdown(
        [f], ranking, {"ipv4": []},
        manifest={"case_id": "abstract-handle",
                  "hostname": "STARK-DC01"})
    text = "\n".join(lines)
    assert "STARK-DC01" in text
    assert "abstract-handle" not in text


def test_diamond_handles_no_public_attribution_surface():
    """When the supporting findings carry no email IOCs the Adversary
    row must NOT echo Infrastructure — IPs/domains alone are pivot
    points, not attribution. The empty-state text spells that out so
    the analyst knows the cell is intentionally empty, not a bug."""
    ranking = [_rank("H_LATERAL_MOVEMENT", "Lateral", 10)]
    iocs = {"ipv4": ["10.0.0.5", "172.16.4.6"]}
    f = _finding("01X", supports=["H_LATERAL_MOVEMENT"],
                  evidence_facts={"attack_techniques": ["T1021.002"]})
    lines = build_diamond_markdown([f], ranking, iocs, manifest={})
    text = "\n".join(lines)
    # Adversary row present but empty-annotated — the new wording
    # explicitly says IPs / domains are not attribution.
    assert "no attribution surface" in text
    assert "IPs / domains alone are pivots" in text
    # Internal IPs still land in the Infrastructure row
    assert "10.0.0.5" in text
    assert "172.16.4.6" in text


def test_diamond_adversary_excludes_public_ips_and_domains():
    """Hard contract: even when IOCs carry public IPs and domains,
    they MUST NOT appear in the Adversary row. They belong in
    Infrastructure. This was the M57-Jean / LoneWolf bug — the two
    vertices rendered identically whenever there were no email IOCs
    and no internal IPs."""
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    iocs = {
        "ipv4": ["203.0.113.10", "198.51.100.42"],
        "domain": ["evil.example.com", "bad.example.net"],
    }
    f = _finding("01X", supports=["H_C2_BEACONING"],
                  evidence_facts={"attack_techniques": ["T1071.001"]})
    lines = build_diamond_markdown([f], ranking, iocs, manifest={})
    text = "\n".join(lines)
    # Slice the Adversary cell out of the table — between the
    # Adversary header and the Capability header.
    adv_idx = text.find("**Adversary**")
    cap_idx = text.find("**Capability**")
    assert adv_idx > 0 and cap_idx > adv_idx
    adv_cell = text[adv_idx:cap_idx]
    for ip in iocs["ipv4"]:
        assert ip not in adv_cell, \
            f"Public IP {ip} leaked into Adversary cell"
    for dom in iocs["domain"]:
        assert dom not in adv_cell, \
            f"Domain {dom} leaked into Adversary cell"
    # …but they do appear in Infrastructure
    inf_idx = text.find("**Infrastructure**")
    assert inf_idx > 0
    inf_cell = text[inf_idx:]
    for ip in iocs["ipv4"]:
        assert ip in inf_cell
    for dom in iocs["domain"]:
        assert dom in inf_cell


def test_diamond_extracts_local_user_into_victim_from_user_profile_fact():
    """LoneWolf shape: a single supporting finding carries
    `user_profile=/.../Users/jcloudy` in extracted_facts. The
    extractor must normalise the path to the bare username and put
    it in Victim (non-insider hypothesis here)."""
    ranking = [_rank("H_ANTI_FORENSICS", "Anti-forensics", 12)]
    f = _finding(
        "01X", supports=["H_ANTI_FORENSICS"],
        evidence_facts={
            "user_profile":
                "/tmp/el-mounts/lonewolf/Users/jcloudy",
            "attack_techniques": ["T1070"],
        },
    )
    lines = build_diamond_markdown([f], ranking, {}, manifest={})
    text = "\n".join(lines)
    vic_idx = text.find("**Victim**")
    adv_idx = text.find("**Adversary**")
    assert vic_idx > 0
    vic_cell = text[vic_idx:]
    assert "jcloudy" in vic_cell
    # Not in Adversary (non-insider hypothesis)
    cap_idx = text.find("**Capability**")
    assert "jcloudy" not in text[adv_idx:cap_idx]


def test_diamond_extracts_local_user_from_claim_text():
    """Several DiskForensicator claims surface the profile inline,
    e.g. "AWS access key cleartext in 'rootkey.csv' under profile
    'jcloudy' on slot003-...". The regex extractor must pick this
    up even when no structured field carries it."""
    ranking = [_rank("H_ANTI_FORENSICS", "Anti-forensics", 12)]
    f = _finding(
        "01X",
        claim=("AWS access key cleartext in 'rootkey.csv' under "
               "profile 'jcloudy' on slot003-off1259520"),
        supports=["H_ANTI_FORENSICS"],
        evidence_facts={"attack_techniques": ["T1552"]},
    )
    lines = build_diamond_markdown([f], ranking, {}, manifest={})
    text = "\n".join(lines)
    assert "jcloudy" in text[text.find("**Victim**"):]


def test_diamond_insider_hypothesis_promotes_user_to_adversary():
    """Under an insider hypothesis the local user IS the actor —
    they must appear in Adversary, NOT Victim, and the two vertices
    must stay mutually exclusive on the same principal (no
    double-counting)."""
    ranking = [_rank("H_PRE_ATTACK_PLANNING", "Lone-wolf planning",
                       23)]
    f = _finding(
        "01X",
        claim=("Pre-attack planning lexicon match in Planning.docx "
               "under profile 'jcloudy'"),
        supports=["H_PRE_ATTACK_PLANNING"],
        evidence_facts={
            "user_profile": "/tmp/el-mounts/lw/Users/jcloudy",
            "attack_techniques": ["T1005"],
        },
    )
    lines = build_diamond_markdown([f], ranking, {}, manifest={})
    text = "\n".join(lines)
    adv_idx = text.find("**Adversary**")
    cap_idx = text.find("**Capability**")
    vic_idx = text.find("**Victim**")
    adv_cell = text[adv_idx:cap_idx]
    vic_cell = text[vic_idx:]
    assert "jcloudy" in adv_cell, \
        "Insider hypothesis must promote local user to Adversary"
    assert "jcloudy" not in vic_cell, \
        "Same user must not appear in BOTH Adversary and Victim"
    # The label text changes too — the analyst knows why
    assert "insider" in adv_cell.lower()


def test_diamond_normalises_user_path_segments():
    """Path-shaped values (`.../Users/<name>/...`) must reduce to
    the bare account name. Bare names pass through. Service-account
    noise (SYSTEM, NT AUTHORITY, …) is dropped."""
    from el.reporting.diamond import _normalise_user
    assert _normalise_user(
        "/tmp/el-mounts/lonewolf/Users/jcloudy") == "jcloudy"
    assert _normalise_user(
        "C:\\Users\\Alice\\AppData") == "alice"
    assert _normalise_user("/home/bob/.ssh") == "bob"
    assert _normalise_user("BareName") == "barename"
    # Noise
    assert _normalise_user("SYSTEM") is None
    assert _normalise_user("NT AUTHORITY") is None
    assert _normalise_user("") is None
    # Email-shaped values are handled by a different code path; the
    # user-profile normaliser rejects them so they don't
    # double-count.
    assert _normalise_user("alice@example.com") is None


def test_diamond_skips_when_no_supporting_findings():
    ranking = [_rank("H_APT_ESPIONAGE", "APT", 10)]
    # Finding supports a DIFFERENT hypothesis — none for the leader
    f = _finding("01X", supports=["H_BENIGN_NO_INCIDENT"])
    assert build_diamond_markdown([f], ranking, {}, manifest={}) == []


def test_diamond_skips_when_no_ranking():
    f = _finding("01X", supports=["H_A"])
    assert build_diamond_markdown([f], [], {}, manifest={}) == []


def test_diamond_extracts_user_principals_from_facts():
    ranking = [_rank("H_CREDENTIAL_ACCESS", "Cred access", 9)]
    f = _finding(
        "01X", supports=["H_CREDENTIAL_ACCESS"],
        evidence_facts={
            "attack_techniques": ["T1558.003"],
            "top_targets": [("spfarm@SHIELDBASE.LAN", 75),
                             ("nromanoff@SHIELDBASE.LAN", 20)],
        },
    )
    lines = build_diamond_markdown([f], ranking,
                                     {"ipv4": []}, manifest={})
    text = "\n".join(lines)
    # When no inferred-local-domain is present (no PST in case), the
    # top_targets legacy path passes through unfiltered — SHIELDBASE.LAN
    # principals land in Victim because the agent already curated them
    # as targets-of-the-attack.
    assert "spfarm@SHIELDBASE.LAN".lower() in text.lower()


# ---------------------------------------------------------------------------
# Email-regex Victim path (M57-Jean BEC regression)
# ---------------------------------------------------------------------------

def test_diamond_email_regex_picks_local_sender_as_victim():
    """M57-Jean BEC shape: email_forensicator emits a finding whose
    extracted_facts include sender / actual_recipient / display_name
    (no top_targets). The Victim quarter must pick up `jean@m57.biz`
    (the local-domain sender) and NOT `tuckgorge@gmail.com` (the
    external recipient — that's adversary, not victim). The local-
    domain heuristic comes from the PST-parsed finding's claim text."""
    ranking = [_rank("H_BEC_ACCOUNT_TAKEOVER", "BEC", 51)]
    pst_parsed = _finding(
        "00P", supports=[],
        claim="PST parsed (Jean--outlook.pst): 258 message(s) "
              "across 10 folder(s) (Calendar, Contacts, Deleted Items, "
              "Drafts, Inbox, Journal, Notes, Outbox, Sent Items, "
              "Tasks). Inferred local domain(s): google.com, m57.biz",
    )
    exfil = _finding(
        "00E", supports=["H_BEC_ACCOUNT_TAKEOVER"],
        evidence_facts={
            "sender": "jean@m57.biz",
            "display_name": "alison@m57.biz",
            "actual_recipient": "tuckgorge@gmail.com",
            "attachments": ["1_m57biz.xls"],
        },
        claim="Email display-name/SMTP mismatch — sender=jean@m57.biz",
    )
    lines = build_diamond_markdown(
        [pst_parsed, exfil], ranking,
        {"domain": ["m57.biz"], "ipv4": []},
        manifest={"case_id": "m57-jean-judges"})
    text = "\n".join(lines)
    # Victim row contains Jean (local-domain principal)
    assert "jean@m57.biz" in text
    # External recipient lands in Adversary/Infrastructure (via the
    # iocs.domain path) but NOT in Victim.
    victim_block = text.split("**Victim**")[1].split("|")[0:2]
    assert "tuckgorge@gmail.com" not in "".join(victim_block)
    # Case ID does not appear anywhere as a victim (regression for
    # the original M57-Jean bug)
    assert "m57-jean-judges" not in text


def test_diamond_email_regex_skips_external_when_no_local_domain():
    """When no PST-parsed finding exists (so no inferred local
    domain), the email regex path must NOT promote external emails
    to Victim. The Victim quarter stays empty rather than naming the
    adversary's address as a victim."""
    ranking = [_rank("H_BEC_ACCOUNT_TAKEOVER", "BEC", 51)]
    exfil = _finding(
        "00E", supports=["H_BEC_ACCOUNT_TAKEOVER"],
        evidence_facts={
            "sender": "jean@m57.biz",
            "actual_recipient": "tuckgorge@gmail.com",
        },
    )
    lines = build_diamond_markdown(
        [exfil], ranking, {"ipv4": []},
        manifest={"case_id": "no-pst-case"})
    text = "\n".join(lines)
    victim_idx = text.find("**Victim**")
    assert victim_idx > 0
    victim_row = text[victim_idx:victim_idx + 200]
    # Both addresses absent from Victim because we can't classify
    # which one is local without a Inferred local domain marker.
    assert "tuckgorge@gmail.com" not in victim_row
    assert "jean@m57.biz" not in victim_row
    assert "_none_" in victim_row


def test_diamond_external_email_lands_in_adversary_not_victim():
    """The inverse of the Victim filter: external (non-local-domain)
    email addresses in supporting findings' extracted_facts are the
    attacker's attribution surface and must appear in Adversary.
    Regression for M57-Jean where `tuckgorge@gmail.com` was the
    attacker's address but the Adversary quarter never named it."""
    ranking = [_rank("H_BEC_ACCOUNT_TAKEOVER", "BEC", 51)]
    pst = _finding(
        "00P", claim="PST parsed: Inferred local domain(s): m57.biz",
    )
    f = _finding(
        "00E", supports=["H_BEC_ACCOUNT_TAKEOVER"],
        evidence_facts={
            "sender": "jean@m57.biz",
            "actual_recipient": "tuckgorge@gmail.com",
        },
    )
    lines = build_diamond_markdown([pst, f], ranking,
                                    {"ipv4": []}, manifest={})
    text = "\n".join(lines)
    adv_idx = text.find("**Adversary**")
    vic_idx = text.find("**Victim**")
    adv_row = text[adv_idx:vic_idx if vic_idx > adv_idx else adv_idx + 200]
    vic_row = text[vic_idx:vic_idx + 200]
    # External email IS in Adversary
    assert "tuckgorge@gmail.com" in adv_row
    # External email is NOT in Victim
    assert "tuckgorge@gmail.com" not in vic_row
    # Local-domain email IS in Victim
    assert "jean@m57.biz" in vic_row


def test_diamond_adversary_holds_emails_carved_domains_stay_in_infrastructure():
    """Carved-domain noise no longer pollutes the Adversary row at
    all — it lands in Infrastructure (where domains belong). The
    M57-Jean cap-overflow concern is moot now that the two vertices
    are vertically separated."""
    ranking = [_rank("H_BEC_ACCOUNT_TAKEOVER", "BEC", 51)]
    pst = _finding(
        "00P", claim="PST parsed: Inferred local domain(s): m57.biz",
    )
    exfil = _finding(
        "00E", supports=["H_BEC_ACCOUNT_TAKEOVER"],
        evidence_facts={"actual_recipient": "tuckgorge@gmail.com"},
    )
    iocs = {"domain": [f"carved{i}.noise" for i in range(30)]}
    lines = build_diamond_markdown([pst, exfil], ranking, iocs,
                                    manifest={})
    text = "\n".join(lines)
    adv_idx = text.find("**Adversary**")
    cap_idx = text.find("**Capability**")
    inf_idx = text.find("**Infrastructure**")
    adv_row = text[adv_idx:cap_idx]
    inf_row = text[inf_idx:text.find("**Victim**")]
    # The attacker email IS in Adversary
    assert "tuckgorge@gmail.com" in adv_row
    # Carved domains are NOT in Adversary
    assert "carved0.noise" not in adv_row
    assert "carved29.noise" not in adv_row
    # …they live in Infrastructure
    assert "carved0.noise" in inf_row, \
        "adversary email must be prepended before carved-domain noise"


def test_diamond_capability_picks_up_email_forensicator_techniques():
    """Capability quarter populates from extracted_facts.attack_techniques
    on supporting findings. The email_forensicator now tags T1566.002
    / T1534 / T1567 on its BEC-shape findings — Capability must show
    them. Regression for M57-Jean where Capability was empty even
    though the case had clear phishing + exfil signal."""
    ranking = [_rank("H_BEC_ACCOUNT_TAKEOVER", "BEC", 51)]
    f = _finding(
        "00E", supports=["H_BEC_ACCOUNT_TAKEOVER"],
        evidence_facts={
            "sender": "jean@m57.biz",
            "actual_recipient": "tuckgorge@gmail.com",
            # The exact tag set the BEC outbound-mismatch site emits
            "attack_techniques": ["T1534", "T1567"],
        },
    )
    lines = build_diamond_markdown([f], ranking, {"ipv4": []}, manifest={})
    text = "\n".join(lines)
    cap_idx = text.find("**Capability**")
    inf_idx = text.find("**Infrastructure**")
    cap_row = text[cap_idx:inf_idx]
    assert "T1534" in cap_row
    assert "T1567" in cap_row
    assert "no technique IDs tagged" not in cap_row


def test_diamond_email_regex_with_local_domain_drops_external():
    """Even when the email regex finds both local and external
    addresses in the same fact dict, only the local-domain one is
    promoted to Victim."""
    ranking = [_rank("H_BEC_ACCOUNT_TAKEOVER", "BEC", 51)]
    pst = _finding(
        "00P", claim="PST parsed: Inferred local domain(s): m57.biz",
    )
    f = _finding(
        "00E", supports=["H_BEC_ACCOUNT_TAKEOVER"],
        evidence_facts={
            "sender": "jean@m57.biz",
            "cc_displayed": "alison@m57.biz",
            "actual_recipient": "tuckgorge@gmail.com",
            "external_forward_to": "attacker@example.com",
        },
    )
    lines = build_diamond_markdown([pst, f], ranking,
                                    {"ipv4": []}, manifest={})
    text = "\n".join(lines)
    victim_idx = text.find("**Victim**")
    victim_row = text[victim_idx:victim_idx + 200]
    # Local-domain addresses present
    assert "jean@m57.biz" in victim_row
    assert "alison@m57.biz" in victim_row
    # External addresses excluded
    assert "tuckgorge@gmail.com" not in victim_row
    assert "attacker@example.com" not in victim_row

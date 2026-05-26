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
    """All four core vertices + the extended Social-Political and
    Direction rows must be present, with IPs/domains in
    Infrastructure (never Adversary) per paper §4.3."""
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
    # All four core vertex headers + the two extended-diamond rows
    for header in ("Adversary", "Capability", "Infrastructure",
                    "Victim", "Social-Political", "Direction"):
        assert header in text
    # IPs + domain land in Infrastructure Type 1 (default — none of
    # the supporting findings carry Type-2 hints).
    inf_idx = text.find("**Infrastructure** — Type 1")
    assert inf_idx > 0
    inf_cell = text[inf_idx:text.find("Type 2")]
    assert "203.0.113.10" in inf_cell
    assert "10.0.0.5" in inf_cell
    assert "evil.example.com" in inf_cell
    # Techniques land in Capability
    assert "T1071.001" in text
    # IPs + domain MUST NOT appear in Adversary — paper §4.3
    # explicitly lists IPs/domains as Infrastructure.
    adv_idx = text.find("**Adversary**")
    adv_cell = text[adv_idx:text.find("**Capability**")]
    assert "203.0.113.10" not in adv_cell
    assert "evil.example.com" not in adv_cell
    # Empty Adversary Operator under non-insider hypothesis: paper
    # §4.1 says Adversary is often empty at discovery time. The
    # renderer cites that wording in the empty cell.
    assert "§4.1" in adv_cell or "often empty" in adv_cell
    # case_id `wkstn-01` IS a hostname-shaped label, so it now
    # correctly surfaces in Victim Asset via the input-path /
    # case_id heuristic — different from the old "case_id is
    # internal handle, never in Victim" rule. The M57-Jean
    # regression (case_id like `m57-jean-judges` containing
    # `case`/`jean` style identifiers) is still guarded against
    # by the blocklist (see test below).
    vic_idx = text.find("**Victim**")
    sp_idx = text.find("**Social-Political**")
    asset_cell = text[vic_idx:sp_idx]
    assert "wkstn-01" in asset_cell


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
    """When the supporting findings carry no Adversary-grade signal
    the Adversary Operator cell cites paper §4.1 explicitly so the
    analyst knows the cell is intentionally empty, not a bug. IPs
    still land in Infrastructure."""
    ranking = [_rank("H_LATERAL_MOVEMENT", "Lateral", 10)]
    iocs = {"ipv4": ["10.0.0.5", "172.16.4.6"]}
    f = _finding("01X", supports=["H_LATERAL_MOVEMENT"],
                  evidence_facts={"attack_techniques": ["T1021.002"]})
    lines = build_diamond_markdown([f], ranking, iocs, manifest={})
    text = "\n".join(lines)
    adv_idx = text.find("**Adversary**")
    adv_cell = text[adv_idx:text.find("**Capability**")]
    # Adversary Operator empty cell cites the paper
    assert "§4.1" in adv_cell or "often empty" in adv_cell
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
    vic_cell = text[vic_idx:text.find("**Social-Political**")]
    assert "jcloudy" in adv_cell, \
        "Insider hypothesis must promote local user to Adversary"
    assert "jcloudy" not in vic_cell, \
        "Same user must not appear in BOTH Adversary and Victim"
    # The Victim Persona sub-row text changes too — analyst sees why
    assert "insider case" in vic_cell.lower()
    # And the motivation surfaces the insider intent
    assert "Insider" in text or "Personal preparation" in text


# ---------------------------------------------------------------------------
# Paper alignment — Infrastructure Type 1/2/SP, Victim Persona/Asset,
# Social-Political, Direction (Caltagirone/Pendergast/Betz 2013)
# ---------------------------------------------------------------------------

def test_diamond_infrastructure_type1_default_for_iocs():
    """Default classification: every IP / domain from the IOC catalog
    is Type 1 (adversary-owned) unless a supporting finding's claim
    text marks it as intermediary infrastructure."""
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    iocs = {"ipv4": ["203.0.113.10"], "domain": ["evil.example.com"]}
    f = _finding("01X", supports=["H_C2_BEACONING"])
    lines = build_diamond_markdown([f], ranking, iocs, manifest={})
    text = "\n".join(lines)
    t1_idx = text.find("Type 1 (adversary-owned)")
    t2_idx = text.find("Type 2 (intermediary)")
    assert t1_idx > 0 and t2_idx > t1_idx
    t1_cell = text[t1_idx:t2_idx]
    t2_cell = text[t2_idx:text.find("Service Providers")]
    assert "203.0.113.10" in t1_cell
    assert "evil.example.com" in t1_cell
    assert "203.0.113.10" not in t2_cell


def test_diamond_infrastructure_type2_when_finding_claims_compromised_account():
    """When a supporting finding's claim mentions 'compromised
    account' / 'BEC' / 'spoof' etc., the IPs / domains it surfaces
    are promoted from Type 1 to Type 2 — paper §4.3: 'Type 2
    infrastructure includes compromised email accounts.'"""
    ranking = [_rank("H_BEC_ACCOUNT_TAKEOVER", "BEC", 10)]
    f = _finding(
        "01X", supports=["H_BEC_ACCOUNT_TAKEOVER"],
        claim=("BEC outbound: compromised account jean@m57.biz "
                "forwarding to external recipient"),
        evidence_facts={"actual_recipient": "tuckgorge@gmail.com"},
    )
    lines = build_diamond_markdown([f], ranking, {}, manifest={})
    text = "\n".join(lines)
    inf_idx = text.find("**Infrastructure**")
    t2_idx = text.find("Type 2 (intermediary)")
    t2_cell = text[t2_idx:text.find("Service Providers")]
    # Email surfaced under a Type-2-shaped claim → Type 2
    assert "tuckgorge@gmail.com" in t2_cell


def test_diamond_emails_always_in_infrastructure_per_paper_section_4_3():
    """Even with no 'compromised account' hint, emails surfaced in
    supporting findings go to Type 2 Infrastructure per paper §4.3
    (Infrastructure examples list 'e-mail addresses' explicitly).
    They never go to Adversary."""
    ranking = [_rank("H_OPPORTUNISTIC_COMMODITY", "Commodity", 5)]
    f = _finding(
        "01X", supports=["H_OPPORTUNISTIC_COMMODITY"],
        evidence_facts={"reported_sender": "scammer@badmail.example"},
    )
    lines = build_diamond_markdown([f], ranking, {}, manifest={})
    text = "\n".join(lines)
    adv_idx = text.find("**Adversary**")
    cap_idx = text.find("**Capability**")
    inf_idx = text.find("**Infrastructure**")
    vic_idx = text.find("**Victim**")
    adv_cell = text[adv_idx:cap_idx]
    inf_block = text[inf_idx:vic_idx]
    assert "scammer@badmail.example" not in adv_cell
    assert "scammer@badmail.example" in inf_block


def test_diamond_victim_persona_vs_asset_split():
    """Victim sub-features per paper §4.4: Persona (people / orgs)
    and Asset (systems / accounts). Local-user names go to Persona;
    hostnames and credential identifiers go to Asset."""
    ranking = [_rank("H_ANTI_FORENSICS", "Anti-forensics", 12)]
    f = _finding(
        "01X", supports=["H_ANTI_FORENSICS"],
        claim="AWS access key exposed under profile 'jcloudy'",
        evidence_facts={
            "user_profile": "/mnt/Users/jcloudy",
            "aws_access_key_id": "AKIAEXAMPLE1234567",
            "attack_techniques": ["T1552"],
        },
    )
    lines = build_diamond_markdown([f], ranking, {},
                                     manifest={"hostname": "DESKTOP-LW01"})
    text = "\n".join(lines)
    persona_idx = text.find("Persona")
    asset_idx = text.find("Asset")
    assert persona_idx > 0 and asset_idx > persona_idx
    persona_cell = text[persona_idx:asset_idx]
    asset_cell = text[asset_idx:text.find("**Social-Political**")]
    assert "jcloudy" in persona_cell
    assert "DESKTOP-LW01" in asset_cell
    assert "AKIAEXAMPLE1234567" in asset_cell


def test_diamond_social_political_row_present_with_motivation():
    """Extended diamond §5.1: Social-Political row carries the
    motivation derived from the leading hypothesis."""
    ranking = [_rank("H_PRE_ATTACK_PLANNING", "Lone-wolf planning",
                       23)]
    f = _finding("01X", supports=["H_PRE_ATTACK_PLANNING"])
    lines = build_diamond_markdown([f], ranking, {}, manifest={})
    text = "\n".join(lines)
    sp_idx = text.find("**Social-Political**")
    assert sp_idx > 0
    sp_cell = text[sp_idx:text.find("**Direction**")]
    # Motivation should mention the violent / kinetic framing
    assert "violent" in sp_cell.lower() or "kinetic" in sp_cell.lower()


def test_diamond_social_political_calls_out_anti_forensics_as_how_not_why():
    """The H_ANTI_FORENSICS motivation must explicitly note it's a
    HOW not a WHY, pointing the reader to the runner-up. This is
    the secondary observation surfaced after the LoneWolf re-run."""
    ranking = [_rank("H_ANTI_FORENSICS", "Anti-forensics", 55)]
    f = _finding("01X", supports=["H_ANTI_FORENSICS"],
                  claim="VSS diff: live Security.evtx scrubbed")
    lines = build_diamond_markdown([f], ranking, {}, manifest={})
    text = "\n".join(lines)
    sp_idx = text.find("**Social-Political**")
    sp_cell = text[sp_idx:text.find("**Direction**")]
    assert "HOW" in sp_cell or "WHY" in sp_cell or \
           "runner-up" in sp_cell.lower()


def test_diamond_direction_row_classifies_supporting_findings():
    """Direction §4.5.4: claim-text patterns map to the seven values
    enumerated in the paper. Inbound RDP → Infrastructure-to-Victim;
    cloud-sync staging → Victim-to-Infrastructure; anti-forensic /
    host-local activity → a 'host-local' annotation since none of
    the seven cleanly cover it."""
    ranking = [_rank("H_ANTI_FORENSICS", "Anti-forensics", 12)]
    findings = [
        _finding("01A", supports=["H_ANTI_FORENSICS"],
                  claim="Inbound RDP brute-force cluster from 1.2.3.4"),
        _finding("01B", supports=["H_ANTI_FORENSICS"],
                  claim="Multi-cloud staging in profile 'jcloudy'"),
        _finding("01C", supports=["H_ANTI_FORENSICS"],
                  claim="VSS diff: Security.evtx scrubbed in live FS"),
    ]
    lines = build_diamond_markdown(findings, ranking, {}, manifest={})
    text = "\n".join(lines)
    dir_idx = text.find("**Direction**")
    dir_cell = text[dir_idx:]
    assert "Infrastructure-to-Victim" in dir_cell
    assert "Victim-to-Infrastructure" in dir_cell
    assert "host-local" in dir_cell


# ---------------------------------------------------------------------------
# Victim Asset — hostname extraction beyond manifest.hostname
# ---------------------------------------------------------------------------

def test_diamond_extracts_hostname_from_input_path_filename():
    """When the manifest carries no `hostname` field but the
    input_path filename matches a corpus naming convention like
    `base-dc-cdrive.E01` or `rocba-cdrive.e01`, extract the host
    segment and put it in Victim Asset."""
    from el.reporting.diamond import _extract_hostname_candidates
    # SRL-2018 shape
    hosts = _extract_hostname_candidates(
        manifest={"input_path":
                   "/media/usb/SRL-2018/base-dc-cdrive.E01"},
        case_id=None)
    assert "dc" in hosts
    # rocba shape
    hosts = _extract_hostname_candidates(
        manifest={"input_path":
                   "/media/usb/Rocba-Cdrive.e01"},
        case_id=None)
    assert "rocba" in hosts
    # multi-word host with hyphen
    hosts = _extract_hostname_candidates(
        manifest={"input_path":
                   "/media/usb/base-wkstn-05-cdrive.E01"},
        case_id=None)
    assert "wkstn-05" in hosts


def test_diamond_victim_asset_from_computer_name_fact():
    """The authoritative path: a finding carrying a `computer_name`
    fact (extracted from the SYSTEM hive by time_baseline) surfaces
    the real NetBIOS name in Victim Asset — strictly better than the
    case-id/filename heuristic."""
    ranking = [_rank("H_APT_ESPIONAGE", "APT", 20)]
    f = _finding(
        "01X", supports=["H_APT_ESPIONAGE"],
        claim="Time-baseline: SYSTEM hive parsed",
        evidence_facts={"computer_name": "BASE-DC",
                         "attack_techniques": ["T1003"]})
    lines = build_diamond_markdown([f], ranking, {}, manifest={})
    text = "\n".join(lines)
    asset_cell = text[text.find("Asset"):text.find("**Social-Political**")]
    assert "BASE-DC" in asset_cell


def test_diamond_extracts_hostname_from_bundle_subcase_id():
    """el.bundle.make_device_case_id produces case_ids like
    `srl-2018__dc`. Extract the device half — that's the host
    name even when the disk image filename is anonymous."""
    from el.reporting.diamond import _extract_hostname_candidates
    hosts = _extract_hostname_candidates(
        manifest={"input_path": "/scratch/srl-2018/dc"},
        case_id="srl-2018__dc")
    assert "dc" in hosts


def test_diamond_accepts_hostname_shaped_single_case_id():
    """When the case_id itself looks like a hostname (`rocba`,
    `wkstn-05`), accept it as an asset. Conservative pattern
    rejects multi-word labels with `case`/`test`/`demo`."""
    from el.reporting.diamond import _extract_hostname_candidates
    assert "rocba" in _extract_hostname_candidates(
        manifest=None, case_id="rocba")
    assert "wkstn-05" in _extract_hostname_candidates(
        manifest=None, case_id="wkstn-05")


def test_diamond_rejects_investigator_label_case_ids():
    """Investigator-chosen case_ids like `lonewolf-v3`, `srl-test`,
    `demo-case` shouldn't be promoted to Victim Asset — they're
    case tracking labels, not hostnames."""
    from el.reporting.diamond import _extract_hostname_candidates
    # `lonewolf` is on the blocklist (investigator pattern)
    hosts = _extract_hostname_candidates(
        manifest=None, case_id="lonewolf-v3")
    assert "lonewolf-v3" not in hosts
    assert "lonewolf" not in hosts


def test_diamond_hostname_extraction_full_render(tmp_path):
    """End-to-end render: when the manifest names a corpus-style
    input_path the rendered Victim Asset cell carries the
    extracted hostname even without an explicit hostname field."""
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    f = _finding(
        "01X", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001"]})
    lines = build_diamond_markdown(
        [f], ranking, {},
        manifest={"case_id": "dc",
                  "input_path": "/media/usb/base-dc-cdrive.E01"})
    text = "\n".join(lines)
    asset_idx = text.find("Asset")
    assert asset_idx > 0
    asset_cell = text[asset_idx:text.find("**Social-Political**")]
    assert "dc" in asset_cell


# ---------------------------------------------------------------------------
# Capability Capacity — derived from observed ATT&CK techniques
# ---------------------------------------------------------------------------

def test_diamond_capacity_populated_from_observed_techniques():
    """The Capacity sub-row must list what the observed techniques
    can reach — pulled from el/intel/attack_capacities.py via
    capacity_for(). Replaces the previous 'not catalogued'
    placeholder text."""
    ranking = [_rank("H_CREDENTIAL_ACCESS", "Cred access", 9)]
    f = _finding(
        "01X", supports=["H_CREDENTIAL_ACCESS"],
        evidence_facts={"attack_techniques": ["T1003.001",
                                                "T1059.001"]})
    lines = build_diamond_markdown([f], ranking, {}, manifest={})
    text = "\n".join(lines)
    cap_idx = text.find("Capacity")
    assert cap_idx > 0
    cap_cell = text[cap_idx:text.find("**Infrastructure**")]
    # T1003.001 capacity references LSASS; T1059.001 references PowerShell
    assert "LSASS" in cap_cell or "lsass" in cap_cell.lower()
    assert "PowerShell" in cap_cell or "powershell" in cap_cell.lower()
    # No more placeholder text
    assert "not catalogued" not in cap_cell


def test_diamond_capability_is_case_wide_not_leader_scoped():
    """The reported bug: ATT&CK techniques are correctly identified
    but don't appear in the Capability vertex. Root cause was that
    Capability was scoped to the LEADING hypothesis's supporting
    findings. When the leader is H_ANTI_FORENSICS (the common real-
    case leader), its supporters (VSS diffs, zeroed binaries) carry
    no techniques — while the technique-rich findings support OTHER
    hypotheses and were filtered out. Capability must be collected
    case-wide so the adversary's 'how' surfaces regardless of which
    hypothesis the technique-bearing finding scores."""
    ranking = [_rank("H_ANTI_FORENSICS", "Anti-forensics", 55)]
    # Leader-supporting finding: anti-forensic, NO techniques
    anti = _finding(
        "01A", supports=["H_ANTI_FORENSICS"],
        claim="VSS diff: Security.evtx scrubbed in live FS",
        evidence_facts={})
    # Off-leader finding: credential dumping WITH techniques. Does
    # NOT support H_ANTI_FORENSICS.
    cred = _finding(
        "02B", supports=["H_CREDENTIAL_ACCESS", "H_APT_ESPIONAGE"],
        claim="LSASS credential dump signature",
        evidence_facts={"attack_techniques": ["T1003.001"]})
    # Off-leader finding: lateral movement WITH techniques.
    lat = _finding(
        "03C", supports=["H_LATERAL_MOVEMENT"],
        claim="PsExec service install on remote host",
        evidence_facts={"attack_techniques": ["T1021.002",
                                                "T1569.002"]})

    lines = build_diamond_markdown(
        [anti, cred, lat], ranking, {}, manifest={})
    text = "\n".join(lines)
    cap_idx = text.find("**Capability**")
    cap_cell = text[cap_idx:text.find("**Infrastructure**")]
    # All three off-leader techniques MUST appear despite the leader
    # being H_ANTI_FORENSICS with no techniques of its own.
    assert "T1003.001" in cap_cell, \
        "case-wide capability must surface off-leader techniques"
    assert "T1021.002" in cap_cell
    assert "T1569.002" in cap_cell
    # And their capacities resolve in the Capacity sub-row
    assert "LSASS" in cap_cell or "credential" in cap_cell.lower()


def test_diamond_capacity_empty_when_no_techniques_tagged():
    """When supporting findings carry no attack_techniques the
    Capacity row says so honestly — doesn't fabricate."""
    ranking = [_rank("H_ANTI_FORENSICS", "Anti-forensics", 12)]
    f = _finding("01X", supports=["H_ANTI_FORENSICS"],
                  evidence_facts={})
    lines = build_diamond_markdown([f], ranking, {}, manifest={})
    text = "\n".join(lines)
    cap_idx = text.find("Capacity")
    cap_cell = text[cap_idx:text.find("**Infrastructure**")]
    assert "cannot be derived" in cap_cell


def test_diamond_capacity_deduplicated():
    """Two findings tagged with the same technique should produce
    one capacity line, not duplicates."""
    ranking = [_rank("H_C2_BEACONING", "C2", 9)]
    f1 = _finding(
        "01A", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001"]})
    f2 = _finding(
        "01B", supports=["H_C2_BEACONING"],
        evidence_facts={"attack_techniques": ["T1071.001"]})
    lines = build_diamond_markdown(
        [f1, f2], ranking, {}, manifest={})
    text = "\n".join(lines)
    cap_idx = text.find("Capacity")
    cap_cell = text[cap_idx:text.find("**Infrastructure**")]
    # Count "HTTP/HTTPS" — should appear at most once
    assert cap_cell.lower().count("http/https") <= 1


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


def test_diamond_external_email_lands_in_infrastructure_type2_not_adversary():
    """Paper §4.3: emails are Infrastructure. Specifically, BEC
    sender addresses are Type 2 (compromised accounts — what the
    victim SEES as the adversary). They do NOT belong in Adversary;
    that vertex is the actor identity, which we usually can't name
    from host evidence alone. Local-domain addresses still go to
    Victim Persona."""
    ranking = [_rank("H_BEC_ACCOUNT_TAKEOVER", "BEC", 51)]
    pst = _finding(
        "00P", claim="PST parsed: Inferred local domain(s): m57.biz",
    )
    f = _finding(
        "00E", supports=["H_BEC_ACCOUNT_TAKEOVER"],
        claim="BEC outbound — actual_recipient is external; "
              "compromised account suspected",
        evidence_facts={
            "sender": "jean@m57.biz",
            "actual_recipient": "tuckgorge@gmail.com",
        },
    )
    lines = build_diamond_markdown([pst, f], ranking,
                                    {"ipv4": []}, manifest={})
    text = "\n".join(lines)
    adv_idx = text.find("**Adversary**")
    cap_idx = text.find("**Capability**")
    inf_idx = text.find("**Infrastructure**")
    vic_idx = text.find("**Victim**")
    adv_cell = text[adv_idx:cap_idx]
    inf_block = text[inf_idx:vic_idx]
    vic_cell = text[vic_idx:text.find("**Social-Political**")]
    # External email NOT in Adversary anymore (paper §4.3 alignment)
    assert "tuckgorge@gmail.com" not in adv_cell
    # External email IS in Infrastructure Type 2 (compromised account)
    type2_idx = inf_block.find("Type 2")
    assert type2_idx > 0
    type2_cell = inf_block[type2_idx:inf_block.find("Service Providers")]
    assert "tuckgorge@gmail.com" in type2_cell
    # Local-domain email IS still in Victim Persona
    assert "jean@m57.biz" in vic_cell


def test_diamond_carved_domains_stay_in_infrastructure():
    """Carved-domain noise from the IOC catalog goes to Infrastructure
    (where domains belong per paper §4.3), never to Adversary."""
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
    adv_cell = text[adv_idx:cap_idx]
    inf_block = text[inf_idx:text.find("**Victim**")]
    # No domains in Adversary
    assert "carved0.noise" not in adv_cell
    assert "carved29.noise" not in adv_cell
    # …they live in Infrastructure (Type 1 by default)
    assert "carved0.noise" in inf_block


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

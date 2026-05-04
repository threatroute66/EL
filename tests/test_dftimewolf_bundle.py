"""dfTimewolf bundle ingestion — unit tests.

Synthetic recipe + log + artifact directories verify the shape detector,
recipe parser, and routing-hint dispatch.
"""
import json
from pathlib import Path

import pytest

from el.skills import dftimewolf_bundle as dftw


# --- _is_recipe_filename / _is_log_filename --------------------------

def test_is_recipe_filename_matches():
    assert dftw._is_recipe_filename("recipe.json")
    assert dftw._is_recipe_filename("recipe_aws.yaml")
    assert dftw._is_recipe_filename("dftimewolf-aws.json")


def test_is_recipe_filename_rejects_non_matches():
    assert not dftw._is_recipe_filename("findings.json")
    assert not dftw._is_recipe_filename("config.txt")


def test_is_log_filename_matches():
    assert dftw._is_log_filename("dftimewolf.log")
    assert dftw._is_log_filename("dftimewolf-2026.log")


def test_is_log_filename_rejects_non_matches():
    assert not dftw._is_log_filename("system.log")
    assert not dftw._is_log_filename("dftimewolf.txt")


# --- _looks_like_dftimewolf_recipe ----------------------------------

def test_looks_like_recipe_real_json():
    text = json.dumps({
        "name": "aws_forensics",
        "modules": [
            {"name": "AWSCollector", "args": {"region": "us-east-1"},
             "wants": []},
            {"name": "TurbiniaProcessor", "args": {}, "wants": ["AWSCollector"]},
        ],
    })
    assert dftw._looks_like_dftimewolf_recipe(text)


def test_looks_like_recipe_rejects_arbitrary_json():
    assert not dftw._looks_like_dftimewolf_recipe(json.dumps({"hello": "world"}))


def test_looks_like_recipe_rejects_modules_without_dftw_keys():
    """A 'modules' array of pure strings (e.g. python imports list) shouldn't
    pass the heuristic."""
    assert not dftw._looks_like_dftimewolf_recipe(json.dumps({
        "modules": ["os", "sys"],
    }))


def test_looks_like_recipe_rejects_invalid_json():
    assert not dftw._looks_like_dftimewolf_recipe("not-json")


# --- _parse_recipe ----------------------------------------------------

def test_parse_recipe_extracts_modules(tmp_path):
    p = tmp_path / "recipe.json"
    p.write_text(json.dumps({
        "name": "gce_forensics",
        "description": "Forensics on a GCE instance",
        "args": {"project": "my-proj", "zone": "us-central1-a"},
        "modules": [
            {"name": "GoogleCloudCollector", "args": {}, "wants": []},
            {"name": "TurbiniaProcessor", "args": {}, "wants": ["GoogleCloudCollector"]},
            {"name": "TimesketchExporter", "args": {}, "wants": ["TurbiniaProcessor"]},
        ],
    }))
    recipe = dftw._parse_recipe(p)
    assert recipe.name == "gce_forensics"
    assert "GCE" in recipe.description or "Forensics" in recipe.description
    assert recipe.module_names == [
        "GoogleCloudCollector", "TurbiniaProcessor", "TimesketchExporter"
    ]
    assert recipe.args["project"] == "my-proj"


def test_parse_recipe_returns_none_on_garbage(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not json")
    assert dftw._parse_recipe(p) is None


# --- _artifact_kind --------------------------------------------------

def test_artifact_kind_known_extensions():
    assert dftw._artifact_kind(Path("evidence.plaso")) == "plaso"
    assert dftw._artifact_kind(Path("capture.pcap")) == "pcap"
    assert dftw._artifact_kind(Path("event_log.evtx")) == "evtx"
    assert dftw._artifact_kind(Path("disk.E01")) == "ewf"


def test_artifact_kind_cloudtrail_sniff(tmp_path):
    p = tmp_path / "logs.json"
    p.write_text(json.dumps([{
        "eventName": "GetCallerIdentity",
        "eventSource": "sts.amazonaws.com",
    }]))
    assert dftw._artifact_kind(p) == "cloudtrail"


def test_artifact_kind_k8s_audit_sniff(tmp_path):
    p = tmp_path / "k8s.json"
    p.write_text(
        '{"kind":"Event","apiVersion":"audit.k8s.io/v1",'
        '"auditID":"abc"}'
    )
    assert dftw._artifact_kind(p) == "k8s_audit"


def test_artifact_kind_falls_back_to_json(tmp_path):
    p = tmp_path / "random.json"
    p.write_text(json.dumps({"hello": "world"}))
    assert dftw._artifact_kind(p) == "json"


def test_artifact_kind_unknown_returns_empty():
    assert dftw._artifact_kind(Path("readme.md")) == ""


# --- looks_like_dftimewolf_bundle -----------------------------------

def test_looks_like_bundle_with_recipe(tmp_path):
    (tmp_path / "recipe.json").write_text(json.dumps({
        "name": "aws_forensics",
        "modules": [{"name": "AWSCollector", "args": {}, "wants": []}],
    }))
    (tmp_path / "evidence.plaso").write_bytes(b"\x00")
    assert dftw.looks_like_dftimewolf_bundle(tmp_path)


def test_looks_like_bundle_with_log_alone(tmp_path):
    (tmp_path / "dftimewolf.log").write_text("INFO Started recipe")
    assert dftw.looks_like_dftimewolf_bundle(tmp_path)


def test_looks_like_bundle_false_for_arbitrary_dir(tmp_path):
    (tmp_path / "evidence.plaso").write_bytes(b"\x00")
    (tmp_path / "notes.txt").write_text("just some files")
    assert not dftw.looks_like_dftimewolf_bundle(tmp_path)


def test_looks_like_bundle_false_for_file(tmp_path):
    f = tmp_path / "alone.json"
    f.write_text("{}")
    assert not dftw.looks_like_dftimewolf_bundle(f)


# --- parse_bundle full-flow -----------------------------------------

def test_parse_bundle_complete(tmp_path):
    (tmp_path / "recipe.json").write_text(json.dumps({
        "name": "aws_forensics",
        "modules": [
            {"name": "AWSCollector", "args": {}, "wants": []},
            {"name": "PlasoProcessor", "args": {}, "wants": ["AWSCollector"]},
        ],
    }))
    (tmp_path / "dftimewolf.log").write_text("INFO recipe started\n")
    (tmp_path / "supertimeline.plaso").write_bytes(b"\x00" * 100)
    (tmp_path / "cloudtrail.json").write_text(json.dumps([{
        "eventName": "GetObject", "eventSource": "s3.amazonaws.com"}]))
    (tmp_path / "extra_text.csv").write_text("col1,col2\nfoo,bar\n")

    bundle = dftw.parse_bundle(tmp_path)
    assert bundle.recipe is not None
    assert bundle.recipe.name == "aws_forensics"
    assert "AWSCollector" in bundle.recipe.module_names
    assert bundle.log_path.name == "dftimewolf.log"
    assert len(bundle.artifact_files) == 3
    assert bundle.artifact_kinds["plaso"] == 1
    assert bundle.artifact_kinds["cloudtrail"] == 1
    assert bundle.artifact_kinds["csv"] == 1


def test_parse_bundle_no_recipe(tmp_path):
    (tmp_path / "dftimewolf.log").write_text("...")
    (tmp_path / "evidence.plaso").write_bytes(b"\x00")
    bundle = dftw.parse_bundle(tmp_path)
    assert bundle.recipe is None
    assert bundle.log_path is not None
    assert len(bundle.artifact_files) == 1


def test_parse_bundle_raises_for_missing_dir(tmp_path):
    with pytest.raises(dftw.DFTimewolfError):
        dftw.parse_bundle(tmp_path / "nope")


# --- routing_hints ---------------------------------------------------

def test_routing_hints_groups_by_kind(tmp_path):
    plaso = tmp_path / "a.plaso"; plaso.write_bytes(b"\x00")
    pcap = tmp_path / "b.pcap"; pcap.write_bytes(b"\x00")
    other = tmp_path / "c.txt"; other.write_text("ignored")
    bundle = dftw.DFTimewolfBundle(
        bundle_root=tmp_path,
        artifact_files=[plaso, pcap, other],
        artifact_kinds={"plaso": 1, "pcap": 1},
    )
    hints = bundle.routing_hints()
    assert hints["plaso"] == [plaso]
    assert hints["pcap"] == [pcap]
    assert "txt" not in hints


# --- as_evidence -----------------------------------------------------

def test_as_evidence_shape(tmp_path):
    bundle = dftw.DFTimewolfBundle(
        bundle_root=tmp_path,
        recipe=dftw.DFTimewolfRecipe(
            name="aws_forensics",
            module_names=["AWSCollector", "PlasoProcessor"],
        ),
        recipe_path=tmp_path / "recipe.json",
        artifact_files=[tmp_path / "x.plaso"],
        artifact_kinds={"plaso": 1},
        output_sha256="b" * 64,
    )
    ev = bundle.as_evidence()
    assert ev.tool == "dftimewolf_bundle"
    assert ev.output_sha256 == "b" * 64
    assert ev.extracted_facts["recipe_name"] == "aws_forensics"
    assert "AWSCollector" in ev.extracted_facts["recipe_modules"]
    assert ev.extracted_facts["artifact_count"] == 1
    assert ev.extracted_facts["artifact_kinds"] == {"plaso": 1}

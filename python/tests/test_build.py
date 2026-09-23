"""Checks on the census build, scripts/build.py, run over small censuses of
their own.

They sit beside the package's tests because ``make test`` runs this directory.
The source distribution leaves this file out (pyproject.toml): it needs
scripts/build.py, which the distribution does not carry.
"""

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]

FACT = {"source": "https://example.com/doc", "quote": "A sentence the vendor wrote.", "verified_at": "2026-09-23"}
TENANCY_FIELDS = ("anonymous_tokens", "tenancy_claims", "not_tenancy", "subject_forms", "owner_charset",
                  "names_unique_regardless_of_case", "match", "tenant_membership", "built_in")


def fact():
    return dict(FACT)


def valid_census():
    """A small census the build accepts: a researched shared issuer, a
    researched per-tenant pattern and an entry this release did not research."""
    return {
        "schema_version": 3,
        "census_date": "2026-09-13",
        "issuers": [
            {"name": "Shared", "issuer": "https://token.example.com", "tenancy_model": "shared",
             "aud_controlled_by": "workload", "vendor_example_verdict": "unverified",
             "researched": "in_release",
             "anonymous_tokens": {"value": "no", "evidence": [fact()]},
             "tenancy_claims": {"value": "verified", "claims": [
                 {"claim": "owner_id", "kind": "id", "scope": "owner", "multi_valued": "no",
                  "immutable": "unverified", "evidence": fact()},
                 {"claim": "owners", "kind": "name", "scope": "owner", "multi_valued": "yes",
                  "immutable": "unverified", "evidence": fact()}]},
             "not_tenancy": {"value": "verified", "claims": [
                 {"claim": "actor", "why": "the person who started the run", "evidence": fact()}]},
             "subject_forms": {"value": "verified", "forms": [
                 {"form": "default", "leading_literal": "org:",
                  "owner_parts": [{"kind": "name", "delimiter_after": ":"}], "evidence": fact()}]},
             "owner_charset": {"value": "verified", "characters": ["a-z", "-"],
                               "description": "lower-case letters and dashes", "evidence": [fact()]},
             "research": {"population": "anyone with an account", "nested": {"read": fact()}}},
            {"name": "Per tenant", "issuer": "https://<tenant>.example.org", "tenancy_model": "per_tenant_host",
             "aud_controlled_by": "unverified", "vendor_example_verdict": "unverified",
             "researched": "in_release",
             "match": {"value": "verified", "issuer_pattern": "https://<tenant>.example.org",
                       "tenant_placeholder": "<tenant>", "tenant_kind": "name", "tenant_recyclable": "unverified",
                       "evidence": [fact()]},
             "tenant_membership": {"value": "controlled", "evidence": [fact()]}},
            {"name": "Unresearched", "issuer": "https://other.example.net", "tenancy_model": "unverified",
             "aud_controlled_by": "unverified", "vendor_example_verdict": "unverified"},
        ],
    }


def build(tmp_path, doc):
    """Run the repository's build script over ``doc`` in a tree of its own, and
    return its exit status, its error output and the tree."""
    (tmp_path / "scripts").mkdir()
    shutil.copy(REPO / "scripts" / "build.py", tmp_path / "scripts" / "build.py")
    package = tmp_path / "python" / "src" / "cloudarq_issuers"
    package.mkdir(parents=True)
    shutil.copy(REPO / "python" / "src" / "cloudarq_issuers" / "_tenancy.py", package / "_tenancy.py")
    (tmp_path / "python" / "tests").mkdir()
    shared = tmp_path / "tenancy" / "testdata"
    shared.mkdir(parents=True)
    for name in ("match_cases.json", "answers.json"):
        (shared / name).write_text("{}", encoding="utf-8")
    (tmp_path / "issuers.yaml").write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    run = subprocess.run([sys.executable, str(tmp_path / "scripts" / "build.py")], capture_output=True, text=True,
                         timeout=60)
    return run.returncode, run.stderr, tmp_path


def test_a_valid_census_builds_and_writes_every_field(tmp_path):
    status, err, tree = build(tmp_path, valid_census())
    assert status == 0, err
    census = json.loads((tree / "issuers.json").read_text(encoding="utf-8"))["issuers"]
    assert [e["name"] for e in census] == ["Shared", "Per tenant", "Unresearched"]
    for e in census:
        assert all(k in e for k in TENANCY_FIELDS), e["name"]
    assert census[2]["researched"] == "not_in_this_release"
    assert all(census[2][k] == {"value": "unverified"} for k in TENANCY_FIELDS)
    assert census[0]["research"]["nested"]["read"] == FACT
    assert (tree / "python" / "src" / "cloudarq_issuers" / "issuers.json").read_text() == (tree / "issuers.json").read_text()
    for name in ("match_cases.json", "answers.json"):
        assert (tree / "python" / "tests" / name).exists(), name


def test_the_sub_package_carries_only_what_is_settled(tmp_path):
    status, err, tree = build(tmp_path, valid_census())
    assert status == 0, err
    sub = json.loads((tree / "tenancy" / "tenancy.json").read_text(encoding="utf-8"))
    assert sub["census_date"] == "2026-09-13"
    assert sub["issuers"] == [
        {"name": "Shared", "issuer": "https://token.example.com", "anonymous_tokens": "no",
         "tenancy_claims": [{"claim": "owner_id", "kind": "id", "scope": "owner"}],
         "subject_forms": [{"leading_literal": "org:", "owner_parts": [{"kind": "name", "delimiter_after": ":"}]}],
         "owner_name_characters": ["a-z", "-"]},
        {"name": "Per tenant", "issuer": "https://<tenant>.example.org", "tenant_placeholder": "<tenant>",
         "tenant_kind": "name", "tenant_membership": "controlled"},
        {"name": "Unresearched", "issuer": "https://other.example.net"},
    ]


def at(doc, path):
    """The mapping or list at a dotted path of names and indices."""
    node = doc
    for part in path.split("."):
        node = node[int(part)] if part.isdigit() else node[part]
    return node


def drop(path, key):
    return lambda doc: at(doc, path).pop(key)


def put(path, key, value):
    def change(doc):
        at(doc, path)[key] = value
    return change


def append_entry(entry):
    return lambda doc: doc["issuers"].append(entry)


SHARED = "issuers.0"
PER_TENANT = "issuers.1"


def overlapping(doc):
    doc["issuers"][1]["issuer"] = doc["issuers"][1]["match"]["issuer_pattern"] = "https://<tenant>.example.org/x"
    doc["issuers"].append({
        "name": "Other pattern", "issuer": "https://h.example.org/<y>", "tenancy_model": "per_tenant_path",
        "aud_controlled_by": "unverified", "vendor_example_verdict": "unverified", "researched": "in_release",
        "match": {"value": "verified", "issuer_pattern": "https://h.example.org/<y>", "tenant_placeholder": "<y>",
                  "tenant_kind": "name", "tenant_recyclable": "unverified", "evidence": [fact()]}})


REFUSALS = {
    "a fact with no quote": (drop(f"{SHARED}.anonymous_tokens.evidence.0", "quote"), "a fact needs its quote"),
    "a fact with no source": (drop(f"{SHARED}.anonymous_tokens.evidence.0", "source"), "a fact needs its source"),
    "a fact whose source is not https": (put(f"{SHARED}.anonymous_tokens.evidence.0", "source", "http://example.com"),
                                         "a fact needs its source"),
    "a fact with no date": (drop(f"{SHARED}.anonymous_tokens.evidence.0", "verified_at"), "verified_at"),
    "a fact with a key a fact does not have": (put(f"{SHARED}.anonymous_tokens.evidence.0", "page", "x"), "unknown key"),
    "a fact deep in research with no quote": (drop(f"{SHARED}.research.nested.read", "quote"), "a fact needs its quote"),
    "YAML's unquoted no": (put(f"{SHARED}.anonymous_tokens", "value", False), "is not one of"),
    "a settled value with nothing behind it": (drop(f"{SHARED}.anonymous_tokens", "evidence"),
                                               "with no evidence and no chain"),
    "a chain with no links": (put(f"{SHARED}.anonymous_tokens", "basis", "chain"), "basis: chain with no chain"),
    "an unverified value that does not say why": (put(f"{SHARED}", "anonymous_tokens", {"value": "unverified"}),
                                                  "why_unverified"),
    "a person as a tenant": (put(f"{SHARED}.tenancy_claims.claims.0", "scope", "actor"), "is not one of"),
    "a claim of no known cardinality word": (put(f"{SHARED}.tenancy_claims.claims.0", "multi_valued", "maybe"),
                                             "is not one of"),
    "an immutable value with nothing behind it": (put(f"{SHARED}.tenancy_claims.claims.0", "immutable", "yes"),
                                                  "no immutable_evidence"),
    "a claim that is tenancy and not": (put(f"{SHARED}.not_tenancy.claims.0", "claim", "owner_id"),
                                        "also a tenancy claim"),
    "a delimiter of two characters": (put(f"{SHARED}.subject_forms.forms.0.owner_parts.0", "delimiter_after", "::"),
                                      "must be one character"),
    "a literal that leads a form and never pins": (put(f"{SHARED}.subject_forms", "never_pin", [
        {"leading_literal": "org:", "why": "names something else", "evidence": fact()}]), "never pins"),
    "a backwards range": (put(f"{SHARED}.owner_charset", "characters", ["z-a"]), "neither one character nor a range"),
    "a character set with nothing behind it": (drop(f"{SHARED}.owner_charset", "evidence"), "non-empty list of facts"),
    "a misspelt key": (put(f"{SHARED}.anonymous_tokens", "evidnce", [fact()]), "unknown key 'evidnce'"),
    "a tenant spelled from no placeholder of the pattern": (put(f"{PER_TENANT}.match", "tenant_placeholder", "<t>"),
                                                            "does not compile"),
    "a pattern that is not the entry's issuer": (put(f"{PER_TENANT}.match", "issuer_pattern", "https://<t>.example.com"),
                                                 "is not the entry's issuer"),
    "a recyclable tenant with nothing behind it": (put(f"{PER_TENANT}.match", "tenant_recyclable", "yes"),
                                                   "tenant_recyclable_evidence"),
    "a controlled membership on no pattern": (put(f"{SHARED}", "tenant_membership", {"value": "controlled",
                                                                                     "evidence": [fact()]}),
                                              "belongs to a verified pattern"),
    "an entry not researched carrying a fact": (put("issuers.2", "anonymous_tokens", {"value": "no",
                                                                                      "evidence": [fact()]}),
                                                "carries no tenancy field"),
    "v0.1.0's spelling of unverified": (put(SHARED, "tenancy_claim", "UNVERIFIED"), "is spelled unverified"),
    "one issuer in two entries": (append_entry({
        "name": "Shared again", "issuer": "https://TOKEN.example.com/", "tenancy_model": "shared",
        "aud_controlled_by": "workload", "vendor_example_verdict": "unverified"}), "the same issuer as"),
    "one pattern in two entries under other placeholder names": (append_entry({
        "name": "Per tenant again", "issuer": "https://<account>.example.org", "tenancy_model": "per_tenant_host",
        "aud_controlled_by": "unverified", "vendor_example_verdict": "unverified"}), "the same issuer as"),
    "two patterns one issuer matches with neither more specific": (overlapping, "neither is more specific"),
}


@pytest.mark.parametrize("name", REFUSALS)
def test_the_build_refuses(tmp_path, name):
    change, message = REFUSALS[name]
    doc = copy.deepcopy(valid_census())
    change(doc)
    status, err, tree = build(tmp_path, doc)
    assert status == 1 and message in err, f"{name}: exit {status}\n{err}"
    assert not (tree / "issuers.json").exists(), f"{name}: the build wrote a census it refused"


def test_several_entries_may_share_a_host(tmp_path):
    """One pattern, one entry: GitHub's enterprise path shares GitHub's host and
    is told apart by its path."""
    doc = valid_census()
    doc["issuers"].append({
        "name": "Shared, by path", "issuer": "https://token.example.com/<org>", "tenancy_model": "per_tenant_path",
        "aud_controlled_by": "unverified", "vendor_example_verdict": "unverified", "researched": "in_release",
        "match": {"value": "verified", "issuer_pattern": "https://token.example.com/<org>", "tenant_placeholder": "<org>",
                  "tenant_kind": "name", "tenant_recyclable": "unverified", "evidence": [fact()]}})
    status, err, tree = build(tmp_path, doc)
    assert status == 0, err
    sub = json.loads((tree / "tenancy" / "tenancy.json").read_text(encoding="utf-8"))
    assert [e["issuer"] for e in sub["issuers"]][-1] == "https://token.example.com/<org>"

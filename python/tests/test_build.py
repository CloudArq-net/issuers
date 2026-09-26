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

FACT = {"source": "https://example.com/doc", "quote": "A sentence the vendor wrote → with an arrow in it.",
        "verified_at": "2026-09-23"}
OBSERVATION = {"observed": "https://example.com/.well-known/openid-configuration", "method": "curl",
               "at": "2026-09-23T00:12Z", "result": "claims_supported includes x"}
# AWS's condition-key table as its page renders it, which ties each recorded
# key to the claim AWS reads it from, and a key written out in an example
# policy, which names the key and no claim.
KEYS_TABLE = {"source": "https://example.com/keys",
              "quote": "Condition key Claim sub sub Yes owner_id owner_id No renamed other No aud azp If no value is "
                       "set for azp, the aud condition key maps to the aud claim. Yes",
              "verified_at": "2026-09-23"}
KEYS_EXAMPLE = {"source": "https://example.com/keys", "quote": '"token.example.com:email": "a@example.com",',
                "verified_at": "2026-09-23"}
TENANCY_FIELDS = ("anonymous_tokens", "tenancy_claims", "not_tenancy", "subject_forms", "owner_charset",
                  "names_unique_regardless_of_case", "match", "tenant_membership", "built_in", "accounts",
                  "aws_condition_keys")

# Python raises on any file it reads or writes in the locale's encoding when
# run this way, so a build that forgot to say UTF-8 fails here, whatever the
# machine's locale happens to be.
UTF8_ONLY = ("-X", "warn_default_encoding", "-W", "error::EncodingWarning")


def fact():
    return dict(FACT)


def observation():
    return dict(OBSERVATION)


def valid_census():
    """A small census the build accepts: a researched shared issuer, a
    researched per-tenant pattern and an entry this release did not research.
    The shared issuer carries an observation where one may stand, in context
    and behind a claim that never pins."""
    return {
        "schema_version": 3,
        "census_date": "2026-09-13",
        "issuers": [
            {"name": "Shared", "category": "ci", "issuer": "https://token.example.com", "tenancy_model": "shared",
             "discovery_status": "ok", "jwks_status": "ok", "control_test_result": "passed",
             "aud_controlled_by": "workload", "vendor_example_verdict": "unverified",
             "researched": "in_release",
             "anonymous_tokens": {"value": "no", "evidence": [fact()], "context": [observation()]},
             "tenancy_claims": {"value": "verified", "claims": [
                 {"claim": "owner_id", "kind": "id", "scope": "owner", "multi_valued": "no",
                  "immutable": "unverified", "evidence": fact()},
                 {"claim": "owners", "kind": "name", "scope": "owner", "multi_valued": "yes",
                  "immutable": "unverified", "evidence": fact()}]},
             "not_tenancy": {"value": "verified", "claims": [
                 {"claim": "actor", "why": "the person who started the run", "evidence": fact()},
                 {"claim": "scope", "why": "no page read says what it names", "evidence": observation()}]},
             "subject_forms": {"value": "verified", "forms": [
                 {"form": "default", "leading_literal": "org:",
                  "owner_parts": [{"kind": "name", "delimiter_after": ":"}], "evidence": fact()}],
                 "never_pin": [{"leading_literal": "job:", "why": "names the called job", "evidence": fact()}]},
             "owner_charset": {"value": "verified", "characters": ["a-z", "-"],
                               "description": "lower-case letters and dashes", "evidence": [fact()]},
             "accounts": {"value": "verified", "platform": "Example", "declaration_namespace": "example",
                          "evidence": [fact()]},
             "aws_condition_keys": {"value": "verified", "keys": [{"key": "sub", "claim": "sub"},
                                                                   {"key": "owner_id", "claim": "owner_id"},
                                                                   {"key": "aud", "claim": "azp",
                                                                    "fallback_claim": "aud"}],
                                    "evidence": [KEYS_TABLE]},
             "research": {"population": "anyone with an account", "nested": {"read": fact()},
                          "live": {"observed": observation()}}},
            {"name": "Per tenant", "issuer": "https://<tenant>.example.org", "tenancy_model": "per_tenant_host",
             "discovery_status": "unverified", "jwks_status": "unverified",
             "aud_controlled_by": "unverified", "vendor_example_verdict": "unverified",
             "researched": "in_release",
             "match": {"value": "verified", "issuer_pattern": "https://<tenant>.example.org",
                       "tenant_placeholder": "<tenant>", "tenant_kind": "name", "tenant_recyclable": "unverified",
                       "evidence": [fact()]},
             "tenant_membership": {"value": "controlled", "evidence": [fact()]}},
            {"name": "Unresearched", "issuer": "https://other.example.net", "tenancy_model": "unverified",
             "discovery_status": "unverified", "jwks_status": "unverified",
             "aud_controlled_by": "unverified", "vendor_example_verdict": "unverified"},
            {"name": "Not an issuer", "issuer": "not an OIDC issuer", "tenancy_model": "unverified",
             "discovery_status": "error", "jwks_uri": "n/a", "jwks_status": "n/a",
             "aud_controlled_by": "unverified", "vendor_example_verdict": "unverified"},
        ],
    }


def build(tmp_path, doc=None, text=None, flags=()):
    """Run the repository's build script over ``doc``, or over YAML ``text``
    as written, in a tree of its own, and return its exit status, its error
    output and the tree."""
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
    if text is None:
        text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    (tmp_path / "issuers.yaml").write_text(text, encoding="utf-8")
    run = subprocess.run([sys.executable, *flags, str(tmp_path / "scripts" / "build.py")], capture_output=True,
                         text=True, encoding="utf-8", timeout=60)
    return run.returncode, run.stderr, tmp_path


def test_a_valid_census_builds_and_writes_every_field(tmp_path):
    status, err, tree = build(tmp_path, valid_census())
    assert status == 0, err
    census = json.loads((tree / "issuers.json").read_text(encoding="utf-8"))["issuers"]
    assert [e["name"] for e in census] == ["Shared", "Per tenant", "Unresearched", "Not an issuer"]
    for e in census:
        assert all(k in e for k in TENANCY_FIELDS), e["name"]
    assert census[2]["researched"] == "not_in_this_release"
    assert all(census[2][k] == {"value": "unverified"} for k in TENANCY_FIELDS)
    assert census[0]["research"]["nested"]["read"] == FACT
    assert census[0]["not_tenancy"]["claims"][1]["evidence"] == OBSERVATION
    assert (tree / "python" / "src" / "cloudarq_issuers" / "issuers.json").read_text(encoding="utf-8") == \
        (tree / "issuers.json").read_text(encoding="utf-8")
    for name in ("match_cases.json", "answers.json"):
        assert (tree / "python" / "tests" / name).exists(), name


def test_the_build_reads_and_writes_utf8_whatever_the_locale(tmp_path):
    status, err, tree = build(tmp_path, valid_census(), flags=UTF8_ONLY)
    assert status == 0, err
    census = json.loads((tree / "issuers.json").read_bytes().decode("utf-8"))["issuers"]
    assert census[0]["anonymous_tokens"]["evidence"][0]["quote"] == FACT["quote"]


def test_the_sub_package_carries_only_what_is_settled(tmp_path):
    status, err, tree = build(tmp_path, valid_census())
    assert status == 0, err
    sub = json.loads((tree / "tenancy" / "tenancy.json").read_text(encoding="utf-8"))
    assert sub["census_date"] == "2026-09-13"
    assert sub["issuers"] == [
        {"name": "Shared", "issuer": "https://token.example.com", "anonymous_tokens": "no",
         "tenancy_claims": [{"claim": "owner_id", "kind": "id", "scope": "owner"}],
         "not_tenancy": ["actor", "scope"],
         "subject_forms": [{"leading_literal": "org:", "owner_parts": [{"kind": "name", "delimiter_after": ":"}]}],
         "never_pin": ["job:"],
         "owner_name_characters": ["a-z", "-"], "platform": "Example", "declaration_namespace": "example",
         "aws_condition_keys": [{"key": "sub", "claim": "sub"}, {"key": "owner_id", "claim": "owner_id"},
                                {"key": "aud", "claim": "azp", "fallback_claim": "aud"}]},
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
UNRESEARCHED = "issuers.2"


def overlapping(doc):
    doc["issuers"][1]["issuer"] = doc["issuers"][1]["match"]["issuer_pattern"] = "https://<tenant>.example.org/x"
    doc["issuers"].append({
        "name": "Other pattern", "issuer": "https://h.example.org/<y>", "tenancy_model": "per_tenant_path",
        "discovery_status": "unverified", "jwks_status": "unverified",
        "aud_controlled_by": "unverified", "vendor_example_verdict": "unverified", "researched": "in_release",
        "match": {"value": "verified", "issuer_pattern": "https://h.example.org/<y>", "tenant_placeholder": "<y>",
                  "tenant_kind": "name", "tenant_recyclable": "unverified", "evidence": [fact()]}})


def unresearched(name, issuer):
    return {"name": name, "issuer": issuer, "tenancy_model": "shared", "discovery_status": "unverified",
            "jwks_status": "unverified", "aud_controlled_by": "workload", "vendor_example_verdict": "unverified"}


SETTLES_NOTHING = "an observation settles no value"

REFUSALS = {
    "a fact with no quote": (drop(f"{SHARED}.anonymous_tokens.evidence.0", "quote"), "a fact needs its quote"),
    "a fact with no source": (drop(f"{SHARED}.anonymous_tokens.evidence.0", "source"), "a fact needs its source"),
    "a fact whose source is not https": (put(f"{SHARED}.anonymous_tokens.evidence.0", "source", "http://example.com"),
                                         "a fact needs its source"),
    "a fact whose source names no page": (put(f"{SHARED}.anonymous_tokens.evidence.0", "source", "https://"),
                                          "a fact needs its source"),
    "a fact whose source is not a URL": (put(f"{SHARED}.anonymous_tokens.evidence.0", "source",
                                             "https:// not a url"), "a fact needs its source"),
    "a fact with no date": (drop(f"{SHARED}.anonymous_tokens.evidence.0", "verified_at"), "verified_at"),
    "a fact read on a day no calendar has": (put(f"{SHARED}.anonymous_tokens.evidence.0", "verified_at",
                                                 "2026-13-45"), "verified_at"),
    "a fact with a key a fact does not have": (put(f"{SHARED}.anonymous_tokens.evidence.0", "page", "x"), "unknown key"),
    "a fact deep in research with no quote": (drop(f"{SHARED}.research.nested.read", "quote"), "a fact needs its quote"),
    "a fact in research under other names": (put(f"{SHARED}.research", "probe", {
        "url": "https://example.com/doc", "sentence": "A sentence.", "verified_at": "2026-09-23"}), "unknown key 'url'"),
    "an observation with no date": (put(f"{SHARED}.anonymous_tokens.context.0", "at", "yesterday"), "is not a date"),
    "an observation on a day no calendar has": (put(f"{SHARED}.anonymous_tokens.context.0", "at", "2026-02-30"),
                                                "is not a date"),
    "an observation behind a settled value": (put(f"{SHARED}.anonymous_tokens", "evidence", [OBSERVATION]),
                                              SETTLES_NOTHING),
    "an observation behind a tenancy claim": (put(f"{SHARED}.tenancy_claims.claims.0", "evidence", OBSERVATION),
                                              SETTLES_NOTHING),
    "an observation behind a subject form": (put(f"{SHARED}.subject_forms.forms.0", "evidence", OBSERVATION),
                                             SETTLES_NOTHING),
    "an observation behind a character set": (put(f"{SHARED}.owner_charset", "evidence", [OBSERVATION]),
                                              SETTLES_NOTHING),
    "an observation behind a pattern": (put(f"{PER_TENANT}.match", "evidence", [OBSERVATION]), SETTLES_NOTHING),
    "an observation behind a controlled membership": (put(f"{PER_TENANT}.tenant_membership", "evidence",
                                                          [OBSERVATION]), SETTLES_NOTHING),
    "an observation in a membership's chain": (put(f"{PER_TENANT}", "tenant_membership", {
        "value": "controlled", "basis": "chain", "chain": [fact(), OBSERVATION]}), SETTLES_NOTHING),
    "a controlled membership with nothing behind it": (drop(f"{PER_TENANT}.tenant_membership", "evidence"),
                                                       "with no evidence and no chain"),
    "a chained membership with no links": (put(f"{PER_TENANT}.tenant_membership", "basis", "chain"),
                                           "basis: chain with no chain"),
    "an unverified membership carrying evidence": (put(f"{PER_TENANT}", "tenant_membership", {
        "value": "unverified", "evidence": [fact()]}), "what was read goes in context"),
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
    "a literal that never pins, extending a lead": (put(f"{SHARED}.subject_forms", "never_pin", [
        {"leading_literal": "org:acme/", "why": "names something else", "evidence": fact()}]),
        "one begins the other"),
    "a lead extending a literal that never pins": (put(f"{SHARED}.subject_forms", "never_pin", [
        {"leading_literal": "or", "why": "names something else", "evidence": fact()}]), "one begins the other"),
    "a claim not tenancy by a trailing * that covers a tenancy claim": (
        put(f"{SHARED}.not_tenancy.claims.0", "claim", "owner_*"), "also a tenancy claim"),
    "a backwards range": (put(f"{SHARED}.owner_charset", "characters", ["z-a"]), "neither one character nor a range"),
    "an owner character outside ASCII": (put(f"{SHARED}.owner_charset", "characters", ["a-z", "é"]),
                                         "neither one character nor a range"),
    "a range that ends outside ASCII": (put(f"{SHARED}.owner_charset", "characters", ["a-é"]),
                                        "neither one character nor a range"),
    "a character set with nothing behind it": (drop(f"{SHARED}.owner_charset", "evidence"), "non-empty list of facts"),
    "a platform with nothing behind it": (drop(f"{SHARED}.accounts", "evidence"), "non-empty list of facts"),
    "a condition key no row shows": (lambda doc: at(doc, f"{SHARED}.aws_condition_keys.keys").append(
        {"key": "extra", "claim": "extra"}), "no quoted row shows 'extra' carrying 'extra'"),
    "a condition key with a claim no row gives it": (put(f"{SHARED}.aws_condition_keys.keys.0", "claim", "subject"),
                                                    "no quoted row shows 'sub' carrying 'subject'"),
    "a condition key recorded without its claim, although an example writes it out": (
        lambda doc: at(doc, f"{SHARED}.aws_condition_keys.keys").append({"key": "email"})
        or at(doc, f"{SHARED}.aws_condition_keys.evidence").append(KEYS_EXAMPLE), "missing 'claim'"),
    "a fallback claim no sentence gives": (put(f"{SHARED}.aws_condition_keys.keys.0", "fallback_claim", "owner_id"),
                                           "no quoted sentence says 'sub' reads 'owner_id'"),
    "a fallback claim no sentence gives this key": (put(f"{SHARED}.aws_condition_keys.keys.2", "fallback_claim",
                                                        "email"), "no quoted sentence says 'aud' reads 'email'"),
    "a condition key listed twice": (lambda doc: at(doc, f"{SHARED}.aws_condition_keys.keys").append(
        {"key": "sub", "claim": "sub"}), "listed twice"),
    "a tenancy claim AWS carries under another claim's name": (
        lambda doc: at(doc, f"{SHARED}.aws_condition_keys.keys").__setitem__(1, {"key": "renamed", "claim": "other"})
        or at(doc, f"{SHARED}.tenancy_claims.claims.0").__setitem__("claim", "renamed"), "under another claim's name"),
    "a condition key with no sentence behind it": (drop(f"{SHARED}.aws_condition_keys", "evidence"),
                                                   "with no evidence and no chain"),
    "an observation behind a condition key": (put(f"{SHARED}.aws_condition_keys", "evidence", [OBSERVATION]),
                                              SETTLES_NOTHING),
    "an unverified key list carrying keys": (put(f"{SHARED}.aws_condition_keys", "value", "unverified"),
                                             "an unverified list carries keys"),
    "a verified accounts block that names no platform": (drop(f"{SHARED}.accounts", "platform"),
                                                         "names no platform"),
    "an observation behind a platform": (put(f"{SHARED}.accounts", "evidence", [OBSERVATION]), SETTLES_NOTHING),
    "an unverified accounts block naming a platform": (put(f"{SHARED}.accounts", "value", "unverified"),
                                                       "carries nothing else"),
    "a declaration namespace in capitals": (put(f"{SHARED}.accounts", "declaration_namespace", "Example"),
                                            "lower-case ASCII letters"),
    "a declaration namespace on an issuer whose claims name no owner": (put(f"{PER_TENANT}", "accounts", {
        "value": "verified", "platform": "Example", "declaration_namespace": "other", "evidence": [fact()]}),
        "names no owner"),
    "one declaration namespace on two entries": (append_entry({
        **unresearched("Shared twin", "https://twin.example.com"), "researched": "in_release",
        "tenancy_claims": {"value": "verified", "claims": [{"claim": "owner_id", "kind": "id", "scope": "owner",
                                                             "multi_valued": "no", "immutable": "unverified",
                                                             "evidence": fact()}]},
        "accounts": {"value": "verified", "platform": "Example", "declaration_namespace": "example",
                     "evidence": [fact()]}}), "declare owners under 'example'"),
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
    "an entry not researched carrying a fact": (put(UNRESEARCHED, "anonymous_tokens", {"value": "no",
                                                                                       "evidence": [fact()]}),
                                                "carries no tenancy field"),
    "v0.1.0's spelling of unverified": (put(SHARED, "tenancy_claim", "UNVERIFIED"), "is spelled unverified"),
    "unverified in capitals in free text": (put(UNRESEARCHED, "jwks_uri", "UNVERIFIED"), "is spelled unverified"),
    "unverified in capitals deep in an entry": (put(UNRESEARCHED, "sub_grammar", {"default": "Unverified"}),
                                                "is spelled unverified"),
    "a discovery status outside its vocabulary": (put(UNRESEARCHED, "discovery_status", "UNVERIFIED"),
                                                  "is not one of"),
    "a JWKS status outside its vocabulary": (put(UNRESEARCHED, "jwks_status", "UNVERIFIED"), "is not one of"),
    "a JWKS that does not apply, on an issuer": (put(UNRESEARCHED, "jwks_status", "n/a"), "is not one of"),
    "a category outside its vocabulary": (put(SHARED, "category", "UNVERIFIED"), "is not one of"),
    "a control test result outside its vocabulary": (put(SHARED, "control_test_result", "UNVERIFIED"),
                                                     "is not one of"),
    "an issuer with its scheme in capitals": (put(SHARED, "issuer", "HTTPS://token.example.com"), "in lower case"),
    "an issuer over http": (put(UNRESEARCHED, "issuer", "http://other.example.net"), "in lower case"),
    "an issuer that is neither a URL nor a note": (put(UNRESEARCHED, "issuer", "other example net"),
                                                   "neither an issuer"),
    "an issuer with space around it": (put(UNRESEARCHED, "issuer", " https://other.example.net"), "neither an issuer"),
    "an issuer with an empty label": (put(UNRESEARCHED, "issuer", "https://other..example.net"), "neither an issuer"),
    "a v0.1.0 pattern that is not an https URL": (put(PER_TENANT, "issuer_pattern", "<tenant>.example.org"),
                                                  "a pattern is written as an https:// URL"),
    "a note where a pattern belongs": (put(PER_TENANT, "issuer_pattern", "unverified"), "neither an issuer"),
    "a tenancy claim with no kind": (drop(f"{SHARED}.tenancy_claims.claims.0", "kind"), "missing 'kind'"),
    "a tenancy claim with no cardinality": (drop(f"{SHARED}.tenancy_claims.claims.0", "multi_valued"),
                                            "missing 'multi_valued'"),
    "a tenancy claim with no evidence": (drop(f"{SHARED}.tenancy_claims.claims.0", "evidence"), "missing 'evidence'"),
    "a subject form with no leading literal": (drop(f"{SHARED}.subject_forms.forms.0", "leading_literal"),
                                               "missing 'leading_literal'"),
    "a subject form with nothing behind it": (drop(f"{SHARED}.subject_forms.forms.0", "evidence"),
                                              "with no evidence and no chain"),
    "a chained subject form with no links": (put(f"{SHARED}.subject_forms.forms.0", "basis", "chain"),
                                             "basis: chain with no chain"),
    "an observation in a subject form's chain": (put(f"{SHARED}.subject_forms.forms.0", "chain", [OBSERVATION]),
                                                 SETTLES_NOTHING),
    "a subject form's chain with no basis": (put(f"{SHARED}.subject_forms.forms.0", "chain", [fact()]),
                                             "a chain with no basis"),
    "a literal that never pins, with no why": (drop(f"{SHARED}.subject_forms.never_pin.0", "why"), "missing 'why'"),
    "a claim that is not tenancy, with no why": (drop(f"{SHARED}.not_tenancy.claims.0", "why"), "missing 'why'"),
    "anonymous_tokens with no value": (drop(f"{SHARED}.anonymous_tokens", "value"), "missing 'value'"),
    "a pattern with no value": (drop(f"{PER_TENANT}.match", "value"), "missing 'value'"),
    "an entry with no name": (drop(SHARED, "name"), "name: must be non-empty text"),
    "a census with no date": (lambda doc: doc.pop("census_date"), "census_date"),
    "a census with no entries": (lambda doc: doc.pop("issuers"), "issuers"),
    "one issuer in two entries": (append_entry({
        **unresearched("Shared again", "https://TOKEN.example.com/")}), "the same issuer as"),
    "one issuer in two entries, the second with its scheme in capitals": (append_entry({
        **unresearched("Shared again", "HTTPS://token.example.com")}), "in lower case"),
    "one pattern in two entries under other placeholder names": (append_entry({
        **unresearched("Per tenant again", "https://<account>.example.org"), "tenancy_model": "per_tenant_host"}),
        "the same issuer as"),
    "two patterns one issuer matches with neither more specific": (overlapping, "neither is more specific"),
}


@pytest.mark.parametrize("name", REFUSALS)
def test_the_build_refuses(tmp_path, name):
    change, message = REFUSALS[name]
    doc = copy.deepcopy(valid_census())
    change(doc)
    status, err, tree = build(tmp_path, doc)
    assert status == 1 and message in err, f"{name}: exit {status}\n{err}"
    assert "Traceback" not in err, f"{name}: the build crashed rather than refusing\n{err}"
    assert not (tree / "issuers.json").exists(), f"{name}: the build wrote a census it refused"


# A key given twice in one mapping, written as YAML text: a mapping built in
# Python cannot hold one. Each edit names the first line it follows, and the
# key is repeated right after it, in the other order as well.
TWICE = {
    "a field given twice in one entry": ("  tenancy_model: shared\n", "  tenancy_model: per_tenant_host\n"),
    "a field given twice, the settled value second": ("  tenancy_model: per_tenant_host\n",
                                                      "  tenancy_model: shared\n"),
    "a tenancy block given twice": ("  researched: in_release\n",
                                    "  anonymous_tokens:\n    value: unverified\n    why_unverified: a second block\n"),
    "the census date given twice": ("census_date: '2026-09-13'\n", "census_date: '2026-09-14'\n"),
}


@pytest.mark.parametrize("name", TWICE)
def test_the_build_refuses_a_key_given_twice(tmp_path, name):
    after, repeat = TWICE[name]
    text = yaml.safe_dump(valid_census(), sort_keys=False, allow_unicode=True)
    assert after in text, f"{name}: the census text has no line {after!r} to follow"
    status, err, tree = build(tmp_path, text=text.replace(after, after + repeat, 1))
    assert status == 1 and "given twice" in err, f"{name}: exit {status}\n{err}"
    assert "Traceback" not in err, err
    assert not (tree / "issuers.json").exists(), f"{name}: the build wrote a census it refused"


def test_a_subject_form_may_rest_on_a_chain(tmp_path):
    """A form no subject the vendor prints shows may rest on a chain of its
    sentences, read in order and marked as one."""
    doc = valid_census()
    form = doc["issuers"][0]["subject_forms"]["forms"][0]
    del form["evidence"]
    form["basis"], form["chain"] = "chain", [fact(), fact()]
    status, err, tree = build(tmp_path, doc)
    assert status == 0, err
    sub = json.loads((tree / "tenancy" / "tenancy.json").read_text(encoding="utf-8"))
    assert sub["issuers"][0]["subject_forms"] == [
        {"leading_literal": "org:", "owner_parts": [{"kind": "name", "delimiter_after": ":"}]}]


def test_a_membership_may_rest_on_a_chain(tmp_path):
    """No single sentence need say a tenant's owner decides who obtains its
    tokens: a chain of them, read in order and marked as one, may."""
    doc = valid_census()
    doc["issuers"][1]["tenant_membership"] = {"value": "controlled", "basis": "chain", "chain": [fact(), fact()]}
    status, err, tree = build(tmp_path, doc)
    assert status == 0, err
    sub = json.loads((tree / "tenancy" / "tenancy.json").read_text(encoding="utf-8"))
    assert sub["issuers"][1]["tenant_membership"] == "controlled"


def test_several_entries_may_share_a_host(tmp_path):
    """One pattern, one entry: GitHub's enterprise path shares GitHub's host and
    is told apart by its path."""
    doc = valid_census()
    doc["issuers"].append({
        "name": "Shared, by path", "issuer": "https://token.example.com/<org>", "tenancy_model": "per_tenant_path",
        "discovery_status": "unverified", "jwks_status": "unverified",
        "aud_controlled_by": "unverified", "vendor_example_verdict": "unverified", "researched": "in_release",
        "match": {"value": "verified", "issuer_pattern": "https://token.example.com/<org>", "tenant_placeholder": "<org>",
                  "tenant_kind": "name", "tenant_recyclable": "unverified", "evidence": [fact()]}})
    status, err, tree = build(tmp_path, doc)
    assert status == 0, err
    sub = json.loads((tree / "tenancy" / "tenancy.json").read_text(encoding="utf-8"))
    assert [e["issuer"] for e in sub["issuers"]][-1] == "https://token.example.com/<org>"

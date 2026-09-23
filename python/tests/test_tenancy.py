"""The tenancy facts and match, held to the same cases as the Go packages.

match_cases.json and answers.json are copies of the files in tenancy/testdata
that scripts/build.py writes, so this directory runs on its own from the source
distribution, and the Go and Python answers are checked against one file.
answers.json holds what the Go packages answer for every census entry; the
Python package must answer the same, entry by entry.
"""

import datetime
import json
import re
import urllib.parse
from pathlib import Path

import pytest

import cloudarq_issuers as ci
from cloudarq_issuers import _tenancy

HERE = Path(__file__).parent
CASES = json.loads((HERE / "match_cases.json").read_text(encoding="utf-8"))
ANSWERS = json.loads((HERE / "answers.json").read_text(encoding="utf-8"))

GITHUB_ENTERPRISE = "https://token.actions.githubusercontent.com/<enterpriseSlug>"
ENTRA = "https://login.microsoftonline.com/<tenant_id>/v2.0"
PERSONAL_MSA = "9188040d-6c67-4c5b-b112-36a304b66dad"

RESEARCHED = {
    "Bitbucket Pipelines", "Buildkite", "CircleCI", "GitHub Actions", "GitHub Actions (enterprise issuer path)",
    "GitLab.com", "HCP Terraform (Terraform Cloud)", "Spacelift",
    "Amazon EKS (Kubernetes service account issuer / IRSA)", "Azure Kubernetes Service (AKS workload identity)",
    "Google Kubernetes Engine (GKE)", "AWS (outbound identity federation)", "Google (accounts.google.com)",
    "Amazon Cognito identity pools", "Login with Amazon", "Facebook", "Microsoft Entra ID",
}
TENANCY_FIELDS = ("anonymous_tokens", "tenancy_claims", "not_tenancy", "subject_forms", "owner_charset",
                  "names_unique_regardless_of_case", "match", "tenant_membership", "built_in")


def match_key(entry):
    """The census string an entry is matched by, stated apart from the package."""
    m = entry.get("match") or {}
    return m["issuer_pattern"] if m.get("value") == "verified" else entry["issuer"]


def by_name(name, issuer=None):
    for e in ci.issuers():
        if e["name"] == name and (issuer is None or e.get("issuer") == issuer):
            return e
    raise AssertionError(f"no census entry {name} {issuer}")


def by_key(key):
    for e in ci.issuers():
        if (e.get("match") or {}).get("value") == "verified" and e["match"]["issuer_pattern"] == key:
            return e
    raise AssertionError(f"no census entry matched by {key}")


def check(case, got, key_of):
    if case["entry"] is None:
        assert got is None, f"match({case['issuer']!r}) = {got and key_of(got[0])!r}; want none ({case.get('why', '')})"
        return
    assert got is not None, f"match({case['issuer']!r}) found nothing; want {case['entry']!r} ({case.get('why', '')})"
    entry, tenant = got
    assert (key_of(entry), tenant) == (case["entry"], case["tenant"]), case


def test_the_shared_cases_exercise_both_answers():
    matched = sum(1 for c in CASES["census"] if c["entry"] is not None)
    refused = sum(1 for c in CASES["census"] if c["entry"] is None)
    assert matched > 0 and refused > 0 and CASES["synthetic"], "a test over no cases examines nothing"


@pytest.mark.parametrize("case", CASES["census"], ids=lambda c: repr(c["issuer"]))
def test_match_reads_the_census_as_the_shared_cases_say(case):
    check(case, ci.match(case["issuer"]), match_key)


@pytest.mark.parametrize("case", CASES["get"], ids=lambda c: repr(c["query"]))
def test_get_reads_the_shared_cases(case):
    """Hosts compare without ASCII case and no other, as the Go package's do:
    a character that lower-cases onto an ASCII letter elsewhere in Unicode
    must not let a look-alike host pass for a census host."""
    got = ci.get(case["query"])
    assert (None if got is None else got["name"]) == case["entry"], case


def test_the_shared_lookups_exercise_both_answers():
    found = sum(1 for c in CASES["get"] if c["entry"] is not None)
    refused = sum(1 for c in CASES["get"] if c["entry"] is None)
    assert found > 0 and refused > 0


def test_match_rules_on_invented_censuses():
    examined = 0
    for s in CASES["synthetic"]:
        m = _tenancy.compile_rules([(e, e["issuer"], e.get("tenant_placeholder", ""), e.get("tenant_syntax", ""))
                                    for e in s["census"]])
        assert s["cases"], s["why"]
        for c in s["cases"]:
            examined += 1
            check(c, m.match(c["issuer"]), lambda e: e["issuer"])
    assert examined > 0


@pytest.mark.parametrize("bad", [
    ("example.com/<t>", "<t>", ""),
    ("https://example.com/a<t>", "<t>", ""),
    ("https://example.com/<t", "<t", ""),
    ("https://example.com/<t>", "<u>", ""),
    ("https://example.com/<t>", "t", ""),
    ("https://<t>.example.com/<t>", "<t>", ""),
    ("https://<t>.example.com", "", ""),
    ("https://example.com", "<t>", ""),
    ("https://example.com/<t>", "<t>", "uuid4"),
    ("https://example.com/<a>/<b>", "<a>/<b>", "guid"),
    ("", "", ""),
])
def test_compile_refuses_a_malformed_pattern(bad):
    key, tenant, syntax = bad
    with pytest.raises(ValueError):
        _tenancy.compile_rules([({"issuer": key}, key, tenant, syntax)])


def test_compile_refuses_one_issuer_twice():
    with pytest.raises(ValueError):
        _tenancy.compile_rules([({}, "https://example.com/x", "", ""), ({}, "https://EXAMPLE.com/x/", "", "")])


def matchable():
    return [e for e in ci.issuers() if _tenancy.rule_of(e) is not None]


def test_every_entry_has_a_shared_case():
    named = {c["entry"] for c in CASES["census"] if c["entry"] is not None}
    entries = matchable()
    assert len(entries) >= 29, f"{len(entries)} matchable entries; the census has at least 29"
    missing = [match_key(e) for e in entries if match_key(e) not in named]
    assert not missing, f"no shared match case names {missing}"


PLACEHOLDER = re.compile(r"<[A-Za-z0-9_-]+>")


def instance(key, tenant_template, fill):
    """Fill every placeholder of a pattern, read by a regular expression rather
    than by the package's parser; return the issuer and the tenant it names."""
    rest = key[len("https://"):]
    host_end = rest.find("/") if "/" in rest else len(rest)
    values, out, last = {}, [], 0
    for m in PLACEHOLDER.finditer(rest):
        v = fill(m.group(0), m.start() < host_end)
        values[m.group(0)] = v
        out.append(rest[last:m.start()])
        out.append(v)
        last = m.end()
    out.append(rest[last:])
    tenant = PLACEHOLDER.sub(lambda m: values[m.group(0)], tenant_template)
    return "https://" + "".join(out), tenant


def path_of(issuer):
    rest = issuer[len("https://"):] if issuer.startswith("https://") else issuer
    return rest[rest.find("/"):] if "/" in rest else ""


def test_every_entry_matches_its_own_issuer():
    patterns = 0
    for e in matchable():
        key = match_key(e)
        m = e["match"]
        if m["value"] != "verified":
            with_slash = key.rstrip("/") + "/"
            shouted = key[:len(key) - len(path_of(key))].upper() + path_of(key)
            for form in (key, with_slash, shouted):
                got = ci.match(form)
                assert got is not None and match_key(got[0]) == key and got[1] == "", (form, got)
            continue
        patterns += 1
        counter = iter(range(1, 100))

        def fill(name, in_host):
            i = next(counter)
            if m.get("tenant_syntax") == "guid" and name == m["tenant_placeholder"]:
                return "0123abcd-4567-89ef-0123-456789ABCDEF"
            return f"host-{i}" if in_host else f"Seg_{i}-x"

        issuer, tenant = instance(key, m["tenant_placeholder"], fill)
        got = ci.match(issuer)
        assert got is not None and (match_key(got[0]), got[1]) == (key, tenant), (issuer, got)
        empty, _ = instance(key, m["tenant_placeholder"], lambda n, h: "")
        got = ci.match(empty)
        assert got is None or match_key(got[0]) != key, empty
        split, _ = instance(key, m["tenant_placeholder"], lambda n, h: "a.b" if h else "a/b")
        got = ci.match(split)
        assert got is None or match_key(got[0]) != key, split
    assert patterns == 9, f"exercised {patterns} issuer patterns; the census researched 9"


def test_an_answer_refuses_to_be_read_as_true_or_false():
    """A pair read as a truth value would be true whatever it says; for a
    controlled tenant that is the wrong direction, so the pair refuses."""
    answer = ci.controlled_tenant(by_name("Facebook"), "acme")
    assert answer == (False, False)
    value, known = answer
    assert (value, known) == (answer.value, answer.known) == (False, False)
    with pytest.raises(TypeError):
        bool(answer)
    with pytest.raises(TypeError):
        if answer:
            pass


def test_controlled_tenant():
    entra = by_key(ENTRA)
    # No sentence says a work tenant's owner decides who obtains its tokens;
    # by default every user can invite guests.
    assert ci.controlled_tenant(entra, "11111111-2222-3333-4444-555555555555") == (False, False)
    assert ci.controlled_tenant(entra, PERSONAL_MSA) == (False, True)
    assert ci.controlled_tenant(entra, PERSONAL_MSA.upper()) == (False, True)
    assert ci.controlled_tenant(entra, "") == (False, False)
    assert ci.controlled_tenant(by_key(GITHUB_ENTERPRISE), "octocorp") == (True, True)
    others = [e for e in ci.issuers() if e["tenant_membership"]["value"] != "controlled"]
    assert others
    for e in others:
        assert ci.controlled_tenant(e, "acme") == (False, False), e["name"]


def test_an_open_tenant_stays_open_under_an_unverified_membership():
    """A tenant listed as open is open on its own sentence, which an
    unverified membership does not unsettle."""
    entry = {"name": "x", "match": {"value": "verified", "issuer_pattern": "https://example.com/<t>",
                                    "tenant_placeholder": "<t>", "tenant_kind": "id",
                                    "not_a_controlled_tenant": [{"tenant": PERSONAL_MSA}]},
             "tenant_membership": {"value": "unverified"}}
    assert ci.controlled_tenant(entry, PERSONAL_MSA) == (False, True)
    assert ci.controlled_tenant(entry, "11111111-2222-3333-4444-555555555555") == (False, False)


def test_issues_anonymous_tokens():
    assert ci.issues_anonymous_tokens(by_name("Amazon Cognito identity pools")) == (True, True)
    assert ci.issues_anonymous_tokens(by_name("GitHub Actions")) == (False, True)
    assert ci.issues_anonymous_tokens(by_name("Facebook")) == (True, False)
    for name in ("GitLab.com", "HCP Terraform (Terraform Cloud)", "Buildkite"):
        assert ci.issues_anonymous_tokens(by_name(name)) == (True, False), name
    assert ci.issues_anonymous_tokens({"name": "x", "anonymous_tokens": {"value": "maybe"}}) == (True, False)


def test_tenant_is_recyclable():
    assert ci.tenant_is_recyclable(by_key(GITHUB_ENTERPRISE)) == (True, True)
    per_tenant = [e for e in ci.issuers() if e["match"]["value"] == "verified" and match_key(e) != GITHUB_ENTERPRISE]
    assert len(per_tenant) == 8
    for e in per_tenant:
        assert ci.tenant_is_recyclable(e) == (True, False), e["name"]
    assert ci.tenant_is_recyclable({"name": "x", "match": {"value": "unverified", "tenant_recyclable": "no"}}) == (True, False)


def test_owner_name_may_contain():
    gh = by_name("GitHub Actions")
    for ch in "/@:%.~ é":
        assert not ci.owner_name_may_contain(gh, ch), ch
    for ch in "aAzZ09-_":
        assert ci.owner_name_may_contain(gh, ch), ch
    for ch in "/@:%":
        assert ci.owner_name_may_contain({"name": "x"}, ch), ch


@pytest.mark.parametrize("n", range(len(ANSWERS["charsets"])), ids=lambda n: repr(ANSWERS["charsets"][n]["characters"]))
def test_an_owner_character_set_reads_as_go_reads_it(n):
    """Character sets the census does not hold, as a caller might hand either
    package one: an item Go cannot read byte by byte, such as a non-ASCII
    character, lets any character through in both."""
    want = ANSWERS["charsets"][n]
    entry = {"name": "x", "owner_charset": {"value": "verified", "characters": want["characters"]}}
    got = "".join("1" if ci.owner_name_may_contain(entry, c) else "0" for c in ANSWERS["probes"]["characters"])
    assert got == want["owner_name_may_contain"], want["characters"]


def test_the_character_set_probes_exercise_both_readings():
    """Some probed sets must read as unreadable, letting every character
    through, and some must let only some through, or the test above could pass
    on sets that never tell the two packages apart."""
    answers = [c["owner_name_may_contain"] for c in ANSWERS["charsets"]]
    assert any(set(a) == {"1"} for a in answers) and any("0" in a for a in answers), answers


def test_an_empty_character_set_is_left_out_as_go_leaves_it():
    entry = {"name": "x", "owner_charset": {"value": "verified", "characters": []}}
    assert "owner_name_characters" not in ci.tenancy(entry)


def test_names_compare_without_case():
    assert ci.names_compare_without_case(by_name("GitHub Actions")) == (False, False)
    for value, want in (("yes", (True, True)), ("no", (False, True)), ("unverified", (False, False))):
        entry = {"name": "x", "names_unique_regardless_of_case": {"value": value}}
        assert ci.names_compare_without_case(entry) == want, value


def test_the_researched_facts_are_the_census_s():
    gh = by_name("GitHub Actions")
    assert gh["anonymous_tokens"]["value"] == "no" and gh["anonymous_tokens"]["basis"] == "chain"
    assert gh["names_unique_regardless_of_case"]["value"] == "unverified"
    forms = [f["leading_literal"] + "".join(" owner " + p["kind"] + p["delimiter_after"] for p in f.get("owner_parts", []))
             + "".join(" repository " + p["kind"] + p["delimiter_after"] for p in f.get("repository_parts", []))
             for f in gh["subject_forms"]["forms"]]
    assert forms == ["repo: owner name/", "repo: owner name@ owner id/", "repository_owner: owner name:",
                     "repository_owner_id: owner id:", "repository_id: repository id:"]
    claims = [(c["claim"], c["kind"], c["scope"], c["multi_valued"], c["immutable"]) for c in gh["tenancy_claims"]["claims"]]
    assert claims == [
        ("repository_owner", "name", "owner", "no", "no"),
        ("repository_owner_id", "id", "owner", "no", "yes"),
        ("repository", "name", "repository", "no", "no"),
        ("repository_id", "id", "repository", "no", "yes"),
        ("enterprise_id", "id", "enterprise", "no", "unverified"),
    ]
    assert gh["owner_charset"]["characters"] == ["A-Z", "a-z", "0-9", "-", "_"]
    assert "job_workflow_ref:" in [n["leading_literal"] for n in gh["subject_forms"]["never_pin"]]
    not_tenancy = {c["claim"] for c in gh["not_tenancy"]["claims"]}
    assert {"actor", "actor_id", "job_workflow_ref", "job_workflow_sha", "environment", "ref", "event_name",
            "runner_environment", "repository_visibility", "workflow_ref", "enterprise"} <= not_tenancy

    assert by_name("Amazon Cognito identity pools")["anonymous_tokens"]["value"] == "yes"
    assert by_name("Login with Amazon")["anonymous_tokens"]["value"] == "no"
    assert by_name("Facebook")["anonymous_tokens"]["value"] == "unverified"
    google = by_name("Google (accounts.google.com)")["anonymous_tokens"]
    assert (google["value"], google["basis"]) == ("no", "chain")
    cognito = by_name("Amazon Cognito identity pools")
    assert cognito["tenancy_claims"] == {"value": "unverified"}
    assert "aud" in {c["claim"] for c in cognito["not_tenancy"]["claims"]}

    per_tenant = {
        GITHUB_ENTERPRISE: ("<enterpriseSlug>", "name", "yes"),
        "https://oidc.eks.<region>.amazonaws.com/id/<cluster_oidc_id>": ("<cluster_oidc_id>", "id", "unverified"),
        "https://<region>.oic.prod-aks.azure.com/<tenant_id>/<cluster_uuid>/":
            ("<region>/<tenant_id>/<cluster_uuid>", "id", "unverified"),
        "https://container.googleapis.com/v1/projects/<project>/locations/<location>/clusters/<cluster>":
            ("<project>/<location>/<cluster>", "name", "unverified"),
        ENTRA: ("<tenant_id>", "id", "unverified"),
        "https://<account>.app.spacelift.io": ("<account>", "name", "unverified"),
        "https://oidc.circleci.com/org/<organization_id>": ("<organization_id>", "id", "unverified"),
        "https://api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc":
            ("<workspace>", "name", "unverified"),
        "https://<tenant_uuid>.tokens.sts.global.api.aws": ("<tenant_uuid>", "id", "unverified"),
    }
    # No sentence in this release says who can cause a Spacelift run or a
    # Bitbucket pipeline, or that a work tenant's owner decides who is in it.
    uncontrolled = {"Spacelift", "Bitbucket Pipelines", "Microsoft Entra ID"}
    for key, (tenant, kind, recyclable) in per_tenant.items():
        e = by_key(key)
        m = e["match"]
        assert (m["tenant_placeholder"], m["tenant_kind"], m["tenant_recyclable"]) == (tenant, kind, recyclable), e["name"]
        membership = "unverified" if e["name"] in uncontrolled else "controlled"
        assert e["tenant_membership"]["value"] == membership, e["name"]
        assert (e["anonymous_tokens"]["value"], e["anonymous_tokens"]["basis"]) == ("no", "chain"), e["name"]
    assert len([e for e in ci.issuers() if e["match"]["value"] == "verified"]) == len(per_tenant)
    entra = by_key(ENTRA)["match"]
    assert entra["tenant_syntax"] == "guid"
    assert [x["tenant"] for x in entra["not_a_controlled_tenant"]] == [PERSONAL_MSA]


def test_every_entry_says_whether_it_was_researched():
    """Every entry carries researched and every tenancy field, and an entry
    this release did not research holds only unverified."""
    in_release = set()
    unresearched = 0
    for e in ci.issuers():
        missing = [k for k in TENANCY_FIELDS if k not in e]
        assert not missing, f"{e['name']} does not write out {missing}"
        assert e["researched"] in ("in_release", "not_in_this_release"), e["name"]
        if e["researched"] == "in_release":
            in_release.add(e["name"])
            continue
        unresearched += 1
        for k in TENANCY_FIELDS:
            assert e[k] == {"value": "unverified"}, f"{e['name']} was not researched, yet its {k} is {e[k]}"
        assert "research" not in e, e["name"]
    assert in_release == RESEARCHED
    assert unresearched >= 27, f"examined {unresearched} entries this release did not research; the census has 27"


FACT_KEYS = {"source", "quote", "verified_at", "role", "observed", "method", "at", "result"}
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MOMENT = re.compile(r"^(\d{4}-\d{2}-\d{2})(T([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?Z)?$")
# Where an observation may stand: beside a value rather than behind it, in
# research, or behind a claim or a leading literal that never pins. Anywhere
# else a fact settles a value, and only the vendor's sentence settles one.
MAY_STAND = re.compile(r"^research|^not_tenancy\.|\.never_pin\[|(^|\.)context(\[|\.|$)")


def facts_in(value, where, out):
    """Every mapping under an entry's tenancy fields that carries any key a
    fact or an observation has, which is what a fact is in this census, so one
    written under other names is caught rather than walked past. A key named
    observed whose value is a mapping or a list names a group."""
    if isinstance(value, dict):
        if any(k in FACT_KEYS and not isinstance(v, (dict, list)) for k, v in value.items()):
            out.append((where, value))
            return
        for k, v in value.items():
            facts_in(v, f"{where}.{k}", out)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            facts_in(v, f"{where}[{i}]", out)


def is_day(value):
    try:
        return bool(DATE.match(value)) and datetime.date.fromisoformat(value) is not None
    except ValueError:
        return False


def is_page(value):
    host = urllib.parse.urlsplit(value).hostname or ""
    return value.startswith("https://") and not any(c.isspace() for c in value) and "." in host.strip(".")


def test_every_fact_has_a_source_a_quote_and_a_date():
    found = []
    for e in ci.issuers():
        for k in TENANCY_FIELDS + ("research",):
            if k in e:
                in_entry = []
                facts_in(e[k], k, in_entry)
                found += [(e["name"], where, f) for where, f in in_entry]
    observations = [where for _, where, f in found if "observed" in f]
    assert len(found) >= 150 and observations, (
        f"examined {len(found)} facts, {len(observations)} observations; the research recorded more than 150, and observations")
    for name, where, f in found:
        assert set(f) <= FACT_KEYS, (name, where, f)
        if "observed" in f:
            assert all(f.get(k) for k in ("observed", "method", "at", "result")) and "quote" not in f, (name, where, f)
            m = MOMENT.match(f["at"])
            assert m and is_day(m.group(1)), (name, where, f)
            assert MAY_STAND.search(where), f"{name} {where}: an observation settles no value; it needs the vendor's sentence"
        else:
            assert is_page(f.get("source", "")) and f.get("quote", "").strip(), (name, where, f)
            assert is_day(f.get("verified_at", "")), (name, where, f)


def test_the_corrections_the_vendors_force():
    azure = by_name("Microsoft (Azure DevOps)")
    assert azure["issuer"] == "unverified" and azure["tenancy_model"] == "unverified"
    assert "nothing to scope on" not in azure.get("notes", "")
    env0 = by_name("env0").get("notes", "")
    assert "WRONG" not in env0 and "not a deployment-token issuer" not in env0
    assert by_name("Codeberg (Forgejo)")["issuer"] == "unverified"
    assert "exploitable" not in by_name("Cursor", "https://api2.cursor.sh/cloud-agent/identity").get("notes", "")
    assert by_name("GitLab.com")["aud_default"] == "unverified"
    assert by_name("GitLab self-managed")["aud_default"] == "unverified"
    bb = by_name("Bitbucket Pipelines")
    assert bb["aud_controlled_by"] == "workload" and "To customize your audiences" in bb["aud_evidence"]
    assert "workspace-pinned anyway" not in bb.get("vendor_example_note", "")
    assert by_name("Chainguard")["tenancy_claim"] == "unverified"
    assert azure["subject_format"] == "unverified"
    assert "name-recyclable" not in bb["notes"]


def test_get_resolves_a_shared_host_to_the_host_s_own_issuer():
    assert ci.get("token.actions.githubusercontent.com")["name"] == "GitHub Actions"
    assert ci.get("https://token.actions.githubusercontent.com/octocorp")["name"] == "GitHub Actions"


def test_a_census_note_is_not_a_host():
    for q in ("unverified", "not an OIDC issuer", "https://unverified"):
        assert ci.get(q) is None, q
    for h in ci.multi_tenant_hosts():
        assert "." in h and " " not in h, h


def test_the_version_is_the_release():
    pyproject = (HERE.parent / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version = "([^"]+)"$', pyproject, re.M).group(1)
    assert declared == ci.__version__ == "0.2.0"


def entries_in_census_order():
    entries = list(ci.issuers())
    assert len(entries) == len(ANSWERS["entries"]), (
        f"answers.json holds {len(ANSWERS['entries'])} entries; the census has {len(entries)}")
    return zip(entries, ANSWERS["entries"])


@pytest.mark.parametrize("n", range(len(ANSWERS["entries"])), ids=lambda n: ANSWERS["entries"][n]["name"])
def test_go_and_python_agree(n):
    """What the Go packages answer about this entry, the Python package
    answers too."""
    entry = ci.issuers()[n]
    want = ANSWERS["entries"][n]
    assert (entry["name"], entry.get("issuer", "")) == (want["name"], want["issuer"])
    got = ci.match(want["instance"])
    assert (None if got is None else {"entry": got[0]["name"], "tenant": got[1]}) == want["match"]
    assert list(ci.issues_anonymous_tokens(entry)) == want["anonymous_tokens"]
    assert list(ci.names_compare_without_case(entry)) == want["names_compare_without_case"]
    assert list(ci.tenant_is_recyclable(entry)) == want["tenant_is_recyclable"]
    assert {t: list(ci.controlled_tenant(entry, t)) for t in want["controlled_tenant"]} == want["controlled_tenant"]
    chars = "".join("1" if ci.owner_name_may_contain(entry, c) else "0" for c in ANSWERS["probes"]["characters"])
    assert chars == want["owner_name_may_contain"]
    assert ci.tenancy(entry) == want["tenancy"]


def test_the_shared_answers_cover_the_census():
    matched = sum(1 for _, want in entries_in_census_order() if want["match"] is not None)
    assert matched >= 29, f"{matched} entries' own issuers matched; the census has at least 29 an issuer can match"

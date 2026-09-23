import json
from pathlib import Path

import cloudarq_issuers as ci


def test_census_is_populated():
    assert len(ci.issuers()) >= 40
    assert ci.CENSUS_DATE


def test_controlled_vocabularies_hold():
    aud = {"relying_party", "issuer", "workload", "unverified"}
    verdict = {"scoped", "admits_whole_org", "admits_any_repo",
               "admits_any_principal", "no_subject_constraint", "unverified"}
    tenancy = {"shared", "per_tenant_host", "per_tenant_path", "unverified"}
    discovery = {"ok", "not_found", "error", "unverified"}
    category = {"ci", "iac", "runtime", "cloud", "ai-agent-platform", "platform"}
    control_test = {"passed", "failed", "inconclusive", "unverified"}
    for e in ci.issuers():
        assert e["aud_controlled_by"] in aud, e["name"]
        assert e["vendor_example_verdict"] in verdict, e["name"]
        assert e["tenancy_model"] in tenancy, e["name"]
        assert e["discovery_status"] in discovery, e["name"]
        # n/a only where the entry records no issuer, so no key set to fetch.
        jwks = {"ok", "error", "unverified"} | ({"n/a"} if e.get("issuer") == "not an OIDC issuer" else set())
        assert e["jwks_status"] in jwks, e["name"]
        assert e.get("category", "ci") in category, e["name"]
        assert e.get("control_test_result", "unverified") in control_test, e["name"]
        assert e.get("issuer") or e.get("issuer_pattern"), e["name"]


def spellings_of_unverified(value):
    if isinstance(value, str):
        return [value] if value.strip().lower() == "unverified" else []
    if isinstance(value, dict):
        return [s for v in value.values() for s in spellings_of_unverified(v)]
    if isinstance(value, list):
        return [s for v in value for s in spellings_of_unverified(v)]
    return []


def test_unverified_is_spelled_one_way():
    """A reader that compares with "unverified" does not recognise
    "UNVERIFIED", and would read a settled answer into it."""
    spellings = spellings_of_unverified(list(ci.issuers()))
    assert spellings, "no value reads unverified, so the spelling was checked on nothing"
    assert set(spellings) == {"unverified"}, sorted(set(spellings))


def test_lookup_by_host_and_url_agree():
    a = ci.get("token.actions.githubusercontent.com")
    b = ci.get("https://token.actions.githubusercontent.com")
    assert a is not None and a == b
    assert ci.get("example.invalid") is None


def test_unverified_audience_is_never_true():
    """The safety property. An unknown must not read as a boundary.

    audience_is_boundary answers by host, for the entry get() returns. Several
    entries may share a host (GitHub's enterprise path shares GitHub's), so the
    answer is held to that entry, and the entry itself is held to the property.
    """
    examined = 0
    for e in ci.issuers():
        u = e.get("issuer") or e.get("issuer_pattern")
        got = ci.audience_is_boundary(u)
        owner = ci.get(u)
        if owner is None:
            assert got is None, e["name"]
            continue
        examined += 1
        if owner["aud_controlled_by"] == "unverified":
            assert got is None, e["name"]
        if owner["aud_controlled_by"] == "workload":
            assert got is False, e["name"]
        if e["aud_controlled_by"] in ("unverified", "workload"):
            assert got is not True, e["name"]
    assert examined >= 30, f"examined {examined} entries with a host"


def test_multi_tenant_hosts_are_bare_hostnames():
    hosts = ci.multi_tenant_hosts()
    assert len(hosts) >= 10
    assert "token.actions.githubusercontent.com" in hosts
    for h in hosts:
        assert "/" not in h and "://" not in h


def test_unsurveyed_host_is_none_not_false():
    """Not in the census means unsurveyed, never safe."""
    assert ci.audience_is_boundary("nobody.surveyed.this") is None
    assert ci.subjects_are_recyclable("nobody.surveyed.this") is None


def scribble(value):
    """Write over every value a caller can reach in ``value``, however deep,
    and return how many it wrote."""
    written = 0
    if isinstance(value, dict):
        for k, v in list(value.items()):
            if isinstance(v, (dict, list)):
                written += scribble(v)
            else:
                value[k] = "scribbled"
                written += 1
    elif isinstance(value, list):
        for i, v in enumerate(value):
            if isinstance(v, (dict, list)):
                written += scribble(v)
            else:
                value[i] = "scribbled"
                written += 1
    return written


def test_answers_are_copies():
    """What issuers, get and match hand out is the caller's to edit: the next
    answer is the census's. Handed the census's own dicts, one caller's edit
    would change every later answer in the process, such as a cautious
    anonymous_tokens turned into a known no."""
    data = Path(ci.__file__).with_name("issuers.json").read_text(encoding="utf-8")
    pristine = json.loads(data)["issuers"]
    written = sum(scribble(e) for e in ci.issuers())
    written += scribble(ci.get("token.actions.githubusercontent.com"))
    written += scribble(ci.match("https://agent.buildkite.com")[0])
    assert written > 1000, f"wrote over {written} values; the census holds more"
    assert list(ci.issuers()) == pristine
    assert ci.get("token.actions.githubusercontent.com") == pristine[[e["name"] for e in pristine].index("GitHub Actions")]
    assert ci.issues_anonymous_tokens(ci.match("https://agent.buildkite.com")[0]) == (True, False)

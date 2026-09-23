import cloudarq_issuers as ci


def test_census_is_populated():
    assert len(ci.issuers()) >= 40
    assert ci.CENSUS_DATE


def test_controlled_vocabularies_hold():
    aud = {"relying_party", "issuer", "workload", "unverified"}
    verdict = {"scoped", "admits_whole_org", "admits_any_repo",
               "admits_any_principal", "no_subject_constraint", "unverified"}
    tenancy = {"shared", "per_tenant_host", "per_tenant_path", "unverified"}
    for e in ci.issuers():
        assert e["aud_controlled_by"] in aud, e["name"]
        assert e["vendor_example_verdict"] in verdict, e["name"]
        assert e["tenancy_model"] in tenancy, e["name"]
        assert e.get("issuer") or e.get("issuer_pattern"), e["name"]


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

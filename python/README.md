# cloudarq-issuers

A census of the OIDC issuers a cloud provider will federate to for workload identity —
GitHub Actions, GitLab, CircleCI, HCP Terraform, Kubernetes and 35 others — with the fields
a policy evaluator actually needs.

**No dependencies. No network calls. Apache-2.0.**

```bash
pip install cloudarq-issuers
```

## Why

Evaluating a cloud trust policy correctly means knowing things about the issuer that are not
in the policy: what its subject looks like, which claims it emits, whether it is shared
between every customer of that vendor. That knowledge is spread across forty vendor
documentation sites, and the closest public reference has not been updated since January 2025.

## The four fields you will not find elsewhere

### `aud_controlled_by` — who picks the audience

`aud` reads like a boundary. On **16 of 40** issuers it is not one, because the workload
requesting the token chooses it. From GitHub's own documentation: *"You can customize values
for `audience` claims."* So any repository on GitHub can request a token carrying
`aud: sts.amazonaws.com`, and a trust policy leaning on `aud` alone has trusted all of them.

```python
from cloudarq_issuers import audience_is_boundary

audience_is_boundary("token.actions.githubusercontent.com")   # False
audience_is_boundary("login.microsoftonline.com")             # True
audience_is_boundary("nobody.surveyed.this")                  # None   <- not False
```

### `vendor_example_verdict` — what the vendor's own example admits

Nobody writes a trust policy from scratch; they copy the documented example. A loose example
is therefore deployed at scale, silently. CircleCI's AWS example carries **no `sub` condition
at all**. Google's recommended attribute condition,
`assertion.repository_owner=='ORGANIZATION'`, admits every repository in the organisation.

### `control_test` — what a bogus tenant returns

Two UUIDs invented at random each returned a complete, well-formed AWS discovery document
echoing the invented UUID back as its own `issuer`. Only the JWKS refused them.

> **A discovery document is not proof a tenant exists. Only the JWKS is.**

### `immutable_id_claims` — names, or identifiers

**27 of 40** entries have none, so every subject written against them is a recyclable name.
Kubernetes is the sharp case: delete a service account, recreate one with the same name in
the same namespace, and it silently re-inherits every role that trusted it.

## `unverified` never means absent

Sixteen entries were fetched live against the public `.well-known` endpoint on the census
date. Everything else says `unverified` — nobody confirmed it, which is a different claim
from *"there is nothing there"*. No field is inferred from another field.

The API keeps that distinction. `audience_is_boundary` returns `None`, never `False`, for
anything unconfirmed, because a caller that reads an unknown as a boundary has widened its
own trust without noticing.

## API

```python
import cloudarq_issuers as ci

ci.CENSUS_DATE                  # "2026-09-13"
ci.issuers()                    # every entry, as plain dicts
ci.get("gitlab.com")            # one entry, or None if unsurveyed
ci.multi_tenant_hosts()         # frozenset[str] -- issuers shared across a vendor's tenants
ci.audience_is_boundary(host)   # True | False | None
ci.subjects_are_recyclable(host)
ci.host_of("https://gitlab.com/x")   # "gitlab.com"
```

`multi_tenant_hosts()` is a drop-in for a hard-coded set of the same shape.

## Also available as a Go module

```bash
go get github.com/CloudArq-net/issuers
```

Same data, same source of truth. The YAML is authoritative and carries the comments; a
generated JSON is what both packages embed, which is why neither needs a YAML parser at
runtime and neither has a dependency.

## Source, contributing, and how it stays current

[github.com/CloudArq-net/issuers](https://github.com/CloudArq-net/issuers)

A scheduled job re-fetches every discovery document and JWKS and opens an issue when anything
changes, so drift is visible rather than silent. Issuers move: Azure DevOps's `vstoken`
retires 2027-07-01, and AWS became an issuer in its own right at
`<uuid>.tokens.sts.global.api.aws` — `sts.amazonaws.com` is not one and returns 400 saying so.

An entry with `discovery_status: ok` must be reproducible: paste the `curl` and its output in
the pull request. Anything else is `unverified`, and that is a perfectly good state for an
entry to be in.

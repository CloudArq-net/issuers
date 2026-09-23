# cloudarq-issuers

A census of the OIDC issuers a cloud provider will federate to for workload identity —
GitHub Actions, GitLab, CircleCI, HCP Terraform, Kubernetes and 39 others — with the fields
a policy evaluator actually needs.

**No dependencies. No network calls. Apache-2.0.**

```bash
pip install cloudarq-issuers
```

## Why

Evaluating a cloud trust policy correctly means knowing things about the issuer that are not
in the policy: what its subject looks like, which claims it emits, whether it is shared
between every customer of that vendor, and who can get a token from it at all. That knowledge
is spread across each vendor's own documentation, and the closest public reference has not
been updated since January 2025.

## The four fields you will not find elsewhere

### `aud_controlled_by` — who picks the audience

`aud` reads like a boundary. On **17 of 44** issuers it is not one, because the workload
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

**29 of 44** entries have none, so every subject written against them is a recyclable name.
Kubernetes is the sharp case: delete a service account, recreate one with the same name in
the same namespace, and it silently re-inherits every role that trusted it.

## Who can hold a token

Since 0.2.0 the census records, for the issuers it has researched, the facts that decide who
can get a token an issuer mints, each resting on the vendor's own sentences kept beside it:
the page, the sentence verbatim, and the date it was read.

- `anonymous_tokens`: whether the issuer mints tokens to people with no account anywhere.
  Amazon Cognito identity pools do, in a pool that allows guests.
- `tenancy_claims` and `not_tenancy`: the claims that name a tenant (an owner, a repository
  or an enterprise), each with its `kind`, `name` or `id`; and the claims that look like
  tenants and are never read as naming one, such as GitHub's `job_workflow_ref`, which names
  the called workflow, and GitHub's `enterprise`, which no sentence shows to name one
  enterprise.
- `subject_forms`: every documented form of `sub` with a tenant at its head, as a leading
  literal and the owner's parts, each with the delimiter after it; `never_pin` lists the
  literals whose subjects name no tenant.
- `owner_charset` and `names_unique_regardless_of_case`: the characters an owner name can
  hold, and whether names that differ only in case are one owner.
- `match` and `tenant_membership`: for an issuer whose URL names its tenant, how to read it,
  and whether the tenant's owner controls who obtains its tokens. Seven of the nine patterns
  record that it does; Spacelift's and Bitbucket Pipelines' read `unverified`.
- `built_in`: the providers AWS STS accepts with no identity provider in the account.
- `researched`: whether this release researched the entry at all.

## `unverified` never means absent

Sixteen entries were fetched live against the public `.well-known` endpoint on the census
date. Everything else says `unverified` — nobody confirmed it, which is a different claim
from *"there is nothing there"*. No field is inferred from another field.

In a tenancy field, `unverified` means exactly that no vendor sentence establishes the value
in this release, whatever the reason, and every reader answers it the cautious way: an issuer
may mint tokens to people with no account, no claim or `sub` prefix pins a tenant, any
character may occur in an owner name, names compare exactly, and a tenant is not known to
control who joins it, and its name may pass to someone else.

The API keeps that distinction. `audience_is_boundary` returns `None`, never `False`, for
anything unconfirmed, because a caller that reads an unknown as a boundary has widened its
own trust without noticing.

## API

```python
import cloudarq_issuers as ci

ci.CENSUS_DATE                  # "2026-09-13"
ci.issuers()                    # every entry, as plain dicts
ci.get("gitlab.com")            # one entry by host, or None if unsurveyed
ci.multi_tenant_hosts()         # frozenset[str] -- issuers shared across a vendor's tenants
ci.audience_is_boundary(host)   # True | False | None
ci.subjects_are_recyclable(host)
ci.host_of("https://gitlab.com/x")   # "gitlab.com"

entry, tenant = ci.match("https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE")
ci.match("https://login.microsoftonline.com/common/v2.0")    # None: common is not a tenant
ci.tenancy(entry)               # the values a classifier reads, nothing unverified

anonymous, known = ci.issues_anonymous_tokens(entry)
controlled, known = ci.controlled_tenant(entry, tenant)
recyclable, known = ci.tenant_is_recyclable(entry)
without_case, known = ci.names_compare_without_case(entry)
ci.owner_name_may_contain(entry, "/")                         # True when nothing is recorded
```

`issuers`, `get` and `match` hand out copies: edit an entry however deep and the next
answer is still the census's. Hosts compare without ASCII case and no other, so a
look-alike such as one spelled with the Kelvin sign is not a census host.

`match` reads an issuer URL's path as well as its host, and returns the entry and the tenant
the URL names, or `None` for an issuer nobody surveyed: never a sign that it is safe. Each
reader returns an `Answer`, a `(value, known)` pair; when `known` is false the value is the
cautious one, and an `Answer` refuses to be read as true or false, so an unknown cannot pass
for an answer by accident.

`multi_tenant_hosts()` is a drop-in for a hard-coded set of the same shape. A host missing
from it is not thereby known to identify a tenant.

## Also available as a Go module

```bash
go get github.com/CloudArq-net/issuers
```

Same data, same source of truth, and the same answers: the Go and Python packages are tested
against one file of what each reader says about every entry. The YAML is authoritative and
carries the comments; a JSON built from it is what both packages embed, which is why neither
needs a YAML parser at runtime and neither has a dependency.

## Source, contributing, and how it stays current

[github.com/CloudArq-net/issuers](https://github.com/CloudArq-net/issuers)

A scheduled job re-fetches every discovery document and JWKS and opens an issue when anything
changes, so drift is visible rather than silent. Issuers move: Azure DevOps's `vstoken`
retires 2027-07-01, and AWS became an issuer in its own right at
`<uuid>.tokens.sts.global.api.aws` — `sts.amazonaws.com` is not one and returns 400 saying so.

An entry with `discovery_status: ok` must be reproducible: paste the `curl` and its output in
the pull request. Anything else is `unverified`, and that is a perfectly good state for an
entry to be in. A tenancy value other than `unverified` needs the vendor's sentence behind it.

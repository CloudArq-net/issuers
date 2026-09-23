# issuers

A census of the OIDC issuers a cloud provider will federate to for workload identity —
GitHub Actions, GitLab, CircleCI, HCP Terraform, Kubernetes, and 39 others — with the
fields a policy evaluator actually needs.

**Apache-2.0. No dependencies. No network calls. Meant to be imported, not cited.**

```
pip install cloudarq-issuers
go get github.com/CloudArq-net/issuers
```

## Why this exists

Evaluating a cloud trust policy correctly means knowing things about the issuer that are
not in the policy: what its subject looks like, which claims it actually emits, whether
it is shared between every customer of that vendor, and who can get a token from it at
all. That knowledge is scattered across each vendor's own documentation, and the closest
public reference has not been updated since January 2025.

## The four fields you will not find elsewhere

**`aud_controlled_by`** — who picks the `aud` value.

`aud` reads like a boundary. On **17 of 44** issuers it is not one, because the workload
requesting the token chooses it. GitHub's own documentation: *"You can customize values
for `audience` claims."* So any repository on GitHub can request a token carrying
`aud: sts.amazonaws.com`. A trust policy leaning on `aud` alone has trusted all of them.

```python
from cloudarq_issuers import audience_is_boundary
audience_is_boundary("token.actions.githubusercontent.com")   # False
audience_is_boundary("login.microsoftonline.com")             # True
audience_is_boundary("nobody.surveyed.this")                  # None  <- not False
```

**`vendor_example_verdict`** — what the vendor's own documented example admits.

Nobody writes a trust policy from scratch; they copy the example. So a loose example is
deployed at scale, silently. CircleCI's AWS example carries **no `sub` condition at all**.
Google's recommended attribute condition, `assertion.repository_owner=='ORGANIZATION'`,
admits every repository in the organisation.

**`control_test`** — what a deliberately bogus tenant returns.

Two UUIDs invented at random each returned a complete, well-formed AWS discovery document
echoing the invented UUID back as its own `issuer`. Only the JWKS refused them.

> **A discovery document is not proof a tenant exists. Only the JWKS is.**

CircleCI returns 200 at *both* layers and serves a key byte-identical to the root: all
orgs share one signing key, so the per-org issuer URL is a filing convention rather than a
cryptographic boundary.

**`immutable_id_claims`** — which claims carry an ID rather than a name.

**29 of 44** entries have none, so every subject written against them is a recyclable
name. Kubernetes is the sharp case: delete a service account, recreate one with the same
name in the same namespace, and it silently re-inherits every role that trusted it.

## Who can hold a token

A trust policy that names an issuer admits whoever can get a token from it and satisfy
the conditions. Since v0.2.0 the census records, for the issuers it has researched, the
facts that decide who that is. Every value rests on the vendor's own sentences, kept
beside it: the page, the sentence verbatim, and the date it was read.

**`anonymous_tokens`** — does the issuer mint tokens to people with no account anywhere?
Amazon Cognito identity pools do, in a pool that allows guests: a guest identity needs no
credential. `basis: chain`
marks a `no` that no single vendor sentence states and a chain of them, read in order,
does.

**`tenancy_claims`** — which claims name a tenant: an owner, a repository or an
enterprise. Each has a `kind` (a `name` can be released and taken by someone else; an
`id` cannot) and says whether it is `multi_valued`; a claim that lists several values
pins nothing. A claim not listed names no tenant.

**`not_tenancy`** — claims that look like tenants and are not, each with the sentence
that says what they name instead. GitHub's `job_workflow_ref` names the *called* reusable
workflow, not the repository the token was minted for, and `actor` names the person who
started the run.

**`subject_forms`** — every documented form of `sub` with a tenant at its head: a leading
literal, then the owner's parts in order, each with its kind and the delimiter after it.
GitHub's `sub` has four such forms: two defaults, `repo:<owner>/…` and, since 15 July
2026, `repo:<owner>@<owner_id>/…`, and two a repository can choose, led by
`repository_owner:` and `repository_owner_id:`. `never_pin` lists leading literals whose
subjects name no tenant of the token's, `job_workflow_ref:` first. A subject led by a
literal the entry does not list names no tenant.

**`owner_charset`** — the characters an owner name can hold. A delimiter outside the set
cannot occur inside a name, which is what lets a `sub` prefix pin an owner. GitHub's is
letters, digits and dashes, plus the underscore of managed users, from GitHub's sentences
and one of AWS's, which the census labels as AWS's.

**`names_unique_regardless_of_case`** — whether two names that differ only in case are one
owner. For GitHub it is `unverified`: no GitHub page read says so, and names compare
exactly.

**`match`** — for an issuer whose URL names its tenant: the pattern, the placeholder the
tenant is spelled from, its kind, and whether a released tenant name can pass to another
customer (`tenant_recyclable`; GitHub's enterprise slug can). Nine patterns are recorded,
EKS clusters and GitHub's enterprise issuer path among them.

**`tenant_membership`** — whether the tenant's owner controls who obtains tokens naming
it. `not_a_controlled_tenant` lists the tenants anyone can join although the pattern
matches them: Microsoft Entra's personal-account tenant.

**`built_in`** — the four providers AWS STS accepts with no identity provider in the
role's account: Amazon Cognito, Google, Login with Amazon and Facebook, as AWS's reference
for the `Principal` element names them. Two other AWS pages name three, leaving out Login
with Amazon; the census records them beside the four.

**`researched`** — `in_release` for the 17 entries this release researched, and
`not_in_this_release` for the rest.

### What `unverified` means for a consumer

In a tenancy field, `unverified` means exactly this: no vendor sentence establishes the
value in this release, whatever the reason. It is never a finding that the thing is
absent, and every reader in both packages answers it the cautious way:

- an issuer may mint tokens to people with no account;
- a claim or a `sub` prefix pins no tenant;
- any character may occur in an owner name, and names compare exactly;
- a tenant is not known to control who joins it, and its name may pass to another
  customer;
- an issuer URL with no verified pattern matches its exact issuer only, and one the
  census does not hold at all is unsurveyed, which is never the same as safe.

An entry with `researched: not_in_this_release` holds `unverified` in every tenancy field.
GitLab.com, HCP Terraform and Buildkite were researched for `anonymous_tokens` alone, and
it is `unverified`: the research recorded who can open an account there, not that a token
needs one.

## `unverified` never means absent

16 entries were fetched live with `curl` against the public `.well-known` endpoint on the
census date. Everything else says `unverified` — nobody confirmed it, which is a
different claim from "there is nothing there". No field is inferred from another field.

The API keeps that distinction. `audience_is_boundary` returns `None`, not `False`, for
anything unconfirmed, because a caller that reads an unknown as a boundary has widened
its own trust without noticing.

## Usage

```python
import cloudarq_issuers as ci

ci.CENSUS_DATE                 # "2026-09-13"
ci.issuers()                   # every entry
ci.get("gitlab.com")           # one entry by host, or None if unsurveyed
ci.multi_tenant_hosts()        # frozenset[str]
ci.subjects_are_recyclable("oidc.eks.us-east-1.amazonaws.com")

entry, tenant = ci.match("https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE")
tenant                         # "EXAMPLED539D4633E53DE1B71EXAMPLE", the cluster
ci.match("https://login.microsoftonline.com/common/v2.0")   # None: common is not a tenant

anonymous, known = ci.issues_anonymous_tokens(ci.get("gitlab.com"))   # True, False
```

`match` reads the path as well as the host: of several entries on one host, the most
specific pattern wins, and a host without the pattern's tenant is no match. Hosts compare
without ASCII case and no other, in `get` and `Get` as in `match`, so a look-alike spelled
with the Kelvin sign is not a census host. Every entry either package hands out is the
caller's own copy: edit it however deep and the next answer is still the census's. The readers
(`issues_anonymous_tokens`, `controlled_tenant`, `tenant_is_recyclable`,
`names_compare_without_case`) return an `Answer`, a `(value, known)` pair; when `known`
is false the value is the cautious one. An `Answer` refuses to be read as true or false,
so an unknown cannot pass for an answer by accident.

```go
import "github.com/CloudArq-net/issuers"

issuers.All()
e, ok := issuers.Get("token.actions.githubusercontent.com")
isBoundary, known := e.AudienceIsBoundary()
issuers.MultiTenantHosts()

e, tenant, ok := issuers.Match("https://token.actions.githubusercontent.com/octocorp")
// e is the enterprise issuer path's entry, with every fact behind it; tenant is "octocorp".
anonymous, known := e.Tenancy().IssuesAnonymousTokens()
```

A program that only classifies issuers can import `github.com/CloudArq-net/issuers/tenancy`
instead. It carries the values a classifier reads and none of the sentences: 4,531 bytes of
data against the root package's 156,387. Built with go1.27.1 for `js/wasm`, a small program
that matches an issuer through `tenancy` came out 188,588 bytes smaller (38,116 after
`gzip -9`) than one doing the same through the root package, and it does not contain the
root census. `scripts/build.py` writes the sub-package's data from the same YAML, and CI
fails when it is out of step.

The raw data is [`issuers.yaml`](issuers.yaml) (source of truth, with comments) and
[`issuers.json`](issuers.json) (generated, what both packages embed). Take either.

## Corrections in v0.2.0

The v0.2.0 research found these v0.1.0 fields contradicted by the vendor's own
documentation. Where this release carries the vendor's sentence the field is corrected;
where it does not, the field now reads `unverified`.

- Bitbucket Pipelines: `aud_controlled_by` is `workload`, not `issuer`. A pipeline declares
  its audiences in its own configuration.
- Microsoft (Azure DevOps): `issuer` and `tenancy_model` read `unverified`, and the note
  that there is nothing to scope on beyond `sub` is withdrawn.
- Codeberg (Forgejo): `issuer` reads `unverified`.
- GitLab.com and GitLab self-managed: `aud_default` reads `unverified`.
- env0: the note that its issuer was probably the wrong one is withdrawn.
- Cursor's legacy endpoint: the note that a trust policy pinned there remains exploitable
  is withdrawn.
- Chainguard: `tenancy_claim` is spelled `unverified`, not `UNVERIFIED`.

Because two of those issuers now read `unverified`, `vstoken.dev.azure.com` and
`codeberg.org` are no longer in `MultiTenantHosts()`. A host missing from that set is not
thereby known to identify a tenant.

## Maintenance

A scheduled job re-fetches every discovery document and JWKS and opens an issue when
anything changes, so drift is visible rather than silent. Issuers move: Azure DevOps's
`vstoken` retires 2027-07-01, and AWS became an issuer in its own right at
`<uuid>.tokens.sts.global.api.aws` — `sts.amazonaws.com` is not one and returns 400
saying so.

`.github/workflows/release.yml` publishes the Python package from `v*` tags by PyPI's
trusted publishing, with attestations. Every action the workflows use is pinned to a
commit.

## Contributing

An entry with a `discovery_status` of `ok` must be reproducible: paste the `curl` and its
output in the pull request. Anything else is `unverified`, and that is a perfectly good
state for an entry to be in.

A tenancy value other than `unverified` needs the vendor's sentence behind it: its page,
the sentence verbatim, and the date it was read. `scripts/build.py` refuses a fact with no
source or no quote, a value that rests on an observation alone, a date no calendar has, a
key given twice, and a value outside its field's vocabulary.

Public metadata only. Nothing in this repository authenticates anywhere, probes anyone's
infrastructure, or enumerates tenant names.

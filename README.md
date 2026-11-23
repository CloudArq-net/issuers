# issuers

A census of the OIDC issuers a cloud provider will federate to for workload identity —
GitHub Actions, GitLab, CircleCI, HCP Terraform, Kubernetes, and 39 others, 44 entries in
all — with the fields a policy evaluator needs. It is data first: one YAML file, the JSON
built from it, and a Go module and a Python package that embed that JSON and answer
questions about it.

Apache-2.0. Neither package has a dependency, and neither makes a network call.

```
pip install cloudarq-issuers
go get github.com/CloudArq-net/issuers
```

## Why this exists

Evaluating a cloud trust policy correctly means knowing things about the issuer that are
not in the policy: what its subject looks like, which claims it actually emits, whether
it is shared between every customer of that vendor, and who can get a token from it at
all. That knowledge is scattered across each vendor's own documentation. This census
collects it in one machine-readable file, with the vendor's sentence beside each value it
rests on.

## Four fields that carry most of the weight

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

A trust policy copied from a vendor's example admits what the example admits. CircleCI's
AWS example carries **no `sub` condition at all**.
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

**`not_tenancy`** — claims that look like tenants and are never read as naming one, each
with the vendor's sentence and why. Most name something else: GitHub's `job_workflow_ref`
names the *called* reusable workflow, not the repository the token was minted for, and
`actor` names the person who started the run. The rest are there because no sentence shows
that their value names one tenant, and their `why` begins *unverified as a tenant claim*:
GitHub's `enterprise` carries "the name of the enterprise", and GitHub does not say whether
that is the enterprise's slug, which one enterprise holds at a time, or a name another can
share.

**`subject_forms`** — every documented form of `sub` with a tenant at its head: a leading
literal, then the owner's parts in order, each with its kind and the delimiter after it.
GitHub's `sub` has five such forms: two defaults, `repo:<owner>/…` and, since 15 July
2026, `repo:<owner>@<owner_id>/…`, and three a repository can choose, led by
`repository_owner:`, `repository_owner_id:` and `repository_id:`. GitHub prints no subject
led by either id, so those two rest on a chain marked `basis: chain`: GitHub's instruction
to require one, the key-colon-value subjects it prints for other templates, and its
encoding of a colon inside a value. `never_pin` lists leading literals whose subjects name
no tenant of the token's, `job_workflow_ref:` first. A subject led by a literal the entry
does not list names no tenant. HCP Terraform's two forms, a workspace run's and a module
test run's, lead with `organization:` and the organization's name.

**`owner_charset`** — the characters an owner name can hold. A delimiter outside the set
cannot occur inside a name, which is what lets a `sub` prefix pin an owner. GitHub's is
letters, digits and dashes, plus the underscore of managed users, from GitHub's sentences
and one of AWS's, which the census labels as AWS's. HCP Terraform's is numbers, letters,
underscores and hyphens, from HashiCorp's sentence. HashiCorp does not say which letters
and numbers: reading them as ASCII is the census's, not HashiCorp's words.

**`repository_charset`** — the characters a repository's name can hold, in `owner_charset`'s
shape. A character outside the set occurs in no repository's name. GitHub's is ASCII letters,
digits and the characters `.`, `-` and `_`, from GitHub's sentence on naming a repository,
with its OIDC reference's sentence that `@` cannot appear in a repository's name. In both
`repo:` forms the repository's name follows the owner's `/`.

**`names_unique_regardless_of_case`** — whether two names that differ only in case are one
owner. For GitHub it is `unverified`: no GitHub page read says so, and names compare
exactly.

**`match`** — for an issuer whose URL names its tenant: the pattern, the placeholder the
tenant is spelled from, its kind, and whether a released tenant name can pass to another
customer (`tenant_recyclable`; GitHub's enterprise slug can). Nine patterns are recorded,
EKS clusters and GitHub's enterprise issuer path among them.

**`tenant_membership`** — whether the tenant's owner controls who obtains tokens naming
it. Six of the nine patterns record `controlled`. Three are clusters, EKS, AKS and GKE,
and rest on a chain marked `basis: chain`: Kubernetes issues a service account's token to
whoever the cluster's authorization lets request one, and each platform's own sentence says
the cluster's owner administers that authorization. Spacelift and Bitbucket Pipelines read
`unverified`: the sentences this release carries say which runs or pipelines hold a token,
not who can cause one. So does Microsoft Entra ID: by default every user of a work tenant,
guests included, can invite external users, and all users can consent to applications for
permissions that don't require administrator consent.
`not_a_controlled_tenant` lists the tenants anyone can join although the pattern matches
them: Microsoft Entra's personal-account tenant, which reads as known open whatever the
issuer's membership.

**`built_in`** — the four providers AWS STS accepts with no identity provider in the
role's account: Amazon Cognito, Google, Login with Amazon and Facebook, as AWS's reference
for the `Principal` element names them. Two other AWS pages name three, leaving out Login
with Amazon; the census records them beside the four.

**`accounts`** — the platform whose accounts hold the issuer's tenants, as the vendor's own
sentence names it: GitHub for GitHub Actions and its enterprise path, Bitbucket, CircleCI
and Google. That is where a platform's population lives, not the product that mints the
token. GitHub Actions also carries a `declaration_namespace`, `github`: the prefix a
consumer declares an owner under by name, as in `github:acme`. No two entries share a
namespace, since the same name under another issuer is another owner.

**`aws_condition_keys`** — the condition keys AWS documents for the issuer, from AWS's
reference for OIDC condition keys: its Default tab for an issuer with no tab of its own,
and the issuer's own tab where it has one. Each key carries the `claim` AWS's table says
AWS reads it from, which is not always the key's own name: on the Default tab `oaud` reads
`aud`, and `aud` reads `azp`, or `aud` when the token sets no `azp`, which the key's
`fallback_claim` records. GitHub's tab has `repository_owner_id` and no `repository_owner`.
Google's `google/organization_number` has no `claim`: AWS's table spells it
`google:organization_number`, Google's reference prints the number as `organization_number`
inside a `google` claim, and no page says which AWS reads, so the key keeps AWS's spelling in
`table_claim` and gives a reader no claim to look up.
AWS does not document what a condition on a key it does not list tests; read as unread,
such a condition never pins and never narrows, whichever it tests. Recorded for 14 of the
17 researched entries. GitHub's enterprise path reads `unverified`: AWS names a condition
key by the provider, and no AWS sentence names a provider at that path. GitLab.com and
Buildkite read `unverified` because this release researched them for `anonymous_tokens`
alone, not because AWS does not read their tokens: AWS's reference has a tab for GitLab.com
and one for Buildkite. HCP Terraform has no tab of its own, so its keys are the Default
tab's. `aws_maps_condition_key` and `AWSMapsConditionKey`
answer whether a key is one, and `aws_condition_key` and `AWSConditionKey` return its
record; both compare names without ASCII case, as AWS does.

Each key also says whether it is `multivalued`. AWS's entry for `amr`, on the Default tab
and again on Amazon Cognito's, says "The key is multivalued, meaning that you test it in a
policy using condition set operators.", and that a signed-in user's `amr` holds
`authenticated` and the name of the login provider. What a condition on it without a set
operator compares, AWS does not document. The ten issuers whose keys include `amr` record it
`yes` on that sentence, quoted from AWS's page. Every other key reads `unverified`: AWS's
reference says of no other of these keys that it is multivalued, and of none that it holds one
value. The build refuses a `yes` without AWS's sentence for that key, and an `unverified` key
whose sentence the census quotes. `aws_condition_key_is_multivalued` and `IsMultivalued` read
it.

**`aws_identity_provider_controls`** — the check AWS makes of a trust policy that trusts the
issuer, which AWS calls its identity-provider controls: the condition `key` the policy must
test, one of the issuer's `aws_condition_keys`, and `existing_trust_policies`. For GitHub
Actions, AWS says "IAM checks the role trust policy condition to verify that the condition
key `token.actions.githubusercontent.com:sub` is present and that its value is not solely a
wildcard character (* and ?) or null", that "IAM performs this check when the trust policy is
created or updated", and that "Identity-provider controls will not be evaluated by IAM for
existing OIDC role trust policies." So a trust policy saved today tests `sub`, and one that
existed before may not and still admit; `existing_trust_policies` reads `not_evaluated`. AWS's
table of shared providers, read the same day, names `sub` or `job_workflow_ref` for GitHub
actions; the census keeps that row as the check's `discrepancy`, since the GitHub sentence names
`sub` alone and no AWS sentence says which values of `job_workflow_ref` the check refuses.
Verified for GitHub Actions alone. The tenancy sub-package carries the key as
`aws_required_condition_key`, and `AWSRequiredConditionKey` in Go.

**`multi_valued_claims`** — the claims the issuer's tokens may carry with several values,
each on the sentences that say so. RFC 7519 says that in the general case `aud` is an array.
Kubernetes says of a service account token's audience "May be repeated to request a token
valid for multiple audiences.", and the EKS, AKS and GKE cluster issuers record `aud` on that
sentence beside their vendor's sentence tying the issuer to the tokens the cluster's API
server signs. AWS's outbound tokens record it on `GetWebIdentityToken`'s audiences, an array
of up to ten that "populates the aud claim in the JWT", and Bitbucket Pipelines on a
pipeline's list of audiences, "Maximum of 10 audiences allowed." A claim not listed is not
thereby one value: no sentence here says a claim holds one. The build refuses a listed claim
with no sentence behind it, and a tenancy claim whose own sentence describes one value.
`claim_is_multi_valued` and `ClaimIsMultiValued` read it, comparing claim names as written,
as a token does.

**`researched`** — `in_release` for the 17 entries this release researched, and
`not_in_this_release` for the rest.

### What `unverified` means for a consumer

In a tenancy field, `unverified` means exactly this: no vendor sentence establishes the
value in this release, whatever the reason. It is never a finding that the thing is
absent, and every reader in both packages answers it the cautious way:

- an issuer may mint tokens to people with no account;
- a claim or a `sub` prefix pins no tenant;
- any character may occur in an owner name, and names compare exactly;
- a condition key may hold several values, and so may a claim;
- a tenant is not known to control who joins it, and its name may pass to another
  customer;
- an issuer URL with no verified pattern matches its exact issuer only, and one the
  census does not hold at all is unsurveyed, which is never the same as safe.

An entry with `researched: not_in_this_release` holds `unverified` in every tenancy field.
GitLab.com and Buildkite were researched for `anonymous_tokens` alone, and it is
`unverified`: the research recorded who can open an account there, not that a token needs
one.

## `unverified` never means absent

16 entries were fetched live with `curl` against the public `.well-known` endpoint, each on
the date in its `verified_at`. Everything else says `unverified` — nobody confirmed it,
which is a different claim from "there is nothing there". No field is inferred from another
field, and where an older value rests on a vendor's example rather than a sentence, its note
says so.

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
ci.subjects_are_recyclable("gitlab.com")     # False: GitLab's tokens carry an id claim

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
`claim_is_recyclable`, `aws_maps_condition_key`, `aws_condition_key_is_multivalued`,
`claim_is_multi_valued`, `names_compare_without_case`) return an
`Answer`, a `(value, known)` pair; when `known` is false the value is the cautious one.
`aws_condition_key` returns the key's record, or `None` when AWS documents no such key or
the census does not record the issuer's keys. A claim's value is recyclable
unless a vendor sentence says it cannot pass to someone else, whatever its kind: GitHub's
`enterprise_id` is an id, and no sentence settles it. An `Answer` refuses to be read as true or false,
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

gh, _, _ := issuers.Match("https://token.actions.githubusercontent.com")
k, ok := gh.Tenancy().AWSConditionKey("oaud")
// k.Claim is "aud": AWS reads the oaud condition key from the aud claim.
amr, _ := gh.Tenancy().AWSConditionKey("amr")
multivalued, known := amr.IsMultivalued()
// true, true: AWS documents amr as multivalued. Of oaud, k.IsMultivalued() is true, false.
eks, _, _ := issuers.Match("https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE")
several, known := eks.Tenancy().ClaimIsMultiValued("aud")
// true, true: a Kubernetes service account token may be requested for several audiences.
```

A program that only classifies issuers can import `github.com/CloudArq-net/issuers/tenancy`
instead. It carries the values a classifier reads and none of the sentences: 8,658 bytes of
data (`tenancy/tenancy.json`) against the root package's 249,536 (`issuers.json`). A small
program whose `main` calls `tenancy.Match(os.Args[1])` and, when it matches,
`fmt.Println(e.Name)` came out 4,540,073 bytes as js/wasm; the same program calling the root
package's `issuers.Match` came out 4,821,769: 281,696 bytes smaller through `tenancy`, and
49,762 smaller after `gzip -9`. Each was built as `wasmsize/main.go` at the root of a copy of
the tree made by `git archive HEAD | tar -x`, which carries no VCS stamp, with go1.27.1 by
`GOOS=js GOARCH=wasm go build -trimpath -o main.wasm ./wasmsize`, and measured by
`wc -c < main.wasm` and `gzip -9 < main.wasm | wc -c`. The sizes move by a few bytes with the
directory's name. None of the census's quoted sentences is in the smaller one.
`scripts/build.py` writes the sub-package's data from the same YAML, and CI fails when it is
out of step.

The raw data is [`issuers.yaml`](issuers.yaml) (source of truth, with comments) and
[`issuers.json`](issuers.json) (generated, what both packages embed). Take either.

## Corrections in v0.2.0

The v0.2.0 research found these v0.1.0 fields contradicted by the vendor's own
documentation. Where this release carries the vendor's sentence the field is corrected;
where it does not, the field now reads `unverified`.

- Bitbucket Pipelines: `aud_controlled_by` is `workload`, not `issuer`. A pipeline declares
  its audiences in its own configuration. The note that no Bitbucket trust policy is
  name-recyclable is withdrawn: the issuer carries the workspace ID, which Atlassian lets a
  workspace rename.
- Microsoft (Azure DevOps): `issuer`, `tenancy_model` and `subject_format` read
  `unverified`, and the note that there is nothing to scope on beyond `sub` is withdrawn.
  The research found subject forms the v0.1.0 value leaves out.
- Codeberg (Forgejo): `issuer` reads `unverified`.
- GitLab.com and GitLab self-managed: `aud_default` reads `unverified`.
- env0: the note that its issuer was probably the wrong one is withdrawn.
- Cursor's legacy endpoint: the note that a trust policy pinned there remains exploitable
  is withdrawn.
- Chainguard: `tenancy_claim` is spelled `unverified`, not `UNVERIFIED`.

Because two of those issuers now read `unverified`, `vstoken.dev.azure.com` and
`codeberg.org` are no longer in `MultiTenantHosts()`. A host missing from that set is not
thereby known to identify a tenant.

Nine entries named no page for their values, only a survey: Depot, Harness's account path,
Namespace, Modal, Cognition, Cursor's two issuers, Warp and Chainguard. Each now carries,
under `evidence`, the vendor's sentences behind every value it states, read on 2026-09-27,
and a value no page supports reads `unverified`. Reading them changed these values:

- Namespace: `aud_controlled_by` is `workload`, not `issuer`. Its CLI mints a token with
  `--audience <aud>`, "the audience claim required by your target system".
- Modal: `aud_controlled_by` reads `unverified`, and the note that all isolation rests on
  `sub` because `aud` is shared is withdrawn. No sentence says who sets the audience.
- Cognition: `vendor_example_verdict` reads `unverified`. The vendor prints no example
  policy; it says the role's subject condition "must match the claims selected by
  subject-keys".
- Cursor's older issuer, `api2.cursor.sh`: `tenancy_claim` and `aud_controlled_by` read
  `unverified`. Cursor: "Minted tokens no longer carry that issuer."
- Harness's account path: `known_defect` reads `unverified`. The discovery document it
  described was not fetched again, and the control test was run again with two made-up
  account IDs.
- Depot: the last segment of `sub_grammar` is `<sandboxID>`, as Depot writes it.
- Warp and Chainguard: notes that no page supports are withdrawn.

## Checks

`make test` builds the JSON from the YAML and runs both packages' tests. CI runs the same
steps and, before any test, fails if the build changed a committed file: the JSON, the
sub-package's data and the Python tests' copies of the shared cases are all written by
`scripts/build.py`, so what is tested is what the YAML says.

```
$ python3 scripts/build.py
issuers.json: 44 entries, 17 researched in this release; tenancy/tenancy.json: 29 entries an issuer can match
$ git status --porcelain            # empty: the committed files are what the YAML builds
$ go vet ./... && go test ./... -count=1
ok  	github.com/CloudArq-net/issuers	0.131s
ok  	github.com/CloudArq-net/issuers/tenancy	0.013s
$ cd python && PYTHONPATH=src python3 -m pytest tests -q
398 passed in 11.70s
```

The Python checks need `pyyaml` and `pytest`; CI installs them, and every dependency, from
`.github/requirements.txt`, pinned to their hashes. The Go module needs Go 1.24 or later.

## Maintenance

A scheduled job (`make drift`, daily in `.github/workflows/drift.yml`) re-fetches each
discovery document the census records as fetched at a fixed URL, and the JWKS the census
records beside it, and opens an issue when one has moved; a `jwks_uri` the live document
names in place of the recorded one is reported and not fetched. It never edits the census. A
run on 2026-09-27:

```
$ python3 scripts/drift.py
checked 13, skipped 31 (unverified or per-tenant)
no drift
```

Issuers do move. Azure DevOps is deprecating its own issuer, `https://vstoken.dev.azure.com`,
which "retires on July 1, 2027", in favour of Microsoft Entra's
([Microsoft's page](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/connect-to-azure?view=azure-devops),
read 2026-09-27). AWS became an issuer in its own right at
`<uuid>.tokens.sts.global.api.aws` — `sts.amazonaws.com` is not one and returns 400
saying so.

`.github/workflows/release.yml` publishes the Python package from `v*` tags by PyPI's
trusted publishing, with attestations. Every action the workflows use is pinned to a
commit, and `python/tests/test_workflows.py` holds the pins, the permissions and the
triggers.

## Contributing

Issues are welcome, and pull requests are accepted under Apache-2.0: a contribution is
licensed as the rest of the repository is.

An entry with a `discovery_status` of `ok` must be reproducible: paste the `curl` and its
output in the pull request. Anything else is `unverified`, and that is a perfectly good
state for an entry to be in.

A tenancy value other than `unverified` needs the vendor's sentence behind it: its page,
the sentence verbatim, and the date it was read. So does every value of an entry that
carries `evidence`. `scripts/build.py` refuses a fact with no
source or no quote, a value that rests on an observation alone, a date no calendar has, a
key given twice, and a value outside its field's vocabulary.

Public metadata only. The code in this repository fetches only the public discovery URLs the
census records, and authenticates nowhere. The control tests recorded in the data were run by
hand against public, unauthenticated endpoints with made-up tenant IDs; where a real tenant was
fetched beside them, its note says so, and no tenant names were enumerated.

A value that could make a consumer trust more than it should — an audience recorded as a
boundary when the workload picks it, a tenant recorded as controlled when anyone can join
it — can be reported privately before it is an issue; [SECURITY.md](SECURITY.md) says how.

## Licence

Apache-2.0: see [`LICENSE`](LICENSE). The census quotes sentences from vendors'
documentation; those sentences are their publishers' text, and [`NOTICE`](NOTICE) names each
publisher and the licence it states for its pages.

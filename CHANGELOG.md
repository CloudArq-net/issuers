# Changelog

## v0.3.0

- **Repository characters.** `repository_charset` records the characters a repository's name
  can hold, in `owner_charset`'s shape. GitHub Actions holds A-Z, a-z, 0-9, `.`, `-` and `_`,
  on GitHub's sentence that a repository name "can only contain ASCII letters, digits, and the
  characters `.`, `-`, and `_`"; every other entry holds `unverified`. The `tenancy` package
  carries the set as `repository_name_characters`.
- **AWS's check on GitHub's trust policies.** `aws_identity_provider_controls` records that,
  when a role's trust policy trusts GitHub's issuer, IAM checks on creating or updating the
  policy that it tests one of its `keys`, and that trust policies that existed before are not
  evaluated (`existing_trust_policies: not_evaluated`). The keys are `sub` and
  `job_workflow_ref`, as AWS's table of shared providers names them; AWS's page on creating a
  role for an OIDC provider names `sub` alone, with a value that is not solely a wildcard or
  null, and is kept as the field's discrepancy, so a policy that tests neither key is refused
  on both pages. Every other entry holds `unverified`. The `tenancy` package carries the keys
  as `aws_identity_provider_control_keys`.
- **HCP Terraform.** AWS's condition-keys page has no tab for HCP Terraform, so its keys are
  read by the Default tab, which AWS says is for an IdP the tabs do not list: `sub`, `aud`
  (from `azp`, or from `aud` where `azp` is not set), `oaud`, `email` and `amr`, which is
  multivalued. Its organization is pinned: `terraform_organization_name` and
  `terraform_organization_id` name it, its subjects lead with `organization:` and the
  organization's name, and the name holds numbers, letters, underscores and hyphens, read as
  ASCII by the census. `anonymous_tokens` reads `no`, on a chain of HashiCorp's sentences.
- **Cognito's `amr`.** Amazon Cognito identity pools now list `amr` in `multi_valued_claims`,
  on Cognito's guide, which calls it "the multi-value amr claim" of the token an identity pool
  issues and says a signed-in user's `amr` holds the providers used as well as `authenticated`.
  The `tenancy` package answers that the claim may hold several values.

## v0.2.0

- **Tenancy.** The 17 entries researched in this release record who can hold a token the
  issuer mints: `anonymous_tokens`, `tenancy_claims`, `not_tenancy`, `subject_forms`,
  `owner_charset`, `names_unique_regardless_of_case`, `tenant_membership` and `match`, each
  value with the vendor's sentence behind it, its page and the date it was read. Every other
  entry holds `unverified` in these fields.
- **AWS condition keys.** `aws_condition_keys` records the keys AWS documents for an issuer's
  tokens and the claim AWS reads each from; `multi_valued_claims` records the claims a token
  may carry with several values.
- **The `tenancy` Go package** (`github.com/CloudArq-net/issuers/tenancy`) carries the values
  a classifier reads and none of the quoted sentences; the Python package's `match` and
  `tenancy` give the same answers, which one shared set of cases checks in both.
- **Four new entries**: Amazon Cognito identity pools, Facebook, Login with Amazon and GitHub
  Actions' per-enterprise issuer path. The census holds 44.
- **Evidence.** Nine entries that named only a survey as their source now carry, under
  `evidence`, the vendor's sentences behind every value they state.
- **Corrections.** The v0.1.0 values the vendors' own pages contradict are corrected or read
  `unverified`; the README lists each under "Corrections in v0.2.0". Codeberg's issuer and
  Azure DevOps' read `unverified`.
- **Drift.** `scripts/drift.py` fetches only the discovery documents and key sets the census
  records; a `jwks_uri` that moved is reported and not fetched.
- **Release.** The Python package is published to PyPI by trusted publishing, with
  attestations. Every action is pinned to a commit, and the Python tools CI and the release
  install are pinned to their hashes.
- **Licence.** `LICENSE` is the Apache License 2.0 text word for word, and `NOTICE` names the
  publishers whose sentences the census quotes.

## v0.1.0

The first release: 40 OIDC issuers that clouds federate to for workload identity, each with
its tenancy model, subject grammar, claim vocabulary, who controls the audience, and the
vendor's example trust policy with a verdict on what it admits.

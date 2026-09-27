# Changelog

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

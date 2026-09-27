# Reporting a vulnerability

Report it privately: through GitHub's private vulnerability reporting on this repository
(**Report a vulnerability** under the **Security** tab), or by email to
**support@cloudarq.net**. Please do not open a public issue, pull request or discussion for a
vulnerability.

A report is acknowledged within three working days. The fix and an advisory are published
together, and we ask that the report stay private until then, or for 90 days from the report,
whichever comes first.

## Supported versions

The latest release, and `main`. Fixes are released as a new version and listed in
[CHANGELOG.md](CHANGELOG.md).

## In scope

The census is read to decide whom a trust policy lets in, so a value that makes a consumer
trust more than it should is treated as a vulnerability, not only as a bug:

- an audience recorded as a boundary when the workload picks it;
- a tenant recorded as controlled when anyone can join it, or an issuer recorded as minting
  no tokens to people without an account when it does;
- a claim recorded as naming a tenant, or a subject form recorded as pinning an owner, when it
  does not;
- a value other than `unverified` with no vendor sentence behind it;
- the Go or Python package answering a question as known, or as safe, when the census holds
  `unverified` for it.

Also in scope:

- `scripts/drift.py` fetching a URL the census does not record, or passing a value an issuer
  serves into the issue it opens as anything but text;
- the release workflow publishing anything a reviewer did not approve, or the published
  package differing from what the tagged tree builds.

## Out of scope

- A value recorded as `unverified` that the vendor's documentation does settle. That is a
  correction; an issue or a pull request with the vendor's sentence is welcome.
- Vulnerabilities in Go, Python or other projects this repository builds with; please report
  those to the project concerned.

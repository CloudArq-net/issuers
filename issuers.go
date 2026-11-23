// Package issuers is a census of the OIDC issuers a cloud provider will federate
// to for workload identity, with the fields a policy evaluator actually needs:
// how the issuer is tenanted, what its subject looks like, which claims it emits,
// which of those claims are immutable, and who chooses the audience.
//
// It has no dependencies and makes no network calls. The data is embedded at
// build time and is a snapshot, not a live view; see the census date.
//
// Four fields carry most of the weight, and three of them exist because the
// obvious reading of the data is wrong:
//
//   - AudControlledBy names who picks the `aud` value. When it is "workload",
//     `aud` is not a boundary: anyone who can run a job on that platform can
//     request a token carrying your audience. Seventeen of the entries here
//     are in that state, GitHub Actions among them.
//
//   - VendorExampleVerdict says what the vendor's own documented example
//     actually admits, because a documentation example is what gets deployed.
//
//   - ControlTest records what a deliberately bogus tenant returns. AWS serves a
//     complete, well-formed discovery document for a UUID invented at random;
//     only the JWKS refuses it. A discovery document is not proof a tenant
//     exists.
//
//   - ImmutableIDClaims is empty for most entries, which means every subject
//     written against them is a recyclable name.
//
// The tenancy fields answer who can hold a token an issuer mints: whether it
// mints them to people with no account (AnonymousTokens), which claims and
// subject forms name a tenant (TenancyClaims, SubjectForms, OwnerCharset,
// RepositoryCharset), which claims look like tenants and are not (NotTenancy),
// and, for an issuer whose URL names the tenant, how to read it (Match,
// TenantMembership). AWSConditionKeys and AWSIdentityProviderControls say how
// AWS reads a trust policy that trusts the issuer. Each value rests on vendor
// sentences kept beside it as Facts, with their source and the date they were
// read. Match finds an issuer's entry and its tenant; the tenancy sub-package
// carries only what a classifier reads.
//
// Anything nobody confirmed says "unverified". In a tenancy field it means
// exactly that no vendor sentence establishes the value in this release,
// whatever the reason, and Researched says whether this release looked at all.
// It never means "absent" in the sense of "there is nothing there".
package issuers

import (
	_ "embed"
	"encoding/json"
	"slices"
	"strings"
	"sync"

	"github.com/CloudArq-net/issuers/tenancy"
)

//go:embed issuers.json
var raw []byte

// Issuer is one entry in the census. Absent fields are absent because nobody
// confirmed them, not because the answer is known to be empty.
type Issuer struct {
	Name   string `json:"name"`
	Vendor string `json:"vendor,omitempty"`
	// Category is one of: ci, iac, runtime, cloud, ai-agent-platform,
	// platform, or empty where the census gives none.
	Category string `json:"category"`

	// Issuer is the exact `iss` claim value. IssuerPattern is set instead when
	// the issuer is per-tenant and the value carries a <placeholder>.
	Issuer        string `json:"issuer,omitempty"`
	IssuerPattern string `json:"issuer_pattern,omitempty"`

	// TenancyModel is one of: shared, per_tenant_host, per_tenant_path, unverified.
	TenancyModel string `json:"tenancy_model"`
	// TenancyClaim is v0.1.0's single tenancy claim, kept for the callers that
	// read it; TenancyClaims carries the researched list with its evidence.
	TenancyClaim string `json:"tenancy_claim,omitempty"`

	// ControlTest is what a deliberately bogus tenant returned, in words.
	// ControlTestResult is the same answer machine-readable: passed, failed,
	// inconclusive or unverified. "failed" means a bogus tenant was served a
	// real-looking answer, so the URL alone proves nothing about the tenant.
	ControlTest       string `json:"control_test,omitempty"`
	ControlTestResult string `json:"control_test_result,omitempty"`

	// DiscoveryStatus is one of: ok, not_found, error, unverified. JWKSStatus
	// is one of: ok, error, unverified, or n/a where the issuer field holds
	// the note "not an OIDC issuer", which has no key set to fetch.
	DiscoveryURL    string `json:"discovery_url,omitempty"`
	DiscoveryStatus string `json:"discovery_status"`
	JWKSURI         string `json:"jwks_uri,omitempty"`
	JWKSStatus      string `json:"jwks_status"`

	SubjectFormat   string            `json:"subject_format,omitempty"`
	SubGrammar      map[string]string `json:"sub_grammar,omitempty"`
	SubjectExamples []string          `json:"subject_examples,omitempty"`

	// Claims is the vocabulary of the workload-identity token, from vendor
	// documentation. ClaimsAdvertised is what the discovery document's
	// claims_supported said when it was last fetched. They are not always the
	// same list: GitLab's discovery document advertises its human sign-in
	// claims, while its CI job token carries project_id, namespace_id and the
	// rest. Compare like with like.
	Claims                    []string `json:"claims,omitempty"`
	ClaimsAdvertised          []string `json:"claims_advertised,omitempty"`
	ClaimsAdvertisedFetchedAt string   `json:"claims_advertised_fetched_at,omitempty"`
	ImmutableIDClaims         []string `json:"immutable_id_claims,omitempty"`
	TokenLifetimeS            int      `json:"token_lifetime_s,omitempty"`

	// AudControlledBy is one of: relying_party, issuer, workload, unverified.
	AudControlledBy string `json:"aud_controlled_by"`
	AudDefault      string `json:"aud_default,omitempty"`
	AudEvidence     string `json:"aud_evidence,omitempty"`

	// VendorExampleVerdict is one of: scoped, admits_whole_org, admits_any_repo,
	// admits_any_principal, no_subject_constraint, unverified.
	VendorExampleVerdict string `json:"vendor_example_verdict"`
	VendorExample        string `json:"vendor_example,omitempty"`
	VendorExampleNote    string `json:"vendor_example_note,omitempty"`

	CorrectCondition  map[string]any `json:"correct_condition,omitempty"`
	KnownDefect       string         `json:"known_defect,omitempty"`
	SelfHostedVariant string         `json:"self_hosted_variant,omitempty"`
	DocsURL           string         `json:"docs_url,omitempty"`
	VerifiedAt        string         `json:"verified_at,omitempty"`
	Notes             string         `json:"notes,omitempty"`
	Source            string         `json:"source,omitempty"`

	// Evidence holds, for an entry that carries it, the facts behind each
	// field above that the entry states, keyed by the field's JSON name. Such
	// an entry carries them for every value it states; a field it leaves
	// unverified has none. What a live endpoint returned (the control test,
	// the discovery and JWKS statuses, a known defect) may rest on an
	// observation; every other value rests on a vendor's sentence.
	Evidence map[string][]Fact `json:"evidence,omitempty"`

	// Researched is "in_release" when this release read the entry's tenancy
	// facts from its vendor, and "not_in_this_release" when it did not, in
	// which case every tenancy field below is unverified.
	Researched                  string                      `json:"researched"`
	AnonymousTokens             AnonymousTokens             `json:"anonymous_tokens"`
	TenancyClaims               TenancyClaims               `json:"tenancy_claims"`
	NotTenancy                  NotTenancy                  `json:"not_tenancy"`
	SubjectForms                SubjectForms                `json:"subject_forms"`
	OwnerCharset                OwnerCharset                `json:"owner_charset"`
	RepositoryCharset           RepositoryCharset           `json:"repository_charset"`
	NamesUniqueRegardlessOfCase NameCase                    `json:"names_unique_regardless_of_case"`
	Match                       MatchRule                   `json:"match"`
	TenantMembership            TenantMembership            `json:"tenant_membership"`
	BuiltIn                     BuiltIn                     `json:"built_in"`
	Accounts                    Accounts                    `json:"accounts"`
	AWSConditionKeys            AWSConditionKeys            `json:"aws_condition_keys"`
	AWSIdentityProviderControls AWSIdentityProviderControls `json:"aws_identity_provider_controls"`
	MultiValuedClaims           MultiValuedClaims           `json:"multi_valued_claims"`
	// Research keeps the rest of what the tenancy research read for this
	// entry, as the research recorded it: context a reader checking a value
	// wants beside it. Every fact inside it carries its source like any other.
	Research map[string]any `json:"research,omitempty"`
}

// Fact is one sentence a vendor wrote, with the page it is on and the date it
// was read, or one observation of a live endpoint, with how and when it was
// made. Every tenancy value other than unverified rests on facts, and the
// census refuses a fact with no source or no quote when it is built.
type Fact struct {
	Source     string `json:"source,omitempty"`
	Quote      string `json:"quote,omitempty"`
	VerifiedAt string `json:"verified_at,omitempty"`
	// Role says what the sentence establishes where a value cites several,
	// and whose sentence it is when it is not the issuer's vendor's.
	Role string `json:"role,omitempty"`

	Observed string `json:"observed,omitempty"`
	Method   string `json:"method,omitempty"`
	At       string `json:"at,omitempty"`
	Result   string `json:"result,omitempty"`
}

// AnonymousTokens records whether the issuer mints tokens to people with no
// account anywhere, which puts every grant trusting it within reach of anyone.
type AnonymousTokens struct {
	// Value is "yes", "no" or "unverified".
	Value string `json:"value"`
	// Basis is "chain" when no single sentence states the value and it
	// follows from the sentences in Chain, read in order.
	Basis    string `json:"basis,omitempty"`
	Evidence []Fact `json:"evidence,omitempty"`
	Chain    []Fact `json:"chain,omitempty"`
	// Context holds sentences read beside the value that do not establish
	// it, such as what an unverified value was looked for in.
	Context       []Fact   `json:"context,omitempty"`
	Note          string   `json:"note,omitempty"`
	WhyUnverified string   `json:"why_unverified,omitempty"`
	LookedIn      []string `json:"looked_in,omitempty"`
}

// TenancyClaims lists the claims whose value names a tenant. A claim the list
// does not carry names no tenant, and neither does any claim of an issuer
// whose list is unverified.
type TenancyClaims struct {
	// Value is "verified" or "unverified".
	Value  string        `json:"value"`
	Claims []TenantClaim `json:"claims,omitempty"`
}

// TenantClaim is a claim whose value names a tenant: an owner, a repository or
// an enterprise.
type TenantClaim struct {
	Claim string `json:"claim"`
	// Kind is "name" or "id". A name can be released and taken by another
	// owner; an id cannot.
	Kind string `json:"kind"`
	// Scope is "owner", "repository" or "enterprise".
	Scope string `json:"scope"`
	// MultiValued is "no" when the vendor's sentence for the claim describes
	// one value; a claim that lists several pins nothing.
	MultiValued string `json:"multi_valued"`
	// Immutable is "yes", "no" or "unverified": whether the value can pass
	// to someone else.
	Immutable         string   `json:"immutable"`
	Evidence          Fact     `json:"evidence"`
	ImmutableEvidence []Fact   `json:"immutable_evidence,omitempty"`
	Context           []Fact   `json:"context,omitempty"`
	Note              string   `json:"note,omitempty"`
	LookedIn          []string `json:"looked_in,omitempty"`
}

// NotTenancy lists claims that look as if they name a tenant and are never
// read as naming one: a claim a vendor sentence says names something else,
// and a claim no sentence in this release shows to name one tenant, whose Why
// begins "unverified as a tenant claim". A classifier reads both the same way
// as a claim listed nowhere: it pins nothing.
type NotTenancy struct {
	// Value is "verified" or "unverified".
	Value  string            `json:"value"`
	Claims []NotTenancyClaim `json:"claims,omitempty"`
}

// NotTenancyClaim is one such claim, with the vendor's sentence about it.
type NotTenancyClaim struct {
	Claim    string `json:"claim"`
	Why      string `json:"why"`
	Evidence Fact   `json:"evidence"`
	Context  []Fact `json:"context,omitempty"`
	// LookedIn lists the pages searched for a sentence that would settle
	// whether the claim names a tenant.
	LookedIn []string `json:"looked_in,omitempty"`
}

// SubjectForms is every form of sub the issuer documents with a tenant at its
// head, and the leading literals that never pin one. A sub led by a literal
// the census does not list here names no tenant.
type SubjectForms struct {
	// Value is "verified" or "unverified". A verified list may be empty, with
	// the evidence that sub names no tenant.
	Value    string        `json:"value"`
	Forms    []SubjectForm `json:"forms,omitempty"`
	NeverPin []NeverPin    `json:"never_pin,omitempty"`
	ChosenBy []Fact        `json:"chosen_by,omitempty"`
	// Customisable is "yes", "no" or "unverified": whether the token's minter
	// can replace the default subject.
	Customisable string   `json:"customisable,omitempty"`
	Evidence     []Fact   `json:"evidence,omitempty"`
	Note         string   `json:"note,omitempty"`
	LookedIn     []string `json:"looked_in,omitempty"`
}

// SubjectForm is one form of sub: a leading literal, then the tenant's parts in
// order, each with the delimiter that ends it.
type SubjectForm struct {
	Form            string        `json:"form"`
	LeadingLiteral  string        `json:"leading_literal"`
	Shape           string        `json:"shape,omitempty"`
	OwnerParts      []SubjectPart `json:"owner_parts,omitempty"`
	RepositoryParts []SubjectPart `json:"repository_parts,omitempty"`
	// Evidence is a subject the vendor prints in this form. Where the vendor
	// prints none, Evidence is the zero Fact, Basis is "chain" and the form
	// follows from the sentences in Chain, read in order.
	Evidence  Fact   `json:"evidence,omitzero"`
	Basis     string `json:"basis,omitempty"`
	Chain     []Fact `json:"chain,omitempty"`
	IssuedFor []Fact `json:"issued_for,omitempty"`
	Note      string `json:"note,omitempty"`
}

// SubjectPart is one part of a subject form's tenant.
type SubjectPart struct {
	// Kind is "name" or "id".
	Kind           string `json:"kind"`
	DelimiterAfter string `json:"delimiter_after"`
}

// NeverPin is a leading literal whose subjects name no tenant of the token's,
// such as GitHub's job_workflow_ref:, which names the called workflow.
type NeverPin struct {
	LeadingLiteral string `json:"leading_literal"`
	Why            string `json:"why"`
	Evidence       Fact   `json:"evidence"`
}

// OwnerCharset is the character set of owner names. A delimiter outside it
// cannot occur inside a name, so it ends the owner in a subject form.
type OwnerCharset struct {
	// Value is "verified" or "unverified".
	Value string `json:"value"`
	// Characters lists single characters and ranges such as "a-z".
	Characters  []string `json:"characters,omitempty"`
	Description string   `json:"description,omitempty"`
	Evidence    []Fact   `json:"evidence,omitempty"`
	Context     []Fact   `json:"context,omitempty"`
}

// RepositoryCharset is the character set of repository names. A character
// outside it occurs in no repository's name.
type RepositoryCharset struct {
	// Value is "verified" or "unverified".
	Value string `json:"value"`
	// Characters lists single characters and ranges such as "a-z".
	Characters  []string `json:"characters,omitempty"`
	Description string   `json:"description,omitempty"`
	Evidence    []Fact   `json:"evidence,omitempty"`
	Context     []Fact   `json:"context,omitempty"`
}

// NameCase records whether owner names are unique regardless of case, which
// decides whether two spellings of a declared owner name one owner.
type NameCase struct {
	// Value is "yes", "no" or "unverified".
	Value    string   `json:"value"`
	Evidence []Fact   `json:"evidence,omitempty"`
	Context  []Fact   `json:"context,omitempty"`
	Note     string   `json:"note,omitempty"`
	LookedIn []string `json:"looked_in,omitempty"`
}

// MatchRule is how an issuer URL that names its tenant is read: the pattern,
// the placeholders the tenant is spelled from, and what the tenant is. It is
// verified only where a vendor sentence gives the pattern; an entry without it
// is matched by its exact issuer, or not at all.
type MatchRule struct {
	// Value is "verified" or "unverified".
	Value             string `json:"value"`
	IssuerPattern     string `json:"issuer_pattern,omitempty"`
	TenantPlaceholder string `json:"tenant_placeholder,omitempty"`
	// TenantKind is "name" or "id".
	TenantKind string `json:"tenant_kind,omitempty"`
	// TenantSyntax is "guid" when the vendor documents the tenant as one.
	TenantSyntax         string `json:"tenant_syntax,omitempty"`
	TenantSyntaxEvidence []Fact `json:"tenant_syntax_evidence,omitempty"`
	// TenantImmutable is "yes", "no" or "unverified".
	TenantImmutable         string `json:"tenant_immutable,omitempty"`
	TenantImmutableEvidence []Fact `json:"tenant_immutable_evidence,omitempty"`
	// TenantRecyclable is "yes" where a vendor sentence says the tenant's
	// name passes to another customer, "no" where one says it never does,
	// and "unverified" otherwise, which reads as recyclable.
	TenantRecyclable         string                 `json:"tenant_recyclable,omitempty"`
	TenantRecyclableEvidence []Fact                 `json:"tenant_recyclable_evidence,omitempty"`
	NotAControlledTenant     []NotAControlledTenant `json:"not_a_controlled_tenant,omitempty"`
	Evidence                 []Fact                 `json:"evidence,omitempty"`
	Context                  []Fact                 `json:"context,omitempty"`
	Note                     string                 `json:"note,omitempty"`
}

// NotAControlledTenant is a tenant the pattern matches that anyone can join.
type NotAControlledTenant struct {
	Tenant   string `json:"tenant"`
	Why      string `json:"why"`
	Evidence Fact   `json:"evidence"`
	// Context holds the sentences that tie Evidence to the issuer, where
	// Evidence describes another claim.
	Context []Fact `json:"context,omitempty"`
}

// TenantMembership records whether a tenant's owner controls who obtains
// tokens naming it.
type TenantMembership struct {
	// Value is "controlled" or "unverified".
	Value string `json:"value"`
	// Basis is "chain" when no single sentence states the value and it
	// follows from the sentences in Chain, read in order.
	Basis    string `json:"basis,omitempty"`
	Evidence []Fact `json:"evidence,omitempty"`
	Chain    []Fact `json:"chain,omitempty"`
	Context  []Fact `json:"context,omitempty"`
	// Notes are conclusions drawn from the facts; a derived one says so.
	Notes []string `json:"notes,omitempty"`
	// Unverified lists what no vendor sentence in this release settles here.
	Unverified []string `json:"unverified,omitempty"`
	LookedIn   []string `json:"looked_in,omitempty"`
}

// BuiltIn records a provider STS accepts tokens from with no identity provider
// in the role's account.
type BuiltIn struct {
	// Value is "yes" or "unverified".
	Value string `json:"value"`
	// Principal is how a trust policy names the provider.
	Principal string `json:"principal,omitempty"`
	Evidence  []Fact `json:"evidence,omitempty"`
	// Discrepancy holds AWS's pages that disagree with Evidence.
	Discrepancy []Fact `json:"discrepancy,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Accounts records the platform whose accounts hold the issuer's tenants,
// and the namespace a consumer declares its owners in.
type Accounts struct {
	// Value is "verified" or "unverified".
	Value string `json:"value"`
	// Platform is how the vendor's sentence names the platform, such as
	// "GitHub": where the accounts are, not the product that mints tokens.
	Platform string `json:"platform,omitempty"`
	// DeclarationNamespace is the prefix a consumer declares this issuer's
	// owners under by name, such as github in github:acme. Only an issuer
	// whose claims name owners has one, and no two entries share one.
	DeclarationNamespace string `json:"declaration_namespace,omitempty"`
	Evidence             []Fact `json:"evidence,omitempty"`
	Note                 string `json:"note,omitempty"`
}

// AWSConditionKeys records the condition keys AWS documents for the issuer,
// each with the claim AWS's table says it reads the key from. What a trust
// policy's condition on <provider>:<key> tests for a key not listed here, AWS
// does not document.
type AWSConditionKeys struct {
	// Value is "verified" or "unverified".
	Value string `json:"value"`
	// Basis is "chain" when no single page says AWS's keys apply to this
	// issuer and it follows from the sentences in Chain, read in order.
	Basis string            `json:"basis,omitempty"`
	Keys  []AWSConditionKey `json:"keys,omitempty"`
	// Evidence holds AWS's sentences and its tables as the page renders
	// them; each key's row is among them.
	Evidence []Fact `json:"evidence,omitempty"`
	Chain    []Fact `json:"chain,omitempty"`
	Context  []Fact `json:"context,omitempty"`
	Note     string `json:"note,omitempty"`
}

// AWSIdentityProviderControls records the check AWS makes of a trust policy
// that trusts the issuer, which AWS calls its identity-provider controls: IAM
// refuses to create or update one whose condition tests none of the Keys as
// <provider>:<key>. Of GitHub's sub, AWS adds that a value that is solely a
// wildcard character (* and ?) or null fails as well. It does not evaluate
// trust policies that existed before, so one of those may test none of the
// keys and still admit.
type AWSIdentityProviderControls struct {
	// Value is "verified" or "unverified".
	Value string `json:"value"`
	// Keys are the condition keys of which the check requires a trust policy
	// to test one, as AWSConditionKeys names keys: each one AWS documents for
	// the issuer. Where AWS's pages name different keys, Keys holds each key
	// a page names and Discrepancy the page that names fewer, so a policy
	// that tests none of them is refused on every page, and one that tests
	// only a key some page leaves out may still be refused.
	Keys []string `json:"keys,omitempty"`
	// ExistingTrustPolicies is "not_evaluated": AWS does not check a trust
	// policy that existed before, until it is changed.
	ExistingTrustPolicies string `json:"existing_trust_policies,omitempty"`
	Evidence              []Fact `json:"evidence,omitempty"`
	// Discrepancy holds AWS's pages that name the check otherwise.
	Discrepancy []Fact `json:"discrepancy,omitempty"`
	Note        string `json:"note,omitempty"`
}

// AWSConditionKey is one condition key AWS documents for an issuer.
type AWSConditionKey struct {
	Key string `json:"key"`
	// Claim is the claim AWS's table says it reads the key from, as the
	// table writes it: not always the key's own name. It is "unverified"
	// when no vendor sentence says the issuer's tokens carry the claim as
	// the table spells it; TableClaim then holds that spelling and Why says
	// what the pages say instead.
	Claim      string `json:"claim"`
	TableClaim string `json:"table_claim,omitempty"`
	Why        string `json:"why,omitempty"`
	// FallbackClaim is the claim AWS reads the key from when the token sets
	// no value for Claim, where AWS's sentence says so: the Default tab's aud
	// reads azp, or aud.
	FallbackClaim string `json:"fallback_claim,omitempty"`
	// Multivalued is "yes" when AWS's sentence says the key is multivalued,
	// quoted among the facts behind the key list, and "unverified" when the
	// census holds no AWS sentence saying so.
	Multivalued string `json:"multivalued"`
}

// MultiValuedClaims records the claims the issuer's tokens may carry with
// several values, each on the sentences that say so, as Kubernetes says of a
// service account token's audience: "May be repeated to request a token valid
// for multiple audiences." A claim not listed is not thereby one value.
type MultiValuedClaims struct {
	// Value is "verified" or "unverified".
	Value  string             `json:"value"`
	Claims []MultiValuedClaim `json:"claims,omitempty"`
}

// MultiValuedClaim is one claim the issuer's tokens may carry with several
// values, and the sentences behind it.
type MultiValuedClaim struct {
	Claim    string `json:"claim"`
	Evidence []Fact `json:"evidence"`
	Context  []Fact `json:"context,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Host is the issuer's hostname, with no scheme and no path. For a per-tenant
// issuer whose tenant sits in the path, this is the shared host. It is empty
// when the issuer field holds a note, such as "unverified", rather than an
// issuer.
func (i Issuer) Host() string {
	if h := hostOf(i.Issuer); h != "" {
		return h
	}
	return hostOf(i.IssuerPattern)
}

// hostOf is the host of an issuer URL or bare host, or "" for a note: a note
// has spaces in it or no dot.
func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if n := strings.IndexByte(u, '/'); n >= 0 {
		u = u[:n]
	}
	if !strings.Contains(u, ".") || strings.ContainsAny(u, " \t\n") {
		return ""
	}
	return u
}

// AudienceIsBoundary reports whether conditioning on `aud` constrains anything
// for this issuer. The second return is false when nobody has confirmed it --
// callers must not read that as "yes".
func (i Issuer) AudienceIsBoundary() (isBoundary, known bool) {
	switch i.AudControlledBy {
	case "workload":
		return false, true
	case "relying_party", "issuer":
		return true, true
	default:
		return false, false
	}
}

// SubjectsAreRecyclable reports whether this issuer offers any immutable
// identifier. When it does not, every subject written against it is a name that
// can be released and re-registered by someone else.
func (i Issuer) SubjectsAreRecyclable() bool { return len(i.ImmutableIDClaims) == 0 }

// Tenancy is the entry as the tenancy sub-package carries it: the values a
// classifier reads, with every unverified value, multi-valued claim and claim
// of unknown cardinality left out, so that absent reads the cautious way.
// scripts/build.py writes the sub-package's data by the same rule, and the
// tests hold the two to each other.
func (i Issuer) Tenancy() tenancy.Issuer {
	t := tenancy.Issuer{Name: i.Name, Issuer: i.Issuer}
	if m := i.Match; m.Value == "verified" {
		t.Issuer, t.TenantPlaceholder, t.TenantKind, t.TenantSyntax = m.IssuerPattern, m.TenantPlaceholder, m.TenantKind, m.TenantSyntax
		t.TenantRecyclable = settled(m.TenantRecyclable)
		for _, x := range m.NotAControlledTenant {
			t.NotAControlledTenant = append(t.NotAControlledTenant, x.Tenant)
		}
	}
	if i.TenantMembership.Value == "controlled" {
		t.TenantMembership = "controlled"
	}
	t.AnonymousTokens = settled(i.AnonymousTokens.Value)
	if i.TenancyClaims.Value == "verified" {
		for _, c := range i.TenancyClaims.Claims {
			if c.MultiValued == "no" {
				t.TenancyClaims = append(t.TenancyClaims, tenancy.Claim{
					Claim: c.Claim, Kind: c.Kind, Scope: c.Scope, Immutable: settled(c.Immutable)})
			}
		}
	}
	if i.NotTenancy.Value == "verified" {
		for _, c := range i.NotTenancy.Claims {
			t.NotTenancy = append(t.NotTenancy, c.Claim)
		}
	}
	if i.SubjectForms.Value == "verified" {
		for _, f := range i.SubjectForms.Forms {
			t.SubjectForms = append(t.SubjectForms, tenancy.SubjectForm{
				LeadingLiteral: f.LeadingLiteral, OwnerParts: parts(f.OwnerParts), RepositoryParts: parts(f.RepositoryParts)})
		}
		for _, n := range i.SubjectForms.NeverPin {
			t.NeverPin = append(t.NeverPin, n.LeadingLiteral)
		}
	}
	if i.OwnerCharset.Value == "verified" {
		t.OwnerNameCharacters = slices.Clone(i.OwnerCharset.Characters)
	}
	if i.RepositoryCharset.Value == "verified" {
		t.RepositoryNameCharacters = slices.Clone(i.RepositoryCharset.Characters)
	}
	t.NamesUniqueRegardlessOfCase = settled(i.NamesUniqueRegardlessOfCase.Value)
	if i.AWSConditionKeys.Value == "verified" {
		for _, k := range i.AWSConditionKeys.Keys {
			key := tenancy.ConditionKey{Key: k.Key, Claim: k.Claim, FallbackClaim: k.FallbackClaim}
			if k.Claim == "unverified" {
				key = tenancy.ConditionKey{Key: k.Key, TableClaim: k.TableClaim}
			}
			if k.Multivalued == "yes" {
				key.Multivalued = "yes"
			}
			t.AWSConditionKeys = append(t.AWSConditionKeys, key)
		}
	}
	if i.AWSIdentityProviderControls.Value == "verified" {
		t.AWSIdentityProviderControlKeys = slices.Clone(i.AWSIdentityProviderControls.Keys)
	}
	if i.MultiValuedClaims.Value == "verified" {
		for _, c := range i.MultiValuedClaims.Claims {
			t.MultiValuedClaims = append(t.MultiValuedClaims, c.Claim)
		}
	}
	if i.Accounts.Value == "verified" {
		t.Platform, t.DeclarationNamespace = i.Accounts.Platform, i.Accounts.DeclarationNamespace
	}
	return t
}

// settled is a yes-or-no value as the sub-package carries it: "yes" and "no"
// stay, and anything else is left out, which reads as unverified.
func settled(v string) string {
	if v == "yes" || v == "no" {
		return v
	}
	return ""
}

func parts(ps []SubjectPart) []tenancy.Part {
	if len(ps) == 0 {
		return nil
	}
	out := make([]tenancy.Part, len(ps))
	for n, p := range ps {
		out[n] = tenancy.Part{Kind: p.Kind, DelimiterAfter: p.DelimiterAfter}
	}
	return out
}

// matchKey is the census string Match reads an entry by, and whether Match
// can return the entry at all: its verified issuer pattern, or its exact
// issuer when that is a URL or host rather than a note or an unverified
// pattern.
func matchKey(e Issuer) (string, bool) {
	if e.Match.Value == "verified" {
		return e.Match.IssuerPattern, true
	}
	if hostOf(e.Issuer) == "" || strings.ContainsAny(e.Issuer, "<>") {
		return "", false
	}
	return e.Issuer, true
}

var (
	once       sync.Once
	censusDate string
	// entries holds each entry as the census wrote it. Every answer is
	// decoded from it afresh, so what a caller is handed is its own, however
	// deep it edits: the census the next caller reads cannot change.
	entries     []json.RawMessage
	byHost      map[string]int
	byMatchKey  map[string]int
	multiTenant []string
)

func load() {
	once.Do(func() {
		var doc struct {
			CensusDate string            `json:"census_date"`
			Issuers    []json.RawMessage `json:"issuers"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			panic("issuers: embedded census is not valid JSON: " + err.Error())
		}
		censusDate, entries = doc.CensusDate, doc.Issuers
		byHost = make(map[string]int, len(entries))
		byMatchKey = make(map[string]int, len(entries))
		shared := map[string]bool{}
		for n := range entries {
			e := entry(n)
			if key, ok := matchKey(e); ok {
				byMatchKey[key] = n
			}
			h := e.Host()
			if h == "" {
				continue
			}
			if (e.TenancyModel == "shared" || e.TenancyModel == "per_tenant_path") && !shared[h] {
				shared[h] = true
				multiTenant = append(multiTenant, h)
			}
			// Several entries can share a host, told apart by path. A lookup
			// by host alone answers with the host's own issuer, as it did
			// before any host had two entries, and otherwise with the first.
			if prev, seen := byHost[foldASCII(h)]; !seen || !ownsHost(entry(prev)) && ownsHost(e) {
				byHost[foldASCII(h)] = n
			}
		}
	})
}

// entry decodes the nth entry of the census afresh.
func entry(n int) Issuer {
	var e Issuer
	if err := json.Unmarshal(entries[n], &e); err != nil {
		panic("issuers: embedded census entry is not valid JSON: " + err.Error())
	}
	return e
}

// ownsHost reports whether the entry's issuer is its host alone, with no path.
func ownsHost(e Issuer) bool {
	u := strings.TrimPrefix(e.Issuer, "https://")
	return u != "" && !strings.Contains(strings.TrimSuffix(u, "/"), "/")
}

// CensusDate is the date the embedded snapshot was taken, as YYYY-MM-DD.
// Facts added since carry their own verified_at.
func CensusDate() string { load(); return censusDate }

// All returns every entry, in census order. Everything in it is the caller's
// own: sort it or edit it, and the next answer is still the census's.
func All() []Issuer {
	load()
	out := make([]Issuer, len(entries))
	for n := range entries {
		out[n] = entry(n)
	}
	return out
}

// Get looks an issuer up by hostname or by a full issuer URL. The second return
// is false when the host is not in the census, which means nobody has surveyed
// it -- not that it is safe. When several entries share the host, it returns
// the one whose issuer is the host itself; Match reads the path as well.
// Hosts compare without ASCII case and no other, as Match's do.
func Get(hostOrURL string) (Issuer, bool) {
	load()
	h := strings.TrimPrefix(strings.TrimPrefix(hostOrURL, "https://"), "http://")
	if n := strings.IndexByte(h, '/'); n >= 0 {
		h = h[:n]
	}
	n, ok := byHost[foldASCII(h)]
	if !ok {
		return Issuer{}, false
	}
	return entry(n), true
}

// foldASCII lower-cases ASCII letters only. strings.ToLower also folds the
// Kelvin sign onto k and U+0130 onto i, which would let a look-alike host pass
// for a census host.
func foldASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// Match finds the census entry for an issuer URL and the tenant the URL names,
// by the rules the tenancy sub-package documents, and returns the whole entry
// with every fact behind it. ok is false when no entry matches: nobody
// surveyed that issuer, which never means it is safe.
func Match(issuer string) (e Issuer, tenant string, ok bool) {
	t, tenant, ok := tenancy.Match(issuer)
	if !ok {
		return Issuer{}, "", false
	}
	load()
	n, ok := byMatchKey[t.Issuer]
	if !ok {
		return Issuer{}, "", false
	}
	return entry(n), tenant, true
}

// MultiTenantHosts returns the hostnames of every issuer shared between the
// tenants of one vendor, so that a token from any tenant carries the same `iss`.
// Conditioning on the issuer alone does not identify a tenant on these. A host
// missing from the list is not thereby known to identify a tenant: its entry
// may be unverified, or not in the census at all.
//
// This is a drop-in for a hard-coded set of the same shape.
func MultiTenantHosts() []string {
	load()
	return append([]string{}, multiTenant...)
}

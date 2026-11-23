// Package tenancy is the part of the issuer census a trust-policy classifier
// reads to decide who can hold a token an issuer mints: which census entry an
// issuer URL is, which tenant the URL names, whether that tenant's owner
// controls who obtains tokens, and which claims and subject forms name a
// tenant at all.
//
// It carries those values and nothing else, so a program that needs them
// links a few kilobytes rather than the whole census. The sentence behind
// every value is in the root package, github.com/CloudArq-net/issuers; this
// package's data, tenancy.json, is generated from the same issuers.yaml by
// scripts/build.py, and the repository's checks fail when the two disagree.
//
// A value no vendor sentence establishes is absent here, never written as a
// guess, and every reader below answers an absent value the cautious way: an
// issuer may mint tokens to people with no account, a tenant is not known to
// control who joins it and its name may pass to someone else, any character
// may occur in an owner's or a repository's name, and names compare exactly.
package tenancy

import (
	_ "embed"
	"encoding/json"
	"slices"
	"sync"
)

//go:embed tenancy.json
var raw []byte

// Issuer is one census entry as a classifier reads it. A field that is empty
// or nil is one the census has not verified for this issuer.
type Issuer struct {
	Name string `json:"name"`
	// Issuer is the census string this entry is matched by: the exact issuer,
	// or, when the issuer URL itself names a tenant, the issuer pattern with
	// its <placeholders>.
	Issuer string `json:"issuer"`
	// TenantPlaceholder spells the tenant a matching URL names from the
	// pattern's placeholders, such as "<project>/<location>/<cluster>".
	// TenantKind is "name" or "id": a name can pass to another owner, an id
	// does not.
	TenantPlaceholder string `json:"tenant_placeholder,omitempty"`
	TenantKind        string `json:"tenant_kind,omitempty"`
	// TenantSyntax is "guid" when the vendor documents the tenant as one, so
	// that a word in its place, such as Entra's "common", names no tenant.
	TenantSyntax string `json:"tenant_syntax,omitempty"`
	// TenantRecyclable is "yes" when a vendor sentence says the tenant's name
	// passes to another customer once released, and "no" when one says it
	// never does.
	TenantRecyclable string `json:"tenant_recyclable,omitempty"`
	// TenantMembership is "controlled" when a vendor sentence says the
	// tenant's owner decides who obtains its tokens.
	TenantMembership string `json:"tenant_membership,omitempty"`
	// NotAControlledTenant lists tenants anyone can join although the pattern
	// matches them, such as Entra's personal-Microsoft-account tenant.
	NotAControlledTenant []string `json:"not_a_controlled_tenant,omitempty"`
	// AnonymousTokens is "yes" when the issuer mints tokens to people with no
	// account anywhere and "no" when vendor sentences rule that out.
	AnonymousTokens string `json:"anonymous_tokens,omitempty"`
	// TenancyClaims are the claims whose single value names an owner, a
	// repository or an enterprise. A claim not listed names no tenant.
	TenancyClaims []Claim `json:"tenancy_claims,omitempty"`
	// NotTenancy are claims that look as if they name a tenant and never pin
	// one. A name ending in * stands for every claim whose name begins with
	// the text before it. The census lists no tenancy claim here.
	NotTenancy []string `json:"not_tenancy,omitempty"`
	// SubjectForms are the forms of sub that lead with a tenant, each a
	// leading literal and the tenant's parts in order. A sub led by anything
	// else names no tenant.
	SubjectForms []SubjectForm `json:"subject_forms,omitempty"`
	// NeverPin are leading literals whose subjects name no tenant of the
	// token's. None begins a form's leading literal or is begun by one.
	NeverPin []string `json:"never_pin,omitempty"`
	// OwnerNameCharacters is the character set of owner names, as single
	// characters and ranges such as "a-z". A delimiter outside it cannot
	// occur inside a name, which is what lets a subject form's delimiter end
	// the owner.
	OwnerNameCharacters []string `json:"owner_name_characters,omitempty"`
	// RepositoryNameCharacters is the character set of repository names, in
	// OwnerNameCharacters' form. A character outside it occurs in no
	// repository's name.
	RepositoryNameCharacters []string `json:"repository_name_characters,omitempty"`
	// NamesUniqueRegardlessOfCase is "yes" when the vendor documents that two
	// owners' names never differ only in case.
	NamesUniqueRegardlessOfCase string `json:"names_unique_regardless_of_case,omitempty"`
	// AWSConditionKeys are the condition keys AWS documents for the issuer,
	// each with the claim AWS reads it from. What a trust policy's condition
	// on <provider>:<key> tests for a key not listed here, AWS does not
	// document. Empty when the census does not record them.
	AWSConditionKeys []ConditionKey `json:"aws_condition_keys,omitempty"`
	// AWSRequiredConditionKey is the condition key, named as AWSConditionKeys
	// names keys, that AWS requires a trust policy trusting the issuer to
	// test: IAM refuses to create or update one whose condition does not test
	// <provider>:<key>, or tests it with a value that is solely a wildcard
	// character (* and ?) or null. IAM does not evaluate trust policies that
	// existed before, so one of those may lack the key. Empty when the census
	// does not record the check.
	AWSRequiredConditionKey string `json:"aws_required_condition_key,omitempty"`
	// MultiValuedClaims are the claims a sentence says the issuer's tokens
	// may carry with several values, as Kubernetes says of a service account
	// token's audience. A claim not listed is not thereby one value.
	MultiValuedClaims []string `json:"multi_valued_claims,omitempty"`
	// Platform is where the issuer's tenants hold their accounts, as a vendor
	// sentence names it, such as "GitHub": the platform, not the product that
	// mints the tokens. Empty when no sentence in this release names it.
	Platform string `json:"platform,omitempty"`
	// DeclarationNamespace is the prefix a consumer declares this issuer's
	// owners under by name, such as github in github:acme. No two entries
	// share one, since the same name under another issuer is another owner;
	// it is empty for an issuer whose owners are not declared by name.
	DeclarationNamespace string `json:"declaration_namespace,omitempty"`
}

// Claim is one claim that names a tenant.
type Claim struct {
	Claim string `json:"claim"`
	// Kind is "name" or "id".
	Kind string `json:"kind"`
	// Scope is "owner", "repository" or "enterprise": the only tenants there
	// are. The person who started a run is never one.
	Scope string `json:"scope"`
	// Immutable is "yes" or "no" when a vendor sentence says whether the
	// value can pass to someone else.
	Immutable string `json:"immutable,omitempty"`
}

// ValueIsRecyclable reports whether a value of this claim can be released and
// pass to someone else, which would put their tokens behind a trust that
// names it. known is false when no vendor sentence settles it, and the answer
// beside it is then the cautious one, true, whatever the claim's kind.
func (c Claim) ValueIsRecyclable() (recyclable, known bool) {
	switch c.Immutable {
	case "yes":
		return false, true
	case "no":
		return true, true
	}
	return true, false
}

// ConditionKey is one condition key AWS documents for an issuer and the
// claim AWS reads it from, which is not always the claim of the key's own
// name: on AWS's Default tab oaud reads aud, and aud reads azp, or aud when
// the token sets no azp. Claims are written as AWS's table writes them,
// which for Login with Amazon and Facebook is a phrase such as "User ID".
type ConditionKey struct {
	Key string `json:"key"`
	// Claim is empty when no vendor sentence says the issuer's tokens carry
	// the claim as AWS's table spells it, and TableClaim then holds that
	// spelling. Google's reference nests the number AWS's table spells
	// google:organization_number inside a google claim, and no page says
	// which AWS reads, so a reader has no claim to look up for that key.
	Claim      string `json:"claim,omitempty"`
	TableClaim string `json:"table_claim,omitempty"`
	// FallbackClaim is the claim AWS reads the key from when the token sets
	// no value for Claim; empty when AWS's table names no other.
	FallbackClaim string `json:"fallback_claim,omitempty"`
	// Multivalued is "yes" when AWS's sentence says the key is multivalued,
	// as it says of amr: "The key is multivalued, meaning that you test it in
	// a policy using condition set operators." A request may then carry
	// several values for the key, as an authenticated user's amr holds
	// authenticated and the provider the user signed in with. Empty when the
	// census holds no AWS sentence saying so.
	Multivalued string `json:"multivalued,omitempty"`
}

// IsMultivalued reports whether a request may carry several values for the
// key. known is false unless AWS's sentence says the key is multivalued: the
// census records no sentence saying a key holds one value, so an unknown
// answer is the cautious one, true, since a key AWS has not said holds one
// value may hold several.
func (c ConditionKey) IsMultivalued() (multivalued, known bool) {
	return true, c.Multivalued == "yes"
}

// ClaimIsMultiValued reports whether the issuer's tokens may carry several
// values in claim. known is false unless a sentence the census holds says
// they may, and the answer beside it is then the cautious one, true. Claim
// names compare as written, as a token's do.
func (i Issuer) ClaimIsMultiValued(claim string) (multiValued, known bool) {
	return true, slices.Contains(i.MultiValuedClaims, claim)
}

// SubjectForm is one way an issuer spells sub with a tenant at its head.
type SubjectForm struct {
	LeadingLiteral  string `json:"leading_literal"`
	OwnerParts      []Part `json:"owner_parts,omitempty"`
	RepositoryParts []Part `json:"repository_parts,omitempty"`
}

// Part is one part of a subject form's tenant and the delimiter after it.
type Part struct {
	// Kind is "name" or "id".
	Kind           string `json:"kind"`
	DelimiterAfter string `json:"delimiter_after"`
}

// IssuesAnonymousTokens reports whether the issuer mints tokens to people with
// no account anywhere. known is false when the census has not verified it, and
// the answer beside it is then the cautious one, true: an unverified issuer
// may.
func (i Issuer) IssuesAnonymousTokens() (anonymous, known bool) {
	switch i.AnonymousTokens {
	case "yes":
		return true, true
	case "no":
		return false, true
	}
	return true, false
}

// ControlledTenant reports whether the owner of tenant, as Match names it,
// controls who obtains tokens naming it. It is known and false for a tenant
// the census lists as open to anyone, which its own sentence settles whatever
// the issuer's membership, and not known for any other tenant when the census
// has not verified the issuer's membership.
func (i Issuer) ControlledTenant(tenant string) (controlled, known bool) {
	if tenant == "" {
		return false, false
	}
	for _, open := range i.NotAControlledTenant {
		// The listed tenants are GUIDs, whose letters are hex digits that
		// name the same tenant in either case.
		if equalFoldASCII(open, tenant) {
			return false, true
		}
	}
	if i.TenantMembership != "controlled" {
		return false, false
	}
	return true, true
}

// TenantIsRecyclable reports whether the tenant a matching issuer URL names
// can be released and taken by another customer, which would put that
// customer's tokens behind the same issuer. known is false when no vendor
// sentence settles it, and the answer beside it is then the cautious one,
// true.
func (i Issuer) TenantIsRecyclable() (recyclable, known bool) {
	switch i.TenantRecyclable {
	case "yes":
		return true, true
	case "no":
		return false, true
	}
	return true, false
}

// AWSMapsConditionKey reports whether AWS documents key as a condition key for
// the issuer, which is what puts a claim in the request context that a trust
// policy's condition on <provider>:<key> reads. Keys compare without ASCII
// case, as AWS reads them: "Context key names are not case-sensitive."
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html).
// known is false when the census does not record AWS's keys for the issuer,
// and the answer beside it is then the cautious one, false: a condition on a
// key not known to be mapped is read as unread, which never pins and never
// narrows.
func (i Issuer) AWSMapsConditionKey(key string) (mapped, known bool) {
	if len(i.AWSConditionKeys) == 0 {
		return false, false
	}
	_, mapped = i.AWSConditionKey(key)
	return mapped, true
}

// AWSConditionKey is AWS's record of key for the issuer: the claim AWS reads
// it from, the one it reads when the token sets no value for that claim, and
// whether AWS says the key is multivalued, which IsMultivalued reads.
// A record with no claim is a key AWS documents whose claim no sentence says
// a token carries as AWS spells it, so what a token carries for the key is
// not known.
// Keys compare without ASCII case, as in AWSMapsConditionKey. ok is false
// when AWS documents no such key for the issuer, or when the census does not
// record its keys; AWSMapsConditionKey tells the two apart.
func (i Issuer) AWSConditionKey(key string) (record ConditionKey, ok bool) {
	for _, c := range i.AWSConditionKeys {
		if equalFoldASCII(c.Key, key) {
			return c, true
		}
	}
	return ConditionKey{}, false
}

// OwnerNameMayContain reports whether r can occur in an owner name. With no
// recorded character set, or one this package cannot read, any character may.
func (i Issuer) OwnerNameMayContain(r rune) bool {
	return mayContain(i.OwnerNameCharacters, r)
}

// RepositoryNameMayContain reports whether r can occur in a repository's
// name. With no recorded character set, or one this package cannot read, any
// character may.
func (i Issuer) RepositoryNameMayContain(r rune) bool {
	return mayContain(i.RepositoryNameCharacters, r)
}

// mayContain reports whether r is in set, single characters and ranges such
// as "a-z"; an empty set, or one with an item it cannot read, holds any
// character.
func mayContain(set []string, r rune) bool {
	if len(set) == 0 {
		return true
	}
	found := false
	for _, c := range set {
		switch {
		case len(c) == 1:
			found = found || rune(c[0]) == r
		case len(c) == 3 && c[1] == '-' && c[0] < c[2]:
			found = found || rune(c[0]) <= r && r <= rune(c[2])
		default:
			return true
		}
	}
	return found
}

// NamesCompareWithoutCase reports whether two owner names that differ only in
// case name one owner. When the census has not verified it, known is false and
// names compare exactly, which can only leave a name unmatched.
func (i Issuer) NamesCompareWithoutCase() (withoutCase, known bool) {
	switch i.NamesUniqueRegardlessOfCase {
	case "yes":
		return true, true
	case "no":
		return false, true
	}
	return false, false
}

// clone is the entry with slices of its own, so a caller that edits what it
// was handed cannot change the census the next caller reads.
func (i Issuer) clone() Issuer {
	i.NotAControlledTenant = slices.Clone(i.NotAControlledTenant)
	i.TenancyClaims = slices.Clone(i.TenancyClaims)
	i.NotTenancy = slices.Clone(i.NotTenancy)
	i.NeverPin = slices.Clone(i.NeverPin)
	i.AWSConditionKeys = slices.Clone(i.AWSConditionKeys)
	i.MultiValuedClaims = slices.Clone(i.MultiValuedClaims)
	i.OwnerNameCharacters = slices.Clone(i.OwnerNameCharacters)
	i.RepositoryNameCharacters = slices.Clone(i.RepositoryNameCharacters)
	if i.SubjectForms != nil {
		forms := make([]SubjectForm, len(i.SubjectForms))
		for n, f := range i.SubjectForms {
			forms[n] = SubjectForm{f.LeadingLiteral, slices.Clone(f.OwnerParts), slices.Clone(f.RepositoryParts)}
		}
		i.SubjectForms = forms
	}
	return i
}

var (
	once   sync.Once
	loaded struct {
		CensusDate string   `json:"census_date"`
		Issuers    []Issuer `json:"issuers"`
	}
	census *matcher
)

func load() {
	once.Do(func() {
		if err := json.Unmarshal(raw, &loaded); err != nil {
			panic("tenancy: embedded census is not valid JSON: " + err.Error())
		}
		m, err := compile(loaded.Issuers)
		if err != nil {
			panic("tenancy: embedded census does not compile: " + err.Error())
		}
		census = m
	})
}

// CensusDate is the date of the census this data was generated from, as
// YYYY-MM-DD. A fact added later carries its own date in the root package.
func CensusDate() string { load(); return loaded.CensusDate }

// All returns every entry an issuer can match, in census order.
func All() []Issuer {
	load()
	out := make([]Issuer, len(loaded.Issuers))
	for n, e := range loaded.Issuers {
		out[n] = e.clone()
	}
	return out
}

// Match finds the census entry for an issuer URL, as a token's iss or a trust
// policy's provider carries it, and the tenant the URL names ("" for an issuer
// that names none). ok is false when no entry matches, which means nobody
// surveyed that issuer: never that it is safe.
//
// An issuer is read with https:// or with no scheme, its host compared without
// ASCII case and its path exactly, one trailing slash ignored. An exact issuer
// matches only itself. A pattern matches when every placeholder holds one
// non-empty host label of letters, digits and dashes, or one path segment of
// letters, digits, dashes and underscores, in the tenant's syntax where the
// census records one. Of several matching entries, the one with the most
// characters outside placeholders wins, and of those the first in census
// order.
func Match(issuer string) (Issuer, string, bool) {
	load()
	return census.match(issuer)
}

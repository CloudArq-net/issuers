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
// may occur in an owner name, and names compare exactly.
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
	// NamesUniqueRegardlessOfCase is "yes" when the vendor documents that two
	// owners' names never differ only in case.
	NamesUniqueRegardlessOfCase string `json:"names_unique_regardless_of_case,omitempty"`
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

// OwnerNameMayContain reports whether r can occur in an owner name. With no
// recorded character set, or one this package cannot read, any character may.
func (i Issuer) OwnerNameMayContain(r rune) bool {
	if len(i.OwnerNameCharacters) == 0 {
		return true
	}
	found := false
	for _, c := range i.OwnerNameCharacters {
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
	i.OwnerNameCharacters = slices.Clone(i.OwnerNameCharacters)
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

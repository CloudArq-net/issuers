// Package issuers is a census of the OIDC issuers a cloud provider will federate
// to for workload identity, with the fields a policy evaluator actually needs:
// how the issuer is tenanted, what its subject looks like, which claims it emits,
// which of those claims are immutable, and who chooses the audience.
//
// It has no dependencies and makes no network calls. The data is embedded at
// build time and is a snapshot, not a live view; see the census date.
//
// Four fields are not published anywhere else, and three of them exist because
// the obvious reading of the data is wrong:
//
//   - AudControlledBy names who picks the `aud` value. When it is "workload",
//     `aud` is not a boundary: anyone who can run a job on that platform can
//     request a token carrying your audience. Sixteen of the entries here are
//     in that state, GitHub Actions among them.
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
// Anything nobody confirmed says "unverified". That never means "absent".
package issuers

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed issuers.json
var raw []byte

// Issuer is one entry in the census. Absent fields are absent because nobody
// confirmed them, not because the answer is known to be empty.
type Issuer struct {
	Name     string `json:"name"`
	Vendor   string `json:"vendor,omitempty"`
	Category string `json:"category"`

	// Issuer is the exact `iss` claim value. IssuerPattern is set instead when
	// the issuer is per-tenant and the value carries a <placeholder>.
	Issuer        string `json:"issuer,omitempty"`
	IssuerPattern string `json:"issuer_pattern,omitempty"`

	// TenancyModel is one of: shared, per_tenant_host, per_tenant_path, unverified.
	TenancyModel string `json:"tenancy_model"`
	TenancyClaim string `json:"tenancy_claim,omitempty"`

	// ControlTest is what a deliberately bogus tenant returned, in words.
	// ControlTestResult is the same answer machine-readable: passed, failed,
	// inconclusive or unverified. "failed" means a bogus tenant was served a
	// real-looking answer, so the URL alone proves nothing about the tenant.
	ControlTest       string `json:"control_test,omitempty"`
	ControlTestResult string `json:"control_test_result,omitempty"`

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
	TokenLifetimeS    int      `json:"token_lifetime_s,omitempty"`

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
}

// Host is the issuer's hostname, with no scheme and no path. For a per-tenant
// issuer whose tenant sits in the path, this is the shared host.
func (i Issuer) Host() string {
	u := i.Issuer
	if u == "" {
		u = i.IssuerPattern
	}
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if n := strings.IndexByte(u, '/'); n >= 0 {
		u = u[:n]
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

type census struct {
	CensusDate string   `json:"census_date"`
	Issuers    []Issuer `json:"issuers"`
}

var (
	once   sync.Once
	parsed census
	byHost map[string]Issuer
)

func load() {
	once.Do(func() {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			panic("issuers: embedded census is not valid JSON: " + err.Error())
		}
		byHost = make(map[string]Issuer, len(parsed.Issuers))
		for _, e := range parsed.Issuers {
			if h := e.Host(); h != "" {
				byHost[h] = e
			}
		}
	})
}

// CensusDate is the date the embedded snapshot was taken, as YYYY-MM-DD.
func CensusDate() string { load(); return parsed.CensusDate }

// All returns every entry. The slice is a copy; callers may sort it.
func All() []Issuer {
	load()
	out := make([]Issuer, len(parsed.Issuers))
	copy(out, parsed.Issuers)
	return out
}

// Get looks an issuer up by hostname or by a full issuer URL. The second return
// is false when the host is not in the census, which means nobody has surveyed
// it -- not that it is safe.
func Get(hostOrURL string) (Issuer, bool) {
	load()
	h := strings.TrimPrefix(strings.TrimPrefix(hostOrURL, "https://"), "http://")
	if n := strings.IndexByte(h, '/'); n >= 0 {
		h = h[:n]
	}
	e, ok := byHost[strings.ToLower(h)]
	return e, ok
}

// MultiTenantHosts returns the hostnames of every issuer shared between the
// tenants of one vendor, so that a token from any tenant carries the same `iss`.
// Conditioning on the issuer alone does not identify a tenant on these.
//
// This is a drop-in for a hard-coded set of the same shape.
func MultiTenantHosts() []string {
	load()
	seen := map[string]struct{}{}
	out := []string{}
	for _, e := range parsed.Issuers {
		if e.TenancyModel != "shared" && e.TenancyModel != "per_tenant_path" {
			continue
		}
		h := e.Host()
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

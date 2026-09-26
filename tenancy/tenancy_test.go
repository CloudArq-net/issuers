package tenancy

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// matchCases is testdata/match_cases.json. The root package and the Python
// package read the same file, so all three answer every case the same way.
type matchCases struct {
	Census    []matchCase `json:"census"`
	Synthetic []struct {
		Why    string      `json:"why"`
		Census []Issuer    `json:"census"`
		Cases  []matchCase `json:"cases"`
	} `json:"synthetic"`
}

type matchCase struct {
	Issuer string  `json:"issuer"`
	Entry  *string `json:"entry"`
	Tenant string  `json:"tenant"`
	Why    string  `json:"why"`
}

func readMatchCases(t *testing.T) matchCases {
	t.Helper()
	b, err := os.ReadFile("testdata/match_cases.json")
	if err != nil {
		t.Fatalf("read the shared match cases: %v", err)
	}
	var mc matchCases
	if err := json.Unmarshal(b, &mc); err != nil {
		t.Fatalf("decode the shared match cases: %v", err)
	}
	if len(mc.Census) == 0 || len(mc.Synthetic) == 0 {
		t.Fatalf("the shared match cases hold %d census and %d synthetic cases; a test over none examines nothing",
			len(mc.Census), len(mc.Synthetic))
	}
	return mc
}

func checkMatch(t *testing.T, c matchCase, got Issuer, tenant string, ok bool) {
	t.Helper()
	switch {
	case c.Entry == nil && ok:
		t.Errorf("Match(%q) = %q, tenant %q; want no match (%s)", c.Issuer, got.Issuer, tenant, c.Why)
	case c.Entry != nil && !ok:
		t.Errorf("Match(%q) found nothing; want %q, tenant %q (%s)", c.Issuer, *c.Entry, c.Tenant, c.Why)
	case c.Entry != nil && (got.Issuer != *c.Entry || tenant != c.Tenant):
		t.Errorf("Match(%q) = %q, tenant %q; want %q, tenant %q (%s)", c.Issuer, got.Issuer, tenant, *c.Entry, c.Tenant, c.Why)
	}
}

func TestMatchReadsTheCensusAsTheSharedCasesSay(t *testing.T) {
	matched, refused := 0, 0
	for _, c := range readMatchCases(t).Census {
		got, tenant, ok := Match(c.Issuer)
		checkMatch(t, c, got, tenant, ok)
		if c.Entry == nil {
			refused++
		} else {
			matched++
		}
	}
	if matched == 0 || refused == 0 {
		t.Fatalf("the shared cases hold %d matches and %d refusals; both kinds must be exercised", matched, refused)
	}
}

func TestMatchRulesOnInventedCensuses(t *testing.T) {
	for _, s := range readMatchCases(t).Synthetic {
		m, err := compile(s.Census)
		if err != nil {
			t.Fatalf("%s: %v", s.Why, err)
		}
		if len(s.Cases) == 0 {
			t.Fatalf("%s: no cases", s.Why)
		}
		for _, c := range s.Cases {
			got, tenant, ok := m.match(c.Issuer)
			checkMatch(t, c, got, tenant, ok)
		}
	}
}

// A malformed pattern must be refused when the census is compiled, never read
// as a looser pattern that matches more than the census says.
func TestCompileRefusesAMalformedPattern(t *testing.T) {
	for _, bad := range []Issuer{
		{Name: "no scheme", Issuer: "example.com/<t>", TenantPlaceholder: "<t>", TenantKind: "name"},
		{Name: "half a placeholder", Issuer: "https://example.com/a<t>", TenantPlaceholder: "<t>", TenantKind: "name"},
		{Name: "unclosed", Issuer: "https://example.com/<t", TenantPlaceholder: "<t", TenantKind: "name"},
		{Name: "tenant not in the pattern", Issuer: "https://example.com/<t>", TenantPlaceholder: "<u>", TenantKind: "name"},
		{Name: "tenant with no placeholder", Issuer: "https://example.com/<t>", TenantPlaceholder: "t", TenantKind: "name"},
		{Name: "placeholder twice", Issuer: "https://<t>.example.com/<t>", TenantPlaceholder: "<t>", TenantKind: "name"},
		{Name: "a pattern with no tenant", Issuer: "https://<t>.example.com"},
		{Name: "a tenant on an exact issuer", Issuer: "https://example.com", TenantPlaceholder: "<t>", TenantKind: "name"},
		{Name: "unknown syntax", Issuer: "https://example.com/<t>", TenantPlaceholder: "<t>", TenantKind: "id", TenantSyntax: "uuid4"},
		{Name: "syntax on a composite tenant", Issuer: "https://example.com/<a>/<b>", TenantPlaceholder: "<a>/<b>", TenantKind: "id", TenantSyntax: "guid"},
		{Name: "empty", Issuer: ""},
	} {
		if _, err := compile([]Issuer{bad}); err == nil {
			t.Errorf("%s: compile accepted %q", bad.Name, bad.Issuer)
		}
	}
	twice := []Issuer{{Name: "a", Issuer: "https://example.com/x"}, {Name: "b", Issuer: "https://EXAMPLE.com/x/"}}
	if _, err := compile(twice); err == nil {
		t.Error("compile accepted two entries with one issuer")
	}
}

// Every entry the sub-package can match must be named by at least one shared
// case, so a new entry cannot arrive without a case the three packages agree on.
func TestEveryEntryHasASharedCase(t *testing.T) {
	named := map[string]bool{}
	for _, c := range readMatchCases(t).Census {
		if c.Entry != nil {
			named[*c.Entry] = true
		}
	}
	entries := All()
	if len(entries) < 29 {
		t.Fatalf("the sub-package holds %d entries; the census has at least 29 an issuer can match", len(entries))
	}
	for _, e := range entries {
		if !named[e.Issuer] {
			t.Errorf("%s (%s): no shared match case names this entry", e.Name, e.Issuer)
		}
	}
}

var placeholder = regexp.MustCompile(`<[A-Za-z0-9_-]+>`)

// instance fills every placeholder of an issuer pattern with a value built
// for it, read here by a regular expression rather than by the package's own
// parser, and returns the issuer and the tenant it should name.
func instance(e Issuer, fill func(name string, inHost bool) string) (issuer, tenant string) {
	rest := strings.TrimPrefix(e.Issuer, "https://")
	hostEnd := strings.IndexByte(rest, '/')
	if hostEnd < 0 {
		hostEnd = len(rest)
	}
	values := map[string]string{}
	var b strings.Builder
	last := 0
	for _, loc := range placeholder.FindAllStringIndex(rest, -1) {
		name := rest[loc[0]:loc[1]]
		v := fill(name, loc[0] < hostEnd)
		values[name] = v
		b.WriteString(rest[last:loc[0]])
		b.WriteString(v)
		last = loc[1]
	}
	b.WriteString(rest[last:])
	tenant = placeholder.ReplaceAllStringFunc(e.TenantPlaceholder, func(n string) string { return values[n] })
	return "https://" + b.String(), tenant
}

func pathOf(issuer string) string {
	rest := strings.TrimPrefix(issuer, "https://")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[i:]
	}
	return ""
}

func TestEveryEntryMatchesItsOwnIssuer(t *testing.T) {
	patterns := 0
	for _, e := range All() {
		if e.TenantPlaceholder == "" {
			withSlash := strings.TrimSuffix(e.Issuer, "/") + "/"
			shouted := strings.ToUpper(strings.TrimSuffix(e.Issuer, pathOf(e.Issuer))) + pathOf(e.Issuer)
			for _, form := range []string{e.Issuer, withSlash, shouted} {
				got, tenant, ok := Match(form)
				if !ok || got.Issuer != e.Issuer || tenant != "" {
					t.Errorf("Match(%q) = %q, %q, %v; want the exact entry %q", form, got.Issuer, tenant, ok, e.Issuer)
				}
			}
			continue
		}
		patterns++
		i := 0
		issuer, tenant := instance(e, func(name string, inHost bool) string {
			i++
			switch {
			case e.TenantSyntax == "guid" && name == e.TenantPlaceholder:
				return "0123abcd-4567-89ef-0123-456789ABCDEF"
			case inHost:
				return fmt.Sprintf("host-%d", i)
			default:
				return fmt.Sprintf("Seg_%d-x", i)
			}
		})
		got, gotTenant, ok := Match(issuer)
		if !ok || got.Issuer != e.Issuer || gotTenant != tenant {
			t.Errorf("Match(%q) = %q, tenant %q, %v; want %q, tenant %q", issuer, got.Issuer, gotTenant, ok, e.Issuer, tenant)
		}
		empty, _ := instance(e, func(string, bool) string { return "" })
		if got, _, ok := Match(empty); ok && got.Issuer == e.Issuer {
			t.Errorf("Match(%q) matched %q with every placeholder empty", empty, e.Issuer)
		}
		split, _ := instance(e, func(_ string, inHost bool) string {
			if inHost {
				return "a.b"
			}
			return "a/b"
		})
		if got, _, ok := Match(split); ok && got.Issuer == e.Issuer {
			t.Errorf("Match(%q) matched %q with a placeholder spanning a delimiter", split, e.Issuer)
		}
	}
	if patterns < 9 {
		t.Fatalf("exercised %d issuer patterns; the census researched 9", patterns)
	}
}

func find(t *testing.T, issuer string) Issuer {
	t.Helper()
	for _, e := range All() {
		if e.Issuer == issuer {
			return e
		}
	}
	t.Fatalf("no entry for %s in the sub-package", issuer)
	return Issuer{}
}

const (
	github      = "https://token.actions.githubusercontent.com"
	githubEnt   = "https://token.actions.githubusercontent.com/<enterpriseSlug>"
	entra       = "https://login.microsoftonline.com/<tenant_id>/v2.0"
	personalMSA = "9188040d-6c67-4c5b-b112-36a304b66dad"
)

// A tenant the census lists as open to anyone is known not to be controlled,
// whatever the issuer's membership; a controlled membership is known
// controlled; an unverified one is not known.
func TestControlledTenant(t *testing.T) {
	e := find(t, entra)
	for _, c := range []struct {
		tenant            string
		controlled, known bool
	}{
		// No sentence says a work tenant's owner decides who obtains its
		// tokens; by default every user can invite guests.
		{"11111111-2222-3333-4444-555555555555", false, false},
		{personalMSA, false, true},
		{strings.ToUpper(personalMSA), false, true},
		{"", false, false},
	} {
		controlled, known := e.ControlledTenant(c.tenant)
		if controlled != c.controlled || known != c.known {
			t.Errorf("Entra ControlledTenant(%q) = %v, %v; want %v, %v", c.tenant, controlled, known, c.controlled, c.known)
		}
	}
	if controlled, known := find(t, githubEnt).ControlledTenant("octocorp"); !controlled || !known {
		t.Errorf("GitHub's enterprise path: ControlledTenant(octocorp) = %v, %v; the census records controlled", controlled, known)
	}
	// A tenant listed as open is open on its own sentence, which an
	// unverified membership does not unsettle.
	open := Issuer{NotAControlledTenant: []string{personalMSA}}
	if controlled, known := open.ControlledTenant(personalMSA); controlled || !known {
		t.Errorf("an open tenant under an unverified membership reads %v, %v; want false, true", controlled, known)
	}
	if controlled, known := open.ControlledTenant("11111111-2222-3333-4444-555555555555"); controlled || known {
		t.Errorf("an unlisted tenant under an unverified membership reads %v, %v; want false, false", controlled, known)
	}
	examined := 0
	for _, e := range All() {
		if e.TenantMembership == "controlled" {
			continue
		}
		examined++
		if controlled, known := e.ControlledTenant("acme"); controlled || known {
			t.Errorf("%s: membership %q, yet ControlledTenant(acme) = %v, %v", e.Name, e.TenantMembership, controlled, known)
		}
	}
	if examined == 0 {
		t.Fatal("no entry without a controlled membership was examined")
	}
}

// yes and no are answers; anything else may mint tokens to people
// with no account, and says so by not being known.
func TestIssuesAnonymousTokens(t *testing.T) {
	for issuer, want := range map[string][2]bool{
		"cognito-identity.amazonaws.com": {true, true},
		github:                           {false, true},
		"graph.facebook.com":             {true, false},
		"https://gitlab.com":             {true, false},
	} {
		anonymous, known := find(t, issuer).IssuesAnonymousTokens()
		if anonymous != want[0] || known != want[1] {
			t.Errorf("%s IssuesAnonymousTokens() = %v, %v; want %v, %v", issuer, anonymous, known, want[0], want[1])
		}
	}
	if anonymous, known := (Issuer{AnonymousTokens: "maybe"}).IssuesAnonymousTokens(); !anonymous || known {
		t.Errorf("a value outside the vocabulary reads %v, %v; want the cautious true, false", anonymous, known)
	}
}

func TestOwnerNameMayContain(t *testing.T) {
	gh := find(t, github)
	for _, r := range "/@:%.~ é" {
		if gh.OwnerNameMayContain(r) {
			t.Errorf("GitHub: an owner name may contain %q; the census says it cannot", r)
		}
	}
	for _, r := range "aAzZ09-_" {
		if !gh.OwnerNameMayContain(r) {
			t.Errorf("GitHub: an owner name may not contain %q; the census says it can", r)
		}
	}
	for _, r := range "/@:%" {
		if !(Issuer{}).OwnerNameMayContain(r) {
			t.Errorf("an entry with no recorded character set says an owner name cannot contain %q", r)
		}
	}
}

func TestNamesCompareWithoutCase(t *testing.T) {
	if without, known := find(t, github).NamesCompareWithoutCase(); without || known {
		t.Errorf("GitHub NamesCompareWithoutCase() = %v, %v; the census records it unverified", without, known)
	}
	for v, want := range map[string][2]bool{"yes": {true, true}, "no": {false, true}, "": {false, false}, "maybe": {false, false}} {
		without, known := (Issuer{NamesUniqueRegardlessOfCase: v}).NamesCompareWithoutCase()
		if without != want[0] || known != want[1] {
			t.Errorf("names_unique_regardless_of_case %q reads %v, %v; want %v, %v", v, without, known, want[0], want[1])
		}
	}
}

// A tenant named by an identifier that can be released
// and re-registered carries the recyclable fact, and an unverified one reads
// as recyclable. GitHub's enterprise slug is the verified case.
func TestTenantIsRecyclable(t *testing.T) {
	if recyclable, known := find(t, githubEnt).TenantIsRecyclable(); !recyclable || !known {
		t.Errorf("GitHub's enterprise path: TenantIsRecyclable() = %v, %v; GitHub releases an old slug to other customers", recyclable, known)
	}
	examined := 0
	for _, e := range All() {
		if e.TenantPlaceholder == "" || e.Issuer == githubEnt {
			continue
		}
		examined++
		if recyclable, known := e.TenantIsRecyclable(); !recyclable || known {
			t.Errorf("%s: TenantIsRecyclable() = %v, %v; no sentence settles it, so it reads recyclable and not known", e.Name, recyclable, known)
		}
	}
	if examined != 8 {
		t.Fatalf("examined %d per-tenant patterns besides the enterprise path; the census researched 8", examined)
	}
	for v, want := range map[string][2]bool{"yes": {true, true}, "no": {false, true}, "": {true, false}, "maybe": {true, false}} {
		recyclable, known := (Issuer{TenantRecyclable: v}).TenantIsRecyclable()
		if recyclable != want[0] || known != want[1] {
			t.Errorf("tenant_recyclable %q reads %v, %v; want %v, %v", v, recyclable, known, want[0], want[1])
		}
	}
}

// AWS puts a claim in the request context only under a condition key it
// documents for the issuer, so a condition on any other key tests a key the
// context does not hold. The census records AWS's keys per issuer; a key it
// does not record for a recorded issuer is known unmapped, and an issuer
// whose keys are not recorded answers not mapped and not known.
func TestAWSConditionKeysAreRecordedPerIssuer(t *testing.T) {
	gitHubKeys := []string{"amr", "aud", "email", "oaud", "sub", "actor", "actor_id", "job_workflow_ref", "repository",
		"repository_id", "repository_owner_id", "workflow", "ref", "environment", "enterprise_id"}
	if got := find(t, github).AWSConditionKeys; !slices.Equal(got, gitHubKeys) {
		t.Errorf("GitHub's AWS condition keys = %q, want %q", got, gitHubKeys)
	}
	for issuer, keys := range map[string]map[string][2]bool{
		github: {"sub": {true, true}, "aud": {true, true}, "repository_owner_id": {true, true}, "enterprise_id": {true, true},
			"repository_owner": {false, true}, "enterprise": {false, true}, "workflow_ref": {false, true}},
		githubEnt: {"sub": {false, false}, "repository_owner": {false, false}},
		"https://oidc.eks.<region>.amazonaws.com/id/<cluster_oidc_id>": {"sub": {true, true}, "repository_owner_id": {false, true}},
		"cognito-identity.amazonaws.com":                               {"amr": {true, true}, "aud": {true, true}, "email": {false, true}},
		"graph.facebook.com":                                           {"id": {true, true}, "app_id": {true, true}, "sub": {false, true}},
		"www.amazon.com":                                               {"user_id": {true, true}, "sub": {true, true}, "aud": {false, true}},
		"https://oidc.circleci.com/org/<organization_id>": {"oidc.circleci.com/project-id": {true, true}, "aud": {true, true},
			"sub": {false, true}},
		"https://accounts.google.com": {"google/organization_number": {true, true}, "sub": {true, true}},
		"https://gitlab.com":          {"sub": {false, false}},
	} {
		e := find(t, issuer)
		for key, want := range keys {
			if mapped, known := e.AWSMapsConditionKey(key); mapped != want[0] || known != want[1] {
				t.Errorf("%s AWSMapsConditionKey(%q) = %v, %v; want %v, %v", e.Name, key, mapped, known, want[0], want[1])
			}
		}
	}
	if mapped, known := (Issuer{}).AWSMapsConditionKey("sub"); mapped || known {
		t.Errorf("an issuer with no recorded keys reads %v, %v; want false, false", mapped, known)
	}
	// AWS reads context key names without regard to case, and ASCII case is
	// the only case the census folds: a long s is not an s.
	gh := find(t, github)
	for key, want := range map[string]bool{"Repository_Owner_ID": true, "SUB": true, "\u017fub": false} {
		if mapped, known := gh.AWSMapsConditionKey(key); mapped != want || !known {
			t.Errorf("GitHub AWSMapsConditionKey(%q) = %v, %v; want %v, true", key, mapped, known, want)
		}
	}
}

// Where an issuer's tenants hold their accounts, and where a consumer declares
// its owners, are census facts, so a classifier names no issuer in its code.
// GitHub's owners alone are declared by name, under github: a name under
// another issuer is another owner's.
func TestThePlatformAndTheDeclarationNamespaceAreData(t *testing.T) {
	want := map[string][2]string{
		github:    {"GitHub", "github"},
		githubEnt: {"GitHub", ""},
		"https://api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc": {"Bitbucket", ""},
		"https://oidc.circleci.com/org/<organization_id>":                                     {"CircleCI", ""},
		"https://accounts.google.com":                                                         {"Google", ""},
	}
	namespaces := map[string]string{}
	for _, e := range All() {
		w := want[e.Issuer]
		if e.Platform != w[0] || e.DeclarationNamespace != w[1] {
			t.Errorf("%s: platform %q, declaration namespace %q; want %q, %q", e.Name, e.Platform, e.DeclarationNamespace, w[0], w[1])
		}
		if e.DeclarationNamespace != "" {
			if other, twice := namespaces[e.DeclarationNamespace]; twice {
				t.Errorf("%s and %s both declare owners under %q", other, e.Name, e.DeclarationNamespace)
			}
			namespaces[e.DeclarationNamespace] = e.Name
		}
	}
	if len(namespaces) != 1 {
		t.Fatalf("examined %d declaration namespaces; the census records 1", len(namespaces))
	}
}

// A claim's value can pass to someone else unless a vendor sentence says it
// cannot. GitHub's enterprise_id is an id whose immutability no sentence
// settles, so it reads recyclable and not known, whatever its kind.
func TestAClaimsValueIsRecyclableUnlessRecordedImmutable(t *testing.T) {
	want := map[string][2]bool{
		"repository_owner": {true, true}, "repository_owner_id": {false, true},
		"repository": {true, true}, "repository_id": {false, true},
		"enterprise_id": {true, false},
	}
	claims := find(t, github).TenancyClaims
	if len(claims) != len(want) {
		t.Fatalf("GitHub carries %d tenancy claims; want %d", len(claims), len(want))
	}
	for _, c := range claims {
		recyclable, known := c.ValueIsRecyclable()
		if w := want[c.Claim]; recyclable != w[0] || known != w[1] {
			t.Errorf("GitHub %s ValueIsRecyclable() = %v, %v; want %v, %v", c.Claim, recyclable, known, w[0], w[1])
		}
	}
	for v, w := range map[string][2]bool{"yes": {false, true}, "no": {true, true}, "": {true, false}, "maybe": {true, false}} {
		recyclable, known := (Claim{Kind: "id", Immutable: v}).ValueIsRecyclable()
		if recyclable != w[0] || known != w[1] {
			t.Errorf("an id claim with immutable %q reads %v, %v; want %v, %v", v, recyclable, known, w[0], w[1])
		}
	}
}

// The classifier's facts, pinned. A generator that drops or misnames a field
// fails here rather than in a ring.
func TestTheResearchedFactsReachTheSubPackage(t *testing.T) {
	gh := find(t, github)
	if gh.AnonymousTokens != "no" {
		t.Errorf("GitHub anonymous_tokens = %q, want no", gh.AnonymousTokens)
	}
	if gh.NamesUniqueRegardlessOfCase != "" {
		t.Errorf("GitHub names_unique_regardless_of_case = %q; the census records it unverified", gh.NamesUniqueRegardlessOfCase)
	}
	wantForms := []string{"repo: owner name/", "repo: owner name@ owner id/", "repository_owner: owner name:",
		"repository_owner_id: owner id:", "repository_id: repository id:"}
	var gotForms []string
	for _, f := range gh.SubjectForms {
		s := f.LeadingLiteral
		for _, p := range f.OwnerParts {
			s += " owner " + p.Kind + p.DelimiterAfter
		}
		for _, p := range f.RepositoryParts {
			s += " repository " + p.Kind + p.DelimiterAfter
		}
		gotForms = append(gotForms, s)
	}
	if !slices.Equal(gotForms, wantForms) {
		t.Errorf("GitHub subject forms = %q, want %q", gotForms, wantForms)
	}
	wantClaims := []Claim{
		{Claim: "repository_owner", Kind: "name", Scope: "owner", Immutable: "no"},
		{Claim: "repository_owner_id", Kind: "id", Scope: "owner", Immutable: "yes"},
		{Claim: "repository", Kind: "name", Scope: "repository", Immutable: "no"},
		{Claim: "repository_id", Kind: "id", Scope: "repository", Immutable: "yes"},
		{Claim: "enterprise_id", Kind: "id", Scope: "enterprise"},
	}
	if !reflect.DeepEqual(gh.TenancyClaims, wantClaims) {
		t.Errorf("GitHub tenancy claims = %+v, want %+v", gh.TenancyClaims, wantClaims)
	}
	if want := []string{"A-Z", "a-z", "0-9", "-", "_"}; !slices.Equal(gh.OwnerNameCharacters, want) {
		t.Errorf("GitHub owner name characters = %q, want %q", gh.OwnerNameCharacters, want)
	}
	// What never pins reaches the classifier too, or a census value the
	// classifier guards against would do nothing outside a test.
	if want := []string{"job_workflow_ref:", "repo_property_"}; !slices.Equal(gh.NeverPin, want) {
		t.Errorf("GitHub never_pin = %q, want %q", gh.NeverPin, want)
	}
	for _, c := range []string{"actor", "actor_id", "job_workflow_ref", "enterprise", "workflow_ref", "repo_property_*", "aud", "issuer_scope"} {
		if !slices.Contains(gh.NotTenancy, c) {
			t.Errorf("GitHub not_tenancy %q does not carry %q", gh.NotTenancy, c)
		}
	}

	// GitLab.com, HCP Terraform and Buildkite carry anonymous_tokens only, and
	// no sentence in this release settles it.
	for issuer, want := range map[string]string{
		"cognito-identity.amazonaws.com": "yes",
		"www.amazon.com":                 "no",
		"graph.facebook.com":             "",
		"https://accounts.google.com":    "no",
		githubEnt:                        "no",
		"https://gitlab.com":             "",
		"https://app.terraform.io":       "",
		"https://agent.buildkite.com":    "",
	} {
		if got := find(t, issuer).AnonymousTokens; got != want {
			t.Errorf("%s anonymous_tokens = %q, want %q", issuer, got, want)
		}
	}
	// A pool id in aud pins the pool, never who can get into it, so Cognito
	// names no tenant by any claim.
	cognito := find(t, "cognito-identity.amazonaws.com")
	if cognito.TenancyClaims != nil {
		t.Errorf("Cognito tenancy claims = %+v; its aud names the pool, not a tenant", cognito.TenancyClaims)
	}
	if len(cognito.SubjectForms) != 0 {
		t.Errorf("Cognito subject forms = %+v; its sub names one identity and no pool", cognito.SubjectForms)
	}

	perTenant := map[string][2]string{
		githubEnt: {"<enterpriseSlug>", "name"},
		"https://oidc.eks.<region>.amazonaws.com/id/<cluster_oidc_id>":                                   {"<cluster_oidc_id>", "id"},
		"https://<region>.oic.prod-aks.azure.com/<tenant_id>/<cluster_uuid>/":                            {"<region>/<tenant_id>/<cluster_uuid>", "id"},
		"https://container.googleapis.com/v1/projects/<project>/locations/<location>/clusters/<cluster>": {"<project>/<location>/<cluster>", "name"},
		entra:                                {"<tenant_id>", "id"},
		"https://<account>.app.spacelift.io": {"<account>", "name"},
		"https://oidc.circleci.com/org/<organization_id>":                                     {"<organization_id>", "id"},
		"https://api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc": {"<workspace>", "name"},
		"https://<tenant_uuid>.tokens.sts.global.api.aws":                                     {"<tenant_uuid>", "id"},
	}
	// No sentence in this release says who can cause a Spacelift run or a
	// Bitbucket pipeline, or that a work tenant's owner decides who is in it,
	// so none of those tenants is known to control who holds its tokens.
	uncontrolled := map[string]bool{"https://<account>.app.spacelift.io": true,
		"https://api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc": true,
		entra: true}
	for issuer, want := range perTenant {
		e := find(t, issuer)
		if e.TenantPlaceholder != want[0] || e.TenantKind != want[1] {
			t.Errorf("%s: tenant %q kind %q, want %q kind %q", e.Name, e.TenantPlaceholder, e.TenantKind, want[0], want[1])
		}
		membership := "controlled"
		if uncontrolled[issuer] {
			membership = ""
		}
		if e.TenantMembership != membership || e.AnonymousTokens != "no" {
			t.Errorf("%s: membership %q, anonymous_tokens %q; the census records %q and no", e.Name, e.TenantMembership, e.AnonymousTokens, membership)
		}
	}
	patterns := 0
	for _, e := range All() {
		if e.TenantPlaceholder != "" {
			patterns++
		}
	}
	if patterns != len(perTenant) {
		t.Errorf("the sub-package holds %d patterns; the census verified %d", patterns, len(perTenant))
	}
	if e := find(t, entra); e.TenantSyntax != "guid" || !slices.Equal(e.NotAControlledTenant, []string{personalMSA}) {
		t.Errorf("Entra: syntax %q, not a controlled tenant %q", e.TenantSyntax, e.NotAControlledTenant)
	}
}

// An entry the tenancy research did not reach carries no fact a classifier
// could read as verified: every question about it reads unverified.
func TestUnresearchedEntriesCarryNothing(t *testing.T) {
	researched := map[string]bool{
		github: true, githubEnt: true, entra: true,
		"https://accounts.google.com": true, "cognito-identity.amazonaws.com": true,
		"www.amazon.com": true, "graph.facebook.com": true,
		"https://oidc.eks.<region>.amazonaws.com/id/<cluster_oidc_id>":                                   true,
		"https://<region>.oic.prod-aks.azure.com/<tenant_id>/<cluster_uuid>/":                            true,
		"https://container.googleapis.com/v1/projects/<project>/locations/<location>/clusters/<cluster>": true,
		"https://<account>.app.spacelift.io":                                                             true,
		"https://oidc.circleci.com/org/<organization_id>":                                                true,
		"https://api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc":            true,
		"https://<tenant_uuid>.tokens.sts.global.api.aws":                                                true,
	}
	unresearched := 0
	for _, e := range All() {
		if researched[e.Issuer] {
			continue
		}
		unresearched++
		if !reflect.DeepEqual(e, Issuer{Name: e.Name, Issuer: e.Issuer}) {
			t.Errorf("%s (%s) carries a tenancy fact the research did not record: %+v", e.Name, e.Issuer, e)
		}
	}
	if unresearched < 15 {
		t.Fatalf("examined %d unresearched entries; the census has at least 15", unresearched)
	}
}

// The sub-package exists so a WebAssembly build links a few kilobytes rather
// than the census: it carries the fields the classifier reads, and no sentence.
func TestTheSubPackageCarriesOnlyTheClassifiersFields(t *testing.T) {
	var doc struct {
		CensusDate string                       `json:"census_date"`
		Issuers    []map[string]json.RawMessage `json:"issuers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode the embedded sub-package: %v", err)
	}
	allowed := map[string]bool{
		"name": true, "issuer": true, "tenant_placeholder": true, "tenant_kind": true, "tenant_syntax": true,
		"tenant_recyclable": true,
		"tenant_membership": true, "not_a_controlled_tenant": true, "anonymous_tokens": true,
		"tenancy_claims": true, "subject_forms": true, "owner_name_characters": true, "names_unique_regardless_of_case": true,
		"not_tenancy": true, "never_pin": true, "platform": true, "declaration_namespace": true,
		"aws_condition_keys": true,
	}
	for _, e := range doc.Issuers {
		for k := range e {
			if !allowed[k] {
				t.Errorf("entry %s carries %q, which the classifier does not read", e["name"], k)
			}
		}
	}
	for _, sentence := range []string{`"quote"`, `"source"`, `"verified_at"`, `"vendor_example_note"`, `"evidence"`, `"unverified"`} {
		if strings.Contains(string(raw), sentence) {
			t.Errorf("the sub-package carries %s: the census's sentences, and its unverified values, stay in the root package", sentence)
		}
	}
	if len(doc.Issuers) == 0 || len(doc.Issuers) != len(All()) {
		t.Fatalf("decoded %d raw entries against %d loaded", len(doc.Issuers), len(All()))
	}
	if doc.CensusDate == "" || doc.CensusDate != CensusDate() {
		t.Errorf("census date %q, CensusDate() %q", doc.CensusDate, CensusDate())
	}
}

// scribble writes over every string and every element of every slice an
// answer lets its holder reach, and returns how many values it wrote.
func scribble(v reflect.Value) int {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString("scribbled")
			return 1
		}
	case reflect.Struct:
		n := 0
		for i := 0; i < v.NumField(); i++ {
			n += scribble(v.Field(i))
		}
		return n
	case reflect.Slice:
		n := 0
		for i := 0; i < v.Len(); i++ {
			n += scribble(v.Index(i))
		}
		return n
	}
	return 0
}

// Every field All and Match hand out, found by reflection rather than listed,
// is the caller's: a field added to Issuer later and left out of clone fails
// here.
func TestEveryFieldOfAnAnswerIsACopy(t *testing.T) {
	var pristine struct {
		Issuers []Issuer `json:"issuers"`
	}
	if err := json.Unmarshal(raw, &pristine); err != nil {
		t.Fatal(err)
	}
	written := 0
	all := All()
	for i := range all {
		written += scribble(reflect.ValueOf(&all[i]).Elem())
	}
	for _, issuer := range []string{github, "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"} {
		e, _, _ := Match(issuer)
		written += scribble(reflect.ValueOf(&e).Elem())
	}
	if written < 100 {
		t.Fatalf("wrote over %d values; the sub-package's answers hold more, so this test examined too little", written)
	}
	if !reflect.DeepEqual(All(), pristine.Issuers) {
		t.Fatal("an edit to an earlier answer reached the census All reads")
	}
}

// What Match and All hand out is the caller's to edit: the next answer is the
// census's, not the last caller's.
func TestAnswersAreCopies(t *testing.T) {
	a, _, _ := Match(github)
	if len(a.TenancyClaims) == 0 || len(a.SubjectForms) == 0 || len(a.SubjectForms[0].OwnerParts) == 0 || len(a.OwnerNameCharacters) == 0 {
		t.Fatalf("GitHub's entry carries nothing to edit, so this test would examine nothing: %+v", a)
	}
	a.TenancyClaims[0].Claim = "edited"
	a.SubjectForms[0].OwnerParts[0].DelimiterAfter = "?"
	a.OwnerNameCharacters[0] = "!-~"
	all := All()
	all[0].Name = "edited"
	b, _, _ := Match(github)
	if b.TenancyClaims[0].Claim == "edited" || b.SubjectForms[0].OwnerParts[0].DelimiterAfter == "?" || b.OwnerNameCharacters[0] == "!-~" {
		t.Fatal("an edit to what Match returned reached the next answer")
	}
	if All()[0].Name == "edited" {
		t.Fatal("an edit to what All returned reached the next answer")
	}
	entraA, _, _ := Match("https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0")
	if len(entraA.NotAControlledTenant) == 0 {
		t.Fatalf("Entra carries no open tenant to edit: %+v", entraA)
	}
	entraA.NotAControlledTenant[0] = "11111111-2222-3333-4444-555555555555"
	entraB, _, _ := Match("https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0")
	if controlled, _ := entraB.ControlledTenant(personalMSA); controlled {
		t.Fatal("an edit to NotAControlledTenant reached the next answer")
	}
}

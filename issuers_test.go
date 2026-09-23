package issuers

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/CloudArq-net/issuers/tenancy"
)

func TestCensusParsesAndIsNotEmpty(t *testing.T) {
	all := All()
	if len(all) < 40 {
		t.Fatalf("census has %d entries, expected at least 40 -- the embedded file is wrong", len(all))
	}
	if CensusDate() == "" {
		t.Fatal("census date is empty")
	}
}

func TestEveryEntryCarriesTheFourFields(t *testing.T) {
	ok := map[string]bool{
		"scoped": true, "admits_whole_org": true, "admits_any_repo": true,
		"admits_any_principal": true, "no_subject_constraint": true, "unverified": true,
	}
	aud := map[string]bool{"relying_party": true, "issuer": true, "workload": true, "unverified": true}
	ten := map[string]bool{"shared": true, "per_tenant_host": true, "per_tenant_path": true, "unverified": true}
	for _, e := range All() {
		if !aud[e.AudControlledBy] {
			t.Errorf("%s: aud_controlled_by %q not in the controlled vocabulary", e.Name, e.AudControlledBy)
		}
		if !ok[e.VendorExampleVerdict] {
			t.Errorf("%s: vendor_example_verdict %q not in the controlled vocabulary", e.Name, e.VendorExampleVerdict)
		}
		if !ten[e.TenancyModel] {
			t.Errorf("%s: tenancy_model %q not in the controlled vocabulary", e.Name, e.TenancyModel)
		}
		if e.Issuer == "" && e.IssuerPattern == "" {
			t.Errorf("%s: neither issuer nor issuer_pattern", e.Name)
		}
	}
}

// The v0.1.0 fields whose vocabulary the census documents keep it, and
// unverified is spelled one way everywhere. A reader that compares a value
// with "unverified" does not recognise "UNVERIFIED", so it would read a
// settled answer into it; and the daily drift check re-reads only entries
// whose discovery_status is exactly "ok".
func TestTheDocumentedVocabulariesHold(t *testing.T) {
	jwks := []string{"ok", "error", "unverified"}
	for _, e := range All() {
		if !oneOf(e.DiscoveryStatus, "ok", "not_found", "error", "unverified") {
			t.Errorf("%s: discovery_status %q not in the controlled vocabulary", e.Name, e.DiscoveryStatus)
		}
		allowed := jwks
		if e.Issuer == "not an OIDC issuer" {
			// No issuer, so no key set to fetch.
			allowed = append(slices.Clone(jwks), "n/a")
		}
		if !oneOf(e.JWKSStatus, allowed...) {
			t.Errorf("%s: jwks_status %q not in the controlled vocabulary", e.Name, e.JWKSStatus)
		}
		if !oneOf(e.Category, "", "ci", "iac", "runtime", "cloud", "ai-agent-platform", "platform") {
			t.Errorf("%s: category %q not in the controlled vocabulary", e.Name, e.Category)
		}
		if !oneOf(e.ControlTestResult, "", "passed", "failed", "inconclusive", "unverified") {
			t.Errorf("%s: control_test_result %q not in the controlled vocabulary", e.Name, e.ControlTestResult)
		}
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	unverified := 0
	var walk func(v any, where string)
	walk = func(v any, where string) {
		switch x := v.(type) {
		case string:
			if strings.EqualFold(strings.TrimSpace(x), "unverified") {
				unverified++
				if x != "unverified" {
					t.Errorf("%s: %q is spelled unverified; the census writes it in lower case", where, x)
				}
			}
		case map[string]any:
			for k, y := range x {
				walk(y, where+"."+k)
			}
		case []any:
			for i, y := range x {
				walk(y, fmt.Sprintf("%s[%d]", where, i))
			}
		}
	}
	walk(doc, "census")
	if unverified == 0 {
		t.Fatal("no value reads unverified, so the spelling was checked on nothing")
	}
}

func TestGetByHostAndByURL(t *testing.T) {
	a, ok := Get("token.actions.githubusercontent.com")
	if !ok {
		t.Fatal("GitHub Actions is not in the census")
	}
	b, ok := Get("https://token.actions.githubusercontent.com")
	if !ok || b.Name != a.Name {
		t.Fatal("lookup by full URL disagrees with lookup by host")
	}
	if _, ok := Get("example.invalid"); ok {
		t.Fatal("an unsurveyed host must not be found")
	}
}

// The safety property: an unverified issuer must never report that `aud`
// constrains anything. Callers that ignore the second return get "not a
// boundary", which is the safe direction.
func TestUnverifiedAudienceIsNeverReportedAsABoundary(t *testing.T) {
	for _, e := range All() {
		isB, known := e.AudienceIsBoundary()
		if e.AudControlledBy == "unverified" {
			if known {
				t.Errorf("%s: unverified audience reported as known", e.Name)
			}
			if isB {
				t.Errorf("%s: unverified audience reported as a boundary", e.Name)
			}
		}
		if e.AudControlledBy == "workload" && isB {
			t.Errorf("%s: workload-controlled audience reported as a boundary", e.Name)
		}
	}
}

func TestMultiTenantHostsIsUsefullyPopulated(t *testing.T) {
	h := MultiTenantHosts()
	if len(h) < 10 {
		t.Fatalf("only %d multi-tenant hosts; expected more", len(h))
	}
	want := "token.actions.githubusercontent.com"
	found := false
	for _, x := range h {
		if x == want {
			found = true
		}
		if strings.Contains(x, "/") || strings.Contains(x, "://") {
			t.Errorf("%q is not a bare hostname", x)
		}
	}
	if !found {
		t.Errorf("%s missing from the multi-tenant set", want)
	}
}

// The entries this release researched: the issuers and per-tenant patterns
// the tenancy research read, and three issuers researched for
// anonymous_tokens alone. Every other entry is not_in_this_release.
var researched = []string{
	"Bitbucket Pipelines", "Buildkite", "CircleCI", "GitHub Actions", "GitHub Actions (enterprise issuer path)",
	"GitLab.com", "HCP Terraform (Terraform Cloud)", "Spacelift",
	"Amazon EKS (Kubernetes service account issuer / IRSA)", "Azure Kubernetes Service (AKS workload identity)",
	"Google Kubernetes Engine (GKE)", "AWS (outbound identity federation)", "Google (accounts.google.com)",
	"Amazon Cognito identity pools", "Login with Amazon", "Facebook", "Microsoft Entra ID",
}

// The nine per-tenant patterns the research verified, with GitHub's
// enterprise path first.
var perTenant = []string{
	"GitHub Actions (enterprise issuer path)", "Amazon EKS (Kubernetes service account issuer / IRSA)",
	"Azure Kubernetes Service (AKS workload identity)", "Google Kubernetes Engine (GKE)", "Microsoft Entra ID",
	"Spacelift", "CircleCI", "Bitbucket Pipelines", "AWS (outbound identity federation)",
}

// matchCase is one case of tenancy/testdata/match_cases.json, which the
// tenancy sub-package and the Python package read too.
type matchCase struct {
	Issuer string  `json:"issuer"`
	Entry  *string `json:"entry"`
	Tenant string  `json:"tenant"`
	Why    string  `json:"why"`
}

// keyOf is the census string an entry is matched by, stated here apart from
// the package: its verified issuer pattern, or its exact issuer.
func keyOf(e Issuer) string {
	if e.Match.Value == "verified" {
		return e.Match.IssuerPattern
	}
	return e.Issuer
}

// matchable is the census's rule for which entries Match can return, written
// out apart from the package: a verified issuer pattern, or an exact issuer
// that is a host and not a note.
func matchable(e Issuer) bool {
	if e.Match.Value == "verified" {
		return true
	}
	host := strings.TrimPrefix(e.Issuer, "https://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	return e.Issuer != "" && !strings.Contains(e.Issuer, "<") && strings.Contains(host, ".") && !strings.ContainsAny(e.Issuer, " \t\n")
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func byName(t *testing.T, name, issuer string) Issuer {
	t.Helper()
	for _, e := range All() {
		if e.Name == name && (issuer == "" || e.Issuer == issuer) {
			return e
		}
	}
	t.Fatalf("no census entry %s %s", name, issuer)
	return Issuer{}
}

func TestMatchReadsTheCensusAsTheSharedCasesSay(t *testing.T) {
	var mc struct {
		Census []matchCase `json:"census"`
	}
	readJSON(t, "tenancy/testdata/match_cases.json", &mc)
	matched, refused := 0, 0
	for _, c := range mc.Census {
		got, tenant, ok := Match(c.Issuer)
		switch {
		case c.Entry == nil && ok:
			t.Errorf("Match(%q) = %s (%q), tenant %q; want no match (%s)", c.Issuer, got.Name, keyOf(got), tenant, c.Why)
		case c.Entry != nil && !ok:
			t.Errorf("Match(%q) found nothing; want %q, tenant %q (%s)", c.Issuer, *c.Entry, c.Tenant, c.Why)
		case c.Entry != nil && (keyOf(got) != *c.Entry || tenant != c.Tenant):
			t.Errorf("Match(%q) = %q, tenant %q; want %q, tenant %q (%s)", c.Issuer, keyOf(got), tenant, *c.Entry, c.Tenant, c.Why)
		}
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

// Get reads hosts as the shared cases say, the Python package too. Hosts
// compare without ASCII case and no other, as Match's do: a character that
// lower-cases onto an ASCII letter elsewhere in Unicode must not let a
// look-alike host pass for a census host.
func TestGetReadsTheSharedCases(t *testing.T) {
	var mc struct {
		Get []struct {
			Query string  `json:"query"`
			Entry *string `json:"entry"`
			Why   string  `json:"why"`
		} `json:"get"`
	}
	readJSON(t, "tenancy/testdata/match_cases.json", &mc)
	found, refused := 0, 0
	for _, c := range mc.Get {
		e, ok := Get(c.Query)
		switch {
		case c.Entry == nil && ok:
			t.Errorf("Get(%q) = %s; want nothing (%s)", c.Query, e.Name, c.Why)
		case c.Entry != nil && (!ok || e.Name != *c.Entry):
			t.Errorf("Get(%q) = %q, %v; want %q (%s)", c.Query, e.Name, ok, *c.Entry, c.Why)
		}
		if c.Entry == nil {
			refused++
		} else {
			found++
		}
	}
	if found == 0 || refused == 0 {
		t.Fatalf("the shared lookups hold %d finds and %d refusals; both kinds must be exercised", found, refused)
	}
}

// Match hands back the census's own entry, with every fact behind it, so a
// caller can quote the sentence that placed a grant.
func TestMatchReturnsTheWholeEntry(t *testing.T) {
	eks, tenant, ok := Match("https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE")
	if !ok || eks.Name != "Amazon EKS (Kubernetes service account issuer / IRSA)" || tenant != "EXAMPLED539D4633E53DE1B71EXAMPLE" {
		t.Fatalf("EKS: %q, tenant %q, %v", eks.Name, tenant, ok)
	}
	if eks.TenantMembership.Value != "controlled" || len(eks.TenantMembership.Evidence) == 0 || eks.SubjectFormat == "" {
		t.Errorf("EKS: the entry came back without its facts: %+v", eks.TenantMembership)
	}
	gh, tenant, ok := Match("https://token.actions.githubusercontent.com/octocorp")
	if !ok || gh.Name != "GitHub Actions (enterprise issuer path)" || tenant != "octocorp" {
		t.Errorf("GitHub's enterprise path: %q, tenant %q, %v", gh.Name, tenant, ok)
	}
}

// scribble writes over everything an answer lets its holder reach: every
// string, every element of every slice and every value in every map, however
// deep. It returns how many values it wrote, so a test over an answer with
// nothing in it can say so.
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
	case reflect.Slice, reflect.Array:
		n := 0
		for i := 0; i < v.Len(); i++ {
			n += scribble(v.Index(i))
		}
		return n
	case reflect.Map:
		n := 0
		for _, k := range v.MapKeys() {
			if elem := v.MapIndex(k); elem.Kind() == reflect.Interface && !elem.IsNil() &&
				(elem.Elem().Kind() == reflect.Map || elem.Elem().Kind() == reflect.Slice) {
				n += scribble(elem.Elem())
				continue
			}
			v.SetMapIndex(k, reflect.ValueOf("scribbled").Convert(v.Type().Elem()))
			n++
		}
		return n
	case reflect.Interface:
		if v.IsNil() {
			return 0
		}
		if inner := v.Elem(); inner.Kind() == reflect.Map || inner.Kind() == reflect.Slice || inner.Kind() == reflect.Pointer {
			return scribble(inner)
		}
		if v.CanSet() {
			v.Set(reflect.ValueOf("scribbled"))
			return 1
		}
	case reflect.Pointer:
		if !v.IsNil() {
			return scribble(v.Elem())
		}
	}
	return 0
}

// What All, Get and Match hand out is the caller's to edit, however deep:
// the next answer is the census's, not the last caller's. Handed the census's
// own slices and maps, one caller's edit would change what every later caller
// in the process reads, such as a claim's multi_valued turned to yes, which
// empties the sub-package's projection of it.
func TestAnswersAreCopies(t *testing.T) {
	var pristine census
	if err := json.Unmarshal(raw, &pristine); err != nil {
		t.Fatal(err)
	}
	const github, eks = "https://token.actions.githubusercontent.com",
		"https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
	written := 0
	all := All()
	for i := range all {
		written += scribble(reflect.ValueOf(&all[i]).Elem())
	}
	got, _ := Get(github)
	written += scribble(reflect.ValueOf(&got).Elem())
	matched, _, _ := Match(eks)
	written += scribble(reflect.ValueOf(&matched).Elem())
	if written < 1000 {
		t.Fatalf("wrote over %d values; the census's answers hold far more, so this test examined too little", written)
	}
	if again := All(); !reflect.DeepEqual(again, pristine.Issuers) {
		for i := range again {
			if !reflect.DeepEqual(again[i], pristine.Issuers[i]) {
				t.Errorf("an edit to an earlier answer reached All()[%d], %s", i, pristine.Issuers[i].Name)
			}
		}
	}
	if e, ok := Get(github); !ok || e.Name != "GitHub Actions" || !reflect.DeepEqual(e, byName(t, "GitHub Actions", "")) {
		t.Error("an edit to an earlier answer reached Get")
	}
	if e, _, ok := Match(eks); !ok || len(e.TenantMembership.Evidence) == 0 || e.TenantMembership.Evidence[0].Quote == "scribbled" {
		t.Error("an edit to an earlier answer reached Match")
	}
}

// The sub-package is generated from this census by scripts/build.py. Each of
// its entries must be the Tenancy projection of one census entry, in census
// order, and every entry the census can match must be in it.
func TestTheTenancySubPackageIsInStepWithTheCensus(t *testing.T) {
	var want []tenancy.Issuer
	for _, e := range All() {
		if matchable(e) {
			want = append(want, e.Tenancy())
		}
	}
	got := tenancy.All()
	if len(want) < 29 || len(got) != len(want) {
		t.Fatalf("the sub-package holds %d entries; the census has %d an issuer can match (at least 29)", len(got), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("entry %d: the sub-package says\n  %+v\nthe census says\n  %+v", i, got[i], want[i])
		}
	}
	if tenancy.CensusDate() != CensusDate() {
		t.Errorf("census date: sub-package %q, census %q", tenancy.CensusDate(), CensusDate())
	}
}

// The projection keeps what a classifier may rely on and nothing it must not:
// no unverified value, no multi-valued claim, no claim of unknown cardinality,
// and nothing from a list that is itself unverified.
func TestTenancyKeepsOnlyWhatIsVerified(t *testing.T) {
	e := Issuer{
		Name: "invented", Issuer: "https://example.com",
		AnonymousTokens: AnonymousTokens{Value: "unverified"},
		TenancyClaims: TenancyClaims{Value: "verified", Claims: []TenantClaim{
			{Claim: "single", Kind: "id", Scope: "owner", MultiValued: "no", Immutable: "unverified"},
			{Claim: "list", Kind: "id", Scope: "owner", MultiValued: "yes", Immutable: "yes"},
			{Claim: "unknown", Kind: "id", Scope: "owner", MultiValued: "unverified", Immutable: "yes"},
		}},
		SubjectForms:                SubjectForms{Value: "unverified", Forms: []SubjectForm{{LeadingLiteral: "x:"}}},
		OwnerCharset:                OwnerCharset{Value: "unverified", Characters: []string{"a-z"}},
		NamesUniqueRegardlessOfCase: NameCase{Value: "unverified"},
		Match:                       MatchRule{Value: "unverified", IssuerPattern: "https://<t>.example.com", TenantRecyclable: "no"},
		TenantMembership:            TenantMembership{Value: "unverified"},
	}
	want := tenancy.Issuer{Name: "invented", Issuer: "https://example.com",
		TenancyClaims: []tenancy.Claim{{Claim: "single", Kind: "id", Scope: "owner"}}}
	if got := e.Tenancy(); !reflect.DeepEqual(got, want) {
		t.Errorf("Tenancy() = %+v, want %+v", got, want)
	}
}

// facts gathers every Fact an entry's tenancy fields carry, with where it sits.
func facts(e Issuer) map[string][]Fact {
	out := map[string][]Fact{}
	add := func(where string, fs ...Fact) { out[where] = append(out[where], fs...) }
	a := e.AnonymousTokens
	add("anonymous_tokens.evidence", a.Evidence...)
	add("anonymous_tokens.chain", a.Chain...)
	add("anonymous_tokens.context", a.Context...)
	for _, c := range e.TenancyClaims.Claims {
		add("tenancy_claims."+c.Claim, c.Evidence)
		add("tenancy_claims."+c.Claim+".immutable_evidence", c.ImmutableEvidence...)
		add("tenancy_claims."+c.Claim+".context", c.Context...)
	}
	for _, c := range e.NotTenancy.Claims {
		add("not_tenancy."+c.Claim, c.Evidence)
		add("not_tenancy."+c.Claim+".context", c.Context...)
	}
	s := e.SubjectForms
	for _, f := range s.Forms {
		add("subject_forms."+f.Form, f.Evidence)
		add("subject_forms."+f.Form+".issued_for", f.IssuedFor...)
	}
	for _, n := range s.NeverPin {
		add("subject_forms.never_pin."+n.LeadingLiteral, n.Evidence)
	}
	add("subject_forms.chosen_by", s.ChosenBy...)
	add("subject_forms.evidence", s.Evidence...)
	add("owner_charset.evidence", e.OwnerCharset.Evidence...)
	add("owner_charset.context", e.OwnerCharset.Context...)
	add("names_unique_regardless_of_case.evidence", e.NamesUniqueRegardlessOfCase.Evidence...)
	add("names_unique_regardless_of_case.context", e.NamesUniqueRegardlessOfCase.Context...)
	m := e.Match
	add("match.evidence", m.Evidence...)
	add("match.context", m.Context...)
	add("match.tenant_syntax_evidence", m.TenantSyntaxEvidence...)
	add("match.tenant_immutable_evidence", m.TenantImmutableEvidence...)
	add("match.tenant_recyclable_evidence", m.TenantRecyclableEvidence...)
	for _, x := range m.NotAControlledTenant {
		add("match.not_a_controlled_tenant."+x.Tenant, x.Evidence)
		add("match.not_a_controlled_tenant."+x.Tenant+".context", x.Context...)
	}
	add("tenant_membership.evidence", e.TenantMembership.Evidence...)
	add("tenant_membership.context", e.TenantMembership.Context...)
	add("built_in.evidence", e.BuiltIn.Evidence...)
	add("built_in.discrepancy", e.BuiltIn.Discrepancy...)
	researchFacts(e.Research, "research", out)
	return out
}

var factKeys = map[string]bool{"source": true, "quote": true, "verified_at": true, "role": true,
	"observed": true, "method": true, "at": true, "result": true}

// researchFacts gathers the facts inside an entry's free-form research block:
// every mapping that carries any key a fact or an observation has, so a fact
// written under other names is reported rather than walked past. A key named
// observed whose value is a mapping or a list names a group, not an
// observation. A mapping that looks like a fact and carries a key a fact does
// not have is reported as broken rather than read as a fact with the key
// dropped.
func researchFacts(v any, where string, out map[string][]Fact) {
	switch x := v.(type) {
	case map[string]any:
		looksLikeFact := false
		for k, v := range x {
			switch v.(type) {
			case map[string]any, []any:
			default:
				looksLikeFact = looksLikeFact || factKeys[k]
			}
		}
		if looksLikeFact {
			for k := range x {
				if !factKeys[k] {
					out[where+" (not a fact: "+k+")"] = append(out[where+" (not a fact: "+k+")"], Fact{})
				}
			}
			var f Fact
			b, err := json.Marshal(x)
			if err == nil {
				err = json.Unmarshal(b, &f)
			}
			if err != nil {
				out[where+" (not a fact)"] = append(out[where+" (not a fact)"], Fact{})
				return
			}
			out[where] = append(out[where], f)
			return
		}
		for k, y := range x {
			researchFacts(y, where+"."+k, out)
		}
	case []any:
		for i, y := range x {
			researchFacts(y, fmt.Sprintf("%s[%d]", where, i), out)
		}
	}
}

// isPage reports whether s is an https URL that names a host: what the source
// of a vendor's sentence must be.
func isPage(s string) bool {
	u, err := url.Parse(s)
	return err == nil && strings.HasPrefix(s, "https://") && !strings.ContainsAny(s, " \t\n") &&
		strings.Contains(strings.Trim(u.Hostname(), "."), ".")
}

// isDay reports whether s is a day on the calendar, written YYYY-MM-DD.
func isDay(s string) bool {
	_, err := time.Parse(time.DateOnly, s)
	return err == nil
}

// isMoment reports whether s is a day, or a day and a UTC time: when an
// observation was made.
func isMoment(s string) bool {
	for _, layout := range []string{time.DateOnly, "2006-01-02T15:04Z", "2006-01-02T15:04:05Z"} {
		if _, err := time.Parse(layout, s); err == nil {
			return true
		}
	}
	return false
}

// observationMayStand reports whether an observation may sit where a fact
// does: beside a value rather than behind it, in research, or behind a claim
// or a leading literal that never pins, which cannot move a grant inward.
// Anywhere else a fact settles a value, and unverified means that no vendor
// sentence establishes it.
func observationMayStand(where string) bool {
	return strings.HasSuffix(where, ".context") || strings.HasPrefix(where, "research") ||
		strings.HasPrefix(where, "not_tenancy.") || strings.HasPrefix(where, "subject_forms.never_pin.")
}

// N5: every fact keeps its own source URL, its exact quote and the date it
// was read; an observation keeps what was requested, how, when and what came
// back, and settles nothing. A fact with no source or no quote is not a fact.
func TestEveryFactHasASourceAQuoteAndADate(t *testing.T) {
	examined, observations := 0, 0
	for _, e := range All() {
		for where, fs := range facts(e) {
			for _, f := range fs {
				examined++
				observation := f.Observed != "" || f.Method != "" || f.At != "" || f.Result != ""
				switch {
				case observation && (f.Observed == "" || f.Method == "" || !isMoment(f.At) || f.Result == "" || f.Quote != "" || f.Source != ""):
					t.Errorf("%s %s: an observation needs observed, method, a dated at and result, and no quote: %+v", e.Name, where, f)
				case observation && !observationMayStand(where):
					t.Errorf("%s %s: an observation settles no value; it needs the vendor's sentence: %+v", e.Name, where, f)
				case !observation && (!isPage(f.Source) || strings.TrimSpace(f.Quote) == "" || !isDay(f.VerifiedAt)):
					t.Errorf("%s %s: a fact needs an https source, a quote and a verified_at date: %+v", e.Name, where, f)
				}
				if observation {
					observations++
				}
			}
		}
	}
	if examined < 150 || observations == 0 {
		t.Fatalf("examined %d facts, %d of them observations; the tenancy research recorded more than 150, and observations",
			examined, observations)
	}
}

// census is the embedded file as the Go type reads it.
type census struct {
	CensusDate string   `json:"census_date"`
	Issuers    []Issuer `json:"issuers"`
}

// recorded is what this release recorded for each entry it researched: the
// facts each field carries, counted where they sit, and the keys of the
// entry's research block. Every other test checks the facts that are there,
// so a block of them that vanished, an entry's research above all, would leave
// those tests green. A change to the census's facts changes this table in the
// same commit.
var recorded = map[string]struct {
	facts    map[string]int
	research []string
}{
	"Bitbucket Pipelines": {map[string]int{"anonymous_tokens": 3, "match": 1, "tenant_membership": 4},
		[]string{"population", "sources"}},
	"Buildkite": {map[string]int{}, nil},
	"CircleCI": {map[string]int{"anonymous_tokens": 2, "match": 1, "tenant_membership": 2},
		[]string{"population", "sources"}},
	"GitHub Actions": {map[string]int{"anonymous_tokens": 5, "names_unique_regardless_of_case": 2, "not_tenancy": 20,
		"owner_charset": 7, "research": 25, "subject_forms": 16, "tenancy_claims": 11},
		[]string{"aws", "context_can_contain", "fork_pull_requests", "immutable_subject", "issuer_variants", "population",
			"population_evidence", "sources"}},
	"GitHub Actions (enterprise issuer path)": {map[string]int{"anonymous_tokens": 7, "match": 7, "tenant_membership": 1},
		[]string{"population", "sources"}},
	"GitLab.com":                      {map[string]int{}, nil},
	"HCP Terraform (Terraform Cloud)": {map[string]int{}, nil},
	"Spacelift": {map[string]int{"anonymous_tokens": 1, "match": 1, "tenant_membership": 2},
		[]string{"population", "sources"}},
	"Amazon EKS (Kubernetes service account issuer / IRSA)": {map[string]int{"anonymous_tokens": 1, "match": 1,
		"tenant_membership": 4}, []string{"population", "sources"}},
	"Azure Kubernetes Service (AKS workload identity)": {map[string]int{"anonymous_tokens": 3, "match": 2,
		"tenant_membership": 4}, []string{"population", "sources"}},
	"Google Kubernetes Engine (GKE)": {map[string]int{"anonymous_tokens": 2, "match": 4, "tenant_membership": 4},
		[]string{"population", "sources"}},
	"AWS (outbound identity federation)": {map[string]int{"anonymous_tokens": 2, "match": 1, "tenant_membership": 1},
		[]string{"population", "sources"}},
	"Google (accounts.google.com)": {map[string]int{"anonymous_tokens": 9, "built_in": 3}, []string{"sources"}},
	"Amazon Cognito identity pools": {map[string]int{"anonymous_tokens": 9, "built_in": 3, "not_tenancy": 4,
		"research": 6, "subject_forms": 2}, []string{"aws", "population", "sources"}},
	"Login with Amazon": {map[string]int{"anonymous_tokens": 3, "built_in": 3, "research": 1},
		[]string{"sources", "token_kind"}},
	"Facebook": {map[string]int{"anonymous_tokens": 3, "built_in": 3, "research": 1},
		[]string{"sources", "token_kind"}},
	"Microsoft Entra ID": {map[string]int{"anonymous_tokens": 1, "match": 7, "tenant_membership": 3},
		[]string{"population", "sources"}},
}

func TestEveryResearchedEntryKeepsWhatWasRecorded(t *testing.T) {
	examined, total := 0, 0
	for _, e := range All() {
		if e.Researched != "in_release" {
			continue
		}
		want, ok := recorded[e.Name]
		if !ok {
			t.Errorf("%s is researched in this release and recorded here nowhere", e.Name)
			continue
		}
		examined++
		got := map[string]int{}
		for where, fs := range facts(e) {
			if len(fs) > 0 {
				got[strings.SplitN(where, ".", 2)[0]] += len(fs)
				total += len(fs)
			}
		}
		if !reflect.DeepEqual(got, want.facts) {
			t.Errorf("%s: facts per field %v; the release recorded %v", e.Name, got, want.facts)
		}
		var keys []string
		for k := range e.Research {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, want.research) {
			t.Errorf("%s: research holds %q; the release recorded %q", e.Name, keys, want.research)
		}
	}
	if examined != len(recorded) || total == 0 {
		t.Fatalf("examined %d of the %d entries recorded, holding %d facts", examined, len(recorded), total)
	}
}

// The embedded census decodes into Issuer with no key left over, so no field
// the census carries is silently dropped by the Go type.
func TestTheGoTypeReadsEveryField(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c census
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("the census carries a field Issuer does not: %v", err)
	}
	if len(c.Issuers) != len(All()) {
		t.Fatalf("strict decode read %d entries, the package %d", len(c.Issuers), len(All()))
	}
}

func oneOf(v string, allowed ...string) bool { return slices.Contains(allowed, v) }

func TestTheNewFieldsKeepTheirVocabularies(t *testing.T) {
	threeWay := []string{"yes", "no", "unverified"}
	claims := 0
	for _, e := range All() {
		n := e.Name
		if !oneOf(e.Researched, "in_release", "not_in_this_release") {
			t.Errorf("%s: researched %q", n, e.Researched)
		}
		if !oneOf(e.AnonymousTokens.Value, threeWay...) || !oneOf(e.AnonymousTokens.Basis, "", "chain") {
			t.Errorf("%s: anonymous_tokens %q, basis %q", n, e.AnonymousTokens.Value, e.AnonymousTokens.Basis)
		}
		for field, v := range map[string]string{"tenancy_claims": e.TenancyClaims.Value, "not_tenancy": e.NotTenancy.Value,
			"subject_forms": e.SubjectForms.Value, "owner_charset": e.OwnerCharset.Value, "match": e.Match.Value} {
			if !oneOf(v, "verified", "unverified") {
				t.Errorf("%s: %s value %q", n, field, v)
			}
		}
		if !oneOf(e.TenantMembership.Value, "controlled", "unverified") {
			t.Errorf("%s: tenant_membership %q", n, e.TenantMembership.Value)
		}
		if !oneOf(e.NamesUniqueRegardlessOfCase.Value, threeWay...) {
			t.Errorf("%s: names_unique_regardless_of_case %q", n, e.NamesUniqueRegardlessOfCase.Value)
		}
		if !oneOf(e.BuiltIn.Value, "yes", "unverified") {
			t.Errorf("%s: built_in %q", n, e.BuiltIn.Value)
		}
		seen := map[string]bool{}
		for _, c := range e.TenancyClaims.Claims {
			claims++
			if !oneOf(c.Kind, "name", "id") || !oneOf(c.Scope, "owner", "repository", "enterprise") ||
				!oneOf(c.MultiValued, threeWay...) || !oneOf(c.Immutable, threeWay...) || seen[c.Claim] {
				t.Errorf("%s: tenancy claim %+v", n, c)
			}
			seen[c.Claim] = true
		}
		for _, c := range e.NotTenancy.Claims {
			if seen[c.Claim] || c.Why == "" {
				t.Errorf("%s: %s is both a tenancy claim and not one, or says no why", n, c.Claim)
			}
		}
		for _, f := range e.SubjectForms.Forms {
			if f.LeadingLiteral == "" || len(f.OwnerParts)+len(f.RepositoryParts) == 0 {
				t.Errorf("%s: subject form %q has no leading literal or no parts", n, f.Form)
			}
			for _, p := range append(slices.Clone(f.OwnerParts), f.RepositoryParts...) {
				if !oneOf(p.Kind, "name", "id") || len(p.DelimiterAfter) != 1 {
					t.Errorf("%s: subject form %q part %+v", n, f.Form, p)
				}
			}
		}
		for _, c := range e.OwnerCharset.Characters {
			if !(len(c) == 1 || len(c) == 3 && c[1] == '-' && c[0] < c[2]) {
				t.Errorf("%s: owner character item %q is neither one character nor a range", n, c)
			}
		}
		if m := e.Match; m.Value == "verified" {
			if !oneOf(m.TenantKind, "name", "id") || !oneOf(m.TenantSyntax, "", "guid") ||
				!oneOf(m.TenantImmutable, "", "yes", "no", "unverified") || !oneOf(m.TenantRecyclable, threeWay...) {
				t.Errorf("%s: match %+v", n, m)
			}
		}
	}
	if claims == 0 {
		t.Fatal("no tenancy claim examined")
	}
}

// A value other than unverified is a claim about a vendor, and a claim with
// nothing behind it is not a fact.
func TestAVerifiedValueCarriesItsEvidence(t *testing.T) {
	controlled, patterns := 0, 0
	for _, e := range All() {
		n := e.Name
		a := e.AnonymousTokens
		if (a.Value == "yes" || a.Value == "no") && len(a.Evidence)+len(a.Chain) == 0 {
			t.Errorf("%s: anonymous_tokens %q with no evidence", n, a.Value)
		}
		if a.Basis == "chain" && len(a.Chain) == 0 {
			t.Errorf("%s: basis chain with no chain", n)
		}
		if a.Value == "unverified" && e.Researched == "in_release" && a.WhyUnverified == "" {
			t.Errorf("%s: researched, and anonymous_tokens unverified with no why", n)
		}
		if e.TenantMembership.Value == "controlled" {
			controlled++
			if len(e.TenantMembership.Evidence) == 0 || e.Match.Value != "verified" {
				t.Errorf("%s: a controlled tenant needs its evidence and a verified pattern", n)
			}
		}
		for _, c := range e.TenancyClaims.Claims {
			if (c.Immutable == "yes" || c.Immutable == "no") && len(c.ImmutableEvidence) == 0 {
				t.Errorf("%s: %s immutable %q with no evidence", n, c.Claim, c.Immutable)
			}
		}
		if s := e.SubjectForms; s.Value == "verified" && len(s.Forms) == 0 && len(s.Evidence) == 0 {
			t.Errorf("%s: subject forms recorded as none, with nothing to say so", n)
		}
		if o := e.OwnerCharset; o.Value == "verified" && (len(o.Characters) == 0 || len(o.Evidence) == 0 || o.Description == "") {
			t.Errorf("%s: an owner character set needs its characters, its description and its evidence", n)
		}
		if v := e.NamesUniqueRegardlessOfCase.Value; (v == "yes" || v == "no") && len(e.NamesUniqueRegardlessOfCase.Evidence) == 0 {
			t.Errorf("%s: names_unique_regardless_of_case %q with no evidence", n, v)
		}
		if m := e.Match; m.Value == "verified" {
			patterns++
			if m.IssuerPattern == "" || m.TenantPlaceholder == "" || len(m.Evidence) == 0 {
				t.Errorf("%s: a verified pattern needs its pattern, its tenant and its evidence", n)
			}
			if m.TenantSyntax != "" && len(m.TenantSyntaxEvidence) == 0 {
				t.Errorf("%s: tenant syntax %q with no evidence", n, m.TenantSyntax)
			}
			if (m.TenantImmutable == "yes" || m.TenantImmutable == "no") && len(m.TenantImmutableEvidence) == 0 {
				t.Errorf("%s: tenant_immutable %q with no evidence", n, m.TenantImmutable)
			}
			if (m.TenantRecyclable == "yes" || m.TenantRecyclable == "no") && len(m.TenantRecyclableEvidence) == 0 {
				t.Errorf("%s: tenant_recyclable %q with no evidence", n, m.TenantRecyclable)
			}
		}
		if e.BuiltIn.Value == "yes" && (len(e.BuiltIn.Evidence) == 0 || e.BuiltIn.Principal == "") {
			t.Errorf("%s: built_in with no evidence or no principal", n)
		}
	}
	// Nine patterns, and seven tenants whose owner the vendor says controls
	// who obtains tokens: no sentence in this release says who can cause a
	// Spacelift run or a Bitbucket pipeline.
	if patterns != 9 || controlled != 7 {
		t.Fatalf("examined %d verified patterns and %d controlled memberships; the census records 9 and 7", patterns, controlled)
	}
}

// Every entry says whether this release researched it, and an entry it did
// not research holds only unverified in its new fields: each is written out,
// and each reads unverified and nothing else.
func TestEveryEntrySaysWhetherItWasResearched(t *testing.T) {
	var doc struct {
		Issuers []map[string]json.RawMessage `json:"issuers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	fields := []string{"anonymous_tokens", "tenancy_claims", "not_tenancy", "subject_forms", "owner_charset",
		"names_unique_regardless_of_case", "match", "tenant_membership", "built_in"}
	var inRelease []string
	unresearched := 0
	for _, e := range doc.Issuers {
		var name, state string
		if err := json.Unmarshal(e["name"], &name); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(e["researched"], &state); err != nil {
			t.Errorf("%s: no researched field: %v", name, err)
			continue
		}
		for _, k := range fields {
			if _, ok := e[k]; !ok {
				t.Errorf("%s does not write out %s", name, k)
			}
		}
		if state == "in_release" {
			inRelease = append(inRelease, name)
			continue
		}
		unresearched++
		for _, k := range fields {
			if string(e[k]) != `{"value":"unverified"}` {
				t.Errorf("%s was not researched in this release, yet its %s reads %s", name, k, e[k])
			}
		}
		if _, ok := e["research"]; ok {
			t.Errorf("%s was not researched in this release, yet carries research", name)
		}
	}
	slices.Sort(inRelease)
	want := slices.Clone(researched)
	slices.Sort(want)
	if !slices.Equal(inRelease, want) {
		t.Errorf("researched in this release: %q\nthe research list: %q", inRelease, want)
	}
	if unresearched < 27 {
		t.Fatalf("examined %d entries this release did not research; the census has 27", unresearched)
	}
}

// GitHub's owner character set cites its sources, and the organisation-name
// sentence is AWS's, not GitHub's, which the census must say.
func TestGitHubsOwnerCharacterSetNamesItsSources(t *testing.T) {
	gh := byName(t, "GitHub Actions", "")
	if gh.OwnerCharset.Value != "verified" || len(gh.OwnerCharset.Characters) == 0 {
		t.Fatalf("GitHub's owner character set is not recorded: %+v", gh.OwnerCharset)
	}
	tg := gh.Tenancy()
	for _, r := range "/@:" {
		if tg.OwnerNameMayContain(r) {
			t.Errorf("GitHub's owner characters %q admit the delimiter %q", gh.OwnerCharset.Characters, r)
		}
	}
	aws, github := 0, 0
	for _, f := range gh.OwnerCharset.Evidence {
		switch {
		case strings.HasPrefix(f.Source, "https://docs.aws.amazon.com/"):
			aws++
			if !strings.Contains(f.Role, "AWS") || !strings.Contains(f.Quote, "organization name") {
				t.Errorf("the organisation-name sentence from %s is not labelled as AWS's: role %q", f.Source, f.Role)
			}
		case strings.HasPrefix(f.Source, "https://docs.github.com/"):
			github++
			if f.Role == "" {
				t.Errorf("a GitHub source of the character set says no role: %+v", f)
			}
		}
	}
	if aws != 1 || github < 3 {
		t.Errorf("GitHub's owner character set cites %d GitHub sentences and %d AWS ones; it rests on GitHub's and one of AWS's",
			github, aws)
	}
	if n := gh.NamesUniqueRegardlessOfCase; n.Value != "unverified" || len(n.LookedIn) == 0 {
		t.Errorf("GitHub names_unique_regardless_of_case = %q, looked in %d pages; no GitHub page states it", n.Value, len(n.LookedIn))
	}
	never := map[string]bool{}
	for _, np := range gh.SubjectForms.NeverPin {
		never[np.LeadingLiteral] = true
	}
	if !never["job_workflow_ref:"] {
		t.Error("GitHub: job_workflow_ref: is not recorded as a leading literal that never pins")
	}
	notTenancy := map[string]bool{}
	for _, c := range gh.NotTenancy.Claims {
		notTenancy[c.Claim] = true
	}
	for _, c := range []string{"actor", "actor_id", "job_workflow_ref", "job_workflow_sha", "environment", "ref",
		"event_name", "runner_environment", "repository_visibility", "workflow_ref", "enterprise"} {
		if !notTenancy[c] {
			t.Errorf("GitHub: %s is not recorded in not_tenancy: it names no owner, repository or enterprise", c)
		}
	}
}

// The four providers STS accepts with no identity provider in the account,
// and the discrepancy between AWS's pages about them.
func TestTheBuiltInProvidersAreRecorded(t *testing.T) {
	for _, name := range []string{"Amazon Cognito identity pools", "Login with Amazon", "Facebook", "Google (accounts.google.com)"} {
		e := byName(t, name, "")
		if e.BuiltIn.Value != "yes" {
			t.Errorf("%s: not recorded as a built-in provider", name)
		}
		if got, _, ok := Match(e.Issuer); !ok || got.Name != name {
			t.Errorf("%s: its issuer %q does not match its own entry", name, e.Issuer)
		}
	}
	if lwa := byName(t, "Login with Amazon", ""); len(lwa.BuiltIn.Discrepancy) < 2 || lwa.BuiltIn.Note == "" {
		t.Errorf("Login with Amazon: the census records %d pages naming three built-ins; AWS has two", len(lwa.BuiltIn.Discrepancy))
	}
	if c := byName(t, "Amazon Cognito identity pools", ""); c.AnonymousTokens.Value != "yes" {
		t.Errorf("Cognito anonymous_tokens %q, want yes", c.AnonymousTokens.Value)
	}
	if l := byName(t, "Login with Amazon", ""); l.AnonymousTokens.Value != "no" || l.AnonymousTokens.Basis != "" {
		t.Errorf("Login with Amazon anonymous_tokens %q, basis %q; the research gives no, on its sentences", l.AnonymousTokens.Value, l.AnonymousTokens.Basis)
	}
	if f := byName(t, "Facebook", ""); f.AnonymousTokens.Value != "unverified" || len(f.AnonymousTokens.LookedIn) == 0 ||
		f.AnonymousTokens.WhyUnverified == "" || len(f.AnonymousTokens.Evidence) != 0 {
		t.Errorf("Facebook anonymous_tokens %+v; the research found it unverified and says why", f.AnonymousTokens)
	}
	for _, e := range All() {
		if e.BuiltIn.Value == "yes" && !slices.Contains([]string{"Amazon Cognito identity pools", "Login with Amazon", "Facebook", "Google (accounts.google.com)"}, e.Name) {
			t.Errorf("%s is recorded as built in; AWS names four providers", e.Name)
		}
	}
}

// Cognito's aud is the identity pool, which pins the pool and never who can
// get into it, so it is recorded as not tenancy and no Cognito claim names a
// tenant.
func TestCognitosAudienceNamesThePoolNotATenant(t *testing.T) {
	c := byName(t, "Amazon Cognito identity pools", "")
	if c.TenancyClaims.Value != "unverified" || len(c.TenancyClaims.Claims) != 0 {
		t.Errorf("Cognito tenancy claims %+v; none is recorded", c.TenancyClaims)
	}
	found := false
	for _, x := range c.NotTenancy.Claims {
		if x.Claim == "aud" {
			found = true
			if !strings.Contains(x.Why, "pool") || !strings.Contains(x.Evidence.Quote, "identity pool ID") {
				t.Errorf("Cognito aud is not tenancy for the wrong reason: %+v", x)
			}
		}
	}
	if !found {
		t.Error("Cognito's aud is not recorded as not tenancy")
	}
	if tc := c.Tenancy().TenancyClaims; tc != nil {
		t.Errorf("Cognito's projection carries tenancy claims %+v", tc)
	}
}

// GitLab.com, HCP Terraform and Buildkite are researched for
// anonymous_tokens only. The research recorded who can open an account,
// not that tokens need one, so the value is unverified and says why, and
// every other tenancy field is unverified too.
func TestGitLabHCPTerraformAndBuildkiteCarryAnonymousTokensOnly(t *testing.T) {
	for _, name := range []string{"GitLab.com", "HCP Terraform (Terraform Cloud)", "Buildkite"} {
		e := byName(t, name, "")
		if e.Researched != "in_release" || e.AnonymousTokens.Value != "unverified" || e.AnonymousTokens.WhyUnverified == "" {
			t.Errorf("%s: researched %q, anonymous_tokens %+v", name, e.Researched, e.AnonymousTokens)
		}
		if anonymous, known := e.Tenancy().IssuesAnonymousTokens(); !anonymous || known {
			t.Errorf("%s: IssuesAnonymousTokens() = %v, %v; unverified reads as may", name, anonymous, known)
		}
		for field, v := range map[string]string{"tenancy_claims": e.TenancyClaims.Value, "not_tenancy": e.NotTenancy.Value,
			"subject_forms": e.SubjectForms.Value, "owner_charset": e.OwnerCharset.Value, "match": e.Match.Value,
			"tenant_membership": e.TenantMembership.Value, "names_unique_regardless_of_case": e.NamesUniqueRegardlessOfCase.Value,
			"built_in": e.BuiltIn.Value} {
			if v != "unverified" {
				t.Errorf("%s: %s is %q; only anonymous_tokens was researched", name, field, v)
			}
		}
	}
}

// A no that rests on a chain of sentences says so. That covers GitHub, the
// enterprise path, Google and the per-tenant patterns, and nothing else.
func TestAChainedValueIsMarked(t *testing.T) {
	want := append([]string{"GitHub Actions", "Google (accounts.google.com)"}, perTenant...)
	var got []string
	for _, e := range All() {
		if e.AnonymousTokens.Basis == "chain" {
			got = append(got, e.Name)
			if e.AnonymousTokens.Value != "no" || len(e.AnonymousTokens.Chain) == 0 {
				t.Errorf("%s: basis chain on %q with %d links", e.Name, e.AnonymousTokens.Value, len(e.AnonymousTokens.Chain))
			}
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("chained values on %q\nwant them on %q", got, want)
	}
	if gh := byName(t, "GitHub Actions", ""); len(gh.AnonymousTokens.Chain) != 5 {
		t.Errorf("GitHub's chain has %d links; the research recorded five", len(gh.AnonymousTokens.Chain))
	}
}

// GitHub's enterprise slug is verified recyclable; every other researched
// tenant's recyclability is unverified, which reads as recyclable.
func TestTheEnterpriseSlugIsRecyclable(t *testing.T) {
	ent := byName(t, "GitHub Actions (enterprise issuer path)", "")
	if ent.Match.TenantRecyclable != "yes" || len(ent.Match.TenantRecyclableEvidence) == 0 ||
		!strings.Contains(ent.Match.TenantRecyclableEvidence[0].Quote, "slug") {
		t.Errorf("GitHub's enterprise path: tenant_recyclable %q with %+v", ent.Match.TenantRecyclable, ent.Match.TenantRecyclableEvidence)
	}
	for _, name := range perTenant[1:] {
		if r := byName(t, name, "").Match.TenantRecyclable; r != "unverified" {
			t.Errorf("%s: tenant_recyclable %q; no sentence in the research settles it", name, r)
		}
	}
}

// No v0.1.0 fact a vendor contradicts survives the release.
func TestTheCorrectionsTheVendorsForce(t *testing.T) {
	if e := byName(t, "Microsoft (Azure DevOps)", ""); e.Issuer != "unverified" || e.TenancyModel != "unverified" || strings.Contains(e.Notes, "nothing to scope on") {
		t.Errorf("Azure DevOps: issuer %q, tenancy_model %q, notes %q", e.Issuer, e.TenancyModel, e.Notes)
	}
	if e := byName(t, "env0", ""); strings.Contains(e.Notes, "WRONG") || strings.Contains(e.Notes, "not a deployment-token issuer") {
		t.Errorf("env0: the contradicted caution survives: %q", e.Notes)
	}
	if e := byName(t, "Codeberg (Forgejo)", ""); e.Issuer != "unverified" {
		t.Errorf("Codeberg: issuer %q, want unverified", e.Issuer)
	}
	if e := byName(t, "Cursor", "https://api2.cursor.sh/cloud-agent/identity"); strings.Contains(e.Notes, "exploitable") {
		t.Errorf("Cursor's legacy entry: the contradicted note survives: %q", e.Notes)
	}
	for _, name := range []string{"GitLab.com", "GitLab self-managed"} {
		if e := byName(t, name, ""); e.AudDefault != "unverified" {
			t.Errorf("%s: aud_default %q, want unverified", name, e.AudDefault)
		}
	}
	e := byName(t, "Bitbucket Pipelines", "")
	if e.AudControlledBy != "workload" || !strings.Contains(e.AudEvidence, "To customize your audiences") ||
		strings.Contains(e.AudEvidence, "I found no documented way") || strings.Contains(e.VendorExampleNote, "workspace-pinned anyway") {
		t.Errorf("Bitbucket: aud_controlled_by %q, aud_evidence %q, vendor_example_note %q", e.AudControlledBy, e.AudEvidence, e.VendorExampleNote)
	}
	if e := byName(t, "Chainguard", ""); e.TenancyClaim != "unverified" {
		t.Errorf("Chainguard: tenancy_claim %q, want unverified", e.TenancyClaim)
	}
	if e := byName(t, "Microsoft (Azure DevOps)", ""); e.SubjectFormat != "unverified" {
		t.Errorf("Azure DevOps: subject_format %q; the vendor documents three forms and the census carries none of their sentences", e.SubjectFormat)
	}
	if strings.Contains(e.Notes, "name-recyclable") {
		t.Errorf("Bitbucket: the note that no trust policy is name-recyclable survives, although the issuer carries the workspace ID, a name Atlassian lets a workspace change: %q", e.Notes)
	}
}

// quotes are the quotes of facts, joined, for a test to look a sentence up.
func quotes(fs ...Fact) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Quote)
		b.WriteByte('\n')
	}
	return b.String()
}

// What the facts QA found, each value put back on a sentence that says it,
// or written unverified where no sentence in this release does.
func TestEachValueRestsOnASentenceThatSaysIt(t *testing.T) {
	for name, why := range map[string]string{
		"Spacelift":           "who can cause a run in an account",
		"Bitbucket Pipelines": "who can run a pipeline in a workspace's repositories",
	} {
		m := byName(t, name, "").TenantMembership
		if m.Value != "unverified" || len(m.Evidence) != 0 || !slices.ContainsFunc(m.Unverified, func(u string) bool {
			return strings.Contains(u, why)
		}) {
			t.Errorf("%s: membership %+v; no sentence here says %s, so it is unverified and says so", name, m, why)
		}
	}
	if m := byName(t, "Spacelift", "").TenantMembership; !strings.Contains(quotes(m.Context...), "available to every run in any paid Spacelift account") {
		t.Error("Spacelift: the sentence that was read stays beside the value as context")
	}

	circle := byName(t, "CircleCI", "")
	if chain := quotes(circle.AnonymousTokens.Chain...); !strings.Contains(chain, "Jobs can be configured to use these OIDC tokens") ||
		!strings.Contains(chain, "OpenID Provider URL") {
		t.Errorf("CircleCI: the chain does not name whom a token is minted for: %q", chain)
	}
	for _, note := range circle.TenantMembership.Notes {
		if strings.Contains(note, "404") {
			t.Errorf("CircleCI: a note says the v0.1.0 docs URL returned 404; it redirects to the page cited: %q", note)
		}
	}

	aks := byName(t, "Azure Kubernetes Service (AKS workload identity)", "")
	if aks.Match.TenantPlaceholder != "<region>/<tenant_id>/<cluster_uuid>" {
		t.Errorf("AKS: tenant %q; no sentence says which GUID is the cluster, so the tenant is the whole issuer", aks.Match.TenantPlaceholder)
	}
	if !strings.Contains(quotes(aks.AnonymousTokens.Chain...), "discover the API server's public signing keys") {
		t.Error("AKS: the chain does not tie the issuer to the cluster's API server")
	}

	bitbucket := byName(t, "Bitbucket Pipelines", "")
	if chain := quotes(bitbucket.AnonymousTokens.Chain...); !strings.Contains(chain, "rename your workspace ID") ||
		!strings.Contains(chain, "workspaces/bbcitest") {
		t.Errorf("Bitbucket: the chain does not tie the repository to the workspace the issuer names: %q", chain)
	}

	const iss = "Identifies the STS that constructs and returns the token, and the Microsoft Entra tenant of the authenticated user."
	entra := byName(t, "Microsoft Entra ID", "").Match
	for field, fs := range map[string][]Fact{"tenant_syntax_evidence": entra.TenantSyntaxEvidence,
		"tenant_immutable_evidence": entra.TenantImmutableEvidence,
		"not_a_controlled_tenant":   append([]Fact{entra.NotAControlledTenant[0].Evidence}, entra.NotAControlledTenant[0].Context...)} {
		if !strings.Contains(quotes(fs...), iss) {
			t.Errorf("Entra %s: the iss claim's sentence is not beside the tid claim's", field)
		}
		for _, f := range fs {
			if strings.Contains(f.Quote, "the GUID is the immutable tenant ID") && !strings.Contains(f.Role, "tid") {
				t.Errorf("Entra %s: the tid claim's sentence is not labelled as the tid claim's: role %q", field, f.Role)
			}
		}
	}

	gh := byName(t, "GitHub Actions", "")
	for _, c := range gh.TenancyClaims.Claims {
		if c.Claim == "enterprise" {
			t.Error("GitHub: enterprise pins, although no sentence says its value names one enterprise")
		}
	}
	found := false
	for _, c := range gh.NotTenancy.Claims {
		if c.Claim == "enterprise" {
			found = true
			if !strings.HasPrefix(c.Why, "unverified as a tenant claim") || !strings.Contains(c.Evidence.Quote, "The name of the enterprise") ||
				len(c.LookedIn) == 0 {
				t.Errorf("GitHub: enterprise is not tenancy for no stated reason: %+v", c)
			}
		}
	}
	if !found {
		t.Error("GitHub: enterprise is recorded nowhere")
	}
}

// v0.1.0's field is kept for the callers that read it.
func TestTheV010TenancyClaimIsKept(t *testing.T) {
	kept := map[string]string{"Depot": "org_id", "Namespace": "tenant_id", "Modal": "workspace_id", "Cognition": "org_id", "Warp": "teams"}
	examined := 0
	for _, e := range All() {
		if want, ok := kept[e.Name]; ok {
			examined++
			if e.TenancyClaim != want {
				t.Errorf("%s: tenancy_claim %q, want v0.1.0's %q", e.Name, e.TenancyClaim, want)
			}
		}
		if strings.EqualFold(e.TenancyClaim, "unverified") && e.TenancyClaim != "unverified" {
			t.Errorf("%s: tenancy_claim %q is not the census's spelling of unverified", e.Name, e.TenancyClaim)
		}
	}
	if examined != len(kept) {
		t.Fatalf("examined %d of the %d entries whose tenancy_claim v0.1.0 recorded", examined, len(kept))
	}
}

// Several entries may share a host. A lookup by host alone returns the
// entry whose issuer is that host, as it did before the enterprise path had
// an entry of its own.
func TestGetResolvesASharedHostToTheHostsOwnIssuer(t *testing.T) {
	for _, q := range []string{"token.actions.githubusercontent.com", "https://token.actions.githubusercontent.com/octocorp"} {
		if e, ok := Get(q); !ok || e.Name != "GitHub Actions" {
			t.Errorf("Get(%q) = %q, %v; want GitHub Actions", q, e.Name, ok)
		}
	}
}

// The issuer field of a few entries carries a note ("unverified", "not an
// OIDC issuer") rather than an issuer. A note is not a host.
func TestACensusNoteIsNotAHost(t *testing.T) {
	notes := 0
	for _, e := range All() {
		if e.Issuer == "unverified" || e.Issuer == "not an OIDC issuer" {
			notes++
			if e.IssuerPattern == "" && e.Host() != "" {
				t.Errorf("%s: Host() = %q for the note %q", e.Name, e.Host(), e.Issuer)
			}
		}
	}
	if notes < 4 {
		t.Fatalf("examined %d entries whose issuer is a note; the census has at least 4", notes)
	}
	for _, q := range []string{"unverified", "not an OIDC issuer", "https://unverified"} {
		if e, ok := Get(q); ok {
			t.Errorf("Get(%q) = %s; a note is not a host", q, e.Name)
		}
	}
	for _, h := range MultiTenantHosts() {
		if !strings.Contains(h, ".") || strings.ContainsAny(h, " \t") {
			t.Errorf("MultiTenantHosts includes %q, which is not a hostname", h)
		}
	}
}

var update = flag.Bool("update", false, "rewrite tenancy/testdata/answers.json from this package's answers")

// answers is what every reader says about every census entry: the Go side of
// tenancy/testdata/answers.json. The Python package's tests compute the same
// answers from the same census and compare them with the file, so the two
// packages agree entry by entry, not only on the cases someone thought of.
type answers struct {
	About   string        `json:"about"`
	Probes  probes        `json:"probes"`
	Entries []entryAnswer `json:"entries"`
	// Charsets are owner character sets the census does not hold, which a
	// caller can still hand either package: what OwnerNameMayContain answers
	// for each probe character, 1 or 0 in order.
	Charsets []charsetAnswer `json:"charsets"`
}

type charsetAnswer struct {
	Characters          []string `json:"characters"`
	OwnerNameMayContain string   `json:"owner_name_may_contain"`
}

// probeCharsets are character sets in and out of the census's rule: ASCII
// characters and ranges each package reads alike, and items it must read as
// unreadable, so that any character may occur.
var probeCharsets = [][]string{
	{"a-z"}, {"A-Z", "a-z", "0-9", "-", "_"}, {"--/"}, {"z-a"}, {"a-\u00e9"}, {"\u00e9"}, {"a-z", "\u00e9"},
	{"\u20ac"}, {"a\u00e9"}, {"ab"}, {""}, {"a-"},
}

type probes struct {
	Characters string   `json:"characters"`
	Tenants    []string `json:"tenants"`
}

type entryAnswer struct {
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
	// Instance is an issuer URL made from the entry's own issuer, with every
	// placeholder filled; Match is what Match(Instance) returns.
	Instance                string             `json:"instance"`
	Match                   *matchAnswer       `json:"match"`
	AnonymousTokens         [2]bool            `json:"anonymous_tokens"`
	NamesCompareWithoutCase [2]bool            `json:"names_compare_without_case"`
	TenantIsRecyclable      [2]bool            `json:"tenant_is_recyclable"`
	ControlledTenant        map[string][2]bool `json:"controlled_tenant"`
	// OwnerNameMayContain holds 1 or 0 for each probe character, in order.
	OwnerNameMayContain string         `json:"owner_name_may_contain"`
	Tenancy             tenancy.Issuer `json:"tenancy"`
}

type matchAnswer struct {
	Entry  string `json:"entry"`
	Tenant string `json:"tenant"`
}

const personalMSA = "9188040d-6c67-4c5b-b112-36a304b66dad"

var placeholderRE = regexp.MustCompile(`<[A-Za-z0-9_-]+>`)

// instanceOf fills every placeholder of an entry's issuer with a value built
// for it, a GUID where the tenant has one's syntax.
func instanceOf(e Issuer) string {
	issuer := e.Issuer
	if e.Match.Value == "verified" {
		issuer = e.Match.IssuerPattern
	} else if issuer == "" {
		issuer = e.IssuerPattern
	}
	n := 0
	return placeholderRE.ReplaceAllStringFunc(issuer, func(p string) string {
		n++
		if p == e.Match.TenantPlaceholder && e.Match.TenantSyntax == "guid" {
			return "0123abcd-4567-89ef-0123-456789abcdef"
		}
		// Lower case and dashes only, so the value fits a host label as well
		// as a path segment.
		return fmt.Sprintf("p%d-%s", n, strings.ReplaceAll(strings.Trim(strings.ToLower(p), "<>"), "_", "-"))
	})
}

func pair(a, b bool) [2]bool { return [2]bool{a, b} }

func goAnswers() answers {
	out := answers{
		About: "What every reader of the census answers about every entry, written by the Go tests " +
			"(go test . -run TestGoAndPythonAgree -update) and checked by the Go and the Python tests alike. " +
			"scripts/build.py copies it to python/tests/answers.json.",
		Probes: probes{Characters: "/@:-_.%aZ09 é", Tenants: []string{"acme", personalMSA}},
	}
	for _, e := range All() {
		t := e.Tenancy()
		a := entryAnswer{Name: e.Name, Issuer: e.Issuer, Instance: instanceOf(e), Tenancy: t,
			ControlledTenant: map[string][2]bool{}}
		tenants := slices.Clone(out.Probes.Tenants)
		if got, tenant, ok := Match(a.Instance); ok {
			a.Match = &matchAnswer{Entry: got.Name, Tenant: tenant}
			if tenant != "" {
				tenants = append(tenants, tenant)
			}
		}
		a.AnonymousTokens = pair(t.IssuesAnonymousTokens())
		a.NamesCompareWithoutCase = pair(t.NamesCompareWithoutCase())
		a.TenantIsRecyclable = pair(t.TenantIsRecyclable())
		for _, tenant := range tenants {
			a.ControlledTenant[tenant] = pair(t.ControlledTenant(tenant))
		}
		a.OwnerNameMayContain = mayContain(t, out.Probes.Characters)
		out.Entries = append(out.Entries, a)
	}
	for _, cs := range probeCharsets {
		out.Charsets = append(out.Charsets, charsetAnswer{Characters: cs,
			OwnerNameMayContain: mayContain(tenancy.Issuer{OwnerNameCharacters: cs}, out.Probes.Characters)})
	}
	return out
}

// mayContain is 1 or 0 for each probe character, in order: whether it can
// occur in an owner name.
func mayContain(t tenancy.Issuer, probe string) string {
	var b strings.Builder
	for _, r := range probe {
		if t.OwnerNameMayContain(r) {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	return b.String()
}

// Every reader, on every entry, answers as the shared file says. The Python
// tests hold the Python package to the same file.
func TestGoAndPythonAgree(t *testing.T) {
	const path = "tenancy/testdata/answers.json"
	got := goAnswers()
	b, err := json.MarshalIndent(got, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var want answers
	readJSON(t, path, &want)
	if len(want.Entries) != len(got.Entries) {
		t.Fatalf("%s holds %d entries; the census has %d. Run go test . -run TestGoAndPythonAgree -update", path, len(want.Entries), len(got.Entries))
	}
	matched, differ := 0, 0
	for i := range got.Entries {
		if got.Entries[i].Match != nil {
			matched++
		}
		if !reflect.DeepEqual(got.Entries[i], want.Entries[i]) {
			differ++
			t.Errorf("%s: the Go packages answer\n  %+v\n%s says\n  %+v", got.Entries[i].Name, got.Entries[i], path, want.Entries[i])
		}
	}
	if differ == 0 && !bytes.Equal(b, mustRead(t, path)) {
		t.Errorf("%s differs from the Go answers in form: run go test . -run TestGoAndPythonAgree -update", path)
	}
	if matched < 29 {
		t.Fatalf("%d entries' own issuers matched; the census has at least 29 an issuer can match", matched)
	}
	if len(got.Charsets) == 0 {
		t.Fatal("no invented character set was probed, so nothing holds the packages to one reading of them")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

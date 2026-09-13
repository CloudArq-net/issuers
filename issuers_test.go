package issuers

import (
	"strings"
	"testing"
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

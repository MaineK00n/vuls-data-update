package cvrf_test

import (
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/cvrf"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/product"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
	cvrfTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/cvrf"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		hasError bool
	}{
		{
			name: "happy",
			args: "./testdata/fixtures",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := cvrf.Extract(tt.args, cvrf.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
				if err != nil {
					t.Error("unexpected error:", err)
				}
				gp, err := filepath.Abs(dir)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				utiltest.Diff(t, ep, gp)
			}
		})
	}
}

// Whitelist enforcement: a Known Affected product that is absent from the tree
// or not in the product table must hard-error rather than be silently dropped.
func TestKnownAffectedCriterionsWhitelist(t *testing.T) {
	tests := []struct {
		name      string
		productID string
		prodMap   map[string]cvrf.ProductVersion
		wantErr   bool
	}{
		{
			name:      "known product, concrete version",
			productID: "FortiOS-7.4.3",
			prodMap:   map[string]cvrf.ProductVersion{"FortiOS-7.4.3": cvrf.NewProductVersion("FortiOS", "7.4.3")},
		},
		{
			name:      "product_id absent from tree → hard error",
			productID: "FortiOS-7.4.3",
			prodMap:   map[string]cvrf.ProductVersion{},
			wantErr:   true,
		},
		{
			name:      "unknown product name → hard error",
			productID: "FortiNonexistent-1.0.0",
			prodMap:   map[string]cvrf.ProductVersion{"FortiNonexistent-1.0.0": cvrf.NewProductVersion("FortiNonexistent", "1.0.0")},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cvrf.KnownAffectedCriterions([]string{tt.productID}, tt.prodMap)
			if (err != nil) != tt.wantErr {
				t.Errorf("KnownAffectedCriterions(%q) error = %v, wantErr %v", tt.productID, err, tt.wantErr)
			}
		})
	}
}

// The only product-status type observed across the corpus is "Known
// Affected", and it must list products (resolvable in the product tree). An
// empty type falls back to the supplement table — content-only when the
// advisory has no entry there. Everything else must fail loudly rather than
// silently emit no detection: an unexpected type, a typed status listing no
// products, or products listed without a type.
func TestExtractStatusType(t *testing.T) {
	tests := []struct {
		name       string
		statusType string
		productIDs []string
		wantErr    bool
	}{
		{name: "known affected with no products → error", statusType: "Known Affected", wantErr: true},
		{name: "known affected with products but no tree → error", statusType: "Known Affected", productIDs: []string{"FortiOS-7.4.3"}, wantErr: true},
		{name: "empty (content-only)", statusType: ""},
		{name: "empty type with products → error", statusType: "", productIDs: []string{"FortiOS-7.4.3"}, wantErr: true},
		{name: "unexpected type → error", statusType: "Known Not Affected", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fetched cvrfTypes.CVRF
			fetched.DocumentTracking.Identification.ID = "FG-IR-24-001"
			fetched.Vulnerability.ProductStatuses.Status.Type = tt.statusType
			fetched.Vulnerability.ProductStatuses.Status.ProductID = tt.productIDs
			_, err := cvrf.ExtractData(fetched, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Every non-empty CVRF vector across the corpus is a parseable CVSS 3.1 vector,
// so an empty or valid 3.1 vector are the only expected shapes; a non-3.1 or
// malformed vector fails the extract rather than being silently dropped.
func TestExtractSeverityVector(t *testing.T) {
	tests := []struct {
		name    string
		vector  string
		wantErr bool
	}{
		{name: "empty (no score)", vector: ""},
		{name: "valid 3.1", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{name: "non-3.1 → error", vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", wantErr: true},
		{name: "malformed 3.1 → error", vector: "CVSS:3.1/not-a-vector", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fetched cvrfTypes.CVRF
			fetched.DocumentTracking.Identification.ID = "FG-IR-24-001"
			fetched.Vulnerability.CVSSScoreSets.ScoreSetV3.VectorV3 = tt.vector
			_, err := cvrf.ExtractData(fetched, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// CVRF reference values put the URL behind citation markers, inside prose, or
// in HTML wrappers; extractReferenceURLs recovers the URL from any position and
// rejects non-URL free text.
func TestExtractReferenceURLs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "bare url", in: "https://example.com/x", want: []string{"https://example.com/x"}},
		{name: "citation marker", in: "[1] https://blog.example.com/x", want: []string{"https://blog.example.com/x"}},
		{name: "dash marker with newline", in: "- https://example.com/x\n", want: []string{"https://example.com/x"}},
		{name: "embedded in prose", in: "see the link: https://example.com/x", want: []string{"https://example.com/x"}},
		{name: "p wrapper", in: "<p>https://nvd.nist.gov/vuln/detail/CVE-2016-0723</p>", want: []string{"https://nvd.nist.gov/vuln/detail/CVE-2016-0723"}},
		{name: "a href (non-url anchor text)", in: `<a href="http://archives.neohapsis.com/x.html">Neohapsis</a>`, want: []string{"http://archives.neohapsis.com/x.html"}},
		{name: "free text", in: `Disable "Save Password" setting`, want: nil},
		{name: "empty", in: "", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cvrf.ExtractReferenceURLs(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("ExtractReferenceURLs(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// The embedded supplement table is frozen curated data. Walking every entry
// exercises the builder's hard errors (unknown product, non-numeric version,
// empty or inverted range, unaudited whole-product row), and the shape
// invariants pin what those errors cannot see: each row yields exactly its
// criterions (one CPEMatches criterion when it enumerates versions, one range
// criterion per range, one bare criterion for an audited whole-product row),
// every range criterion carries at least one bound and the range type the
// product table assigns to its CPE, no advisory lists a product twice, and
// every key is a plausible advisory ID (an ID typo would orphan the entry —
// the CVRF document it supplements could never reference it).
func TestSupplementCriterions(t *testing.T) {
	if len(cvrf.SupplementTable) == 0 {
		t.Fatal("supplement table is empty")
	}
	idRe := regexp.MustCompile(`^FG-IR-\d{2,3}-\d{3}$`)
	for _, id := range slices.Sorted(maps.Keys(cvrf.SupplementTable)) {
		t.Run(id, func(t *testing.T) {
			if !idRe.MatchString(id) {
				t.Errorf("advisory ID %q does not match the FG-IR shape", id)
			}
			rows := cvrf.SupplementTable[id]
			wantN := 0
			typeOf := make(map[string]ccRangeTypes.RangeType, len(rows))
			seen := make(map[string]bool, len(rows))
			for _, row := range rows {
				if seen[row.Product] {
					t.Errorf("duplicate product %q", row.Product)
				}
				seen[row.Product] = true
				cpe, rt, ok := product.Resolve(row.Product)
				if !ok {
					t.Fatalf("product %q not in the product table", row.Product)
				}
				typeOf[cpe] = rt
				if len(row.Versions) > 0 {
					wantN++
				}
				wantN += len(row.Ranges)
				if len(row.Versions) == 0 && len(row.Ranges) == 0 {
					wantN++
				}
			}
			cs, err := cvrf.SupplementCriterions(cvrf.SupplementTable, id)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cs) != wantN {
				t.Fatalf("criterion count = %d, want %d", len(cs), wantN)
			}
			for _, c := range cs {
				if c.Type != criterionTypes.CriterionTypeCPE || c.CPE == nil {
					t.Errorf("not a CPE criterion: %+v", c)
					continue
				}
				if !c.CPE.Vulnerable || c.CPE.CPE == "" {
					t.Errorf("criterion lacks the vulnerable flag or a CPE: %+v", c.CPE)
				}
				if r := c.CPE.Range; r != nil {
					if r.GreaterEqual == "" && r.GreaterThan == "" && r.LessEqual == "" && r.LessThan == "" {
						t.Errorf("range criterion for %s has no bounds", c.CPE.CPE)
					}
					if want, ok := typeOf[string(c.CPE.CPE)]; !ok || r.Type != want {
						t.Errorf("range type for %s = %q, want %q", c.CPE.CPE, r.Type, want)
					}
				}
			}
		})
	}
}

// The whole-table walk above checks shapes, not values — these pin one
// advisory of each shape (ranges, exact versions, audited whole product)
// against expectations written out by hand from the advisory notes.
func TestSupplementCriterionsRepresentative(t *testing.T) {
	rangeCriterion := func(cpe string, r ccRangeTypes.Range) criterionTypes.Criterion {
		return criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeCPE,
			CPE: &ccTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
				CPE:        ccTypes.CPE(cpe),
				Range:      &r,
			},
		}
	}
	tests := []struct {
		id   string
		want []criterionTypes.Criterion
	}{
		{
			// Solutions: "5.0 branch: 5.0.13 or above / 5.2 branch: 5.2.4 or
			// above / 4.3 and lower branches are not affected".
			id: "FG-IR-16-003",
			want: []criterionTypes.Criterion{
				rangeCriterion("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
					ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeFortinetFortiOS, GreaterEqual: "5.0.0", LessThan: "5.0.13"}),
				rangeCriterion("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
					ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeFortinetFortiOS, GreaterEqual: "5.2.0", LessThan: "5.2.4"}),
			},
		},
		{
			// "FortiIsolator version 2.3.2 and below" — enumerated releases.
			id: "FG-IR-21-040",
			want: []criterionTypes.Criterion{{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        "cpe:2.3:o:fortinet:fortiisolator:*:*:*:*:*:*:*:*",
					CPEMatches: []ccTypes.CPE{
						"cpe:2.3:o:fortinet:fortiisolator:2.3.0:*:*:*:*:*:*:*",
						"cpe:2.3:o:fortinet:fortiisolator:2.3.1:*:*:*:*:*:*:*",
						"cpe:2.3:o:fortinet:fortiisolator:2.3.2:*:*:*:*:*:*:*",
					},
				},
			}},
		},
		{
			// Audited whole-product row (CVE rejected, FortiOS-bundle-only
			// bounds) — the bare wildcard CPE with no narrowing.
			id: "FG-IR-16-041",
			want: []criterionTypes.Criterion{{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        "cpe:2.3:a:fortinet:forticlient_ssl_vpn:*:*:*:*:*:*:*:*",
				},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, err := cvrf.SupplementCriterions(cvrf.SupplementTable, tt.id)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("(-expected +got):\n%s", diff)
			}
		})
	}
}

// An advisory outside the table is not an error — the caller falls back to
// content-only extraction.
func TestSupplementCriterionsUnknownID(t *testing.T) {
	if cs, err := cvrf.SupplementCriterions(cvrf.SupplementTable, "FG-IR-99-999"); err != nil || cs != nil {
		t.Errorf("SupplementCriterions(unknown) = %v, %v, want nil, nil", cs, err)
	}
}

// Every wholeProductAudited entry must still back a live constraint-less row;
// a stale entry would silently pre-authorize a future whole-product widening
// of that (advisory, product) pair.
func TestSupplementWholeProductAuditedLive(t *testing.T) {
	for _, p := range cvrf.WholeProductAuditedPairs() {
		ok := slices.ContainsFunc(cvrf.SupplementTable[p[0]], func(row cvrf.SupplementProduct) bool {
			return row.Product == p[1] && len(row.Versions) == 0 && len(row.Ranges) == 0
		})
		if !ok {
			t.Errorf("wholeProductAudited entry (%s, %s) backs no constraint-less row in the table", p[0], p[1])
		}
	}
}

// A cve[] entry is normally a bare CVE ID; the three known malformed
// FG-IR-14-010 entries are normalized by exact-string fixup, and any other
// non-bare shape must fail the extract instead of becoming a junk (or
// silently mis-normalized) vulnerability ID.
func TestExtractCVEEntries(t *testing.T) {
	tests := []struct {
		name    string
		cves    []string
		wantIDs []string
		wantErr bool
	}{
		{name: "bare id", cves: []string{"CVE-2020-12345"}, wantIDs: []string{"CVE-2020-12345"}},
		{name: "known fixup", cves: []string{"CVE-<br />2014-2722 key issue"}, wantIDs: []string{"CVE-2014-2722"}},
		{name: "fixup + bare, deduped", cves: []string{"CVE-2014-2721 password issue", "CVE-2014-2721"}, wantIDs: []string{"CVE-2014-2721"}},
		{name: "unknown malformed entry → error", cves: []string{"CVE-2020-12345 some new junk"}, wantErr: true},
		{name: "short sequence → error", cves: []string{"CVE-2014-1"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fetched cvrfTypes.CVRF
			fetched.DocumentTracking.Identification.ID = "FG-IR-24-001"
			fetched.Vulnerability.CVE = tt.cves
			data, err := cvrf.ExtractData(fetched, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExtractData() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			got := make([]string, 0, len(data.Vulnerabilities))
			for _, v := range data.Vulnerabilities {
				got = append(got, string(v.Content.ID))
			}
			if !slices.Equal(got, tt.wantIDs) {
				t.Errorf("vulnerability IDs = %q, want %q", got, tt.wantIDs)
			}
		})
	}
}

// A row with no version constraint matches every version of its product, so
// only pairs audited into wholeProductAudited may emit one; a hand edit that
// accidentally deletes a row's constraints must fail instead of silently
// widening detection to the whole product.
func TestSupplementWholeProductGuard(t *testing.T) {
	table := map[string][]cvrf.SupplementProduct{"FG-IR-99-998": {{Product: "FortiOS"}}}
	if _, err := cvrf.SupplementCriterions(table, "FG-IR-99-998"); err == nil {
		t.Error("SupplementCriterions() with an unaudited whole-product row: expected error, got nil")
	}
}

// A range with every bound blank would extract into a criterion that never
// matches — a silent detection false negative, and the likeliest shape of a
// hand edit that blanks a row's bounds without deleting the range (which
// would instead trip the whole-product guard above).
func TestSupplementEmptyRangeGuard(t *testing.T) {
	table := map[string][]cvrf.SupplementProduct{"FG-IR-99-997": {{Product: "FortiOS", Ranges: []cvrf.SupplementRange{{}}}}}
	if _, err := cvrf.SupplementCriterions(table, "FG-IR-99-997"); err == nil {
		t.Error("SupplementCriterions() with an empty range: expected error, got nil")
	}
}

package csaf_test

import (
	"encoding/json/v2"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/csaf"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
	csafTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/csaf"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		golden   string
		hasError bool
	}{
		{
			name:   "happy",
			args:   "./testdata/fixtures",
			golden: "./testdata/golden",
		},
		{
			// A product branch at the top of the tree, with no vendor branch
			// above it: the leaves moved out of it must land in the tree.
			name:   "tree fix on a tree without a vendor branch",
			args:   "./testdata/fixtures-no-vendor",
			golden: "./testdata/golden-no-vendor",
		},
		{
			name:     "tree fix no longer matching the advisory",
			args:     "./testdata/fixtures-stale-tree-fix",
			hasError: true,
		},
		{
			name:     "undefined known_not_affected product of no known shape",
			args:     "./testdata/fixtures-undefined-not-affected",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := csaf.Extract(tt.args, csaf.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				return
			default:
				if err := utiltest.Diff(tt.golden, dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}

func TestToCriterion(t *testing.T) {
	type args struct {
		productID string
		refMap    map[string]csaf.ProductRef
	}
	tests := []struct {
		name    string
		args    args
		want    criterionTypes.Criterion
		wantErr bool
	}{
		{
			name: "concrete version baked",
			args: args{
				productID: "FortiOS 7.4.3",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.4.3": csaf.NewProductRef("FortiOS", "7.4.3"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*"),
				},
			},
		},
		{
			name: "range expr → range, wildcard cpe",
			args: args{
				productID: "FortiOS >=7.0.0|<=7.0.5",
				refMap: map[string]csaf.ProductRef{
					"FortiOS >=7.0.0|<=7.0.5": csaf.NewProductRef("FortiOS", ">=7.0.0|<=7.0.5"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"),
					Range: &ccRangeTypes.Range{
						Type:         ccRangeTypes.RangeTypeFortinetFortiOS,
						GreaterEqual: "7.0.0",
						LessEqual:    "7.0.5",
					},
				},
			},
		},
		{
			name: "whole product (all versions)",
			args: args{
				productID: "FortiOS all versions",
				refMap: map[string]csaf.ProductRef{
					"FortiOS all versions": csaf.NewProductRef("FortiOS", "all versions"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"),
				},
			},
		},
		{
			name: "product_id not in tree map rejected",
			args: args{
				productID: "FortiOS 6.0.0",
				refMap:    map[string]csaf.ProductRef{},
			},
			wantErr: true,
		},
		{
			name: "known product via tree ref with range",
			args: args{
				productID: "FortiOS >=7.0.0|<=7.0.5",
				refMap: map[string]csaf.ProductRef{
					"FortiOS >=7.0.0|<=7.0.5": csaf.NewProductRef("FortiOS", ">=7.0.0|<=7.0.5"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"),
					Range: &ccRangeTypes.Range{
						Type:         ccRangeTypes.RangeTypeFortinetFortiOS,
						GreaterEqual: "7.0.0",
						LessEqual:    "7.0.5",
					},
				},
			},
		},
		{
			name: "X.Y all versions → train range, wildcard cpe",
			args: args{
				productID: "FortiOS 7.0 all versions",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.0 all versions": csaf.NewProductRef("FortiOS", "7.0 all versions"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"),
					Range: &ccRangeTypes.Range{
						Type:         ccRangeTypes.RangeTypeFortinetFortiOS,
						GreaterEqual: "7.0",
						LessThan:     "7.1",
					},
				},
			},
		},
		{
			name: "numeric and above ok (numeric product)",
			args: args{
				productID: "FortiOS 7.0.0 and above",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.0.0 and above": csaf.NewProductRef("FortiOS", "7.0.0 and above"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"),
					Range: &ccRangeTypes.Range{
						Type:         ccRangeTypes.RangeTypeFortinetFortiOS,
						GreaterEqual: "7.0.0",
					},
				},
			},
		},
		{
			name: "non-numeric product train range ok",
			args: args{
				productID: "FortiSASE 25.2 all versions",
				refMap: map[string]csaf.ProductRef{
					"FortiSASE 25.2 all versions": csaf.NewProductRef("FortiSASE", "25.2 all versions"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*"),
					Range: &ccRangeTypes.Range{
						Type:         ccRangeTypes.RangeTypeFortinetFortiSASE,
						GreaterEqual: "25.2",
						LessThan:     "25.3",
					},
				},
			},
		},
		{
			name: "non-numeric product whole-product ok",
			args: args{
				productID: "FortiSASE all versions",
				refMap: map[string]csaf.ProductRef{
					"FortiSASE all versions": csaf.NewProductRef("FortiSASE", "all versions"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*"),
				},
			},
		},
		{
			name: "non-numeric concrete version baked, not a bound",
			args: args{
				productID: "FortiSASE 25.2.a",
				refMap: map[string]csaf.ProductRef{
					"FortiSASE 25.2.a": csaf.NewProductRef("FortiSASE", "25.2.a"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:a:fortinet:fortisase:25.2.a:*:*:*:*:*:*:*"),
				},
			},
		},
		{
			name: "product in tree but not whitelisted → hard error",
			args: args{
				productID: "FortiNonexistent >=1.0.0|<=2.0.0",
				refMap: map[string]csaf.ProductRef{
					"FortiNonexistent >=1.0.0|<=2.0.0": csaf.NewProductRef("FortiNonexistent", ">=1.0.0|<=2.0.0"),
				},
			},
			wantErr: true,
		},
		{
			// A product name leaked into the version ("<name> all versions") is a
			// non-numeric train and must hard-error, not be widened to whole product.
			name: "leaked product name all versions → hard error",
			args: args{
				productID: "FortiOS FortiClient iOS all versions",
				refMap: map[string]csaf.ProductRef{
					"FortiOS FortiClient iOS all versions": csaf.NewProductRef("FortiOS", "FortiClient iOS all versions"),
				},
			},
			wantErr: true,
		},
		{
			name: "non-numeric lower bound rejected",
			args: args{
				productID: "FortiOS >=25.2.a|<=25.2.5",
				refMap: map[string]csaf.ProductRef{
					"FortiOS >=25.2.a|<=25.2.5": csaf.NewProductRef("FortiOS", ">=25.2.a|<=25.2.5"),
				},
			},
			wantErr: true,
		},
		{
			name: "non-numeric upper bound rejected",
			args: args{
				productID: "FortiOS >=25.2.0|<=25.2.c",
				refMap: map[string]csaf.ProductRef{
					"FortiOS >=25.2.0|<=25.2.c": csaf.NewProductRef("FortiOS", ">=25.2.0|<=25.2.c"),
				},
			},
			wantErr: true,
		},
		{
			name: "non-numeric and above rejected",
			args: args{
				productID: "FortiOS 25.2.a and above",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 25.2.a and above": csaf.NewProductRef("FortiOS", "25.2.a and above"),
				},
			},
			wantErr: true,
		},
		{
			name: "build suffix bound rejected",
			args: args{
				productID: "FortiOS >=7.1-b5955",
				refMap: map[string]csaf.ProductRef{
					"FortiOS >=7.1-b5955": csaf.NewProductRef("FortiOS", ">=7.1-b5955"),
				},
			},
			wantErr: true,
		},
		{
			name: "non-numeric product multi-component range rejected",
			args: args{
				productID: "FortiSASE >=25.2.0|<=25.2.5",
				refMap: map[string]csaf.ProductRef{
					"FortiSASE >=25.2.0|<=25.2.5": csaf.NewProductRef("FortiSASE", ">=25.2.0|<=25.2.5"),
				},
			},
			wantErr: true,
		},
		{
			name: "non-numeric product 3-component and-above rejected",
			args: args{
				productID: "FortiSASE 25.2.0 and above",
				refMap: map[string]csaf.ProductRef{
					"FortiSASE 25.2.0 and above": csaf.NewProductRef("FortiSASE", "25.2.0 and above"),
				},
			},
			wantErr: true,
		},
		{
			// Empty bound after an operator would be silently treated as "no
			// constraint" and over-match.
			name: "empty bound after operator rejected",
			args: args{
				productID: "FortiOS >=7.0.0|<=",
				refMap: map[string]csaf.ProductRef{
					"FortiOS >=7.0.0|<=": csaf.NewProductRef("FortiOS", ">=7.0.0|<="),
				},
			},
			wantErr: true,
		},
		{
			name: "bare operator with no version rejected",
			args: args{
				productID: "FortiOS >",
				refMap: map[string]csaf.ProductRef{
					"FortiOS >": csaf.NewProductRef("FortiOS", ">"),
				},
			},
			wantErr: true,
		},
		{
			// "and above" with no version before it would yield an empty lower
			// bound (treated as no constraint) → reject.
			name: "and above with no version rejected",
			args: args{
				productID: "FortiOS  and above",
				refMap: map[string]csaf.ProductRef{
					"FortiOS  and above": csaf.NewProductRef("FortiOS", " and above"),
				},
			},
			wantErr: true,
		},
		{
			// Bogus concrete version that BakeVersion would otherwise accept (CPE
			// legal but no scanner reports it) — a silent false-negative.
			name: "bogus concrete version with letter component rejected",
			args: args{
				productID: "FortiOS 7.0.x",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.0.x": csaf.NewProductRef("FortiOS", "7.0.x"),
				},
			},
			wantErr: true,
		},
		{
			name: "concrete version with leading v rejected",
			args: args{
				productID: "FortiOS v7.0.0",
				refMap: map[string]csaf.ProductRef{
					"FortiOS v7.0.0": csaf.NewProductRef("FortiOS", "v7.0.0"),
				},
			},
			wantErr: true,
		},
		{
			// A stray non-numeric symbol (and no <> operator) is neither a range
			// nor a valid concrete version, so it falls through to the bake path,
			// where numericBound rejects it.
			name: "concrete version with stray symbol rejected",
			args: args{
				productID: "FortiOS 7.0.0$7.2.1",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.0.0$7.2.1": csaf.NewProductRef("FortiOS", "7.0.0$7.2.1"),
				},
			},
			wantErr: true,
		},
		{
			// A non-numeric-versioned product may bake a single-letter milestone
			// (25.2.a), but an ambiguous multi-char component the comparator can't
			// order (25.1.a10, 25.2.alpha) must hard-error, not be baked.
			name: "non-numeric product bogus milestone version rejected",
			args: args{
				productID: "FortiSASE 25.1.a10",
				refMap: map[string]csaf.ProductRef{
					"FortiSASE 25.1.a10": csaf.NewProductRef("FortiSASE", "25.1.a10"),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := csaf.ToCriterion(tt.args.productID, tt.args.refMap)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ToCriterion(%q) error = %v, wantErr %v", tt.args.productID, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ToCriterion(%q) (-want +got):\n%s", tt.args.productID, diff)
			}
		})
	}
}

func TestExtractScoreScope(t *testing.T) {
	const (
		v74 = "FortiOS 7.4 all versions"
		v72 = "FortiOS 7.2 all versions"
		vA  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		vB  = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N"
	)
	// doc wraps one vulnerability object (its scores and threats) in an
	// advisory whose FortiOS product node has the 7.4 and 7.2 train leaves,
	// both known_affected.
	doc := func(scores, threats string) string {
		return fmt.Sprintf(`{
			"document": {"title": "t", "tracking": {"id": "FG-IR-99-001", "initial_release_date": "2099-01-01T00:00:00", "current_release_date": "2099-01-01T00:00:00"}},
			"product_tree": {"branches": [{"category": "vendor", "name": "Fortinet PSIRT", "branches": [{"category": "product", "name": "FortiOS", "branches": [
				{"category": "product_version_range", "name": "FortiOS/7.4 all versions", "product": {"name": "FortiOS", "product_id": %q}},
				{"category": "product_version_range", "name": "FortiOS/7.2 all versions", "product": {"name": "FortiOS", "product_id": %q}}
			]}]}]},
			"vulnerabilities": [{"cve": "CVE-2099-0001", "product_status": {"known_affected": [%q, %q]}, "scores": %s, "threats": %s}]
		}`, v74, v72, v74, v72, scores, threats)
	}
	score := func(vector string, products ...string) string {
		qs := make([]string, 0, len(products))
		for _, p := range products {
			qs = append(qs, fmt.Sprintf("%q", p))
		}
		return fmt.Sprintf(`{"cvss_v3": {"version": "3.1", "vectorString": %q, "baseScore": 0, "baseSeverity": ""}, "products": [%s]}`, vector, strings.Join(qs, ", "))
	}
	criterion := func(pid string) criterionTypes.Criterion {
		c, err := csaf.ToCriterion(pid, map[string]csaf.ProductRef{
			v74: csaf.NewProductRef("FortiOS", "7.4 all versions"),
			v72: csaf.NewProductRef("FortiOS", "7.2 all versions"),
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	tests := []struct {
		name    string
		scores  string
		threats string
		// want maps "<vector> <impact>" to the criterions of the Vulnerability
		// record carrying that severity.
		want    map[string][]criterionTypes.Criterion
		wantErr bool
	}{
		{
			name:    "product-name score covers every leaf",
			scores:  fmt.Sprintf("[%s]", score(vA, "FortiOS")),
			threats: `[{"category": "impact", "details": "Code execution"}]`,
			want: map[string][]criterionTypes.Criterion{
				vA + " Code execution": {criterion(v74), criterion(v72)},
			},
		},
		{
			name:    "leaf-scoped scores split the key",
			scores:  fmt.Sprintf("[%s, %s]", score(vA, v74), score(vB, v72)),
			threats: `[{"category": "impact", "details": "Code execution"}]`,
			want: map[string][]criterionTypes.Criterion{
				vA + " Code execution": {criterion(v74)},
				vB + " Code execution": {criterion(v72)},
			},
		},
		{
			name:    "leaf-scoped threats split the key",
			scores:  fmt.Sprintf("[%s]", score(vA, "FortiOS")),
			threats: fmt.Sprintf(`[{"category": "impact", "details": "Code execution", "product_ids": [%q]}, {"category": "impact", "details": "Information disclosure", "product_ids": [%q]}]`, v74, v72),
			want: map[string][]criterionTypes.Criterion{
				vA + " Code execution":         {criterion(v74)},
				vA + " Information disclosure": {criterion(v72)},
			},
		},
		{
			name:    "leaf with no score",
			scores:  fmt.Sprintf("[%s]", score(vA, v74)),
			threats: `[{"category": "impact", "details": "Code execution"}]`,
			wantErr: true,
		},
		{
			name:    "leaf with two distinct scores",
			scores:  fmt.Sprintf("[%s, %s]", score(vA, "FortiOS"), score(vB, v72)),
			threats: `[{"category": "impact", "details": "Code execution"}]`,
			wantErr: true,
		},
		{
			name:    "score naming an unknown product",
			scores:  fmt.Sprintf("[%s, %s]", score(vA, "FortiOS"), score(vB, "FortiProxy")),
			threats: `[{"category": "impact", "details": "Code execution"}]`,
			wantErr: true,
		},
		{
			name:    "threat scoped by product group",
			scores:  fmt.Sprintf("[%s]", score(vA, "FortiOS")),
			threats: `[{"category": "impact", "details": "Code execution", "group_ids": ["g1"]}]`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fetched csafTypes.CSAF
			if err := json.UnmarshalRead(strings.NewReader(doc(tt.scores, tt.threats)), &fetched); err != nil {
				t.Fatal(err)
			}
			data, err := csaf.ExtractCSAF(fetched, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("extract() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			got := make(map[string][]criterionTypes.Criterion)
			for _, v := range data.Vulnerabilities {
				var vector, impact string
				for _, s := range v.Content.Severity {
					switch {
					case s.CVSSv31 != nil:
						vector = s.CVSSv31.Vector
					case s.Vendor != nil:
						impact = *s.Vendor
					}
				}
				if len(v.Segments) != 1 {
					t.Fatalf("unexpected segments. expected: 1, actual: %d", len(v.Segments))
				}
				for _, c := range data.Detections[0].Conditions {
					if c.Tag == v.Segments[0].Tag {
						got[fmt.Sprintf("%s %s", vector, impact)] = c.Criteria.Criterions
					}
				}
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("(-expected +got):\n%s", diff)
			}
		})
	}
}

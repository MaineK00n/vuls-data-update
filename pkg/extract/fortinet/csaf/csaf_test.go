package csaf_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/csaf"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
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
			err := csaf.Extract(tt.args, csaf.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
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

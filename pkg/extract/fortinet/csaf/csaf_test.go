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
	csafTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/csaf"
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
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
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
		{
			// A parenthesized remark after "<train> all versions" qualifies how
			// the train is affected, not which versions; it is dropped.
			name: "train all versions with parenthesized remark → train range",
			args: args{
				productID: "FortiOS 6.0 all versions (need to be authenticated to provoke a crash)",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 6.0 all versions (need to be authenticated to provoke a crash)": csaf.NewProductRef("FortiOS", "6.0 all versions (need to be authenticated to provoke a crash)"),
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
						GreaterEqual: "6.0",
						LessThan:     "6.1",
					},
				},
			},
		},
		{
			// FG-IR-23-001 carries the other remark wording on five trains; each
			// leaf is its own known_affected entry (no list syntax).
			name: "train all versions with special-note remark → train range",
			args: args{
				productID: "FortiOS 5.0 all versions (special note for fortios in additional note section)",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 5.0 all versions (special note for fortios in additional note section)": csaf.NewProductRef("FortiOS", "5.0 all versions (special note for fortios in additional note section)"),
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
						GreaterEqual: "5.0",
						LessThan:     "5.1",
					},
				},
			},
		},
		{
			// A remark after a bare "all versions" (no train) could be the only
			// place the versions are stated; it is not dropped, so the
			// expression falls through and is rejected instead of widening to
			// the whole product.
			name: "bare all versions with remark rejected",
			args: args{
				productID: "FortiOS all versions (7.0 and 7.2)",
				refMap: map[string]csaf.ProductRef{
					"FortiOS all versions (7.0 and 7.2)": csaf.NewProductRef("FortiOS", "all versions (7.0 and 7.2)"),
				},
			},
			wantErr: true,
		},
		{
			// Only one parenthesized group closing the expression is a remark;
			// text after it, a second group, or an empty group is malformed
			// input and must not be reduced to the train.
			name: "remark followed by trailing text rejected",
			args: args{
				productID: "FortiOS 7.0 all versions (note) trailing)",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.0 all versions (note) trailing)": csaf.NewProductRef("FortiOS", "7.0 all versions (note) trailing)"),
				},
			},
			wantErr: true,
		},
		{
			name: "two remarks rejected",
			args: args{
				productID: "FortiOS 7.0 all versions (note) (other)",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.0 all versions (note) (other)": csaf.NewProductRef("FortiOS", "7.0 all versions (note) (other)"),
				},
			},
			wantErr: true,
		},
		{
			name: "empty remark rejected",
			args: args{
				productID: "FortiOS 7.0 all versions ()",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.0 all versions ()": csaf.NewProductRef("FortiOS", "7.0 all versions ()"),
				},
			},
			wantErr: true,
		},
		{
			name: "remark before all versions rejected",
			args: args{
				productID: "FortiOS 6.0 (note) all versions",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 6.0 (note) all versions": csaf.NewProductRef("FortiOS", "6.0 (note) all versions"),
				},
			},
			wantErr: true,
		},
		{
			// Dropping the remark must not let a leaked product name through.
			name: "leaked product name with remark still rejected",
			args: args{
				productID: "FortiOS FortiClient iOS all versions (note)",
				refMap: map[string]csaf.ProductRef{
					"FortiOS FortiClient iOS all versions (note)": csaf.NewProductRef("FortiOS", "FortiClient iOS all versions (note)"),
				},
			},
			wantErr: true,
		},
		{
			name: "through range → inclusive range",
			args: args{
				productID: "FortiAnalyzer-BigData 7.2.0 through 7.2.7",
				refMap: map[string]csaf.ProductRef{
					"FortiAnalyzer-BigData 7.2.0 through 7.2.7": csaf.NewProductRef("FortiAnalyzer-BigData", "7.2.0 through 7.2.7"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:o:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*"),
					Range: &ccRangeTypes.Range{
						Type:         ccRangeTypes.RangeTypeFortinetFortiAnalyzerBigData,
						GreaterEqual: "7.2.0",
						LessEqual:    "7.2.7",
					},
				},
			},
		},
		{
			// FG-IR-24-098 spells it "though".
			name: "though (typo of through) range → inclusive range",
			args: args{
				productID: "FortiAnalyzer-BigData 7.2.0 though 7.2.7",
				refMap: map[string]csaf.ProductRef{
					"FortiAnalyzer-BigData 7.2.0 though 7.2.7": csaf.NewProductRef("FortiAnalyzer-BigData", "7.2.0 though 7.2.7"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:o:fortinet:fortianalyzer-bigdata:*:*:*:*:*:*:*:*"),
					Range: &ccRangeTypes.Range{
						Type:         ccRangeTypes.RangeTypeFortinetFortiAnalyzerBigData,
						GreaterEqual: "7.2.0",
						LessEqual:    "7.2.7",
					},
				},
			},
		},
		{
			// A train end would stop at 7.4 instead of covering the 7.4 train.
			name: "through range with train end rejected",
			args: args{
				productID: "FortiOS 7.2 through 7.4",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.2 through 7.4": csaf.NewProductRef("FortiOS", "7.2 through 7.4"),
				},
			},
			wantErr: true,
		},
		{
			name: "through range with missing end rejected",
			args: args{
				productID: "FortiOS 7.2.0 through ",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.2.0 through ": csaf.NewProductRef("FortiOS", "7.2.0 through "),
				},
			},
			wantErr: true,
		},
		{
			name: "through range with non-numeric end rejected",
			args: args{
				productID: "FortiOS 7.2.0 through 7.2.x",
				refMap: map[string]csaf.ProductRef{
					"FortiOS 7.2.0 through 7.2.x": csaf.NewProductRef("FortiOS", "7.2.0 through 7.2.x"),
				},
			},
			wantErr: true,
		},
		{
			name: "FortiMonitorOnSight resolves to its CNA CPE and range type",
			args: args{
				productID: "FortiMonitorOnSight >=7.2.4|<=7.2.7",
				refMap: map[string]csaf.ProductRef{
					"FortiMonitorOnSight >=7.2.4|<=7.2.7": csaf.NewProductRef("FortiMonitorOnSight", ">=7.2.4|<=7.2.7"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:a:fortinet:fortimonitoronsight:*:*:*:*:*:*:*:*"),
					Range: &ccRangeTypes.Range{
						Type:         ccRangeTypes.RangeTypeFortinetFortiMonitorOnSight,
						GreaterEqual: "7.2.4",
						LessEqual:    "7.2.7",
					},
				},
			},
		},
		{
			name: "FortiPAM Chrome Extension resolves to its CNA CPE and range type",
			args: args{
				productID: "FortiPAM Chrome Extension 8.0 all versions",
				refMap: map[string]csaf.ProductRef{
					"FortiPAM Chrome Extension 8.0 all versions": csaf.NewProductRef("FortiPAM Chrome Extension", "8.0 all versions"),
				},
			},
			want: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE("cpe:2.3:a:fortinet:fortipam_chrome_extension:*:*:*:*:*:*:*:*"),
					Range: &ccRangeTypes.Range{
						Type:         ccRangeTypes.RangeTypeFortinetFortiPAMChromeExtension,
						GreaterEqual: "8.0",
						LessThan:     "8.1",
					},
				},
			},
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

// TestBuildProductRefs covers the advisory-bound repair of FG-IR-24-125's
// product tree, whose "FortiManager Cloud" leaves sit under "FortiManager"
// with "cloud" carried into the version expression.
func TestBuildProductRefs(t *testing.T) {
	leaf := func(name, pid string) csafTypes.Branch {
		return csafTypes.Branch{Category: "product_version_range", Name: name, Product: &csafTypes.FullProductName{Name: name, ProductID: csafTypes.ProductID(pid)}}
	}
	product := func(name string, leaves ...csafTypes.Branch) csafTypes.Branch {
		return csafTypes.Branch{Category: "product", Name: name, Branches: leaves}
	}
	type args struct {
		id       string
		branches []csafTypes.Branch
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]csaf.ProductRef
		wantErr bool
	}{
		{
			name: "FG-IR-24-125: misfiled FortiManager/cloud leaves re-homed to FortiManager Cloud",
			args: args{
				id: "FG-IR-24-125",
				branches: []csafTypes.Branch{product("FortiManager",
					leaf("FortiManager/cloud 7.0 all versions", "FortiManager cloud 7.0 all versions"),
					leaf("FortiManager/7.0 all versions", "FortiManager 7.0 all versions"),
				)},
			},
			want: map[string]csaf.ProductRef{
				"FortiManager cloud 7.0 all versions": csaf.NewProductRef("FortiManager Cloud", "7.0 all versions"),
				"FortiManager 7.0 all versions":       csaf.NewProductRef("FortiManager", "7.0 all versions"),
			},
		},
		{
			// Fortinet correcting the tree must retire the exception loudly.
			name: "FG-IR-24-125: no misfiled leaf → stale exception rejected",
			args: args{
				id:       "FG-IR-24-125",
				branches: []csafTypes.Branch{product("FortiManager", leaf("FortiManager/7.0 all versions", "FortiManager 7.0 all versions"))},
			},
			wantErr: true,
		},
		{
			name: "FG-IR-24-125: cloud prefix under another product rejected",
			args: args{
				id:       "FG-IR-24-125",
				branches: []csafTypes.Branch{product("FortiAnalyzer", leaf("FortiAnalyzer/cloud 7.0 all versions", "FortiAnalyzer cloud 7.0 all versions"))},
			},
			wantErr: true,
		},
		{
			// The repair is bound to the one advisory; elsewhere the leaf is
			// mapped as written and left for toCriterion to reject.
			name: "other advisory: cloud-prefixed leaf mapped as written",
			args: args{
				id:       "FG-IR-24-999",
				branches: []csafTypes.Branch{product("FortiManager", leaf("FortiManager/cloud 7.0 all versions", "FortiManager cloud 7.0 all versions"))},
			},
			want: map[string]csaf.ProductRef{
				"FortiManager cloud 7.0 all versions": csaf.NewProductRef("FortiManager", "cloud 7.0 all versions"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := csaf.BuildProductRefs(tt.args.id, tt.args.branches)
			if (err != nil) != tt.wantErr {
				t.Fatalf("BuildProductRefs(%q) error = %v, wantErr %v", tt.args.id, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(csaf.ProductRef{})); diff != "" {
				t.Errorf("BuildProductRefs(%q) (-want +got):\n%s", tt.args.id, diff)
			}
		})
	}
}

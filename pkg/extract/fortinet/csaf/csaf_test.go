package csaf_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/csaf"
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

// Whitelist enforcement: a known_affected product that is not in the product
// table must hard-error rather than be silently dropped.
func TestToCriterionWhitelist(t *testing.T) {
	tests := []struct {
		name      string
		productID string
		refMap    map[string]csaf.ProductRef
		wantErr   bool
	}{
		{
			name:      "known product, bare (whole product)",
			productID: "FortiOS",
			refMap:    map[string]csaf.ProductRef{},
		},
		{
			name:      "known product via tree ref with range",
			productID: "FortiOS >=7.0.0|<=7.0.5",
			refMap:    map[string]csaf.ProductRef{"FortiOS >=7.0.0|<=7.0.5": csaf.NewProductRef("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", ">=7.0.0|<=7.0.5")},
		},
		{
			name:      "unknown product → hard error",
			productID: "FortiNonexistent >=1.0.0|<=2.0.0",
			refMap:    map[string]csaf.ProductRef{},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := csaf.ToCriterion(tt.productID, tt.refMap)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToCriterion(%q) error = %v, wantErr %v", tt.productID, err, tt.wantErr)
			}
		})
	}
}

// Version interpretation: ranges narrow the CPE, concrete versions are baked
// into it, and "whole product" expressions (including a leaked product name
// like "FortiClient iOS all versions") leave the version wildcarded rather than
// baking the bogus string.
func TestToCriterionVersion(t *testing.T) {
	const fortios = "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"
	tests := []struct {
		name       string
		versionExp string
		wantCPE    string
		wantRange  bool
	}{
		{name: "concrete version baked", versionExp: "7.4.3", wantCPE: "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*"},
		{name: "X.Y all versions → range, wildcard cpe", versionExp: "7.0 all versions", wantCPE: fortios, wantRange: true},
		{name: "range expr → range, wildcard cpe", versionExp: ">=7.0.0|<=7.0.5", wantCPE: fortios, wantRange: true},
		{name: "whole product (all versions)", versionExp: "all versions", wantCPE: fortios},
		{name: "leaked product name all versions → whole product, not baked", versionExp: "FortiClient iOS all versions", wantCPE: fortios},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refMap := map[string]csaf.ProductRef{"X": csaf.NewProductRef(fortios, tt.versionExp)}
			cn, err := csaf.ToCriterion("X", refMap)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if got := string(cn.CPE.CPE); got != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", got, tt.wantCPE)
			}
			if (cn.CPE.Range != nil) != tt.wantRange {
				t.Errorf("range present = %v, want %v", cn.CPE.Range != nil, tt.wantRange)
			}
		})
	}
}

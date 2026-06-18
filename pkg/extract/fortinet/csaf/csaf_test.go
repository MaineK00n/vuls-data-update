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

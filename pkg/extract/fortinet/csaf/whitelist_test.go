package csaf

import "testing"

// Whitelist enforcement: a known_affected product that is not in the product
// table must hard-error rather than be silently dropped.
func TestToCriterionWhitelist(t *testing.T) {
	tests := []struct {
		name      string
		productID string
		refMap    map[string]productRef
		wantErr   bool
	}{
		{
			name:      "known product, bare (whole product)",
			productID: "FortiOS",
			refMap:    map[string]productRef{},
		},
		{
			name:      "known product via tree ref with range",
			productID: "FortiOS >=7.0.0|<=7.0.5",
			refMap:    map[string]productRef{"FortiOS >=7.0.0|<=7.0.5": {cpe: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", versionExp: ">=7.0.0|<=7.0.5"}},
		},
		{
			name:      "unknown product → hard error",
			productID: "FortiNonexistent >=1.0.0|<=2.0.0",
			refMap:    map[string]productRef{},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := toCriterion(tt.productID, tt.refMap)
			if (err != nil) != tt.wantErr {
				t.Errorf("toCriterion(%q) error = %v, wantErr %v", tt.productID, err, tt.wantErr)
			}
		})
	}
}

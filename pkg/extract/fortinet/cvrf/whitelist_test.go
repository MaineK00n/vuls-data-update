package cvrf

import "testing"

// Whitelist enforcement: a Known Affected product that is absent from the tree
// or not in the product table must hard-error rather than be silently dropped.
func TestToCriterionWhitelist(t *testing.T) {
	tests := []struct {
		name      string
		productID string
		prodMap   map[string]productVersion
		wantErr   bool
	}{
		{
			name:      "known product, concrete version",
			productID: "FortiOS-7.4.3",
			prodMap:   map[string]productVersion{"FortiOS-7.4.3": {productName: "FortiOS", version: "7.4.3"}},
		},
		{
			name:      "product_id absent from tree → hard error",
			productID: "FortiOS-7.4.3",
			prodMap:   map[string]productVersion{},
			wantErr:   true,
		},
		{
			name:      "unknown product name → hard error",
			productID: "FortiNonexistent-1.0.0",
			prodMap:   map[string]productVersion{"FortiNonexistent-1.0.0": {productName: "FortiNonexistent", version: "1.0.0"}},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := toCriterion(tt.productID, tt.prodMap)
			if (err != nil) != tt.wantErr {
				t.Errorf("toCriterion(%q) error = %v, wantErr %v", tt.productID, err, tt.wantErr)
			}
		})
	}
}

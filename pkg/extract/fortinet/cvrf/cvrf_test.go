package cvrf_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/cvrf"
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
			_, err := cvrf.KnownAffectedCriterions("FG-IR-TEST", []string{tt.productID}, tt.prodMap)
			if (err != nil) != tt.wantErr {
				t.Errorf("KnownAffectedCriterions(%q) error = %v, wantErr %v", tt.productID, err, tt.wantErr)
			}
		})
	}
}

// isExactVersion keeps only concrete x.y.z[...] releases; coarse trains are
// dropped from the enumeration.
func TestIsExactVersion(t *testing.T) {
	tests := []struct {
		ver  string
		want bool
	}{
		{ver: "7.4.3", want: true},
		{ver: "7.4.3.1", want: true},
		{ver: "25.2.a", want: true},
		{ver: "25.1.a.2", want: true},
		{ver: "7.4", want: false},
		{ver: "24", want: false},
		{ver: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.ver, func(t *testing.T) {
			if got := cvrf.IsExactVersion(tt.ver); got != tt.want {
				t.Errorf("IsExactVersion(%q) = %v, want %v", tt.ver, got, tt.want)
			}
		})
	}
}

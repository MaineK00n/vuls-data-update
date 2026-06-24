package cvrf_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/cvrf"
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

// The only product-status type observed across the corpus is "Known Affected";
// an empty type is a content-only advisory, and any other type must fail loudly
// rather than silently emit no detection.
func TestExtractStatusType(t *testing.T) {
	tests := []struct {
		name       string
		statusType string
		productIDs []string
		wantErr    bool
	}{
		{name: "known affected", statusType: "Known Affected"},
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

package json_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	paloaltoJSON "github.com/MaineK00n/vuls-data-update/pkg/extract/paloalto/json"
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
			err := paloaltoJSON.Extract(tt.args, paloaltoJSON.WithDir(dir))
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

// TestPanosStanzaIntervals pins the PAN-OS changes[] interpretation directly,
// independent of the end-to-end golden test. Each expected interval set is
// derived by hand from the documented rules so a future change to the
// interpretation surfaces here rather than hiding in a golden diff.
func TestPanosStanzaIntervals(t *testing.T) {
	tests := []struct {
		name    string
		stanza  paloaltoJSON.PanosStanza
		want    []paloaltoJSON.PanosInterval
		wantErr bool
	}{
		{
			// Simple fix point: the whole series up to the fix release.
			name:   "simple fix: X.Y lessThan release",
			stanza: paloaltoJSON.PanosStanza{Status: "affected", Version: "9.0", LessThan: "9.0.7"},
			want:   []paloaltoJSON.PanosInterval{{GE: "9.0.0", LT: "9.0.7", Fixed: []string{"9.0.7"}}},
		},
		{
			// A change coinciding with the release fix.
			name: "simple fix: change at the fix release",
			stanza: paloaltoJSON.PanosStanza{
				Status: "affected", Version: "8.1", LessThan: "8.1.13",
				Changes: []paloaltoJSON.PanosChange{{At: "8.1.13", Status: "unaffected"}},
			},
			want: []paloaltoJSON.PanosInterval{{GE: "8.1.0", LT: "8.1.13", Fixed: []string{"8.1.13"}}},
		},
		{
			// "X.Y.*" series form.
			name:   "series X.Y.* affected",
			stanza: paloaltoJSON.PanosStanza{Status: "affected", Version: "8.0.*"},
			want:   []paloaltoJSON.PanosInterval{{GE: "8.0.0", LT: "8.1.0"}},
		},
		{
			// "X.Y All" series form.
			name:   "series X.Y All affected",
			stanza: paloaltoJSON.PanosStanza{Status: "affected", Version: "7.1 All"},
			want:   []paloaltoJSON.PanosInterval{{GE: "7.1.0", LT: "7.2.0"}},
		},
		{
			// "All" affected → one zero-value interval (every bound empty), NOT
			// nil: it maps to a bare CPE criterion matching every PAN-OS version.
			// Contrast with the unaffected case below, which returns nil.
			name:   "All affected → one empty-bounds interval",
			stanza: paloaltoJSON.PanosStanza{Status: "affected", Version: "All"},
			want:   []paloaltoJSON.PanosInterval{{}},
		},
		{
			// "All" unaffected → nothing affected → nil (no criterion).
			name:   "All unaffected → no interval",
			stanza: paloaltoJSON.PanosStanza{Status: "unaffected", Version: "All"},
			want:   nil,
		},
		{
			// Bare affected X.Y.Z (no bound, no changes) → whole series.
			name:   "bare affected X.Y.Z → series",
			stanza: paloaltoJSON.PanosStanza{Status: "affected", Version: "8.1.0"},
			want:   []paloaltoJSON.PanosInterval{{GE: "8.1.0", LT: "8.2.0"}},
		},
		{
			// version None + lessThanOrEqual: inclusive upper, unbounded lower.
			name:   "None with lessThanOrEqual",
			stanza: paloaltoJSON.PanosStanza{Status: "affected", Version: "None", LessThanOrEqual: "6.0.14"},
			want:   []paloaltoJSON.PanosInterval{{LE: "6.0.14"}},
		},
		{
			// version None with no bound: no constraint → no interval, no error.
			name:   "None without bound → no interval",
			stanza: paloaltoJSON.PanosStanza{Status: "affected", Version: "None"},
			want:   nil,
		},
		{
			// Unaffected complement: "unaffected 7.0.2 lessThan 7.0*" means
			// 7.0.0..7.0.2 was affected (PAN-SA-2015-0006).
			name:   "unaffected complement",
			stanza: paloaltoJSON.PanosStanza{Status: "unaffected", Version: "7.0.2", LessThan: "7.0*"},
			want:   []paloaltoJSON.PanosInterval{{GE: "7.0.0", LT: "7.0.2", Fixed: []string{"7.0.2"}}},
		},
		{
			// Backport fixes: every maintenance line affected from its base
			// release until its own hotfix fix (CVE-2024-0012, 11.1 line). The
			// hotfix-level lessThan (11.1.5-h1) is the 11.1.5 line's fix.
			name: "backport fixes across maintenance lines",
			stanza: paloaltoJSON.PanosStanza{Status: "affected", Version: "11.1.0", LessThan: "11.1.5-h1",
				Changes: []paloaltoJSON.PanosChange{
					{At: "11.1.5-h1", Status: "unaffected"},
					{At: "11.1.0-h4", Status: "unaffected"},
					{At: "11.1.1-h2", Status: "unaffected"},
					{At: "11.1.2-h15", Status: "unaffected"},
					{At: "11.1.3-h11", Status: "unaffected"},
					{At: "11.1.4-h7", Status: "unaffected"},
				}},
			want: []paloaltoJSON.PanosInterval{
				{GE: "11.1.0", LT: "11.1.0-h4", Fixed: []string{"11.1.0-h4"}},
				{GE: "11.1.1", LT: "11.1.1-h2", Fixed: []string{"11.1.1-h2"}},
				{GE: "11.1.2", LT: "11.1.2-h15", Fixed: []string{"11.1.2-h15"}},
				{GE: "11.1.3", LT: "11.1.3-h11", Fixed: []string{"11.1.3-h11"}},
				{GE: "11.1.4", LT: "11.1.4-h7", Fixed: []string{"11.1.4-h7"}},
				{GE: "11.1.5", LT: "11.1.5-h1", Fixed: []string{"11.1.5-h1"}},
			},
		},
		{
			// Introduced-by-version: a base-release change switches the
			// cross-line timeline (CVE-2024-3393 shape, minimal).
			name: "introduced then fixed at base releases",
			stanza: paloaltoJSON.PanosStanza{Status: "unaffected", Version: "10.2.0",
				Changes: []paloaltoJSON.PanosChange{
					{At: "10.2.8", Status: "affected"},
					{At: "10.2.14", Status: "unaffected"},
				}},
			want: []paloaltoJSON.PanosInterval{{GE: "10.2.8", LT: "10.2.14", Fixed: []string{"10.2.14"}}},
		},
		{
			// Hotfix-level lessThan is the first line's fix, folded into the
			// changes rather than treated as the stanza end (CVE-2024-3400).
			name: "hotfix-level lessThan folded into changes",
			stanza: paloaltoJSON.PanosStanza{Status: "affected", Version: "10.2", LessThan: "10.2.0-h3",
				Changes: []paloaltoJSON.PanosChange{
					{At: "10.2.0-h3", Status: "unaffected"},
					{At: "10.2.1-h2", Status: "unaffected"},
				}},
			want: []paloaltoJSON.PanosInterval{
				{GE: "10.2.0", LT: "10.2.0-h3", Fixed: []string{"10.2.0-h3"}},
				{GE: "10.2.1", LT: "10.2.1-h2", Fixed: []string{"10.2.1-h2"}},
			},
		},
		{
			// Comma-separated changes.at (CVE-2019-17440 shape): both versions
			// are parsed; here the earlier base fix closes the series.
			name: "comma-separated changes.at",
			stanza: paloaltoJSON.PanosStanza{Status: "affected", Version: "9.1",
				Changes: []paloaltoJSON.PanosChange{{At: "9.1.3, 9.1.5", Status: "unaffected"}}},
			want: []paloaltoJSON.PanosInterval{{GE: "9.1.0", LT: "9.1.3", Fixed: []string{"9.1.3"}}},
		},
		{
			name:    "invalid status",
			stanza:  paloaltoJSON.PanosStanza{Status: "unknown", Version: "9.0.0"},
			wantErr: true,
		},
		{
			name:    "unparseable version",
			stanza:  paloaltoJSON.PanosStanza{Status: "affected", Version: "garbage"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := paloaltoJSON.PanosStanzaIntervals(tt.stanza)
			if (err != nil) != tt.wantErr {
				t.Fatalf("PanosStanzaIntervals() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("PanosStanzaIntervals() intervals (-want +got):\n%s", diff)
			}
		})
	}
}

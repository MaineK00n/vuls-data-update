package panos_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/paloalto/internal/panos"
)

// TestStanzaIntervals pins the PAN-OS changes interpretation directly. Each
// expected interval set is derived by hand from the documented rules so a
// future change to the interpretation surfaces here rather than hiding in a
// golden diff.
func TestStanzaIntervals(t *testing.T) {
	tests := []struct {
		name    string
		stanza  panos.Stanza
		want    []panos.Interval
		wantErr bool
	}{
		{
			// Simple fix point: the whole series up to the fix release.
			name:   "simple fix: X.Y lessThan release",
			stanza: panos.Stanza{Status: "affected", Version: "9.0", LessThan: "9.0.7"},
			want:   []panos.Interval{{GE: "9.0.0", LT: "9.0.7", Fixed: []string{"9.0.7"}}},
		},
		{
			// A change coinciding with the release fix.
			name: "simple fix: change at the fix release",
			stanza: panos.Stanza{
				Status: "affected", Version: "8.1", LessThan: "8.1.13",
				Changes: []panos.Change{{At: "8.1.13", Status: "unaffected"}},
			},
			want: []panos.Interval{{GE: "8.1.0", LT: "8.1.13", Fixed: []string{"8.1.13"}}},
		},
		{
			// "X.Y.*" series form.
			name:   "series X.Y.* affected",
			stanza: panos.Stanza{Status: "affected", Version: "8.0.*"},
			want:   []panos.Interval{{GE: "8.0.0", LT: "8.1.0"}},
		},
		{
			// "X.Y All" series form.
			name:   "series X.Y All affected",
			stanza: panos.Stanza{Status: "affected", Version: "7.1 All"},
			want:   []panos.Interval{{GE: "7.1.0", LT: "7.2.0"}},
		},
		{
			// "All" affected → one zero-value interval (every bound empty), NOT
			// nil: it maps to a bare CPE criterion matching every PAN-OS version.
			// Contrast with the unaffected case below, which returns nil.
			name:   "All affected → one empty-bounds interval",
			stanza: panos.Stanza{Status: "affected", Version: "All"},
			want:   []panos.Interval{{}},
		},
		{
			// "All" unaffected → nothing affected → nil (no criterion).
			name:   "All unaffected → no interval",
			stanza: panos.Stanza{Status: "unaffected", Version: "All"},
			want:   nil,
		},
		{
			// Bare affected X.Y.Z (no bound, no changes) → whole series.
			name:   "bare affected X.Y.Z → series",
			stanza: panos.Stanza{Status: "affected", Version: "8.1.0"},
			want:   []panos.Interval{{GE: "8.1.0", LT: "8.2.0"}},
		},
		{
			// version None + lessThanOrEqual: inclusive upper, unbounded lower.
			name:   "None with lessThanOrEqual",
			stanza: panos.Stanza{Status: "affected", Version: "None", LessThanOrEqual: "6.0.14"},
			want:   []panos.Interval{{LE: "6.0.14"}},
		},
		{
			// version None with no bound: no constraint → no interval, no error.
			name:   "None without bound → no interval",
			stanza: panos.Stanza{Status: "affected", Version: "None"},
			want:   nil,
		},
		{
			// Unaffected complement: "unaffected 7.0.2 lessThan 7.0*" means
			// 7.0.0..7.0.2 was affected (PAN-SA-2015-0006).
			name:   "unaffected complement",
			stanza: panos.Stanza{Status: "unaffected", Version: "7.0.2", LessThan: "7.0*"},
			want:   []panos.Interval{{GE: "7.0.0", LT: "7.0.2", Fixed: []string{"7.0.2"}}},
		},
		{
			// Backport fixes: every maintenance line affected from its base
			// release until its own hotfix fix (CVE-2024-0012, 11.1 line). The
			// hotfix-level lessThan (11.1.5-h1) is the 11.1.5 line's fix.
			name: "backport fixes across maintenance lines",
			stanza: panos.Stanza{Status: "affected", Version: "11.1.0", LessThan: "11.1.5-h1",
				Changes: []panos.Change{
					{At: "11.1.5-h1", Status: "unaffected"},
					{At: "11.1.0-h4", Status: "unaffected"},
					{At: "11.1.1-h2", Status: "unaffected"},
					{At: "11.1.2-h15", Status: "unaffected"},
					{At: "11.1.3-h11", Status: "unaffected"},
					{At: "11.1.4-h7", Status: "unaffected"},
				}},
			want: []panos.Interval{
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
			stanza: panos.Stanza{Status: "unaffected", Version: "10.2.0",
				Changes: []panos.Change{
					{At: "10.2.8", Status: "affected"},
					{At: "10.2.14", Status: "unaffected"},
				}},
			want: []panos.Interval{{GE: "10.2.8", LT: "10.2.14", Fixed: []string{"10.2.14"}}},
		},
		{
			// Hotfix-level lessThan is the first line's fix, folded into the
			// changes rather than treated as the stanza end (CVE-2024-3400).
			name: "hotfix-level lessThan folded into changes",
			stanza: panos.Stanza{Status: "affected", Version: "10.2", LessThan: "10.2.0-h3",
				Changes: []panos.Change{
					{At: "10.2.0-h3", Status: "unaffected"},
					{At: "10.2.1-h2", Status: "unaffected"},
				}},
			want: []panos.Interval{
				{GE: "10.2.0", LT: "10.2.0-h3", Fixed: []string{"10.2.0-h3"}},
				{GE: "10.2.1", LT: "10.2.1-h2", Fixed: []string{"10.2.1-h2"}},
			},
		},
		{
			// Comma-separated changes.at (CVE-2019-17440 shape): both versions
			// are parsed; here the earlier base fix closes the series.
			name: "comma-separated changes.at",
			stanza: panos.Stanza{Status: "affected", Version: "9.1",
				Changes: []panos.Change{{At: "9.1.3, 9.1.5", Status: "unaffected"}}},
			want: []panos.Interval{{GE: "9.1.0", LT: "9.1.3", Fixed: []string{"9.1.3"}}},
		},
		{
			// Regression backported into a hotfix line (CVE-2025-4619 shape):
			// line 10.2.1 is unaffected at its base (10.2.1, 10.2.1-h1); a
			// regression reappears at 10.2.1-h2 and is fixed at 10.2.1-h5. This
			// exercises the priority tie-break — line 10.2.1's own start status
			// (unaffected) must beat the previous line's revert marker
			// (affected) at version 10.2.1, else the interval would wrongly
			// start at 10.2.1 instead of 10.2.1-h2.
			name: "regression in a hotfix line (priority tie-break)",
			stanza: panos.Stanza{Status: "affected", Version: "10.2.0", LessThan: "10.2.3",
				Changes: []panos.Change{
					{At: "10.2.0-h1", Status: "unaffected"},
					{At: "10.2.1-h2", Status: "affected"},
					{At: "10.2.1-h5", Status: "unaffected"},
				}},
			want: []panos.Interval{
				{GE: "10.2.0", LT: "10.2.0-h1", Fixed: []string{"10.2.0-h1"}},
				{GE: "10.2.1-h2", LT: "10.2.1-h5", Fixed: []string{"10.2.1-h5"}},
				{GE: "10.2.2", LT: "10.2.3", Fixed: []string{"10.2.3"}},
			},
		},
		{
			// "unknown" is a valid CVE 5.0 status but not a valid input to this
			// function: the caller (detections) skips unknown stanzas before
			// calling, so reaching here with anything other than affected /
			// unaffected is an error.
			name:    "non-affected/unaffected status is an error",
			stanza:  panos.Stanza{Status: "unknown", Version: "9.0.0"},
			wantErr: true,
		},
		{
			name:    "unparseable version",
			stanza:  panos.Stanza{Status: "affected", Version: "garbage"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := panos.StanzaIntervals(tt.stanza)
			if (err != nil) != tt.wantErr {
				t.Fatalf("StanzaIntervals() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("StanzaIntervals() intervals (-want +got):\n%s", diff)
			}
		})
	}
}

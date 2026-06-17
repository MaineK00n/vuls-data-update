package json

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestPanosStanzaIntervals pins the PAN-OS changes[] interpretation spec
// (docs/paloalto-extract-design.md §4) directly, independent of the
// end-to-end golden test. Each expected interval set is derived by hand from
// the documented rules so a future change to the interpretation surfaces here.
func TestPanosStanzaIntervals(t *testing.T) {
	tests := []struct {
		name    string
		stanza  panosStanza
		want    []panosInterval
		wantErr bool
	}{
		{
			// §4.2 (1) simple fix point: the whole series up to the fix.
			name:   "simple fix: X.Y lessThan release",
			stanza: panosStanza{status: "affected", version: "9.0", lessThan: "9.0.7"},
			want:   []panosInterval{{ge: "9.0.0", lt: "9.0.7", fixed: []string{"9.0.7"}}},
		},
		{
			// A change coinciding with the release fix.
			name: "simple fix: change at the fix release",
			stanza: panosStanza{status: "affected", version: "8.1", lessThan: "8.1.13",
				changes: []panosChange{{at: "8.1.13", status: "unaffected"}}},
			want: []panosInterval{{ge: "8.1.0", lt: "8.1.13", fixed: []string{"8.1.13"}}},
		},
		{
			// §3.1 "X.Y.*" series form.
			name:   "series X.Y.* affected",
			stanza: panosStanza{status: "affected", version: "8.0.*"},
			want:   []panosInterval{{ge: "8.0.0", lt: "8.1.0"}},
		},
		{
			// §3.1 "X.Y All" series form.
			name:   "series X.Y All affected",
			stanza: panosStanza{status: "affected", version: "7.1 All"},
			want:   []panosInterval{{ge: "7.1.0", lt: "7.2.0"}},
		},
		{
			// "All" → every version, no range narrowing (a bare criterion).
			name:   "All affected → unbounded interval",
			stanza: panosStanza{status: "affected", version: "All"},
			want:   []panosInterval{{}},
		},
		{
			name:   "All unaffected → no interval",
			stanza: panosStanza{status: "unaffected", version: "All"},
			want:   nil,
		},
		{
			// §4.2.1 bare affected X.Y.Z (no bound, no changes) → whole series.
			name:   "bare affected X.Y.Z → series",
			stanza: panosStanza{status: "affected", version: "8.1.0"},
			want:   []panosInterval{{ge: "8.1.0", lt: "8.2.0"}},
		},
		{
			// version None + lessThanOrEqual: inclusive upper, unbounded lower.
			name:   "None with lessThanOrEqual",
			stanza: panosStanza{status: "affected", version: "None", lessThanOrEqual: "6.0.14"},
			want:   []panosInterval{{le: "6.0.14"}},
		},
		{
			// §4.2.1 unaffected complement: "unaffected 7.0.2 lessThan 7.0*"
			// means 7.0.0..7.0.2 was affected (PAN-SA-2015-0006).
			name:   "unaffected complement",
			stanza: panosStanza{status: "unaffected", version: "7.0.2", lessThan: "7.0*"},
			want:   []panosInterval{{ge: "7.0.0", lt: "7.0.2", fixed: []string{"7.0.2"}}},
		},
		{
			// §4.2 (2) backport fixes: every maintenance line affected from its
			// base release until its own hotfix fix (CVE-2024-0012, 11.1 line).
			// The hotfix-level lessThan (11.1.5-h1) is the 11.1.5 line's fix.
			name: "backport fixes across maintenance lines",
			stanza: panosStanza{status: "affected", version: "11.1.0", lessThan: "11.1.5-h1",
				changes: []panosChange{
					{at: "11.1.5-h1", status: "unaffected"},
					{at: "11.1.0-h4", status: "unaffected"},
					{at: "11.1.1-h2", status: "unaffected"},
					{at: "11.1.2-h15", status: "unaffected"},
					{at: "11.1.3-h11", status: "unaffected"},
					{at: "11.1.4-h7", status: "unaffected"},
				}},
			want: []panosInterval{
				{ge: "11.1.0", lt: "11.1.0-h4", fixed: []string{"11.1.0-h4"}},
				{ge: "11.1.1", lt: "11.1.1-h2", fixed: []string{"11.1.1-h2"}},
				{ge: "11.1.2", lt: "11.1.2-h15", fixed: []string{"11.1.2-h15"}},
				{ge: "11.1.3", lt: "11.1.3-h11", fixed: []string{"11.1.3-h11"}},
				{ge: "11.1.4", lt: "11.1.4-h7", fixed: []string{"11.1.4-h7"}},
				{ge: "11.1.5", lt: "11.1.5-h1", fixed: []string{"11.1.5-h1"}},
			},
		},
		{
			// §4.2 (3) introduced-by-version: a base-release change switches the
			// cross-line timeline (CVE-2024-3393 shape, minimal).
			name: "introduced then fixed at base releases",
			stanza: panosStanza{status: "unaffected", version: "10.2.0",
				changes: []panosChange{
					{at: "10.2.8", status: "affected"},
					{at: "10.2.14", status: "unaffected"},
				}},
			want: []panosInterval{{ge: "10.2.8", lt: "10.2.14", fixed: []string{"10.2.14"}}},
		},
		{
			// §4.2.1 hotfix-level lessThan is the first line's fix, folded into
			// the changes rather than treated as the stanza end (CVE-2024-3400).
			name: "hotfix-level lessThan folded into changes",
			stanza: panosStanza{status: "affected", version: "10.2", lessThan: "10.2.0-h3",
				changes: []panosChange{
					{at: "10.2.0-h3", status: "unaffected"},
					{at: "10.2.1-h2", status: "unaffected"},
				}},
			want: []panosInterval{
				{ge: "10.2.0", lt: "10.2.0-h3", fixed: []string{"10.2.0-h3"}},
				{ge: "10.2.1", lt: "10.2.1-h2", fixed: []string{"10.2.1-h2"}},
			},
		},
		{
			// §4.2.1 comma-separated changes.at (CVE-2019-17440 shape): both
			// versions are parsed; here the earlier base fix closes the series.
			name: "comma-separated changes.at",
			stanza: panosStanza{status: "affected", version: "9.1",
				changes: []panosChange{{at: "9.1.3, 9.1.5", status: "unaffected"}}},
			want: []panosInterval{{ge: "9.1.0", lt: "9.1.3", fixed: []string{"9.1.3"}}},
		},
		{
			name:    "invalid status",
			stanza:  panosStanza{status: "unknown", version: "9.0.0"},
			wantErr: true,
		},
		{
			name:    "unparseable version",
			stanza:  panosStanza{status: "affected", version: "garbage"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := panosStanzaIntervals(tt.stanza)
			if (err != nil) != tt.wantErr {
				t.Fatalf("panosStanzaIntervals() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(panosInterval{})); diff != "" {
				t.Errorf("panosStanzaIntervals() intervals (-want +got):\n%s", diff)
			}
		})
	}
}

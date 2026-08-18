package securityreleases

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseAvailableFor(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want *availableFor
	}{
		{
			name: "a line with no version, the shape a third of the macOS entries use",
			arg:  "macOS Sonoma",
			want: &availableFor{line: "14", low: "14"},
		},
		{
			name: "a version closes the range itself",
			arg:  "macOS High Sierra 10.13.6",
			want: &availableFor{line: "10.13", high: "10.13.6"},
		},
		{
			name: "the older spelling carries no marketing name",
			arg:  "Mac OS X v10.6.8",
			want: &availableFor{line: "10.6", high: "10.6.8"},
		},
		{
			name: "a range states both ends",
			arg:  "Mac OS X v10.6 through v10.6.6",
			want: &availableFor{line: "10.6", low: "10.6", high: "10.6.6"},
		},
		{
			name: "the range repeats the system name on the right",
			arg:  "Mac OS X Server v10.4 through Mac OS X Server v10.4.11",
			want: &availableFor{line: "10.4", low: "10.4", high: "10.4.11", server: true},
		},
		{
			name: "or later states the lower end only",
			arg:  "Mac OS X v10.6.2 or later",
			want: &availableFor{line: "10.6", low: "10.6.2"},
		},
		{
			name: "server sits after the system name",
			arg:  "Mac OS X Server v10.5.8",
			want: &availableFor{line: "10.5", high: "10.5.8", server: true},
		},
		{
			name: "server sits after the marketing name instead",
			arg:  "OS X Lion Server v10.7.3",
			want: &availableFor{line: "10.7", high: "10.7.3", server: true},
		},
		{
			name: "a component precedes the system",
			arg:  "QuickTime 7.1.3 on Mac OS X v10.3.9",
			want: &availableFor{line: "10.3", high: "10.3.9"},
		},
		{
			name: "an x stands in for the patch level",
			arg:  "Mac OS X v10.3.x",
			want: &availableFor{line: "10.3", high: "10.3"},
		},
		{
			name: "a stray Impact paragraph is folded into the field",
			arg:  "OS X Lion v10.7.3\nImpact: The Java browser plugin",
			want: &availableFor{line: "10.7", high: "10.7.3"},
		},
		{
			name: "hardware names no system",
			arg:  "Mac Studio (2022 and later), iMac (2019 and later)",
			want: nil,
		},
		{
			name: "the system with no version at all",
			arg:  "Mac OS X",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAvailableFor(tt.arg)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(availableFor{})); diff != "" {
				t.Errorf("parseAvailableFor(). (-expected +got):\n%s", diff)
			}
		})
	}
}

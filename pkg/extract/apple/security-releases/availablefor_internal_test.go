package securityreleases

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

func TestParseAvailableFor(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		want     *availableFor
		hasError bool
	}{
		{
			name: "a line with no version, the shape a third of the macOS entries use",
			arg:  "macOS Sonoma",
			want: &availableFor{line: "14"},
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
			want: &availableFor{line: "10.6", low: "10.6.2", orLater: true},
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
			name: "an x stands in for every patch level, naming the line",
			arg:  "Mac OS X v10.3.x",
			want: &availableFor{line: "10.3", low: "10.3"},
		},
		{
			name: "a stray Impact paragraph is folded into the field",
			arg:  "OS X Lion v10.7.3\nImpact: The Java browser plugin",
			want: &availableFor{line: "10.7", high: "10.7.3"},
		},
		{
			name: "and later states the lower end too",
			arg:  "OS X Mountain Lion 10.8 and later",
			want: &availableFor{line: "10.8", low: "10.8", orLater: true},
		},
		{
			name: "a version equal to the start of its line names the line",
			arg:  "macOS Catalina 10.15",
			want: &availableFor{line: "10.15", low: "10.15"},
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
		{
			name:     "a marketing name this does not know",
			arg:      "macOS Ridgecrest",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAvailableFor(tt.arg)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(availableFor{})); diff != "" {
					t.Errorf("parseAvailableFor(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

func TestIsMacOSSection(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want bool
	}{
		{name: "a release", arg: "macOS Sonoma 14.7.5", want: true},
		{name: "the older spelling", arg: "OS X Yosemite v10.10.2", want: true},
		{name: "an update that leaves the version alone", arg: "macOS High Sierra 10.13.3 Supplemental Update", want: true},
		{name: "a page covering several lines", arg: "macOS Mojave 10.14.1, Security Update 2018-002 High Sierra", want: true},
		{name: "the server edition has the shape of a release", arg: "OS X Server v4.1", want: false},
		{name: "the server edition, newer spelling", arg: "macOS Server 5.11", want: false},
		{name: "the server edition with the word in the middle", arg: "OS X Lion Server v10.7.3", want: false},
		{name: "an application", arg: "Xcode 16", want: false},
		{name: "an application that names the system", arg: "Java for Mac OS X 10.6 Update 5", want: false},
		{name: "another family", arg: "Safari 17.5", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMacOSSection(tt.arg); got != tt.want {
				t.Errorf("isMacOSSection(%q). expected: %v, actual: %v", tt.arg, tt.want, got)
			}
		})
	}
}

// TestMacOSCriterionsFor covers where each end of the range comes from, the
// field stating what is vulnerable and the heading what fixes it. The ranges
// the heading cannot close are the subtle part: "and later" names every line
// from its own up, so it stops below the release the page is about, and only
// within the same product.
func TestMacOSCriterionsFor(t *testing.T) {
	rng := func(r ccRangeTypes.Range) *ccRangeTypes.Range {
		r.Type = ccRangeTypes.RangeTypeApple
		return &r
	}
	tests := []struct {
		name         string
		availableFor []string
		fixesByLine  map[string]string
		want         []criterionTypes.Criterion
		hasError     bool
	}{
		{
			name:         "the heading fixes the line the field names",
			availableFor: []string{"macOS Catalina 10.15"},
			fixesByLine:  map[string]string{"10.15": "10.15.7"},
			want: []criterionTypes.Criterion{
				releaseCriterion(macOSXCPE, rng(ccRangeTypes.Range{GreaterEqual: "10.15", LessThan: "10.15.7"}), "10.15.7"),
			},
		},
		{
			name:         "the field names a version, which the update is for and leaves alone",
			availableFor: []string{"macOS Mojave 10.14.6"},
			fixesByLine:  map[string]string{"10.15": "10.15.7"},
			want: []criterionTypes.Criterion{
				releaseCriterion(macOSXCPE, rng(ccRangeTypes.Range{GreaterEqual: "10.14", LessEqual: "10.14.6"}), ""),
			},
		},
		{
			name:         "and later stops below the release the page is about",
			availableFor: []string{"OS X Mountain Lion 10.8 and later"},
			fixesByLine:  map[string]string{"10.13": "10.13"},
			want: []criterionTypes.Criterion{
				releaseCriterion(macOSXCPE, rng(ccRangeTypes.Range{GreaterEqual: "10.8", LessThan: "10.13"}), "10.13"),
			},
		},
		{
			name:         "and later with nothing above it to close the range",
			availableFor: []string{"OS X Mountain Lion 10.8 and later"},
			fixesByLine:  map[string]string{"10.8": "10.8.5"},
			want: []criterionTypes.Criterion{
				releaseCriterion(macOSXCPE, rng(ccRangeTypes.Range{GreaterEqual: "10.8", LessThan: "10.8.5"}), "10.8.5"),
			},
		},
		{
			name:         "and later closed by nothing at all",
			availableFor: []string{"OS X Mountain Lion 10.8 and later"},
			fixesByLine:  map[string]string{},
		},
		{
			name:         "a range from mac_os_x into macos is no range at all",
			availableFor: []string{"OS X Mountain Lion 10.8 and later"},
			fixesByLine:  map[string]string{"14": "14.7.5"},
		},
		{
			name:         "a Supplemental Update fixes the version in place",
			availableFor: []string{"macOS High Sierra 10.13"},
			fixesByLine:  map[string]string{},
			want: []criterionTypes.Criterion{
				releaseCriterion(macOSXCPE, rng(ccRangeTypes.Range{GreaterEqual: "10.13", LessEqual: "10.13"}), ""),
			},
		},
		{
			name:         "the line alone, with no fix to close it",
			availableFor: []string{"macOS Sonoma"},
			fixesByLine:  map[string]string{"15": "15.3"},
		},
		{
			name:         "the newer product, from Big Sur on",
			availableFor: []string{"macOS Sonoma"},
			fixesByLine:  map[string]string{"14": "14.7.5"},
			want: []criterionTypes.Criterion{
				releaseCriterion(macOSCPE, rng(ccRangeTypes.Range{GreaterEqual: "14", LessThan: "14.7.5"}), "14.7.5"),
			},
		},
		{
			name:         "the server edition is a product of its own",
			availableFor: []string{"Mac OS X Server v10.5.8"},
			fixesByLine:  map[string]string{"10.5": "10.5.8"},
		},
		{
			name:         "hardware names no system",
			availableFor: []string{"Mac Studio (2022 and later), iMac (2019 and later)"},
			fixesByLine:  map[string]string{"13": "13.1"},
		},
		{
			name:         "several systems in one field, each closed on its own",
			availableFor: []string{"macOS Mojave 10.14.6, macOS Catalina 10.15"},
			fixesByLine:  map[string]string{"10.15": "10.15.7"},
			want: []criterionTypes.Criterion{
				releaseCriterion(macOSXCPE, rng(ccRangeTypes.Range{GreaterEqual: "10.14", LessEqual: "10.14.6"}), ""),
				releaseCriterion(macOSXCPE, rng(ccRangeTypes.Range{GreaterEqual: "10.15", LessThan: "10.15.7"}), "10.15.7"),
			},
		},
		{
			name:         "a marketing name this does not know",
			availableFor: []string{"macOS Ridgecrest"},
			fixesByLine:  map[string]string{"27": "27.1"},
			hasError:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := macOSCriterionsFor(tt.availableFor, tt.fixesByLine)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("macOSCriterionsFor(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

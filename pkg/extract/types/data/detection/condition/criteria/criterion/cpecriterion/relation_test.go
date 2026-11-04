package cpecriterion_test

import (
	"testing"

	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
)

func TestRelatePatterns(t *testing.T) {
	tests := []struct {
		name string
		x, y string
		want ccTypes.Relation
	}{
		{name: "identical", x: `4\.*`, y: `4\.*`, want: ccTypes.RelationEqual},
		{name: "identical up to case", x: `4\.1A*`, y: `4\.1a*`, want: ccTypes.RelationEqual},
		{name: "longer prefix is a subset", x: `4\.1*`, y: `4\.*`, want: ccTypes.RelationSubset},
		{name: "shorter prefix is a superset", x: `4\.*`, y: `4\.1*`, want: ccTypes.RelationSuperset},
		{name: "different prefixes are disjoint", x: `4\.*`, y: `5\.*`, want: ccTypes.RelationDisjoint},
		{name: "prefix and suffix overlap", x: `4\.*`, y: `*\.1`, want: ccTypes.RelationOverlap},
		{name: "prefix and suffix that meet in an overlapping name", x: `4\.*`, y: `*\.4\.`, want: ccTypes.RelationOverlap},
		{name: "leading question marks around a core", x: `?a`, y: `*a*`, want: ccTypes.RelationSubset},
		{name: "unbounded lead is not within a bounded one", x: `*a`, y: `?a`, want: ccTypes.RelationSuperset},
		{name: "question marks on opposite sides share only the core", x: `ab?`, y: `?ab`, want: ccTypes.RelationOverlap},
		{name: "question-mark runs are length bounds", x: `???`, y: `*`, want: ccTypes.RelationSubset},
		{name: "longer question-mark run is a superset", x: `????`, y: `???`, want: ccTypes.RelationSuperset},
		{name: "bounded run overlaps a core only at its full length", x: `?`, y: `?a`, want: ccTypes.RelationOverlap},
		{name: "cores that meet through the question marks", x: `?b`, y: `a?`, want: ccTypes.RelationOverlap},
		{name: "cores that never line up", x: `?b`, y: `?a`, want: ccTypes.RelationDisjoint},
		{name: "escaped wild card is literal", x: `4\.\**`, y: `4\.1*`, want: ccTypes.RelationDisjoint},
		{name: "escaped wild card against itself", x: `4\.\**`, y: `4\.\*`, want: ccTypes.RelationSuperset},
		{name: "wild card after an escaped backslash is unquoted", x: `a\\*`, y: `a\\?`, want: ccTypes.RelationSuperset},
		{name: "star alone contains everything", x: `*`, y: `4\.*`, want: ccTypes.RelationSuperset},
		{name: "trailing escaped question mark is part of the core", x: `a\?`, y: `a?`, want: ccTypes.RelationSubset},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ccTypes.RelatePatterns(tt.x, tt.y); got != tt.want {
				t.Errorf("RelatePatterns(%q, %q) = %v, want %v", tt.x, tt.y, got, tt.want)
			}
		})
	}
}

func TestParsePattern(t *testing.T) {
	tests := []struct {
		s    string
		want ccTypes.Pattern
	}{
		{s: `*`, want: ccTypes.Pattern{Lead: ccTypes.Unbounded, Trail: 0, Core: ""}},
		{s: `???`, want: ccTypes.Pattern{Lead: 3, Trail: 0, Core: ""}},
		{s: `*4\.1*`, want: ccTypes.Pattern{Lead: ccTypes.Unbounded, Trail: ccTypes.Unbounded, Core: "4.1"}},
		{s: `??A??`, want: ccTypes.Pattern{Lead: 2, Trail: 2, Core: "a"}},
		{s: `a\?`, want: ccTypes.Pattern{Lead: 0, Trail: 0, Core: "a?"}},
		{s: `a\\?`, want: ccTypes.Pattern{Lead: 0, Trail: 1, Core: `a\`}},
		{s: `4\.\**`, want: ccTypes.Pattern{Lead: 0, Trail: ccTypes.Unbounded, Core: "4.*"}},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := ccTypes.ParsePattern(tt.s); got != tt.want {
				t.Errorf("ParsePattern(%q) = %+v, want %+v", tt.s, got, tt.want)
			}
		})
	}
}

// overlapsRef is overlaps by way of the full relation, with no shortcut:
// Table 6-2 for NA, and relateParsed for everything else, ANY being the
// pattern "*".
func overlapsRef(a, b ccTypes.Value) bool {
	switch {
	case a.NA:
		return b.NA || b.Any
	case b.NA:
		return a.Any
	default:
		return ccTypes.RelateParsed(a.Pattern, b.Pattern) != ccTypes.RelationDisjoint
	}
}

// diffOverlaps reports how overlaps departs from overlapsRef on the two
// formatted-string values x and y; a value unbindValueFS rejects is skipped.
func diffOverlaps(t *testing.T, x, y string) {
	t.Helper()
	a, err := ccTypes.UnbindValueFS(x)
	if err != nil {
		return
	}
	b, err := ccTypes.UnbindValueFS(y)
	if err != nil {
		return
	}
	if got, want := ccTypes.Overlaps(a, b), overlapsRef(a, b); got != want {
		t.Errorf("Overlaps(%q, %q) = %v, by relation %v", x, y, got, want)
	}
}

var overlapsSeeds = []string{
	"*", "-", "", "?", "??", "?*", "*?",
	"12.0", "12.0.6099.109", "120.0.6099.109", "RC1", "12.0rc1",
	"12.*", "12.0.*", "*.109", "*109", "*2*", "*.0.*", "*",
	"?2.0", "12.?", "??.0", "12.0??", "?2.?",
	`12\.0`, `12\.*`, `8.2\:1`, `1\\`, `\*`, `a\**`,
	"バージョン", "1*2",
}

func FuzzOverlaps(f *testing.F) {
	for _, x := range overlapsSeeds {
		for _, y := range overlapsSeeds {
			f.Add(x, y)
		}
	}
	f.Fuzz(func(t *testing.T, x, y string) {
		diffOverlaps(t, x, y)
	})
}

package cpecriterion_test

import (
	"testing"

	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
)

func TestRelatePatterns(t *testing.T) {
	tests := []struct {
		name string
		x, y string
		want ccTypes.PatternRelation
	}{
		{name: "identical", x: `4\.*`, y: `4\.*`, want: ccTypes.PatternEqual},
		{name: "identical up to case", x: `4\.1A*`, y: `4\.1a*`, want: ccTypes.PatternEqual},
		{name: "longer prefix is a subset", x: `4\.1*`, y: `4\.*`, want: ccTypes.PatternSubset},
		{name: "shorter prefix is a superset", x: `4\.*`, y: `4\.1*`, want: ccTypes.PatternSuperset},
		{name: "different prefixes are disjoint", x: `4\.*`, y: `5\.*`, want: ccTypes.PatternDisjoint},
		{name: "prefix and suffix overlap", x: `4\.*`, y: `*\.1`, want: ccTypes.PatternOverlap},
		{name: "prefix and suffix that cannot meet", x: `4\.*`, y: `*\.4\.`, want: ccTypes.PatternOverlap},
		{name: "leading question marks around a core", x: `?a`, y: `*a*`, want: ccTypes.PatternSubset},
		{name: "unbounded lead is not within a bounded one", x: `*a`, y: `?a`, want: ccTypes.PatternSuperset},
		{name: "question marks on opposite sides share only the core", x: `ab?`, y: `?ab`, want: ccTypes.PatternOverlap},
		{name: "question-mark runs are length bounds", x: `???`, y: `*`, want: ccTypes.PatternSubset},
		{name: "longer question-mark run is a superset", x: `????`, y: `???`, want: ccTypes.PatternSuperset},
		{name: "bounded run cannot reach a core", x: `?`, y: `?a`, want: ccTypes.PatternOverlap},
		{name: "cores that meet through the question marks", x: `?b`, y: `a?`, want: ccTypes.PatternOverlap},
		{name: "cores that never line up", x: `?b`, y: `?a`, want: ccTypes.PatternDisjoint},
		{name: "escaped wild card is literal", x: `4\.\**`, y: `4\.1*`, want: ccTypes.PatternDisjoint},
		{name: "escaped wild card against itself", x: `4\.\**`, y: `4\.\*`, want: ccTypes.PatternSuperset},
		{name: "wild card after an escaped backslash is unquoted", x: `a\\*`, y: `a\\?`, want: ccTypes.PatternSuperset},
		{name: "star alone contains everything", x: `*`, y: `4\.*`, want: ccTypes.PatternSuperset},
		{name: "trailing escaped question mark is part of the core", x: `a\?`, y: `a?`, want: ccTypes.PatternSubset},
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

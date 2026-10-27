package cpecriterion

import "testing"

func TestRelatePatterns(t *testing.T) {
	tests := []struct {
		name string
		x, y string
		want patternRelation
	}{
		{name: "identical", x: `4\.*`, y: `4\.*`, want: patternEqual},
		{name: "identical up to case", x: `4\.1A*`, y: `4\.1a*`, want: patternEqual},
		{name: "longer prefix is a subset", x: `4\.1*`, y: `4\.*`, want: patternSubset},
		{name: "shorter prefix is a superset", x: `4\.*`, y: `4\.1*`, want: patternSuperset},
		{name: "different prefixes are disjoint", x: `4\.*`, y: `5\.*`, want: patternDisjoint},
		{name: "prefix and suffix overlap", x: `4\.*`, y: `*\.1`, want: patternOverlap},
		{name: "prefix and suffix that cannot meet", x: `4\.*`, y: `*\.4\.`, want: patternOverlap},
		{name: "leading question marks around a core", x: `?a`, y: `*a*`, want: patternSubset},
		{name: "unbounded lead is not within a bounded one", x: `*a`, y: `?a`, want: patternSuperset},
		{name: "question marks on opposite sides share only the core", x: `ab?`, y: `?ab`, want: patternOverlap},
		{name: "question-mark runs are length bounds", x: `???`, y: `*`, want: patternSubset},
		{name: "longer question-mark run is a superset", x: `????`, y: `???`, want: patternSuperset},
		{name: "bounded run cannot reach a core", x: `?`, y: `?a`, want: patternOverlap},
		{name: "cores that meet through the question marks", x: `?b`, y: `a?`, want: patternOverlap},
		{name: "cores that never line up", x: `?b`, y: `?a`, want: patternDisjoint},
		{name: "escaped wild card is literal", x: `4\.\**`, y: `4\.1*`, want: patternDisjoint},
		{name: "escaped wild card against itself", x: `4\.\**`, y: `4\.\*`, want: patternSuperset},
		{name: "star alone contains everything", x: `*`, y: `4\.*`, want: patternSuperset},
		{name: "trailing escaped question mark is part of the core", x: `a\?`, y: `a?`, want: patternSubset},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := relatePatterns(tt.x, tt.y); got != tt.want {
				t.Errorf("relatePatterns(%q, %q) = %v, want %v", tt.x, tt.y, got, tt.want)
			}
		})
	}
}

func TestParsePattern(t *testing.T) {
	tests := []struct {
		s    string
		want pattern
	}{
		{s: `*`, want: pattern{lead: unbounded, trail: 0, core: ""}},
		{s: `???`, want: pattern{lead: 3, trail: 0, core: ""}},
		{s: `*4\.1*`, want: pattern{lead: unbounded, trail: unbounded, core: "4.1"}},
		{s: `??A??`, want: pattern{lead: 2, trail: 2, core: "a"}},
		{s: `a\?`, want: pattern{lead: 0, trail: 0, core: "a?"}},
		{s: `a\\?`, want: pattern{lead: 0, trail: 1, core: `a\`}},
		{s: `4\.\**`, want: pattern{lead: 0, trail: unbounded, core: "4.*"}},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := parsePattern(tt.s); got != tt.want {
				t.Errorf("parsePattern(%q) = %+v, want %+v", tt.s, got, tt.want)
			}
		})
	}
}
